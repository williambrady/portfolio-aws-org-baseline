#!/usr/bin/env python3
"""
Enable AWS Config recorders in member accounts and management account.

This script handles two scenarios:

1. Standard mode (no Control Tower):
   - Enables Config recorders in member accounts (excludes management, audit, log-archive)
   - Uses the S3 bucket and KMS key created by Terraform

2. Control Tower mode:
   - Control Tower manages Config for audit, log-archive, and member accounts
   - BUT Control Tower 4.x does NOT manage Config for the management account
   - This script reads Config settings from the audit account (Control Tower reference)
   - Then applies those settings to the management account

Prerequisites:
- Terraform must have been applied
- Must be run from the management account with OrganizationAccountAccessRole available

Usage:
    # Dry run - show what would be enabled
    python enable-config-member-accounts.py --dry-run

    # Actually enable Config
    python enable-config-member-accounts.py
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

import boto3
import yaml
from botocore.exceptions import ClientError


def load_config() -> dict:
    """Load configuration from config.yaml."""
    config_path = Path("/work/config.yaml")
    if not config_path.exists():
        # Fallback for local development
        config_path = Path(__file__).parent.parent / "config.yaml"

    if not config_path.exists():
        print("Error: config.yaml not found")
        sys.exit(1)

    with open(config_path) as f:
        return yaml.safe_load(f)


def load_discovery_json() -> dict:
    """Load discovery.json to check for Control Tower."""
    discovery_path = Path("/work/terraform/discovery.json")
    if not discovery_path.exists():
        # Fallback for local development
        discovery_path = Path(__file__).parent.parent / "terraform" / "discovery.json"

    if not discovery_path.exists():
        return {}

    try:
        with open(discovery_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def is_control_tower_mode(discovery: dict, tf_outputs: dict) -> bool:
    """Determine if Control Tower is managing Config.

    Returns True if Control Tower exists AND Terraform Config outputs are missing
    (meaning the Config module was skipped).
    """
    control_tower_exists = discovery.get("control_tower_exists", False)
    config_s3_bucket = tf_outputs.get("config_s3_bucket")

    # Control Tower mode: CT exists and no Terraform Config outputs
    return control_tower_exists and not config_s3_bucket


def get_control_tower_config_settings(
    audit_account_id: str, primary_region: str
) -> dict:
    """Read Config settings from the audit account (Control Tower reference).

    Control Tower configures Config in the audit account, so we read those
    settings to apply to the management account.

    Returns dict with:
        - s3_bucket: S3 bucket name for Config delivery
        - s3_key_prefix: S3 key prefix (usually the org ID)
        - kms_key_arn: KMS key ARN (may be None)
        - delivery_frequency: Snapshot delivery frequency
        - error: Error message if failed
    """
    result = {
        "s3_bucket": None,
        "s3_key_prefix": None,
        "kms_key_arn": None,
        "delivery_frequency": "TwentyFour_Hours",
        "error": None,
    }

    # Assume role into audit account
    session = assume_role(audit_account_id, primary_region)
    if session is None:
        result["error"] = "Could not assume role into audit account"
        return result

    config_client = session.client("config", region_name=primary_region)

    try:
        # Get delivery channel settings
        channels = config_client.describe_delivery_channels()
        if channels.get("DeliveryChannels"):
            channel = channels["DeliveryChannels"][0]
            result["s3_bucket"] = channel.get("s3BucketName")
            result["s3_key_prefix"] = channel.get("s3KeyPrefix")
            result["kms_key_arn"] = channel.get("s3KmsKeyArn")

            delivery_props = channel.get("configSnapshotDeliveryProperties", {})
            result["delivery_frequency"] = delivery_props.get(
                "deliveryFrequency", "TwentyFour_Hours"
            )
    except ClientError as e:
        result["error"] = f"Could not read Config settings from audit account: {e}"

    return result


def enable_config_for_management_account(
    management_account_id: str,
    regions: list,
    config: dict,
    ct_config_settings: dict,
    primary_region: str,
    dry_run: bool = False,
) -> dict:
    """Enable Config for the management account using Control Tower settings.

    Unlike member accounts, we don't need to assume a role - we're already
    running in the management account.
    """
    account_result = {
        "account_id": management_account_id,
        "account_name": "Management Account",
        "slr_created": False,
        "slr_exists": False,
        "slr_error": None,
        "regions": {},
        "success": True,
    }

    s3_bucket = ct_config_settings.get("s3_bucket")
    s3_key_prefix = ct_config_settings.get("s3_key_prefix")
    kms_key_arn = ct_config_settings.get("kms_key_arn")
    delivery_frequency = ct_config_settings.get(
        "delivery_frequency", "TwentyFour_Hours"
    )

    if not s3_bucket:
        account_result["slr_error"] = "No S3 bucket found in Control Tower settings"
        account_result["success"] = False
        return account_result

    print("  Checking service-linked role...", end=" ", flush=True)

    # Check/create service-linked role (no role assumption needed for management)
    iam_client = boto3.client("iam", region_name=primary_region)

    if dry_run:
        try:
            iam_client.get_role(RoleName="AWSServiceRoleForConfig")
            account_result["slr_exists"] = True
            print("exists")
        except ClientError:
            account_result["slr_exists"] = False
            print("needs creation")
    else:
        try:
            iam_client.get_role(RoleName="AWSServiceRoleForConfig")
            account_result["slr_exists"] = True
            print("exists")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                try:
                    iam_client.create_service_linked_role(
                        AWSServiceName="config.amazonaws.com"
                    )
                    account_result["slr_created"] = True
                    print("created")
                except ClientError as create_err:
                    if (
                        "has been taken" in str(create_err)
                        or "already exists" in str(create_err).lower()
                    ):
                        account_result["slr_exists"] = True
                        print("exists")
                    else:
                        account_result["slr_error"] = str(create_err)
                        account_result["success"] = False
                        print(f"error: {create_err}")
                        return account_result
            else:
                account_result["slr_error"] = str(e)
                account_result["success"] = False
                print(f"error: {e}")
                return account_result

    expected_role_arn = f"arn:aws:iam::{management_account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

    print(f"  Scanning {len(regions)} regions...", end=" ", flush=True)

    regions_processed = 0
    for region in regions:
        is_primary = region == primary_region
        config_client = boto3.client("config", region_name=region)

        result = {
            "region": region,
            "enabled": False,
            "created_recorder": False,
            "created_channel": False,
            "updated_recorder": False,
            "updated_channel": False,
            "started": False,
            "already_correct": False,
            "would_enable": False,
            "would_update": False,
            "issues": [],
            "error": None,
        }

        # Check current status
        status = get_recorder_status(config_client)

        # Determine if updates are needed
        needs_recorder_update = False
        needs_channel_update = False

        if status["exists"]:
            if status["role_arn"] != expected_role_arn:
                needs_recorder_update = True
                result["issues"].append(
                    f"Wrong IAM role: {status['role_arn'] or 'None'} (expected SLR)"
                )

        if status["has_channel"]:
            if status["channel_s3_bucket"] != s3_bucket:
                needs_channel_update = True
                result["issues"].append(
                    f"Wrong S3 bucket: {status['channel_s3_bucket']} (expected {s3_bucket})"
                )
            if kms_key_arn and status["channel_kms_key"] != kms_key_arn:
                needs_channel_update = True
                result["issues"].append(
                    f"Wrong KMS key: {status['channel_kms_key'] or 'None'}"
                )

        # If everything is correct
        if (
            status["exists"]
            and status["has_channel"]
            and status["recording"]
            and not needs_recorder_update
            and not needs_channel_update
        ):
            result["already_correct"] = True
            result["enabled"] = True
            account_result["regions"][region] = result
            regions_processed += 1
            if regions_processed % 5 == 0:
                print(f"{regions_processed}", end=" ", flush=True)
            continue

        # Dry run mode
        if dry_run:
            if not status["exists"] or not status["has_channel"]:
                result["would_enable"] = True
            elif needs_recorder_update or needs_channel_update:
                result["would_update"] = True
            elif not status["recording"]:
                result["would_enable"] = True
            account_result["regions"][region] = result
            regions_processed += 1
            if regions_processed % 5 == 0:
                print(f"{regions_processed}", end=" ", flush=True)
            continue

        # Actually create/update
        try:
            recorder_name = status["name"] if status["exists"] else "default"
            channel_name = (
                status["channel_name"] if status["has_channel"] else "default"
            )

            recorder_config = {
                "name": recorder_name,
                "roleARN": expected_role_arn,
                "recordingGroup": {
                    "allSupported": True,
                    "includeGlobalResourceTypes": is_primary,
                },
                "recordingMode": {
                    "recordingFrequency": "CONTINUOUS",
                },
            }

            if not status["exists"]:
                config_client.put_configuration_recorder(
                    ConfigurationRecorder=recorder_config
                )
                result["created_recorder"] = True
            elif needs_recorder_update:
                config_client.put_configuration_recorder(
                    ConfigurationRecorder=recorder_config
                )
                result["updated_recorder"] = True

            channel_config = {
                "name": channel_name,
                "s3BucketName": s3_bucket,
                "configSnapshotDeliveryProperties": {
                    "deliveryFrequency": delivery_frequency,
                },
            }
            if s3_key_prefix:
                channel_config["s3KeyPrefix"] = s3_key_prefix
            if kms_key_arn:
                channel_config["s3KmsKeyArn"] = kms_key_arn

            if not status["has_channel"]:
                config_client.put_delivery_channel(DeliveryChannel=channel_config)
                result["created_channel"] = True
            elif needs_channel_update:
                config_client.put_delivery_channel(DeliveryChannel=channel_config)
                result["updated_channel"] = True

            if not status["recording"]:
                config_client.start_configuration_recorder(
                    ConfigurationRecorderName=recorder_name
                )
                result["started"] = True

            result["enabled"] = True

        except ClientError as e:
            result["error"] = str(e)
            account_result["success"] = False

        account_result["regions"][region] = result
        regions_processed += 1
        if regions_processed % 5 == 0:
            print(f"{regions_processed}", end=" ", flush=True)

    print("done")
    return account_result


def load_terraform_outputs() -> dict:
    """Load Terraform outputs for Config bucket/KMS details."""
    tf_dir = Path("/work/terraform")
    if not tf_dir.exists():
        # Fallback for local development
        tf_dir = Path(__file__).parent.parent / "terraform"

    try:
        result = subprocess.run(
            ["terraform", "output", "-json"],
            cwd=tf_dir,
            capture_output=True,
            text=True,
            check=True,
        )
        outputs = json.loads(result.stdout)
        # Extract values from Terraform output format
        return {k: v.get("value") for k, v in outputs.items()}
    except subprocess.CalledProcessError as e:
        print(f"Error getting Terraform outputs: {e.stderr}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing Terraform outputs: {e}")
        sys.exit(1)


def get_all_regions() -> list:
    """Get all active AWS regions."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    regions = ec2_client.describe_regions(AllRegions=False)["Regions"]
    return sorted([r["RegionName"] for r in regions])


def get_organization_accounts() -> list:
    """Get all accounts in the organization."""
    org_client = boto3.client("organizations", region_name="us-east-1")
    accounts = []

    try:
        paginator = org_client.get_paginator("list_accounts")
        for page in paginator.paginate():
            for account in page["Accounts"]:
                if account["Status"] == "ACTIVE":
                    accounts.append(
                        {
                            "id": account["Id"],
                            "name": account["Name"],
                        }
                    )
    except ClientError as e:
        print(f"Error listing accounts: {e}")
        sys.exit(1)

    return accounts


def get_excluded_account_ids(tf_outputs: dict) -> set:
    """Get account IDs managed by Terraform (management, audit, log-archive)."""
    excluded = set()

    # Management account
    if tf_outputs.get("management_account_id"):
        excluded.add(tf_outputs["management_account_id"])

    # Log archive account
    if tf_outputs.get("log_archive_account_id"):
        excluded.add(tf_outputs["log_archive_account_id"])

    # Audit account
    if tf_outputs.get("audit_account_id"):
        excluded.add(tf_outputs["audit_account_id"])

    # Security tooling account (if exists)
    if tf_outputs.get("security_tooling_account_id"):
        excluded.add(tf_outputs["security_tooling_account_id"])

    return excluded


def assume_role(account_id: str, region: str) -> boto3.Session:
    """Assume OrganizationAccountAccessRole in target account."""
    sts_client = boto3.client("sts", region_name=region)
    role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"

    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="org-baseline-config-enablement",
            DurationSeconds=900,
        )
        credentials = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region,
        )
    except ClientError:
        return None


def ensure_service_linked_role(session: boto3.Session) -> dict:
    """Create Config service-linked role if it doesn't exist.

    Returns dict with:
        - created: True if role was created
        - exists: True if role already existed
        - error: Error message if failed
    """
    result = {"created": False, "exists": False, "error": None}

    iam_client = session.client("iam")

    try:
        # Check if role exists
        iam_client.get_role(RoleName="AWSServiceRoleForConfig")
        result["exists"] = True
        return result
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            result["error"] = str(e)
            return result

    # Role doesn't exist, create it
    try:
        iam_client.create_service_linked_role(AWSServiceName="config.amazonaws.com")
        result["created"] = True
    except ClientError as e:
        if "has been taken" in str(e) or "already exists" in str(e).lower():
            # Race condition - role was created between check and create
            result["exists"] = True
        else:
            result["error"] = str(e)

    return result


def get_recorder_status(config_client) -> dict:
    """Get current Config recorder status with full configuration details.

    Returns dict with:
        - exists: True if recorder exists
        - name: Recorder name if exists
        - role_arn: IAM role ARN used by recorder
        - recording: True if currently recording
        - has_channel: True if delivery channel exists
        - channel_name: Delivery channel name
        - channel_s3_bucket: S3 bucket configured in delivery channel
        - channel_kms_key: KMS key ARN configured in delivery channel
    """
    result = {
        "exists": False,
        "name": None,
        "role_arn": None,
        "recording": False,
        "has_channel": False,
        "channel_name": None,
        "channel_s3_bucket": None,
        "channel_kms_key": None,
    }

    try:
        recorders = config_client.describe_configuration_recorders()
        if recorders.get("ConfigurationRecorders"):
            recorder = recorders["ConfigurationRecorders"][0]
            result["exists"] = True
            result["name"] = recorder["name"]
            result["role_arn"] = recorder.get("roleARN")

            # Check if recording
            status = config_client.describe_configuration_recorder_status()
            if status.get("ConfigurationRecordersStatus"):
                result["recording"] = status["ConfigurationRecordersStatus"][0].get(
                    "recording", False
                )
    except ClientError:
        pass

    try:
        channels = config_client.describe_delivery_channels()
        if channels.get("DeliveryChannels"):
            channel = channels["DeliveryChannels"][0]
            result["has_channel"] = True
            result["channel_name"] = channel.get("name")
            result["channel_s3_bucket"] = channel.get("s3BucketName")
            result["channel_kms_key"] = channel.get("s3KmsKeyArn")
    except ClientError:
        pass

    return result


def enable_config_recorder(
    session: boto3.Session,
    region: str,
    config: dict,
    tf_outputs: dict,
    is_primary_region: bool,
    dry_run: bool = False,
) -> dict:
    """Enable Config recorder in a single region.

    Ensures the recorder uses the Service-Linked Role and delivers to the
    central S3 bucket with KMS encryption. Updates existing configurations
    if they don't match the expected settings.

    Returns dict with:
        - enabled: True if Config is now enabled
        - created_recorder: True if recorder was created
        - created_channel: True if channel was created
        - updated_recorder: True if existing recorder was updated
        - updated_channel: True if existing channel was updated
        - started: True if recording was started
        - already_correct: True if existing config matches expected
        - would_enable: True if dry-run and would be created
        - would_update: True if dry-run and would be updated
        - issues: List of issues found with existing config
        - error: Error message if failed
    """
    result = {
        "region": region,
        "enabled": False,
        "created_recorder": False,
        "created_channel": False,
        "updated_recorder": False,
        "updated_channel": False,
        "started": False,
        "already_correct": False,
        "would_enable": False,
        "would_update": False,
        "issues": [],
        "error": None,
    }

    resource_prefix = config.get("resource_prefix", "org-baseline")
    recorder_name = f"{resource_prefix}-config-recorder"
    channel_name = f"{resource_prefix}-config-delivery"
    s3_bucket = tf_outputs.get("config_s3_bucket")
    kms_key_arn = tf_outputs.get("config_kms_key_arn")

    if not s3_bucket:
        result["error"] = "Config S3 bucket not found in Terraform outputs"
        return result

    config_client = session.client("config", region_name=region)

    # Get account ID for expected SLR ARN
    sts_client = session.client("sts")
    account_id = sts_client.get_caller_identity()["Account"]
    expected_role_arn = f"arn:aws:iam::{account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

    # Check current status
    status = get_recorder_status(config_client)

    # Determine if existing configuration needs updates
    needs_recorder_update = False
    needs_channel_update = False

    if status["exists"]:
        # Check if using the correct Service-Linked Role
        if status["role_arn"] != expected_role_arn:
            needs_recorder_update = True
            result["issues"].append(
                f"Wrong IAM role: {status['role_arn'] or 'None'} (expected SLR)"
            )

    if status["has_channel"]:
        # Check if delivering to the correct S3 bucket
        if status["channel_s3_bucket"] != s3_bucket:
            needs_channel_update = True
            result["issues"].append(
                f"Wrong S3 bucket: {status['channel_s3_bucket']} (expected {s3_bucket})"
            )

        # Check if using the correct KMS key
        if kms_key_arn and status["channel_kms_key"] != kms_key_arn:
            needs_channel_update = True
            result["issues"].append(
                f"Wrong KMS key: {status['channel_kms_key'] or 'None'}"
            )

    # If everything exists and is correct, we're done
    if (
        status["exists"]
        and status["has_channel"]
        and status["recording"]
        and not needs_recorder_update
        and not needs_channel_update
    ):
        result["already_correct"] = True
        result["enabled"] = True
        return result

    # In dry-run mode, report what would be done
    if dry_run:
        if not status["exists"] or not status["has_channel"]:
            result["would_enable"] = True
        elif needs_recorder_update or needs_channel_update:
            result["would_update"] = True
        elif not status["recording"]:
            result["would_enable"] = True  # Would start recording
        return result

    try:
        # Create or update recorder
        recorder_config = {
            "name": status["name"] if status["exists"] else recorder_name,
            "roleARN": expected_role_arn,
            "recordingGroup": {
                "allSupported": True,
                "includeGlobalResourceTypes": is_primary_region,
            },
            "recordingMode": {
                "recordingFrequency": "CONTINUOUS",
            },
        }

        if not status["exists"]:
            config_client.put_configuration_recorder(
                ConfigurationRecorder=recorder_config
            )
            result["created_recorder"] = True
        elif needs_recorder_update:
            config_client.put_configuration_recorder(
                ConfigurationRecorder=recorder_config
            )
            result["updated_recorder"] = True

        # Create or update delivery channel
        channel_config = {
            "name": status["channel_name"] if status["has_channel"] else channel_name,
            "s3BucketName": s3_bucket,
            "configSnapshotDeliveryProperties": {
                "deliveryFrequency": "TwentyFour_Hours",
            },
        }

        if kms_key_arn:
            channel_config["s3KmsKeyArn"] = kms_key_arn

        if not status["has_channel"]:
            config_client.put_delivery_channel(DeliveryChannel=channel_config)
            result["created_channel"] = True
        elif needs_channel_update:
            config_client.put_delivery_channel(DeliveryChannel=channel_config)
            result["updated_channel"] = True

        # Start recording if not already recording
        actual_recorder_name = status["name"] if status["exists"] else recorder_name
        if not status["recording"]:
            config_client.start_configuration_recorder(
                ConfigurationRecorderName=actual_recorder_name
            )
            result["started"] = True

        result["enabled"] = True

    except ClientError as e:
        result["error"] = str(e)

    return result


def enable_config_for_account(
    account: dict,
    regions: list,
    config: dict,
    tf_outputs: dict,
    dry_run: bool = False,
    verbose: bool = True,
) -> dict:
    """Enable Config for a single account across all regions."""
    account_result = {
        "account_id": account["id"],
        "account_name": account["name"],
        "slr_created": False,
        "slr_exists": False,
        "slr_error": None,
        "regions": {},
        "success": True,
    }

    primary_region = config.get("primary_region", "us-east-1")

    if verbose:
        print("  Checking service-linked role...", end=" ", flush=True)

    # First, check/ensure service-linked role exists (only need to do this once per account)
    # Use primary region for IAM operations
    session = assume_role(account["id"], primary_region)
    if session is None:
        if verbose:
            print("failed (could not assume role)")
        account_result["slr_error"] = "Could not assume role"
        account_result["success"] = False
        return account_result

    if dry_run:
        # In dry-run mode, just check if SLR exists
        iam_client = session.client("iam")
        try:
            iam_client.get_role(RoleName="AWSServiceRoleForConfig")
            account_result["slr_exists"] = True
            if verbose:
                print("exists")
        except ClientError:
            account_result["slr_exists"] = False
            if verbose:
                print("needs creation")
    else:
        slr_result = ensure_service_linked_role(session)
        if slr_result.get("error"):
            if verbose:
                print(f"error: {slr_result['error']}")
            account_result["slr_error"] = slr_result["error"]
            account_result["success"] = False
            return account_result
        account_result["slr_created"] = slr_result.get("created", False)
        account_result["slr_exists"] = slr_result.get("exists", False)
        if verbose:
            if slr_result.get("created"):
                print("created")
            else:
                print("exists")

    # Enable Config in each region
    if verbose:
        print(f"  Scanning {len(regions)} regions...", end=" ", flush=True)

    regions_processed = 0
    for region in regions:
        # Reuse session if same region, otherwise create new one
        if region != primary_region:
            session = assume_role(account["id"], region)
            if session is None:
                account_result["regions"][region] = {
                    "enabled": False,
                    "error": "Could not assume role",
                }
                account_result["success"] = False
                continue

        is_primary = region == primary_region
        result = enable_config_recorder(
            session, region, config, tf_outputs, is_primary, dry_run=dry_run
        )
        account_result["regions"][region] = result

        if result.get("error"):
            account_result["success"] = False

        regions_processed += 1
        if verbose and regions_processed % 5 == 0:
            # Show progress every 5 regions
            print(f"{regions_processed}", end=" ", flush=True)

    if verbose:
        print("done")

    return account_result


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Enable AWS Config recorders in member accounts"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be enabled without making changes",
    )
    return parser.parse_args()


def main():
    """Main function."""
    args = parse_args()
    dry_run = args.dry_run

    if dry_run:
        print("=" * 60)
        print("  AWS Config Enablement - DRY RUN")
        print("=" * 60)
    else:
        print("=" * 60)
        print("  AWS Config Enablement")
        print("=" * 60)
    print("")

    # Load configuration
    print("Loading configuration...")
    config = load_config()
    resource_prefix = config.get("resource_prefix", "org-baseline")
    primary_region = config.get("primary_region", "us-east-1")
    print(f"  Resource prefix: {resource_prefix}")
    print(f"  Primary region: {primary_region}")
    print("")

    # Load discovery results and Terraform outputs
    print("Loading discovery results and Terraform outputs...")
    discovery = load_discovery_json()
    tf_outputs = load_terraform_outputs()

    s3_bucket = tf_outputs.get("config_s3_bucket")
    kms_key = tf_outputs.get("config_kms_key_arn")

    # Check for Control Tower mode
    control_tower_mode = is_control_tower_mode(discovery, tf_outputs)

    if control_tower_mode:
        print("Control Tower detected - Config is managed by Control Tower.")
        print("")
        print("Control Tower 4.x manages Config for:")
        print("  - Audit account")
        print("  - Log archive account")
        print("  - All member accounts")
        print("")
        print(
            "However, Control Tower does NOT manage Config for the management account."
        )
        print(
            "This script will configure the management account to match Control Tower settings."
        )
        print("")

        # Get management account ID
        management_account_id = tf_outputs.get("management_account_id")
        audit_account_id = tf_outputs.get("audit_account_id")

        if not management_account_id or not audit_account_id:
            print("Error: Could not determine management or audit account IDs.")
            print("Ensure Terraform has been applied first.")
            return 1

        # Get all regions
        print("Getting AWS regions...")
        regions = get_all_regions()
        print(f"Found {len(regions)} regions")
        print("")

        # Read Config settings from audit account (Control Tower reference)
        print(f"Reading Config settings from audit account ({audit_account_id})...")
        ct_config_settings = get_control_tower_config_settings(
            audit_account_id, primary_region
        )

        if ct_config_settings.get("error"):
            print(f"Error: {ct_config_settings['error']}")
            return 1

        print(f"  S3 bucket: {ct_config_settings.get('s3_bucket')}")
        print(f"  S3 key prefix: {ct_config_settings.get('s3_key_prefix') or 'None'}")
        print(f"  KMS key: {ct_config_settings.get('kms_key_arn') or 'None (SSE-S3)'}")
        print(f"  Delivery frequency: {ct_config_settings.get('delivery_frequency')}")
        print("")

        if dry_run:
            print("Checking management account Config status...")
        else:
            print("Enabling Config for management account...")

        print(f"Processing Management Account ({management_account_id})...")

        result = enable_config_for_management_account(
            management_account_id,
            regions,
            config,
            ct_config_settings,
            primary_region,
            dry_run=dry_run,
        )

        # Summarize results
        print("")
        print("=" * 60)
        if dry_run:
            print("  Control Tower Mode - Dry Run Summary")
        else:
            print("  Control Tower Mode - Summary")
        print("=" * 60)

        total_would_enable = 0
        total_would_update = 0
        total_enabled = 0
        total_updated = 0
        total_already_correct = 0
        total_errors = 0
        issues = []

        for region, region_result in result.get("regions", {}).items():
            if region_result.get("error"):
                total_errors += 1
            elif region_result.get("already_correct"):
                total_already_correct += 1
            elif region_result.get("would_enable"):
                total_would_enable += 1
            elif region_result.get("would_update"):
                total_would_update += 1
                issues.extend(region_result.get("issues", []))
            elif region_result.get("created_recorder") or region_result.get(
                "created_channel"
            ):
                total_enabled += 1
            elif region_result.get("updated_recorder") or region_result.get(
                "updated_channel"
            ):
                total_updated += 1

        if dry_run:
            if not result.get("slr_exists"):
                print("  Service-linked role: needs creation")
            else:
                print("  Service-linked role: exists")
            print(f"  Regions to enable: {total_would_enable}")
            print(f"  Regions to update (misconfigured): {total_would_update}")
            print(f"  Regions already correct: {total_already_correct}")
            print(f"  Errors: {total_errors}")
            print("")

            if issues:
                print("Issues that would be fixed:")
                # Deduplicate issues
                issue_counts = {}
                for issue in issues:
                    issue_counts[issue] = issue_counts.get(issue, 0) + 1
                for issue, count in sorted(issue_counts.items(), key=lambda x: -x[1]):
                    print(f"  - {issue} ({count} regions)")
                print("")

            total_changes = total_would_enable + total_would_update
            if total_changes > 0:
                print(
                    f"Dry run complete - {total_changes} region(s) would be changed in management account."
                )
                print("Run without --dry-run to apply changes.")
            else:
                print(
                    "Dry run complete - management account already correctly configured."
                )
        else:
            if result.get("slr_created"):
                print("  Service-linked role: created")
            else:
                print("  Service-linked role: exists")
            print(f"  Regions newly enabled: {total_enabled}")
            print(f"  Regions updated: {total_updated}")
            print(f"  Regions already correct: {total_already_correct}")
            print(f"  Errors: {total_errors}")
            print("")

            if total_errors > 0:
                print("Some regions had errors. Review the output above.")
                return 1

            print("Config enablement complete for management account!")
            print("")
            print("Note: Control Tower manages Config for all other accounts.")

        return 0

    # Standard mode (no Control Tower) - configure member accounts
    if not s3_bucket:
        print("Config S3 bucket not found in Terraform outputs.")
        print("")
        print("This can happen if:")
        print("  - Terraform hasn't been applied yet")
        print("  - An existing organization Config aggregator was detected")
        print("")
        print("No Config enablement needed.")
        return 0  # Not an error - just nothing to do

    print(f"  Config S3 bucket: {s3_bucket}")
    print(f"  Config KMS key: {kms_key or 'None (using SSE-S3)'}")
    print("")

    # Get excluded accounts (managed by Terraform)
    excluded_ids = get_excluded_account_ids(tf_outputs)
    print(f"Accounts managed by Terraform (excluded): {len(excluded_ids)}")
    for account_id in sorted(excluded_ids):
        print(f"  - {account_id}")
    print("")

    # Get all regions
    print("Getting AWS regions...")
    regions = get_all_regions()
    print(f"Found {len(regions)} regions")
    print("")

    # Get all organization accounts
    print("Getting organization accounts...")
    all_accounts = get_organization_accounts()
    print(f"Found {len(all_accounts)} active accounts")

    # Filter to member accounts only
    member_accounts = [a for a in all_accounts if a["id"] not in excluded_ids]
    print(f"Member accounts to configure: {len(member_accounts)}")
    print("")

    if not member_accounts:
        print("No member accounts to configure.")
        if dry_run:
            print("Dry run complete - no changes would be made.")
        else:
            print("Config enablement complete!")
        return 0

    # Process each member account
    total_enabled = 0
    total_updated = 0
    total_would_enable = 0
    total_would_update = 0
    total_already_correct = 0
    total_errors = 0
    total_slr_created = 0
    total_slr_would_create = 0
    all_issues = []  # Collect issues for summary

    for account in member_accounts:
        print(f"Processing {account['name']} ({account['id']})...")

        result = enable_config_for_account(
            account, regions, config, tf_outputs, dry_run=dry_run
        )

        if dry_run:
            if not result.get("slr_exists"):
                total_slr_would_create += 1
                print("  Would create service-linked role")
        else:
            if result.get("slr_created"):
                total_slr_created += 1
                print("  Created service-linked role")

        if result.get("slr_error"):
            print(f"  Error with SLR: {result['slr_error']}")
            total_errors += 1
            continue

        enabled_regions = []
        updated_regions = []
        would_enable_regions = []
        would_update_regions = []
        already_correct_regions = []
        error_regions = []
        account_issues = []

        for region, region_result in result["regions"].items():
            if region_result.get("error"):
                error_regions.append(f"{region}: {region_result['error']}")
                total_errors += 1
            elif region_result.get("already_correct"):
                already_correct_regions.append(region)
                total_already_correct += 1
            elif region_result.get("would_update"):
                would_update_regions.append(region)
                total_would_update += 1
                # Collect issues for this region
                for issue in region_result.get("issues", []):
                    account_issues.append(f"{region}: {issue}")
            elif region_result.get("would_enable"):
                would_enable_regions.append(region)
                total_would_enable += 1
            elif region_result.get("updated_recorder") or region_result.get(
                "updated_channel"
            ):
                updated_regions.append(region)
                total_updated += 1
            elif region_result.get("enabled"):
                enabled_regions.append(region)
                total_enabled += 1

        if dry_run:
            if would_enable_regions:
                print(f"  Would enable Config in: {len(would_enable_regions)} regions")
            if would_update_regions:
                print(f"  Would update Config in: {len(would_update_regions)} regions")
                # Show issues that would be fixed
                for issue in account_issues[:3]:
                    print(f"    - {issue}")
                if len(account_issues) > 3:
                    print(f"    ... and {len(account_issues) - 3} more issues")
                all_issues.extend(account_issues)
            if already_correct_regions:
                print(f"  Already correct: {len(already_correct_regions)} regions")
        else:
            if enabled_regions:
                print(f"  Enabled Config in: {len(enabled_regions)} regions")
            if updated_regions:
                print(f"  Updated Config in: {len(updated_regions)} regions")
            if already_correct_regions:
                print(f"  Already correct: {len(already_correct_regions)} regions")

        if error_regions:
            for err in error_regions[:3]:  # Show first 3 errors
                print(f"  Error: {err}")
            if len(error_regions) > 3:
                print(f"  ... and {len(error_regions) - 3} more errors")

    # Summary
    print("")
    print("=" * 60)
    if dry_run:
        print("  Dry Run Summary")
    else:
        print("  Summary")
    print("=" * 60)
    print(f"  Member accounts processed: {len(member_accounts)}")

    if dry_run:
        print(f"  Service-linked roles to create: {total_slr_would_create}")
        print(f"  Regions to enable: {total_would_enable}")
        print(f"  Regions to update (misconfigured): {total_would_update}")
        print(f"  Regions already correct: {total_already_correct}")
        print(f"  Errors: {total_errors}")
        print("")

        if total_would_update > 0:
            print("Issues that would be fixed:")
            # Deduplicate and summarize issues
            issue_counts = {}
            for issue in all_issues:
                # Extract the issue type (after the region:)
                issue_type = issue.split(": ", 1)[1] if ": " in issue else issue
                issue_counts[issue_type] = issue_counts.get(issue_type, 0) + 1
            for issue_type, count in sorted(issue_counts.items(), key=lambda x: -x[1]):
                print(f"  - {issue_type} ({count} regions)")
            print("")

        if total_would_enable > 0 or total_would_update > 0:
            total_changes = total_would_enable + total_would_update
            print(f"Dry run complete - {total_changes} region(s) would be changed.")
            print("Run without --dry-run to apply changes.")
        else:
            print("Dry run complete - all regions correctly configured.")
    else:
        print(f"  Service-linked roles created: {total_slr_created}")
        print(f"  Regions newly enabled: {total_enabled}")
        print(f"  Regions updated: {total_updated}")
        print(f"  Regions already correct: {total_already_correct}")
        print(f"  Errors: {total_errors}")
        print("")

        if total_errors > 0:
            print("Some regions had errors. Review the output above.")
            return 1

        print("Config enablement complete!")
        print("")
        print("Note: The Config aggregator in the audit account will automatically")
        print("      collect data from all member accounts once recorders are active.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
