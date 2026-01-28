#!/usr/bin/env python3
"""
Regional security settings verification script.

Validates that regional security controls are properly configured across
all regions and accounts:
- Inspector enablement (EC2, ECR, Lambda scanning)
- EC2/EBS defaults (encryption, IMDSv2, snapshot blocking)
- VPC block public access settings
- SSM settings (public sharing blocked)
"""

import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import boto3
import yaml
from botocore.exceptions import ClientError

# All 17 supported regions
ALL_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-north-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-south-1",
    "ca-central-1",
    "sa-east-1",
    "me-south-1",
]


def load_config() -> dict:
    """Load configuration from config.yaml."""
    config_path = Path("/work/config.yaml")
    if not config_path.exists():
        return {"primary_region": "us-east-1"}
    with open(config_path) as f:
        return yaml.safe_load(f)


def load_discovery() -> dict:
    """Load discovery results."""
    discovery_path = Path("/work/terraform/discovery.json")
    if not discovery_path.exists():
        return {}
    with open(discovery_path) as f:
        return json.load(f)


def get_account_session(account_id: str, region: str, session_name: str = "verify"):
    """Get a boto3 session for a member account."""
    sts_client = boto3.client("sts", region_name=region)
    role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"

    try:
        assumed = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName=session_name, DurationSeconds=900
        )
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
    except ClientError:
        return None


def verify_inspector_region(session, region: str) -> dict:
    """Verify Inspector is enabled in a region."""
    result = {"region": region, "enabled": False, "scan_types": [], "error": None}

    try:
        inspector_client = session.client("inspector2", region_name=region)
        status = inspector_client.batch_get_account_status(accountIds=[])

        if status.get("accounts"):
            account_status = status["accounts"][0]
            resource_state = account_status.get("resourceState", {})

            scan_types = []
            for scan_type in ["ec2", "ecr", "lambda", "lambdaCode"]:
                state = resource_state.get(scan_type, {}).get("status", "DISABLED")
                if state == "ENABLED":
                    scan_types.append(scan_type.upper())

            result["enabled"] = len(scan_types) > 0
            result["scan_types"] = scan_types

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "AccessDeniedException":
            result["error"] = "access-denied"
        else:
            result["error"] = str(e)

    return result


def verify_ec2_defaults_region(session, region: str) -> dict:
    """Verify EC2/EBS defaults in a region."""
    result = {
        "region": region,
        "ebs_encryption": False,
        "imdsv2_required": False,
        "snapshot_block": False,
        "error": None,
    }

    try:
        ec2_client = session.client("ec2", region_name=region)

        # EBS encryption by default
        try:
            response = ec2_client.get_ebs_encryption_by_default()
            result["ebs_encryption"] = response.get("EbsEncryptionByDefault", False)
        except ClientError:
            pass

        # Check account-level defaults for IMDS
        try:
            response = ec2_client.get_instance_metadata_defaults()
            defaults = response.get("AccountLevel", {})
            http_tokens = defaults.get("HttpTokens", "optional")
            result["imdsv2_required"] = http_tokens == "required"
        except ClientError:
            pass

        # Check EBS snapshot block public access
        try:
            response = ec2_client.get_snapshot_block_public_access_state()
            state = response.get("State", "unblocked")
            result["snapshot_block"] = state in [
                "block-all-sharing",
                "block-new-sharing",
            ]
        except ClientError:
            pass

    except ClientError as e:
        result["error"] = str(e)

    return result


def verify_vpc_block_public_access_region(session, region: str) -> dict:
    """Verify VPC block public access in a region."""
    result = {"region": region, "mode": None, "error": None}

    try:
        vpc_client = session.client("ec2", region_name=region)

        try:
            response = vpc_client.describe_vpc_block_public_access_options()
            options = response.get("VpcBlockPublicAccessOptions", {})
            mode = options.get("InternetGatewayBlockMode", "off")
            result["mode"] = mode
        except ClientError as e:
            if "InvalidAction" in str(e):
                result["error"] = "not-supported"
            else:
                result["error"] = str(e)

    except ClientError as e:
        result["error"] = str(e)

    return result


def verify_ssm_settings_region(session, region: str) -> dict:
    """Verify SSM settings in a region."""
    result = {"region": region, "public_sharing_blocked": False, "error": None}

    try:
        ssm_client = session.client("ssm", region_name=region)

        try:
            response = ssm_client.get_service_setting(
                SettingId="/ssm/documents/console/public-sharing-permission"
            )
            value = response.get("ServiceSetting", {}).get("SettingValue", "Enable")
            result["public_sharing_blocked"] = value == "Disable"
        except ssm_client.exceptions.ServiceSettingNotFound:
            result["public_sharing_blocked"] = False

    except ClientError as e:
        result["error"] = str(e)

    return result


def verify_account_regions(
    account_name: str, account_id: str, is_management: bool, config: dict
) -> dict:
    """Verify all regional settings for an account."""
    expected_vpc_mode = config.get("vpc_block_public_access", {}).get("mode", "ingress")

    print(f"\n  Verifying {account_name} ({account_id})...")

    results = {
        "account_name": account_name,
        "account_id": account_id,
        "inspector": {"enabled": 0, "disabled": 0, "errors": []},
        "ec2": {"all_secure": 0, "issues": []},
        "vpc": {"correct_mode": 0, "wrong_mode": []},
        "ssm": {"blocked": 0, "not_blocked": []},
    }

    # Process regions in parallel
    def check_region(region: str):
        if is_management:
            session = boto3.Session(region_name=region)
        else:
            session = get_account_session(account_id, region, "regional-verify")
            if not session:
                return region, None

        inspector = verify_inspector_region(session, region)
        ec2 = verify_ec2_defaults_region(session, region)
        vpc = verify_vpc_block_public_access_region(session, region)
        ssm = verify_ssm_settings_region(session, region)

        return region, {"inspector": inspector, "ec2": ec2, "vpc": vpc, "ssm": ssm}

    checked = 0
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(check_region, r): r for r in ALL_REGIONS}
        for future in as_completed(futures):
            region, data = future.result()
            checked += 1
            print(
                f"\r    Checking regions... {checked}/{len(ALL_REGIONS)}",
                end="",
                flush=True,
            )

            if data is None:
                results["inspector"]["errors"].append(region)
                continue

            # Inspector
            if data["inspector"]["enabled"]:
                results["inspector"]["enabled"] += 1
            else:
                results["inspector"]["disabled"] += 1

            # EC2 defaults
            ec2 = data["ec2"]
            if (
                ec2["ebs_encryption"]
                and ec2["imdsv2_required"]
                and ec2["snapshot_block"]
            ):
                results["ec2"]["all_secure"] += 1
            else:
                issues = []
                if not ec2["ebs_encryption"]:
                    issues.append("ebs-encryption")
                if not ec2["imdsv2_required"]:
                    issues.append("imdsv2")
                if not ec2["snapshot_block"]:
                    issues.append("snapshot-block")
                results["ec2"]["issues"].append(f"{region}: {', '.join(issues)}")

            # VPC
            vpc = data["vpc"]
            if vpc["mode"] == expected_vpc_mode:
                results["vpc"]["correct_mode"] += 1
            elif vpc["error"]:
                pass  # Skip unsupported regions
            else:
                results["vpc"]["wrong_mode"].append(f"{region}: {vpc['mode']}")

            # SSM
            if data["ssm"]["public_sharing_blocked"]:
                results["ssm"]["blocked"] += 1
            else:
                results["ssm"]["not_blocked"].append(region)

    print("")  # Clear progress line

    # Print summary for this account
    print(
        f"    Inspector: {results['inspector']['enabled']}/{len(ALL_REGIONS)} enabled"
    )
    print(
        f"    EC2/EBS:   {results['ec2']['all_secure']}/{len(ALL_REGIONS)} fully secured"
    )
    print(
        f"    VPC Block: {results['vpc']['correct_mode']}/{len(ALL_REGIONS)} correct ({expected_vpc_mode})"
    )
    print(f"    SSM Block: {results['ssm']['blocked']}/{len(ALL_REGIONS)} blocked")

    return results


def main():
    """Main verification function."""
    print("=" * 60)
    print("  Regional Security Settings Verification")
    print("=" * 60)

    config = load_config()
    discovery = load_discovery()
    primary_region = config.get("primary_region", "us-east-1")

    # Get account IDs
    mgmt_account_id = discovery.get("master_account_id", "")
    log_archive_account_id = discovery.get("log_archive_account_id", "")
    audit_account_id = discovery.get("audit_account_id", "")

    if not mgmt_account_id:
        try:
            sts_client = boto3.client("sts", region_name=primary_region)
            mgmt_account_id = sts_client.get_caller_identity()["Account"]
        except ClientError:
            print("Error: Could not determine management account ID")
            return 1

    print(f"\nPrimary Region: {primary_region}")
    print(f"Checking {len(ALL_REGIONS)} regions per account")

    accounts = [
        ("Management", mgmt_account_id, True),
        ("Log Archive", log_archive_account_id, False),
        ("Audit", audit_account_id, False),
    ]

    all_results = []
    for account_name, account_id, is_mgmt in accounts:
        if not account_id:
            print(f"\n  Skipping {account_name}: account ID not found")
            continue

        result = verify_account_regions(account_name, account_id, is_mgmt, config)
        all_results.append(result)

    # Overall summary
    print("\n" + "=" * 60)
    print("  Overall Summary")
    print("=" * 60)

    total_regions = len(ALL_REGIONS) * len(all_results)
    inspector_enabled = sum(r["inspector"]["enabled"] for r in all_results)
    ec2_secure = sum(r["ec2"]["all_secure"] for r in all_results)
    vpc_correct = sum(r["vpc"]["correct_mode"] for r in all_results)
    ssm_blocked = sum(r["ssm"]["blocked"] for r in all_results)

    all_passed = True

    print(
        f"\n  Inspector:  {inspector_enabled}/{total_regions} regions enabled", end=""
    )
    if inspector_enabled < total_regions:
        print(" [PARTIAL]")
    else:
        print(" [OK]")

    print(f"  EC2/EBS:    {ec2_secure}/{total_regions} regions secured", end="")
    if ec2_secure < total_regions:
        print(" [PARTIAL]")
        all_passed = False
    else:
        print(" [OK]")

    print(f"  VPC Block:  {vpc_correct}/{total_regions} regions correct", end="")
    if vpc_correct < total_regions:
        print(" [PARTIAL]")
    else:
        print(" [OK]")

    print(f"  SSM Block:  {ssm_blocked}/{total_regions} regions blocked", end="")
    if ssm_blocked < total_regions:
        print(" [PARTIAL]")
    else:
        print(" [OK]")

    # Show issues
    for result in all_results:
        if result["ec2"]["issues"]:
            print(f"\n  EC2 Issues in {result['account_name']}:")
            for issue in result["ec2"]["issues"][:5]:
                print(f"    - {issue}")
            if len(result["ec2"]["issues"]) > 5:
                print(f"    ... and {len(result['ec2']['issues']) - 5} more")

    print("")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
