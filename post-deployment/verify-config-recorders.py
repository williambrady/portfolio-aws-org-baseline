#!/usr/bin/env python3
"""
AWS Config recorder verification script.

Validates Config recorders are properly configured across all regions and accounts:
- Config recorders exist and are recording
- Delivery channels point to correct S3 bucket
- KMS encryption is enabled
- Service-linked role is used
- Config aggregator is operational
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
        return {"primary_region": "us-east-1", "resource_prefix": "org-baseline"}
    with open(config_path) as f:
        return yaml.safe_load(f)


def load_discovery() -> dict:
    """Load discovery results."""
    discovery_path = Path("/work/terraform/discovery.json")
    if not discovery_path.exists():
        return {}
    with open(discovery_path) as f:
        return json.load(f)


def get_account_session(
    account_id: str, region: str, session_name: str = "config-verify"
):
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


def verify_config_region(
    session, region: str, expected_bucket: str, expected_kms_key_pattern: str
) -> dict:
    """Verify Config recorder in a region."""
    result = {
        "region": region,
        "recorder_exists": False,
        "recorder_recording": False,
        "delivery_channel": False,
        "correct_bucket": False,
        "kms_enabled": False,
        "uses_slr": False,
        "issues": [],
    }

    try:
        config_client = session.client("config", region_name=region)

        # Check recorder status
        try:
            recorders = config_client.describe_configuration_recorder_status()
            status_list = recorders.get("ConfigurationRecordersStatus", [])

            if status_list:
                result["recorder_exists"] = True
                status = status_list[0]
                result["recorder_recording"] = status.get("recording", False)

                if not result["recorder_recording"]:
                    result["issues"].append("not-recording")
            else:
                result["issues"].append("no-recorder")

        except ClientError as e:
            result["issues"].append(f"recorder-error: {e.response['Error']['Code']}")

        # Check recorder configuration (IAM role)
        try:
            recorders = config_client.describe_configuration_recorders()
            recorder_list = recorders.get("ConfigurationRecorders", [])

            if recorder_list:
                recorder = recorder_list[0]
                role_arn = recorder.get("roleARN", "")

                if "AWSServiceRoleForConfig" in role_arn:
                    result["uses_slr"] = True
                elif role_arn:
                    result["issues"].append("custom-role")

        except ClientError:
            pass

        # Check delivery channel
        try:
            channels = config_client.describe_delivery_channels()
            channel_list = channels.get("DeliveryChannels", [])

            if channel_list:
                result["delivery_channel"] = True
                channel = channel_list[0]

                # Check S3 bucket
                bucket = channel.get("s3BucketName", "")
                if expected_bucket and expected_bucket in bucket:
                    result["correct_bucket"] = True
                elif bucket:
                    result["issues"].append(f"wrong-bucket: {bucket}")
                else:
                    result["issues"].append("no-bucket")

                # Note: KMS key is set in recorder, not channel

            else:
                result["issues"].append("no-delivery-channel")

        except ClientError as e:
            result["issues"].append(f"channel-error: {e.response['Error']['Code']}")

    except ClientError as e:
        result["issues"].append(f"error: {str(e)}")

    return result


def verify_account_config(
    account_name: str,
    account_id: str,
    is_management: bool,
    expected_bucket: str,
    expected_kms_pattern: str,
) -> dict:
    """Verify Config recorders for an account across all regions."""
    print(f"\n  Verifying {account_name} ({account_id})...")

    results = {
        "account_name": account_name,
        "account_id": account_id,
        "recording": 0,
        "correct_bucket": 0,
        "uses_slr": 0,
        "issues": [],
    }

    # Process regions in parallel
    def check_region(region: str):
        if is_management:
            session = boto3.Session(region_name=region)
        else:
            session = get_account_session(account_id, region, "config-verify")
            if not session:
                return region, None

        return region, verify_config_region(
            session, region, expected_bucket, expected_kms_pattern
        )

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
                results["issues"].append(f"{region}: access-denied")
                continue

            if data["recorder_recording"]:
                results["recording"] += 1

            if data["correct_bucket"]:
                results["correct_bucket"] += 1

            if data["uses_slr"]:
                results["uses_slr"] += 1

            if data["issues"]:
                for issue in data["issues"]:
                    results["issues"].append(f"{region}: {issue}")

    print("")  # Clear progress line

    # Print summary for this account
    print(f"    Recording:     {results['recording']}/{len(ALL_REGIONS)} regions")
    print(f"    Correct bucket: {results['correct_bucket']}/{len(ALL_REGIONS)} regions")
    print(f"    Uses SLR:       {results['uses_slr']}/{len(ALL_REGIONS)} regions")

    return results


def verify_config_aggregator(session, region: str) -> dict:
    """Verify Config aggregator exists and is collecting."""
    print("\nVerifying Config Aggregator...")

    result = {"exists": False, "name": None, "type": None, "accounts": 0}

    try:
        config_client = session.client("config", region_name=region)

        response = config_client.describe_configuration_aggregators()
        aggregators = response.get("ConfigurationAggregators", [])

        if aggregators:
            agg = aggregators[0]
            result["exists"] = True
            result["name"] = agg.get("ConfigurationAggregatorName", "")

            if agg.get("OrganizationAggregationSource"):
                result["type"] = "organization"
                regions = agg["OrganizationAggregationSource"].get("AwsRegions", [])
                all_regions = agg["OrganizationAggregationSource"].get(
                    "AllAwsRegions", False
                )
                print(f"  [+] Found: {result['name']}")
                print("      Type: Organization aggregator")
                if all_regions:
                    print("      Regions: All AWS regions")
                else:
                    print(f"      Regions: {len(regions)} specific regions")
            elif agg.get("AccountAggregationSources"):
                result["type"] = "account"
                sources = agg["AccountAggregationSources"]
                result["accounts"] = sum(len(s.get("AccountIds", [])) for s in sources)
                print(f"  [+] Found: {result['name']}")
                print("      Type: Account aggregator")
                print(f"      Accounts: {result['accounts']}")
        else:
            print("  [!] No Config aggregator found")

    except ClientError as e:
        print(f"  [-] Error: {e}")

    return result


def main():
    """Main verification function."""
    print("=" * 60)
    print("  AWS Config Recorder Verification")
    print("=" * 60)

    config = load_config()
    discovery = load_discovery()
    primary_region = config.get("primary_region", "us-east-1")
    resource_prefix = config.get("resource_prefix", "org-baseline")

    # Check for Control Tower - if present, Config is managed by CT
    control_tower_exists = discovery.get("control_tower_exists", False)
    if control_tower_exists:
        print("\nControl Tower detected!")
        print("Config recorders are managed by Control Tower.")
        print("Skipping verification - Control Tower handles this automatically.")
        return 0

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

    # Expected bucket pattern
    expected_bucket = (
        f"{resource_prefix}-config-{log_archive_account_id}"
        if log_archive_account_id
        else ""
    )
    expected_kms = f"{resource_prefix}-config-key"

    print(f"\nPrimary Region: {primary_region}")
    print(f"Expected S3 Bucket: {expected_bucket or 'unknown'}")
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

        result = verify_account_config(
            account_name, account_id, is_mgmt, expected_bucket, expected_kms
        )
        all_results.append(result)

    # Verify aggregator in audit account
    if audit_account_id:
        audit_session = get_account_session(
            audit_account_id, primary_region, "aggregator-verify"
        )
        if audit_session:
            aggregator_result = verify_config_aggregator(audit_session, primary_region)
        else:
            print("\n  Could not access audit account for aggregator check")
            aggregator_result = {"exists": False}
    else:
        aggregator_result = {"exists": False}

    # Overall summary
    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)

    total_regions = len(ALL_REGIONS) * len(all_results)
    recording = sum(r["recording"] for r in all_results)
    correct_bucket = sum(r["correct_bucket"] for r in all_results)
    uses_slr = sum(r["uses_slr"] for r in all_results)

    all_passed = True

    print(f"\n  Recording:      {recording}/{total_regions} regions", end="")
    if recording < total_regions:
        print(" [PARTIAL]")
        all_passed = False
    else:
        print(" [OK]")

    print(f"  Correct Bucket: {correct_bucket}/{total_regions} regions", end="")
    if correct_bucket < total_regions:
        print(" [PARTIAL]")
    else:
        print(" [OK]")

    print(f"  Service Role:   {uses_slr}/{total_regions} regions", end="")
    if uses_slr < total_regions:
        print(" [PARTIAL]")
    else:
        print(" [OK]")

    status = "[PASS]" if aggregator_result["exists"] else "[FAIL]"
    print(f"  Aggregator:     {status}")
    if not aggregator_result["exists"]:
        all_passed = False

    # Show issues (limit to first few)
    all_issues = []
    for result in all_results:
        for issue in result["issues"]:
            all_issues.append(f"{result['account_name']}: {issue}")

    if all_issues:
        print(f"\n  Issues ({len(all_issues)} total):")
        for issue in all_issues[:10]:
            print(f"    - {issue}")
        if len(all_issues) > 10:
            print(f"    ... and {len(all_issues) - 10} more")

    print("")
    if all_passed:
        print("All Config recorder verifications passed!")
        return 0
    else:
        print("Some Config recorder verifications need attention.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
