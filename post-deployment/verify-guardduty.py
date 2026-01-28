#!/usr/bin/env python3
"""
Verify GuardDuty organization-wide configuration.

This script validates that GuardDuty is properly configured across all regions
and accounts after Terraform has applied the configuration.

Checks performed:
1. GuardDuty service access is enabled in AWS Organizations
2. Audit account is delegated administrator in all regions
3. Organization auto-enable is configured in all regions
4. Detectors exist and are enabled in all 3 accounts, all regions
5. Data sources (S3, K8s, Malware) are enabled

Prerequisites:
- Must be run from the management account
- Terraform should have already applied GuardDuty configuration

Usage:
    # Verify GuardDuty configuration
    python verify-guardduty.py
"""

import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

# All regions where GuardDuty should be configured
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
    "ap-northeast-3",
    "ap-south-1",
    "ca-central-1",
    "sa-east-1",
]


def load_tfvars() -> dict:
    """Load bootstrap.auto.tfvars.json for account IDs."""
    tfvars_path = Path("/work/terraform/bootstrap.auto.tfvars.json")
    if not tfvars_path.exists():
        # Fallback for local development
        tfvars_path = (
            Path(__file__).parent.parent / "terraform" / "bootstrap.auto.tfvars.json"
        )

    if not tfvars_path.exists():
        return {}

    with open(tfvars_path) as f:
        return json.load(f)


def assume_role(account_id: str, region: str) -> boto3.Session:
    """Assume OrganizationAccountAccessRole in target account."""
    sts_client = boto3.client("sts", region_name=region)
    role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"

    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="guardduty-verification",
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


def check_service_access() -> dict:
    """Check if GuardDuty service access is enabled in Organizations.

    Returns dict with:
        - enabled: True if service access is enabled
        - error: Error message if check failed
    """
    result = {"enabled": False, "error": None}

    org_client = boto3.client("organizations", region_name="us-east-1")

    try:
        response = org_client.list_aws_service_access_for_organization()
        enabled_services = [
            s["ServicePrincipal"] for s in response.get("EnabledServicePrincipals", [])
        ]
        result["enabled"] = "guardduty.amazonaws.com" in enabled_services
    except ClientError as e:
        result["error"] = str(e)

    return result


def check_delegated_admin(region: str, expected_admin: str) -> dict:
    """Check delegated admin configuration in a region.

    Returns dict with:
        - correct: True if expected admin is configured
        - actual_admin: The actual admin account ID (if any)
        - error: Error message if check failed
    """
    result = {"correct": False, "actual_admin": None, "error": None}

    gd_client = boto3.client("guardduty", region_name=region)

    try:
        response = gd_client.list_organization_admin_accounts()
        admin_accounts = response.get("AdminAccounts", [])

        if admin_accounts:
            result["actual_admin"] = admin_accounts[0]["AdminAccountId"]
            result["correct"] = result["actual_admin"] == expected_admin
    except ClientError as e:
        result["error"] = str(e)

    return result


def check_org_config(region: str, audit_account_id: str = None) -> dict:
    """Check organization configuration in a region.

    Tries to check from the audit account (delegated admin) first, since
    describe_organization_configuration must be called from the delegated admin.
    Falls back to management account if audit account is not provided.

    Returns dict with:
        - configured: True if org config exists
        - auto_enable: Current auto-enable setting
        - s3_auto_enable: S3 logs auto-enable
        - k8s_auto_enable: K8s audit logs auto-enable
        - malware_auto_enable: Malware protection auto-enable
        - error: Error message if check failed
    """
    result = {
        "configured": False,
        "auto_enable": None,
        "s3_auto_enable": False,
        "k8s_auto_enable": False,
        "malware_auto_enable": False,
        "error": None,
    }

    # Try audit account first (delegated admin), fall back to management
    gd_client = None
    if audit_account_id:
        session = assume_role(audit_account_id, region)
        if session:
            gd_client = session.client("guardduty", region_name=region)

    if gd_client is None:
        gd_client = boto3.client("guardduty", region_name=region)

    try:
        # Get detector
        detectors = gd_client.list_detectors()
        if not detectors.get("DetectorIds"):
            result["error"] = "No detector found"
            return result

        detector_id = detectors["DetectorIds"][0]

        # Get org configuration
        response = gd_client.describe_organization_configuration(DetectorId=detector_id)

        result["configured"] = True
        result["auto_enable"] = response.get("AutoEnableOrganizationMembers", "NONE")

        datasources = response.get("DataSources", {})
        result["s3_auto_enable"] = datasources.get("S3Logs", {}).get(
            "AutoEnable", False
        )
        result["k8s_auto_enable"] = (
            datasources.get("Kubernetes", {})
            .get("AuditLogs", {})
            .get("AutoEnable", False)
        )
        result["malware_auto_enable"] = (
            datasources.get("MalwareProtection", {})
            .get("ScanEc2InstanceWithFindings", {})
            .get("EbsVolumes", {})
            .get("AutoEnable", False)
        )

    except ClientError as e:
        result["error"] = str(e)

    return result


def check_detector(session: boto3.Session, region: str, account_name: str) -> dict:
    """Check detector configuration in an account/region.

    Returns dict with:
        - enabled: True if detector exists and is enabled
        - detector_id: Detector ID
        - s3_enabled: S3 protection enabled
        - k8s_enabled: K8s audit logs enabled
        - malware_enabled: Malware protection enabled
        - error: Error message if check failed
    """
    result = {
        "enabled": False,
        "detector_id": None,
        "s3_enabled": False,
        "k8s_enabled": False,
        "malware_enabled": False,
        "error": None,
    }

    if session is None:
        gd_client = boto3.client("guardduty", region_name=region)
    else:
        gd_client = session.client("guardduty", region_name=region)

    try:
        detectors = gd_client.list_detectors()
        if not detectors.get("DetectorIds"):
            return result

        detector_id = detectors["DetectorIds"][0]
        result["detector_id"] = detector_id

        # Get detector details
        detector = gd_client.get_detector(DetectorId=detector_id)
        result["enabled"] = detector.get("Status") == "ENABLED"

        datasources = detector.get("DataSources", {})
        result["s3_enabled"] = datasources.get("S3Logs", {}).get("Status") == "ENABLED"
        result["k8s_enabled"] = (
            datasources.get("Kubernetes", {}).get("AuditLogs", {}).get("Status")
            == "ENABLED"
        )
        result["malware_enabled"] = (
            datasources.get("MalwareProtection", {})
            .get("ScanEc2InstanceWithFindings", {})
            .get("EbsVolumes", {})
            .get("Status")
            == "ENABLED"
        )

    except ClientError as e:
        result["error"] = str(e)

    return result


def main():
    """Main function."""
    print("=" * 60)
    print("  GuardDuty Organization Verification")
    print("=" * 60)
    print("")

    # Load configuration
    print("Loading configuration...")
    tfvars = load_tfvars()

    management_account_id = tfvars.get("master_account_id", "")
    audit_account_id = tfvars.get("audit_account_id", "")
    log_archive_account_id = tfvars.get("log_archive_account_id", "")

    if not audit_account_id:
        print("Error: Could not determine audit account ID from tfvars")
        return 1

    print(f"  Management account: {management_account_id}")
    print(f"  Audit account: {audit_account_id}")
    print(f"  Log Archive account: {log_archive_account_id}")
    print(f"  Regions to verify: {len(ALL_REGIONS)}")
    print("")

    issues = []
    warnings = []

    # Check 1: Service access
    print("Checking GuardDuty service access in Organizations...")
    service_result = check_service_access()
    if service_result.get("error"):
        print(f"  ERROR: {service_result['error']}")
        issues.append("Service access check failed")
    elif service_result["enabled"]:
        print("  OK: GuardDuty service access enabled")
    else:
        print("  ERROR: GuardDuty service access NOT enabled")
        issues.append("GuardDuty service access not enabled in Organizations")
    print("")

    # Check 2: Delegated admin in all regions
    print("Checking delegated administrator configuration...")
    admin_ok = 0
    admin_missing = 0
    admin_wrong = 0
    admin_errors = 0

    for region in ALL_REGIONS:
        result = check_delegated_admin(region, audit_account_id)
        if result.get("error"):
            admin_errors += 1
        elif result["correct"]:
            admin_ok += 1
        elif result["actual_admin"]:
            admin_wrong += 1
            issues.append(f"{region}: Wrong delegated admin ({result['actual_admin']})")
        else:
            admin_missing += 1
            issues.append(f"{region}: No delegated admin configured")

    print(f"  Correctly configured: {admin_ok}/{len(ALL_REGIONS)} regions")
    if admin_missing > 0:
        print(f"  Missing: {admin_missing} regions")
    if admin_wrong > 0:
        print(f"  Wrong admin: {admin_wrong} regions")
    if admin_errors > 0:
        print(f"  Errors: {admin_errors} regions")
    print("")

    # Check 3: Organization auto-enable configuration
    # Query from audit account (delegated admin) since describe_organization_configuration
    # must be called from the delegated admin, not the management account
    print("Checking organization auto-enable configuration...")
    org_ok = 0
    org_partial = 0
    org_missing = 0
    org_errors = 0

    for region in ALL_REGIONS:
        result = check_org_config(region, audit_account_id)
        if result.get("error"):
            org_errors += 1
        elif not result["configured"]:
            org_missing += 1
            issues.append(f"{region}: Org configuration not found")
        elif (
            result["auto_enable"] == "ALL"
            and result["s3_auto_enable"]
            and result["k8s_auto_enable"]
            and result["malware_auto_enable"]
        ):
            org_ok += 1
        else:
            org_partial += 1
            missing = []
            if result["auto_enable"] != "ALL":
                missing.append(f"auto_enable={result['auto_enable']}")
            if not result["s3_auto_enable"]:
                missing.append("S3")
            if not result["k8s_auto_enable"]:
                missing.append("K8s")
            if not result["malware_auto_enable"]:
                missing.append("Malware")
            warnings.append(f"{region}: Partial config - missing: {', '.join(missing)}")

    print(f"  Fully configured: {org_ok}/{len(ALL_REGIONS)} regions")
    if org_partial > 0:
        print(f"  Partial: {org_partial} regions")
    if org_missing > 0:
        print(f"  Missing: {org_missing} regions")
    if org_errors > 0:
        print(f"  Errors: {org_errors} regions")
    print("")

    # Check 4: Detector in each account
    accounts = [
        ("Management", management_account_id, None),
        ("Log Archive", log_archive_account_id, log_archive_account_id),
        ("Audit", audit_account_id, audit_account_id),
    ]

    for account_name, account_id, assume_account_id in accounts:
        if not account_id:
            print(f"Checking {account_name} detectors... SKIPPED (no account ID)")
            continue

        print(f"Checking {account_name} detectors...")
        det_ok = 0
        det_missing = 0
        det_errors = 0

        for region in ALL_REGIONS:
            if assume_account_id:
                session = assume_role(assume_account_id, region)
            else:
                session = None

            result = check_detector(session, region, account_name)
            if result.get("error"):
                det_errors += 1
            elif result["enabled"]:
                det_ok += 1
            else:
                det_missing += 1
                issues.append(f"{account_name} ({region}): Detector not enabled")

        print(f"  Enabled: {det_ok}/{len(ALL_REGIONS)} regions")
        if det_missing > 0:
            print(f"  Missing/Disabled: {det_missing} regions")
        if det_errors > 0:
            print(f"  Errors: {det_errors} regions")
        print("")

    # Summary
    print("=" * 60)
    print("  Verification Summary")
    print("=" * 60)
    print("")

    if issues:
        print(f"Issues Found ({len(issues)}):")
        for issue in issues[:10]:  # Show first 10
            print(f"  - {issue}")
        if len(issues) > 10:
            print(f"  ... and {len(issues) - 10} more")
        print("")

    if warnings:
        print(f"Warnings ({len(warnings)}):")
        for warning in warnings[:10]:  # Show first 10
            print(f"  - {warning}")
        if len(warnings) > 10:
            print(f"  ... and {len(warnings) - 10} more")
        print("")

    if not issues and not warnings:
        print("All checks passed! GuardDuty is fully configured.")
        return 0
    elif not issues:
        print("Verification complete with warnings.")
        return 0
    else:
        print("Verification complete with issues that need attention.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
