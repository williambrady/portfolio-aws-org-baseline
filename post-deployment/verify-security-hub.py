#!/usr/bin/env python3
"""
Security Hub verification script.

Validates Security Hub organization configuration:
- Delegated administrator is set correctly
- Organization configuration type (CENTRAL vs LOCAL)
- Standards are enabled as configured
- Disabled controls match configuration
- Member accounts are enrolled
"""

import json
import sys
from pathlib import Path

import boto3
import yaml
from botocore.exceptions import ClientError

# Map config names to Security Hub standard ARN patterns
STANDARD_ARN_MAP = {
    "aws-foundational": "aws-foundational-security-best-practices",
    "cis-1.2": "cis-aws-foundations-benchmark/v/1.2.0",
    "cis-1.4": "cis-aws-foundations-benchmark/v/1.4.0",
    "nist-800-53": "nist-800-53",
    "pci-dss": "pci-dss",
}


def load_config() -> dict:
    """Load configuration from config.yaml."""
    config_path = Path("/work/config.yaml")
    if not config_path.exists():
        return {"primary_region": "us-east-1", "security_hub": {}}
    with open(config_path) as f:
        return yaml.safe_load(f)


def load_discovery() -> dict:
    """Load discovery results."""
    discovery_path = Path("/work/terraform/discovery.json")
    if not discovery_path.exists():
        return {}
    with open(discovery_path) as f:
        return json.load(f)


def get_audit_session(audit_account_id: str, region: str):
    """Get a boto3 session for the audit account."""
    sts_client = boto3.client("sts", region_name=region)
    role_arn = f"arn:aws:iam::{audit_account_id}:role/OrganizationAccountAccessRole"

    try:
        assumed = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName="securityhub-verify", DurationSeconds=900
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


def verify_delegated_admin(org_client, expected_admin_id: str) -> bool:
    """Verify Security Hub delegated administrator."""
    print("Verifying Delegated Administrator...")

    try:
        response = org_client.list_delegated_administrators(
            ServicePrincipal="securityhub.amazonaws.com"
        )
        admins = response.get("DelegatedAdministrators", [])

        if not admins:
            print("  [-] No delegated administrator configured")
            return False

        admin_id = admins[0]["Id"]
        if admin_id == expected_admin_id:
            print(f"  [+] Delegated admin: {admin_id}")
            return True
        else:
            print(f"  [!] Delegated admin: {admin_id} (expected: {expected_admin_id})")
            return False

    except ClientError as e:
        print(f"  [-] Error: {e}")
        return False


def verify_org_configuration(session, region: str) -> dict:
    """Verify Security Hub organization configuration."""
    print("\nVerifying Organization Configuration...")

    result = {
        "config_type": None,
        "auto_enable": False,
        "members": {"active": 0, "pending": 0, "total": 0},
    }

    try:
        securityhub_client = session.client("securityhub", region_name=region)

        # Get organization configuration
        try:
            response = securityhub_client.describe_organization_configuration()
            auto_enable = response.get("AutoEnable", False)
            config_type = response.get("OrganizationConfiguration", {}).get(
                "ConfigurationType", "LOCAL"
            )

            result["config_type"] = config_type
            result["auto_enable"] = auto_enable

            print(f"  [+] Configuration type: {config_type}")
            print(f"  [+] Auto-enable new accounts: {auto_enable}")

        except ClientError as e:
            if "not subscribed" in str(e).lower():
                print("  [!] Security Hub not enabled in this account")
            else:
                print(f"  [-] Error getting org config: {e}")

        # Count member accounts
        try:
            paginator = securityhub_client.get_paginator("list_members")
            for page in paginator.paginate():
                for member in page.get("Members", []):
                    result["members"]["total"] += 1
                    status = member.get("MemberStatus", "")
                    if status == "Enabled":
                        result["members"]["active"] += 1
                    elif status in ["Invited", "Created"]:
                        result["members"]["pending"] += 1

            print(
                f"  [+] Members: {result['members']['active']} active, {result['members']['pending']} pending"
            )

        except ClientError:
            pass

    except ClientError as e:
        print(f"  [-] Error: {e}")

    return result


def verify_enabled_standards(session, region: str, expected_standards: list) -> dict:
    """Verify enabled security standards."""
    print("\nVerifying Enabled Standards...")

    result = {"enabled": [], "missing": [], "extra": []}

    try:
        securityhub_client = session.client("securityhub", region_name=region)

        # Get enabled standards
        try:
            paginator = securityhub_client.get_paginator("get_enabled_standards")
            enabled_arns = []
            for page in paginator.paginate():
                for sub in page.get("StandardsSubscriptions", []):
                    arn = sub.get("StandardsArn", "")
                    enabled_arns.append(arn)

            # Map expected standards to ARN patterns
            expected_patterns = []
            for std in expected_standards:
                if std in STANDARD_ARN_MAP:
                    expected_patterns.append(STANDARD_ARN_MAP[std])

            # Check which standards are enabled
            for pattern in expected_patterns:
                found = any(pattern in arn for arn in enabled_arns)
                if found:
                    result["enabled"].append(pattern)
                    print(f"  [+] {pattern}: Enabled")
                else:
                    result["missing"].append(pattern)
                    print(f"  [-] {pattern}: Not enabled")

            # Check for extra standards not in config
            for arn in enabled_arns:
                is_expected = any(pattern in arn for pattern in expected_patterns)
                if not is_expected:
                    # Extract just the standard name from ARN
                    std_name = arn.split("/")[-1] if "/" in arn else arn
                    result["extra"].append(std_name)

            if result["extra"]:
                print(
                    f"  [!] Extra standards enabled: {', '.join(result['extra'][:3])}"
                )

        except ClientError as e:
            print(f"  [-] Error getting standards: {e}")

    except ClientError as e:
        print(f"  [-] Error: {e}")

    return result


def verify_disabled_controls(session, region: str, expected_disabled: list) -> dict:
    """Verify disabled controls match configuration."""
    print("\nVerifying Disabled Controls...")

    result = {
        "disabled_count": 0,
        "expected_disabled": len(expected_disabled),
        "matches": [],
    }

    if not expected_disabled:
        print("  [+] No controls expected to be disabled")
        return result

    try:
        securityhub_client = session.client("securityhub", region_name=region)

        # Get all standards subscriptions first
        enabled_subscriptions = []
        try:
            paginator = securityhub_client.get_paginator("get_enabled_standards")
            for page in paginator.paginate():
                for sub in page.get("StandardsSubscriptions", []):
                    enabled_subscriptions.append(
                        sub.get("StandardsSubscriptionArn", "")
                    )
        except ClientError:
            pass

        # Check each subscription for disabled controls
        disabled_controls = set()
        for sub_arn in enabled_subscriptions:
            try:
                paginator = securityhub_client.get_paginator(
                    "describe_standards_controls"
                )
                for page in paginator.paginate(StandardsSubscriptionArn=sub_arn):
                    for control in page.get("Controls", []):
                        status = control.get("ControlStatus", "")
                        control_id = control.get("ControlId", "")
                        if status == "DISABLED":
                            disabled_controls.add(control_id)
            except ClientError:
                continue

        result["disabled_count"] = len(disabled_controls)

        # Check for expected disabled controls
        for expected in expected_disabled:
            if expected in disabled_controls:
                result["matches"].append(expected)
                print(f"  [+] {expected}: Disabled")
            else:
                print(f"  [-] {expected}: Not disabled (expected to be)")

        matched = len(result["matches"])
        total_expected = len(expected_disabled)
        print(f"\n  Summary: {matched}/{total_expected} expected controls disabled")

    except ClientError as e:
        print(f"  [-] Error: {e}")

    return result


def main():
    """Main verification function."""
    print("=" * 60)
    print("  Security Hub Verification")
    print("=" * 60)

    config = load_config()
    discovery = load_discovery()
    primary_region = config.get("primary_region", "us-east-1")

    # Get configuration
    securityhub_config = config.get("security_hub", {})
    expected_standards = securityhub_config.get("standards", ["aws-foundational"])
    expected_disabled = securityhub_config.get("disabled_controls", [])

    # Get account IDs
    audit_account_id = discovery.get("audit_account_id", "")

    if not audit_account_id:
        print("\nError: Audit account ID not found in discovery")
        print("Run 'make discover' first to populate account information")
        return 1

    print(f"\nPrimary Region: {primary_region}")
    print(f"Audit Account: {audit_account_id}")
    print(f"Expected Standards: {', '.join(expected_standards)}")
    print(f"Expected Disabled: {len(expected_disabled)} controls")
    print("")

    # Verify delegated admin from management account
    org_client = boto3.client("organizations", region_name=primary_region)
    admin_ok = verify_delegated_admin(org_client, audit_account_id)

    # Get session for audit account
    session = get_audit_session(audit_account_id, primary_region)
    if not session:
        print("\nError: Could not assume role in audit account")
        return 1

    # Verify organization configuration
    org_config = verify_org_configuration(session, primary_region)

    # Verify enabled standards
    standards_result = verify_enabled_standards(
        session, primary_region, expected_standards
    )

    # Verify disabled controls
    controls_result = verify_disabled_controls(
        session, primary_region, expected_disabled
    )

    # Summary
    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)

    all_passed = True

    # Delegated admin check
    status = "[PASS]" if admin_ok else "[FAIL]"
    print(f"  {status} Delegated Administrator")
    if not admin_ok:
        all_passed = False

    # Org config check
    org_ok = org_config["config_type"] == "CENTRAL" and org_config["auto_enable"]
    status = "[PASS]" if org_ok else "[WARN]"
    print(f"  {status} Organization Configuration ({org_config['config_type']})")

    # Standards check
    standards_ok = len(standards_result["missing"]) == 0
    status = "[PASS]" if standards_ok else "[FAIL]"
    print(
        f"  {status} Enabled Standards ({len(standards_result['enabled'])}/{len(expected_standards)})"
    )
    if not standards_ok:
        all_passed = False

    # Disabled controls check
    controls_ok = len(controls_result["matches"]) == len(expected_disabled)
    status = "[PASS]" if controls_ok else "[WARN]"
    print(
        f"  {status} Disabled Controls ({len(controls_result['matches'])}/{len(expected_disabled)})"
    )

    print("")
    if all_passed:
        print("All critical Security Hub verifications passed!")
        return 0
    else:
        print("Some Security Hub verifications failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
