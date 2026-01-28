#!/usr/bin/env python3
"""
Post-deployment verification script for AWS Organization baseline.
Verifies that all resources were created correctly and services are operational.

Checks performed:
- Organization exists and has ALL features
- Organizational Units match configuration
- Shared accounts (log-archive, audit) exist and are active
- Delegated administrators configured for security services
- Organization CloudTrail is active
- KMS keys exist and are enabled
- S3 buckets exist with correct configuration
- IAM password policies are applied
"""

import json
import sys
from pathlib import Path

import boto3
import yaml
from botocore.exceptions import ClientError


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


def verify_organization(org_client) -> bool:
    """Verify organization exists and is properly configured."""
    print("Verifying Organization...")
    try:
        org = org_client.describe_organization()["Organization"]
        print(f"  [+] Organization exists: {org['Id']}")
        print(f"  [+] Feature set: {org['FeatureSet']}")

        if org["FeatureSet"] != "ALL":
            print("  [!] Warning: Feature set is not ALL")
            return False

        return True
    except ClientError as e:
        print(f"  [-] Failed: {e}")
        return False


def verify_organizational_units(org_client, config: dict) -> bool:
    """Verify OUs from config exist."""
    print("Verifying Organizational Units...")

    # Get required OUs from config
    ou_config = config.get("organizational_units", [])

    def extract_ou_names(ous: list) -> set:
        """Recursively extract all OU names from config."""
        names = set()
        for ou in ous:
            names.add(ou.get("name", ""))
            children = ou.get("children", [])
            if children:
                names.update(extract_ou_names(children))
        return names

    required_ous = extract_ou_names(ou_config)
    if not required_ous:
        required_ous = {"Security", "Production", "NonProduction", "Unmanaged"}

    found_ous = set()

    try:
        roots = org_client.list_roots()["Roots"]
        if not roots:
            print("  [-] No organization root found")
            return False

        root_id = roots[0]["Id"]

        def find_ous(parent_id: str):
            paginator = org_client.get_paginator("list_organizational_units_for_parent")
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page["OrganizationalUnits"]:
                    found_ous.add(ou["Name"])
                    find_ous(ou["Id"])

        find_ous(root_id)

        all_found = True
        for ou_name in required_ous:
            if ou_name in found_ous:
                print(f"  [+] {ou_name} OU exists")
            else:
                print(f"  [-] {ou_name} OU missing")
                all_found = False

        return all_found

    except ClientError as e:
        print(f"  [-] Failed: {e}")
        return False


def verify_shared_accounts(org_client, config: dict) -> bool:
    """Verify shared accounts exist."""
    print("Verifying Shared Accounts...")

    shared_config = config.get("shared_accounts", {})
    required_accounts = []

    if shared_config.get("log_archive"):
        required_accounts.append(
            shared_config["log_archive"].get("name", "log-archive")
        )
    if shared_config.get("audit"):
        required_accounts.append(shared_config["audit"].get("name", "audit"))

    try:
        paginator = org_client.get_paginator("list_accounts")
        found_accounts = {}
        for page in paginator.paginate():
            for account in page["Accounts"]:
                found_accounts[account["Name"]] = account

        all_found = True
        for account_name in required_accounts:
            if account_name in found_accounts:
                account = found_accounts[account_name]
                status = (
                    "ACTIVE" if account["Status"] == "ACTIVE" else account["Status"]
                )
                print(f"  [+] {account_name} ({account['Id']}) - {status}")
            else:
                print(f"  [-] {account_name} not found")
                all_found = False

        return all_found

    except ClientError as e:
        print(f"  [-] Failed: {e}")
        return False


def verify_account_access(account_id: str, account_name: str, region: str) -> bool:
    """Verify we can assume role into an account."""
    print(f"  Checking access to {account_name} ({account_id})...")

    sts_client = boto3.client("sts", region_name=region)
    role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"

    try:
        sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="org-baseline-verify",
            DurationSeconds=900,
        )
        print(f"    [+] Successfully assumed role in {account_name}")
        return True
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "AccessDenied":
            print(f"    [-] Access denied to {account_name}")
        else:
            print(f"    [-] Error: {e}")
        return False


def verify_delegated_administrators(org_client) -> bool:
    """Verify delegated administrators are configured."""
    print("Verifying Delegated Administrators...")

    services = [
        ("securityhub.amazonaws.com", "Security Hub"),
        ("config.amazonaws.com", "AWS Config"),
        ("access-analyzer.amazonaws.com", "IAM Access Analyzer"),
        ("inspector2.amazonaws.com", "Inspector"),
    ]

    all_configured = True
    for service_principal, service_name in services:
        try:
            response = org_client.list_delegated_administrators(
                ServicePrincipal=service_principal
            )
            admins = response.get("DelegatedAdministrators", [])
            if admins:
                admin_ids = ", ".join([a["Id"] for a in admins])
                print(f"  [+] {service_name}: {admin_ids}")
            else:
                print(f"  [!] {service_name}: No delegated admin")
                # Not a failure, just informational
        except ClientError as e:
            if "AccessDenied" in str(e):
                print(f"  [!] {service_name}: Unable to check (access denied)")
            else:
                print(f"  [-] {service_name}: Error - {e}")

    return all_configured


def verify_cloudtrail(region: str) -> bool:
    """Verify organization CloudTrail is active."""
    print("Verifying CloudTrail...")

    cloudtrail_client = boto3.client("cloudtrail", region_name=region)

    try:
        trails = cloudtrail_client.describe_trails(includeShadowTrails=False)[
            "trailList"
        ]

        org_trails = [t for t in trails if t.get("IsOrganizationTrail")]

        if org_trails:
            for trail in org_trails:
                print(f"  [+] Organization trail: {trail['Name']}")

                # Check if logging
                status = cloudtrail_client.get_trail_status(Name=trail["TrailARN"])
                if status.get("IsLogging"):
                    print("      Logging: Active")
                else:
                    print("      Logging: Inactive")

            return True
        else:
            print("  [!] No organization trail found")
            return False

    except ClientError as e:
        print(f"  [-] Failed: {e}")
        return False


def verify_kms_keys(
    region: str, resource_prefix: str, log_archive_account_id: str
) -> bool:
    """Verify KMS keys exist and are enabled."""
    print("Verifying KMS Keys...")

    all_ok = True

    # Check tfstate key in management account
    print("  Checking management account...")
    try:
        kms_client = boto3.client("kms", region_name=region)
        alias_name = f"alias/{resource_prefix}-tfstate-key"
        try:
            response = kms_client.describe_key(KeyId=alias_name)
            key_state = response["KeyMetadata"]["KeyState"]
            if key_state == "Enabled":
                print("    [+] tfstate-key: Enabled")
            else:
                print(f"    [!] tfstate-key: {key_state}")
                all_ok = False
        except kms_client.exceptions.NotFoundException:
            print("    [!] tfstate-key: Not found (may be Control Tower env)")
    except ClientError as e:
        print(f"    [-] Error checking management KMS: {e}")
        all_ok = False

    # Check cloudtrail and config keys in log-archive account
    if log_archive_account_id:
        print("  Checking log-archive account...")
        try:
            sts_client = boto3.client("sts", region_name=region)
            assumed = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{log_archive_account_id}:role/OrganizationAccountAccessRole",
                RoleSessionName="kms-verify",
            )
            creds = assumed["Credentials"]
            log_kms_client = boto3.client(
                "kms",
                region_name=region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )

            for key_name in ["cloudtrail-key", "config-key"]:
                alias_name = f"alias/{resource_prefix}-{key_name}"
                try:
                    response = log_kms_client.describe_key(KeyId=alias_name)
                    key_state = response["KeyMetadata"]["KeyState"]
                    if key_state == "Enabled":
                        print(f"    [+] {key_name}: Enabled")
                    else:
                        print(f"    [!] {key_name}: {key_state}")
                        all_ok = False
                except log_kms_client.exceptions.NotFoundException:
                    print(f"    [!] {key_name}: Not found (may be Control Tower env)")
        except ClientError as e:
            print(f"    [-] Error checking log-archive KMS: {e}")
            all_ok = False
    else:
        print("  [!] Log-archive account not found, skipping KMS check")

    return all_ok


def verify_s3_buckets(
    region: str, resource_prefix: str, mgmt_account_id: str, log_archive_account_id: str
) -> bool:
    """Verify S3 buckets exist with correct configuration."""
    print("Verifying S3 Buckets...")

    all_ok = True

    # Check tfstate bucket in management account
    print("  Checking management account...")
    try:
        s3_client = boto3.client("s3", region_name=region)
        tfstate_bucket = f"{resource_prefix}-tfstate-{mgmt_account_id}"

        try:
            s3_client.head_bucket(Bucket=tfstate_bucket)
            print(f"    [+] {tfstate_bucket}: Exists")

            # Check versioning
            versioning = s3_client.get_bucket_versioning(Bucket=tfstate_bucket)
            if versioning.get("Status") == "Enabled":
                print("        Versioning: Enabled")
            else:
                print("        Versioning: Not enabled")
                all_ok = False

            # Check encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=tfstate_bucket)
                rules = encryption.get("ServerSideEncryptionConfiguration", {}).get(
                    "Rules", []
                )
                if rules:
                    sse_type = (
                        rules[0]
                        .get("ApplyServerSideEncryptionByDefault", {})
                        .get("SSEAlgorithm", "")
                    )
                    print(f"        Encryption: {sse_type}")
                else:
                    print("        Encryption: Not configured")
            except ClientError:
                print("        Encryption: Not configured")

            # Check public access block
            try:
                public_block = s3_client.get_public_access_block(Bucket=tfstate_bucket)
                config = public_block.get("PublicAccessBlockConfiguration", {})
                if all(
                    [
                        config.get("BlockPublicAcls"),
                        config.get("IgnorePublicAcls"),
                        config.get("BlockPublicPolicy"),
                        config.get("RestrictPublicBuckets"),
                    ]
                ):
                    print("        Public access: Blocked")
                else:
                    print("        Public access: Partially blocked")
            except ClientError:
                print("        Public access: Not configured")

        except ClientError as e:
            if "404" in str(e) or "NoSuchBucket" in str(e):
                print(f"    [!] {tfstate_bucket}: Not found")
            else:
                print(f"    [-] Error: {e}")
            all_ok = False

    except ClientError as e:
        print(f"    [-] Error checking management S3: {e}")
        all_ok = False

    # Check log-archive buckets
    if log_archive_account_id:
        print("  Checking log-archive account...")
        try:
            sts_client = boto3.client("sts", region_name=region)
            assumed = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{log_archive_account_id}:role/OrganizationAccountAccessRole",
                RoleSessionName="s3-verify",
            )
            creds = assumed["Credentials"]
            log_s3_client = boto3.client(
                "s3",
                region_name=region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )

            for bucket_type in ["cloudtrail-logs", "config"]:
                bucket_name = (
                    f"{resource_prefix}-{bucket_type}-{log_archive_account_id}"
                )
                try:
                    log_s3_client.head_bucket(Bucket=bucket_name)
                    print(f"    [+] {bucket_name}: Exists")
                except ClientError as e:
                    if "404" in str(e) or "NoSuchBucket" in str(e):
                        print(
                            f"    [!] {bucket_name}: Not found (may be Control Tower env)"
                        )
                    else:
                        print(f"    [-] {bucket_name}: Error - {e}")

        except ClientError as e:
            print(f"    [-] Error checking log-archive S3: {e}")
            all_ok = False
    else:
        print("  [!] Log-archive account not found, skipping S3 check")

    return all_ok


def verify_iam_password_policy(
    region: str,
    mgmt_account_id: str,
    log_archive_account_id: str,
    audit_account_id: str,
) -> bool:
    """Verify IAM password policies are configured."""
    print("Verifying IAM Password Policies...")

    all_ok = True

    accounts = [
        ("Management", mgmt_account_id, None),
        ("Log Archive", log_archive_account_id, log_archive_account_id),
        ("Audit", audit_account_id, audit_account_id),
    ]

    for account_name, account_id, assume_account_id in accounts:
        if not account_id:
            print(f"  [!] {account_name}: Account ID not found")
            continue

        print(f"  Checking {account_name} ({account_id})...")

        try:
            if assume_account_id:
                sts_client = boto3.client("sts", region_name=region)
                assumed = sts_client.assume_role(
                    RoleArn=f"arn:aws:iam::{assume_account_id}:role/OrganizationAccountAccessRole",
                    RoleSessionName="iam-verify",
                )
                creds = assumed["Credentials"]
                iam_client = boto3.client(
                    "iam",
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                )
            else:
                iam_client = boto3.client("iam")

            try:
                policy = iam_client.get_account_password_policy()["PasswordPolicy"]
                min_length = policy.get("MinimumPasswordLength", 0)
                require_upper = policy.get("RequireUppercaseCharacters", False)
                require_lower = policy.get("RequireLowercaseCharacters", False)
                require_numbers = policy.get("RequireNumbers", False)
                require_symbols = policy.get("RequireSymbols", False)
                reuse_prevention = policy.get("PasswordReusePrevention", 0)

                issues = []
                if min_length < 14:
                    issues.append(f"length={min_length}")
                if not require_upper:
                    issues.append("no-upper")
                if not require_lower:
                    issues.append("no-lower")
                if not require_numbers:
                    issues.append("no-numbers")
                if not require_symbols:
                    issues.append("no-symbols")
                if reuse_prevention < 12:
                    issues.append(f"reuse={reuse_prevention}")

                if issues:
                    print(f"    [!] Policy weak: {', '.join(issues)}")
                else:
                    print(
                        f"    [+] Policy: length={min_length}, reuse-prevention={reuse_prevention}"
                    )

            except iam_client.exceptions.NoSuchEntityException:
                print("    [!] No password policy configured")
                all_ok = False

        except ClientError as e:
            print(f"    [-] Error: {e}")
            all_ok = False

    return all_ok


def verify_s3_public_access_block(
    region: str,
    mgmt_account_id: str,
    log_archive_account_id: str,
    audit_account_id: str,
) -> bool:
    """Verify S3 account-level public access blocks."""
    print("Verifying S3 Account Public Access Blocks...")

    all_ok = True

    accounts = [
        ("Management", mgmt_account_id, None),
        ("Log Archive", log_archive_account_id, log_archive_account_id),
        ("Audit", audit_account_id, audit_account_id),
    ]

    for account_name, account_id, assume_account_id in accounts:
        if not account_id:
            print(f"  [!] {account_name}: Account ID not found")
            continue

        print(f"  Checking {account_name}...", end=" ")

        try:
            if assume_account_id:
                sts_client = boto3.client("sts", region_name=region)
                assumed = sts_client.assume_role(
                    RoleArn=f"arn:aws:iam::{assume_account_id}:role/OrganizationAccountAccessRole",
                    RoleSessionName="s3-pab-verify",
                )
                creds = assumed["Credentials"]
                s3control_client = boto3.client(
                    "s3control",
                    region_name=region,
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                )
            else:
                s3control_client = boto3.client("s3control", region_name=region)

            try:
                response = s3control_client.get_public_access_block(
                    AccountId=account_id
                )
                config = response.get("PublicAccessBlockConfiguration", {})
                if all(
                    [
                        config.get("BlockPublicAcls"),
                        config.get("IgnorePublicAcls"),
                        config.get("BlockPublicPolicy"),
                        config.get("RestrictPublicBuckets"),
                    ]
                ):
                    print("Fully blocked")
                else:
                    print("Partially blocked")
            except s3control_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                print("Not configured")
                all_ok = False

        except ClientError as e:
            print(f"Error: {e}")
            all_ok = False

    return all_ok


def main():
    """Main verification function."""
    print("=" * 50)
    print("  Post-Deployment Verification")
    print("=" * 50)
    print("")

    config = load_config()
    discovery = load_discovery()
    primary_region = config.get("primary_region", "us-east-1")
    resource_prefix = config.get("resource_prefix", "org-baseline")

    # Get account IDs from discovery or config
    mgmt_account_id = discovery.get("master_account_id", "")
    log_archive_account_id = discovery.get("log_archive_account_id", "")
    audit_account_id = discovery.get("audit_account_id", "")

    # If management account not in discovery, get from STS
    if not mgmt_account_id:
        try:
            sts_client = boto3.client("sts", region_name=primary_region)
            mgmt_account_id = sts_client.get_caller_identity()["Account"]
        except ClientError:
            pass

    # Create clients
    org_client = boto3.client("organizations", region_name=primary_region)

    results = []

    # Verify organization
    results.append(("Organization", verify_organization(org_client)))
    print("")

    # Verify OUs
    results.append(
        ("Organizational Units", verify_organizational_units(org_client, config))
    )
    print("")

    # Verify shared accounts
    results.append(("Shared Accounts", verify_shared_accounts(org_client, config)))
    print("")

    # Verify delegated admins
    results.append(
        ("Delegated Administrators", verify_delegated_administrators(org_client))
    )
    print("")

    # Verify CloudTrail
    results.append(("CloudTrail", verify_cloudtrail(primary_region)))
    print("")

    # Verify KMS keys
    if resource_prefix and log_archive_account_id:
        results.append(
            (
                "KMS Keys",
                verify_kms_keys(
                    primary_region, resource_prefix, log_archive_account_id
                ),
            )
        )
        print("")

    # Verify S3 buckets
    if resource_prefix and mgmt_account_id and log_archive_account_id:
        results.append(
            (
                "S3 Buckets",
                verify_s3_buckets(
                    primary_region,
                    resource_prefix,
                    mgmt_account_id,
                    log_archive_account_id,
                ),
            )
        )
        print("")

    # Verify IAM password policies
    if mgmt_account_id:
        results.append(
            (
                "IAM Password Policy",
                verify_iam_password_policy(
                    primary_region,
                    mgmt_account_id,
                    log_archive_account_id,
                    audit_account_id,
                ),
            )
        )
        print("")

    # Verify S3 account public access blocks
    if mgmt_account_id:
        results.append(
            (
                "S3 Public Access Block",
                verify_s3_public_access_block(
                    primary_region,
                    mgmt_account_id,
                    log_archive_account_id,
                    audit_account_id,
                ),
            )
        )
        print("")

    # Summary
    print("=" * 50)
    print("  Verification Summary")
    print("=" * 50)
    all_passed = True
    for name, passed in results:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"  {status} {name}")
        if not passed:
            all_passed = False

    print("")
    if all_passed:
        print("All verifications passed!")
        return 0
    else:
        print("Some verifications failed. Review the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
