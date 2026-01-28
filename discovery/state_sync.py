#!/usr/bin/env python3
"""
Terraform State Sync Script.
Ensures bootstrap resources (KMS key and S3 bucket) are properly imported
into Terraform state before plan/apply runs.

Also handles orphaned resources that may exist from previous failed runs:
- SSM CloudWatch Log Groups across all accounts and regions
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import boto3
import yaml
from botocore.exceptions import ClientError

# All regions where SSM settings are deployed
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


def load_config() -> dict:
    """Load configuration from config.yaml with environment variable overrides."""
    config_path = Path("/work/config.yaml")
    if not config_path.exists():
        print("Warning: config.yaml not found, using defaults")
        config = {"primary_region": "us-east-1", "resource_prefix": "org-baseline"}
    else:
        with open(config_path) as f:
            config = yaml.safe_load(f)

    if os.environ.get("VPC_BLOCK_MODE"):
        if "vpc_block_public_access" not in config:
            config["vpc_block_public_access"] = {}
        config["vpc_block_public_access"]["mode"] = os.environ["VPC_BLOCK_MODE"]

    return config


def run_terraform_cmd(args: list, capture_output: bool = True) -> tuple:
    """Run a terraform command and return (success, output)."""
    cmd = ["terraform"] + args
    try:
        result = subprocess.run(
            cmd, capture_output=capture_output, text=True, cwd="/work/terraform"
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


def get_state_resources() -> set:
    """Get set of resources currently in Terraform state."""
    success, output = run_terraform_cmd(["state", "list"])
    if not success:
        return set()
    return set(line.strip() for line in output.strip().split("\n") if line.strip())


def resource_exists_in_state(resource_address: str, state_resources: set) -> bool:
    """Check if a resource exists in state."""
    return resource_address in state_resources


def import_resource(address: str, resource_id: str) -> bool:
    """Import a resource into Terraform state."""
    print(f"  Importing {address}...")
    success, output = run_terraform_cmd(["import", address, resource_id])
    if success:
        print("    Imported successfully")
    else:
        # Check if already exists
        if "Resource already managed" in output:
            print("    Already in state")
            return True
        print(f"    Import failed: {output[:200]}")
    return success


def sync_bootstrap_resources(config: dict, account_id: str):
    """Sync bootstrap resources (KMS key and S3 bucket) into state.

    Each resource is checked individually to avoid skipping resources
    when only some are in state.
    """
    print("\n=== Syncing Bootstrap Resources ===\n")

    resource_prefix = config["resource_prefix"]
    primary_region = config.get("primary_region", "us-east-1")
    state_bucket = f"{resource_prefix}-tfstate-{account_id}"

    # Get current state
    state_resources = get_state_resources()

    # KMS resources
    kms_client = boto3.client("kms", region_name=primary_region)

    # Check KMS key
    kms_key_address = "module.kms_tfstate.aws_kms_key.main"
    kms_alias_address = "module.kms_tfstate.aws_kms_alias.main"
    kms_alias_name = f"alias/{resource_prefix}-tfstate"

    try:
        key_response = kms_client.describe_key(KeyId=kms_alias_name)
        kms_key_id = key_response["KeyMetadata"]["KeyId"]

        # Import KMS key if not in state
        if not resource_exists_in_state(kms_key_address, state_resources):
            import_resource(kms_key_address, kms_key_id)
        else:
            print(f"  {kms_key_address} already in state")

        # Import KMS alias if not in state (check separately!)
        if not resource_exists_in_state(kms_alias_address, state_resources):
            import_resource(kms_alias_address, kms_alias_name)
        else:
            print(f"  {kms_alias_address} already in state")

    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            print(
                f"  KMS key {kms_alias_name} not found in AWS - will be created by Terraform"
            )
        else:
            print(f"  Error checking KMS key: {e}")

    # S3 bucket resources
    s3_client = boto3.client("s3", region_name=primary_region)

    s3_resources = [
        ("module.s3_tfstate.module.bucket.aws_s3_bucket.main", state_bucket),
        ("module.s3_tfstate.module.bucket.aws_s3_bucket_versioning.main", state_bucket),
        (
            "module.s3_tfstate.module.bucket.aws_s3_bucket_server_side_encryption_configuration.main",
            state_bucket,
        ),
        (
            "module.s3_tfstate.module.bucket.aws_s3_bucket_public_access_block.main",
            state_bucket,
        ),
        ("module.s3_tfstate.module.bucket.aws_s3_bucket_policy.main[0]", state_bucket),
    ]

    try:
        s3_client.head_bucket(Bucket=state_bucket)
        bucket_exists = True
    except ClientError:
        bucket_exists = False
        print(
            f"  S3 bucket {state_bucket} not found in AWS - will be created by Terraform"
        )

    if bucket_exists:
        for address, resource_id in s3_resources:
            if not resource_exists_in_state(address, state_resources):
                import_resource(address, resource_id)
            else:
                print(f"  {address} already in state")


def get_account_ids_from_tfvars() -> dict:
    """Get account IDs from bootstrap.auto.tfvars.json.

    Returns dict with keys: management, log_archive, audit
    """
    tfvars_path = Path("/work/terraform/bootstrap.auto.tfvars.json")
    result = {"management": "", "log_archive": "", "audit": ""}

    if tfvars_path.exists():
        try:
            with open(tfvars_path) as f:
                tfvars = json.load(f)
            result["management"] = tfvars.get("master_account_id", "")
            result["log_archive"] = tfvars.get("log_archive_account_id", "")
            result["audit"] = tfvars.get("audit_account_id", "")
        except Exception:
            pass

    return result


def get_cross_account_session(account_id: str, region: str):
    """Get boto3 session for cross-account access via OrganizationAccountAccessRole."""
    sts = boto3.client("sts")
    try:
        response = sts.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole",
            RoleSessionName="state-sync",
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


def region_to_module_suffix(region: str) -> str:
    """Convert region name to terraform module suffix (e.g., us-east-1 -> us_east_1)."""
    return region.replace("-", "_")


def cleanup_config_resources_if_external(config: dict, state_resources: set):
    """Remove Config module resources from state when organization Config exists.

    When Control Tower manages Config (organization_config_exists = true), we should
    not try to delete the service linked roles or buckets that may have been created
    in a previous run. This function removes them from state to prevent deletion errors.
    """
    # Read the full tfvars to check organization_config_exists
    tfvars_path = Path("/work/terraform/bootstrap.auto.tfvars.json")
    if not tfvars_path.exists():
        return

    with open(tfvars_path) as f:
        full_tfvars = json.load(f)

    if not full_tfvars.get("organization_config_exists", False):
        return

    print("\n=== Cleaning Up Config Resources (Control Tower Detected) ===\n")

    # Resources to remove from state (not delete from AWS)
    resources_to_remove = [
        "module.config[0].aws_iam_service_linked_role.config_management",
        "module.config[0].aws_iam_service_linked_role.config_log_archive",
        "module.config[0].aws_iam_service_linked_role.config_audit",
        "module.config[0].module.bucket.aws_s3_bucket.main",
    ]

    removed_count = 0
    for resource in resources_to_remove:
        if resource_exists_in_state(resource, state_resources):
            print(f"  Removing from state: {resource}")
            success, output = run_terraform_cmd(["state", "rm", resource])
            if success:
                print("    Removed successfully")
                removed_count += 1
            else:
                print(f"    Failed to remove: {output[:100]}")

    if removed_count > 0:
        print(
            f"\n  Removed {removed_count} Config resources from state (Control Tower manages these)"
        )
    else:
        print("  No Config resources to remove from state")


def sync_accounts(config: dict, state_resources: set):
    """Sync shared accounts (log_archive, audit) into Terraform state.

    Handles existing accounts that were discovered but not yet imported.
    """
    print("\n=== Syncing Shared Accounts ===\n")

    primary_region = config.get("primary_region", "us-east-1")

    # Get account IDs from tfvars
    account_ids = get_account_ids_from_tfvars()

    imported_count = 0
    skipped_count = 0

    # Define accounts to sync
    accounts = [
        ("log_archive", account_ids.get("log_archive")),
        ("audit", account_ids.get("audit")),
    ]

    org_client = boto3.client("organizations", region_name=primary_region)

    for account_name, account_id in accounts:
        if not account_id:
            print(f"  {account_name}: No account ID found, skipping")
            continue

        tf_address = f"module.accounts.aws_organizations_account.{account_name}"

        if resource_exists_in_state(tf_address, state_resources):
            print(f"  {tf_address} already in state")
            skipped_count += 1
            continue

        # Verify account exists in AWS
        try:
            org_client.describe_account(AccountId=account_id)

            print(f"  Importing {tf_address}...")
            success, output = run_terraform_cmd(["import", tf_address, account_id])
            if success:
                print("    Imported successfully")
                imported_count += 1
            elif "Resource already managed" in output:
                print("    Already in state")
                skipped_count += 1
            else:
                print(f"    Import failed: {output[:200]}")
        except ClientError as e:
            print(f"  Could not verify account {account_id}: {e}")

    print(
        f"\n  Shared Accounts: {imported_count} imported, {skipped_count} already in state"
    )


def sync_ssm_log_groups(config: dict, management_account_id: str, state_resources: set):
    """Sync SSM CloudWatch Log Groups into Terraform state.

    Handles orphaned log groups that may exist from previous failed runs.
    Checks all accounts (management, log_archive, audit) and all regions.
    """
    print("\n=== Syncing SSM CloudWatch Log Groups ===\n")

    resource_prefix = config["resource_prefix"]
    log_group_name = f"/{resource_prefix}/ssm/automation"

    # Get account IDs from tfvars
    account_ids = get_account_ids_from_tfvars()
    if not account_ids["management"]:
        account_ids["management"] = management_account_id

    # Define account types and their module prefixes
    account_types = [
        ("mgmt", account_ids["management"], None),  # None = use default session
        ("log_archive", account_ids["log_archive"], account_ids["log_archive"]),
        ("audit", account_ids["audit"], account_ids["audit"]),
    ]

    imported_count = 0
    skipped_count = 0

    for account_prefix, account_id, assume_account_id in account_types:
        if not account_id:
            print(f"  {account_prefix}: No account ID found, skipping")
            continue

        for region in ALL_REGIONS:
            region_suffix = region_to_module_suffix(region)
            tf_address = f"module.ssm_{account_prefix}_{region_suffix}[0].aws_cloudwatch_log_group.ssm_automation"

            # Skip if already in state
            if resource_exists_in_state(tf_address, state_resources):
                skipped_count += 1
                continue

            # Get session for this account/region
            if assume_account_id:
                session = get_cross_account_session(assume_account_id, region)
                if not session:
                    continue
                logs_client = session.client("logs")
            else:
                logs_client = boto3.client("logs", region_name=region)

            # Check if log group exists in AWS
            try:
                response = logs_client.describe_log_groups(
                    logGroupNamePrefix=log_group_name
                )
                log_groups = response.get("logGroups", [])
                exists = any(
                    lg.get("logGroupName") == log_group_name for lg in log_groups
                )

                if exists:
                    print(f"  Importing {tf_address}...")
                    success, output = run_terraform_cmd(
                        ["import", tf_address, log_group_name]
                    )
                    if success:
                        print("    Imported successfully")
                        imported_count += 1
                    elif "Resource already managed" in output:
                        print("    Already in state")
                        skipped_count += 1
                    else:
                        print(f"    Import failed: {output[:200]}")
            except ClientError:
                # Log group doesn't exist or access denied - will be created by Terraform
                pass

    print(
        f"\n  SSM Log Groups: {imported_count} imported, {skipped_count} already in state"
    )


def remove_organization_from_state_if_external(state_resources: set):
    """Remove organization from state if discovered as external.

    When discovery marks the organization as external (organization_exists=true),
    Terraform sees count change from 1 to 0 and tries to delete the organization.
    This function removes the organization from state to prevent that deletion.
    """
    print("\n=== Checking Organization State ===\n")

    org_address = "module.organization.aws_organizations_organization.main[0]"

    if resource_exists_in_state(org_address, state_resources):
        # Check bootstrap.auto.tfvars.json to see if org is marked as external
        tfvars_path = Path("/work/terraform/bootstrap.auto.tfvars.json")
        if tfvars_path.exists():
            try:
                with open(tfvars_path) as f:
                    tfvars = json.load(f)
                if tfvars.get("organization_exists", False):
                    print(
                        "  Organization discovered as external - removing from state to prevent deletion"
                    )
                    success, output = run_terraform_cmd(["state", "rm", org_address])
                    if success:
                        print("    Removed successfully")
                    else:
                        print(f"    Remove failed: {output[:200]}")
                else:
                    print("  Organization managed by Terraform - keeping in state")
            except Exception as e:
                print(f"  Could not check tfvars: {e}")
    else:
        print("  Organization not in state - no action needed")


def cleanup_old_inspector_enablers(state_resources: set):
    """Remove old inspector enabler resources from state.

    The inspector enabler for the audit account was moved from
    module.inspector[0].aws_inspector2_enabler.audit to the new regional
    enabler modules (inspector_audit_* in inspector-regional.tf).

    These old resources cannot be deleted by Terraform because the audit
    account is the delegated admin with associated members. Instead, we
    remove them from state since they're replaced by the new regional modules.

    Also removes stale org_config resources that were created before enablers
    existed, causing AccessDeniedException on update.
    """
    print("\n=== Cleaning Up Old Inspector Resources ===\n")

    # Old resources from module.inspector to remove
    old_resources = [
        "module.inspector[0].aws_inspector2_enabler.audit",
        "module.inspector[0].aws_inspector2_organization_configuration.main",
        "module.inspector[0].time_sleep.wait_for_enabler",
    ]

    removed_count = 0

    # Remove old module.inspector resources
    for resource in old_resources:
        if resource_exists_in_state(resource, state_resources):
            print(f"  Removing from state: {resource}")
            success, output = run_terraform_cmd(["state", "rm", resource])
            if success:
                print("    Removed successfully")
                removed_count += 1
            else:
                print(f"    Failed to remove: {output[:100]}")

    # Note: Org config cleanup disabled - handled by disabling org_config modules
    # The UpdateOrganizationConfiguration API has persistent AccessDeniedException issues
    # Inspector org config will be managed via post-deployment script instead

    if removed_count > 0:
        print(f"\n  Removed {removed_count} Inspector resources from state")


def sync_service_linked_roles(config: dict, state_resources: set):
    """Sync IAM Service Linked Roles into Terraform state.

    Handles:
    - module.config[0].aws_iam_service_linked_role.config_management
    - module.config[0].aws_iam_service_linked_role.config_log_archive
    - module.config[0].aws_iam_service_linked_role.config_audit
    """
    print("\n=== Syncing IAM Service Linked Roles ===\n")

    primary_region = config.get("primary_region", "us-east-1")

    # Get account IDs from tfvars
    account_ids = get_account_ids_from_tfvars()

    imported_count = 0
    skipped_count = 0

    # Define roles to check
    roles = [
        (
            "config_management",
            None,
            "arn:aws:iam::{account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
        ),
        (
            "config_log_archive",
            account_ids.get("log_archive"),
            "arn:aws:iam::{account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
        ),
        (
            "config_audit",
            account_ids.get("audit"),
            "arn:aws:iam::{account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
        ),
    ]

    for role_suffix, cross_account_id, role_arn_template in roles:
        tf_address = f"module.config[0].aws_iam_service_linked_role.{role_suffix}"

        if resource_exists_in_state(tf_address, state_resources):
            skipped_count += 1
            continue

        # Get IAM client for appropriate account
        if cross_account_id:
            session = get_cross_account_session(cross_account_id, primary_region)
            if not session:
                continue
            iam_client = session.client("iam")
            account_id = cross_account_id
        else:
            iam_client = boto3.client("iam", region_name=primary_region)
            sts_client = boto3.client("sts", region_name=primary_region)
            account_id = sts_client.get_caller_identity()["Account"]

        role_arn = role_arn_template.format(account=account_id)

        # Check if role exists
        try:
            iam_client.get_role(RoleName="AWSServiceRoleForConfig")
            print(f"  Importing {tf_address}...")
            success, output = run_terraform_cmd(["import", tf_address, role_arn])
            if success:
                print("    Imported successfully")
                imported_count += 1
            elif "Resource already managed" in output:
                skipped_count += 1
            else:
                print(f"    Import failed: {output[:200]}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                pass  # Role doesn't exist, will be created

    print(
        f"\n  IAM Service Linked Roles: {imported_count} imported, {skipped_count} already in state"
    )


def sync_organizational_units(config: dict, state_resources: set):
    """Sync organizational units into Terraform state.

    Handles existing OUs that may have been created in previous failed runs.
    """
    print("\n=== Syncing Organizational Units ===\n")

    primary_region = config.get("primary_region", "us-east-1")
    org_client = boto3.client("organizations", region_name=primary_region)

    imported_count = 0
    skipped_count = 0

    # Get root ID
    try:
        roots = org_client.list_roots()["Roots"]
        if not roots:
            print("  No organization root found")
            return
        root_id = roots[0]["Id"]
    except ClientError:
        print("  Could not get organization root")
        return

    # Get expected OUs from config
    tfvars_path = Path("/work/terraform/bootstrap.auto.tfvars.json")
    expected_ous = []
    if tfvars_path.exists():
        try:
            with open(tfvars_path) as f:
                tfvars = json.load(f)
            ou_config = tfvars.get("organizational_units", [])
            for ou in ou_config:
                expected_ous.append(ou["name"])
        except Exception:
            # Default expected OUs
            expected_ous = ["Security", "Production", "NonProduction", "Unmanaged"]

    if not expected_ous:
        expected_ous = ["Security", "Production", "NonProduction", "Unmanaged"]

    # List existing OUs at root level
    try:
        response = org_client.list_organizational_units_for_parent(ParentId=root_id)
        existing_ous = {
            ou["Name"]: ou["Id"] for ou in response.get("OrganizationalUnits", [])
        }
    except ClientError:
        print("  Could not list organizational units")
        return

    # Import OUs that exist but aren't in state
    for ou_name in expected_ous:
        tf_address = f'module.organization.aws_organizations_organizational_unit.level1["{ou_name}"]'

        if resource_exists_in_state(tf_address, state_resources):
            skipped_count += 1
            continue

        if ou_name in existing_ous:
            ou_id = existing_ous[ou_name]
            print(f"  Importing {tf_address}...")
            success, output = run_terraform_cmd(["import", tf_address, ou_id])
            if success:
                print("    Imported successfully")
                imported_count += 1
            elif "Resource already managed" in output:
                skipped_count += 1
            else:
                print(f"    Import failed: {output[:200]}")

    print(
        f"\n  Organizational Units: {imported_count} imported, {skipped_count} already in state"
    )


def sync_delegated_admins(config: dict, state_resources: set):
    """Sync delegated administrators into Terraform state.

    Handles:
    - module.organization.aws_organizations_delegated_administrator.securityhub[0]
    - module.organization.aws_organizations_delegated_administrator.config[0]
    - module.organization.aws_organizations_delegated_administrator.access_analyzer[0]
    - module.organization.aws_organizations_delegated_administrator.inspector[0]
    """
    print("\n=== Syncing Delegated Administrators ===\n")

    primary_region = config.get("primary_region", "us-east-1")

    # Get account IDs from tfvars
    account_ids = get_account_ids_from_tfvars()

    if not account_ids["audit"]:
        print("  No audit account ID found, skipping")
        return

    audit_account_id = account_ids["audit"]
    org_client = boto3.client("organizations", region_name=primary_region)

    imported_count = 0
    skipped_count = 0

    # Define delegated admin services
    services = [
        ("securityhub", "securityhub.amazonaws.com"),
        ("config", "config.amazonaws.com"),
        ("access_analyzer", "access-analyzer.amazonaws.com"),
        ("inspector", "inspector2.amazonaws.com"),
    ]

    for tf_name, service_principal in services:
        tf_address = f"module.organization.aws_organizations_delegated_administrator.{tf_name}[0]"

        if resource_exists_in_state(tf_address, state_resources):
            skipped_count += 1
            continue

        # Check if delegated admin exists in AWS
        try:
            response = org_client.list_delegated_administrators(
                ServicePrincipal=service_principal
            )
            admins = response.get("DelegatedAdministrators", [])

            if any(admin["Id"] == audit_account_id for admin in admins):
                import_id = f"{audit_account_id}/{service_principal}"
                print(f"  Importing {tf_address}...")
                success, output = run_terraform_cmd(["import", tf_address, import_id])
                if success:
                    print("    Imported successfully")
                    imported_count += 1
                elif "Resource already managed" in output:
                    skipped_count += 1
                else:
                    print(f"    Import failed: {output[:200]}")
        except ClientError:
            pass

    print(
        f"\n  Delegated Admins: {imported_count} imported, {skipped_count} already in state"
    )


def sync_securityhub_accounts(
    config: dict, management_account_id: str, state_resources: set
):
    """Sync Security Hub accounts into Terraform state.

    Handles:
    - module.security_hub[0].aws_securityhub_account.management
    - module.security_hub[0].aws_securityhub_account.audit
    - module.security_hub[0].aws_securityhub_organization_admin_account.main
    """
    print("\n=== Syncing Security Hub Accounts ===\n")

    primary_region = config.get("primary_region", "us-east-1")

    # Get account IDs from tfvars
    account_ids = get_account_ids_from_tfvars()
    if not account_ids["management"]:
        account_ids["management"] = management_account_id

    imported_count = 0
    skipped_count = 0

    # Check management account Security Hub
    mgmt_tf_address = "module.security_hub[0].aws_securityhub_account.management"
    if not resource_exists_in_state(mgmt_tf_address, state_resources):
        sh_client = boto3.client("securityhub", region_name=primary_region)
        try:
            sh_client.describe_hub()
            # Security Hub is enabled
            print(f"  Importing {mgmt_tf_address}...")
            success, output = run_terraform_cmd(
                ["import", mgmt_tf_address, account_ids["management"]]
            )
            if success:
                print("    Imported successfully")
                imported_count += 1
            elif "Resource already managed" in output:
                skipped_count += 1
            else:
                print(f"    Import failed: {output[:200]}")
        except ClientError as e:
            if "not subscribed" in str(e).lower():
                pass  # Not enabled, will be created
    else:
        skipped_count += 1

    # Check audit account Security Hub
    audit_tf_address = "module.security_hub[0].aws_securityhub_account.audit"
    if (
        not resource_exists_in_state(audit_tf_address, state_resources)
        and account_ids["audit"]
    ):
        session = get_cross_account_session(account_ids["audit"], primary_region)
        if session:
            sh_client = session.client("securityhub")
            try:
                sh_client.describe_hub()
                # Security Hub is enabled
                print(f"  Importing {audit_tf_address}...")
                success, output = run_terraform_cmd(
                    ["import", audit_tf_address, account_ids["audit"]]
                )
                if success:
                    print("    Imported successfully")
                    imported_count += 1
                elif "Resource already managed" in output:
                    skipped_count += 1
                else:
                    print(f"    Import failed: {output[:200]}")
            except ClientError as e:
                if "not subscribed" in str(e).lower():
                    pass  # Not enabled, will be created
    else:
        skipped_count += 1

    # Check Security Hub Organization Admin Account
    admin_tf_address = (
        "module.security_hub[0].aws_securityhub_organization_admin_account.main"
    )
    if (
        not resource_exists_in_state(admin_tf_address, state_resources)
        and account_ids["audit"]
    ):
        sh_client = boto3.client("securityhub", region_name=primary_region)
        try:
            response = sh_client.list_organization_admin_accounts()
            admin_accounts = response.get("AdminAccounts", [])
            if any(a["AccountId"] == account_ids["audit"] for a in admin_accounts):
                print(f"  Importing {admin_tf_address}...")
                success, output = run_terraform_cmd(
                    ["import", admin_tf_address, account_ids["audit"]]
                )
                if success:
                    print("    Imported successfully")
                    imported_count += 1
                elif "Resource already managed" in output:
                    skipped_count += 1
                else:
                    print(f"    Import failed: {output[:200]}")
        except ClientError:
            pass
    else:
        skipped_count += 1

    # Check Security Hub Finding Aggregator (in audit account)
    aggregator_tf_address = (
        "module.security_hub[0].aws_securityhub_finding_aggregator.main"
    )
    if (
        not resource_exists_in_state(aggregator_tf_address, state_resources)
        and account_ids["audit"]
    ):
        session = get_cross_account_session(account_ids["audit"], primary_region)
        if session:
            sh_client = session.client("securityhub")
            try:
                response = sh_client.list_finding_aggregators()
                aggregators = response.get("FindingAggregators", [])
                if aggregators:
                    aggregator_arn = aggregators[0]["FindingAggregatorArn"]
                    print(f"  Importing {aggregator_tf_address}...")
                    success, output = run_terraform_cmd(
                        ["import", aggregator_tf_address, aggregator_arn]
                    )
                    if success:
                        print("    Imported successfully")
                        imported_count += 1
                    elif "Resource already managed" in output:
                        skipped_count += 1
                    else:
                        print(f"    Import failed: {output[:200]}")
            except ClientError:
                pass
    else:
        skipped_count += 1

    print(
        f"\n  Security Hub Accounts: {imported_count} imported, {skipped_count} already in state"
    )


def sync_guardduty_org_admin(config: dict, state_resources: set):
    """Sync GuardDuty delegated administrator into Terraform state.

    Handles:
    - module.guardduty_org_*[0].aws_guardduty_organization_admin_account.main

    These resources are created from the management account context for each region.
    """
    print("\n=== Syncing GuardDuty Delegated Admin ===\n")

    # Get account IDs from tfvars
    account_ids = get_account_ids_from_tfvars()

    if not account_ids["audit"]:
        print("  No audit account ID found, skipping")
        return

    audit_account_id = account_ids["audit"]
    imported_count = 0
    skipped_count = 0

    for region in ALL_REGIONS:
        region_suffix = region_to_module_suffix(region)

        # Terraform address for delegated admin in this region
        admin_tf_address = f"module.guardduty_org_{region_suffix}[0].aws_guardduty_organization_admin_account.main"

        if resource_exists_in_state(admin_tf_address, state_resources):
            skipped_count += 1
            continue

        # Get GuardDuty client for management account in this region
        gd_client = boto3.client("guardduty", region_name=region)

        # Check if delegated admin exists
        try:
            response = gd_client.list_organization_admin_accounts()
            admin_accounts = response.get("AdminAccounts", [])
            is_delegated_admin = any(
                a["AdminAccountId"] == audit_account_id for a in admin_accounts
            )

            if is_delegated_admin:
                print(f"  Importing {admin_tf_address}...")
                success, output = run_terraform_cmd(
                    ["import", admin_tf_address, audit_account_id]
                )
                if success:
                    print("    Imported successfully")
                    imported_count += 1
                elif "Resource already managed" in output:
                    skipped_count += 1
                else:
                    print(f"    Import failed: {output[:200]}")
        except ClientError:
            # GuardDuty delegated admin doesn't exist - will be created by Terraform
            pass

    print(
        f"\n  GuardDuty Delegated Admin: {imported_count} imported, {skipped_count} already in state"
    )


def sync_guardduty_org_config(config: dict, state_resources: set):
    """Sync GuardDuty organization configuration into Terraform state.

    Handles:
    - module.guardduty_org_config_*[0].aws_guardduty_organization_configuration.main

    These resources are created from the management account context for each region.
    The UpdateOrganizationConfiguration API requires organization master permissions.
    """
    print("\n=== Syncing GuardDuty Org Config ===\n")

    imported_count = 0
    skipped_count = 0

    for region in ALL_REGIONS:
        region_suffix = region_to_module_suffix(region)

        # Terraform address for org config in this region (uses guardduty_org_config module)
        org_config_tf_address = f"module.guardduty_org_config_{region_suffix}[0].aws_guardduty_organization_configuration.main"

        if resource_exists_in_state(org_config_tf_address, state_resources):
            skipped_count += 1
            continue

        # Use management account (current session) to check org config
        gd_client = boto3.client("guardduty", region_name=region)

        # Get detector ID from management account and check if org config exists
        try:
            detector_response = gd_client.list_detectors()
            detector_ids = detector_response.get("DetectorIds", [])
            if detector_ids:
                detector_id = detector_ids[0]
                # Try to describe org config to see if it exists
                try:
                    gd_client.describe_organization_configuration(
                        DetectorId=detector_id
                    )
                    # Org config exists, import it
                    print(f"  Importing {org_config_tf_address}...")
                    success, output = run_terraform_cmd(
                        ["import", org_config_tf_address, detector_id]
                    )
                    if success:
                        print("    Imported successfully")
                        imported_count += 1
                    elif "Resource already managed" in output:
                        skipped_count += 1
                    else:
                        print(f"    Import failed: {output[:200]}")
                except ClientError:
                    # Org config doesn't exist - will be created by Terraform
                    pass
        except ClientError:
            pass

    print(
        f"\n  GuardDuty Org Config: {imported_count} imported, {skipped_count} already in state"
    )


def sync_guardduty_detectors(
    config: dict, management_account_id: str, state_resources: set
):
    """Sync GuardDuty detectors into Terraform state.

    Handles orphaned detectors that may exist from previous failed runs.
    Only syncs audit account detectors - management and log_archive accounts
    are auto-enrolled by the organization configuration with auto_enable_organization_members = "ALL".
    """
    print("\n=== Syncing GuardDuty Detectors ===\n")

    # Get account IDs from tfvars
    account_ids = get_account_ids_from_tfvars()

    # Only sync audit account detectors - management and log_archive are auto-enrolled
    # by the GuardDuty organization configuration (auto_enable_organization_members = "ALL")
    # and don't have explicit Terraform modules.
    if not account_ids["audit"]:
        print("  No audit account ID found, skipping")
        return

    imported_count = 0
    skipped_count = 0

    # Only audit account has explicit detector modules in Terraform
    account_prefix = "audit"
    assume_account_id = account_ids["audit"]

    for region in ALL_REGIONS:
        region_suffix = region_to_module_suffix(region)
        tf_address = f"module.guardduty_{account_prefix}_{region_suffix}[0].aws_guardduty_detector.main"

        # Skip if already in state
        if resource_exists_in_state(tf_address, state_resources):
            skipped_count += 1
            continue

        # Get session for audit account in this region
        session = get_cross_account_session(assume_account_id, region)
        if not session:
            continue
        gd_client = session.client("guardduty")

        # Check if detector exists in AWS
        try:
            response = gd_client.list_detectors()
            detector_ids = response.get("DetectorIds", [])

            if detector_ids:
                detector_id = detector_ids[0]  # Use first detector
                print(f"  Importing {tf_address}...")
                success, output = run_terraform_cmd(["import", tf_address, detector_id])
                if success:
                    print("    Imported successfully")
                    imported_count += 1
                elif "Resource already managed" in output:
                    print("    Already in state")
                    skipped_count += 1
                else:
                    print(f"    Import failed: {output[:200]}")
        except ClientError:
            # Detector doesn't exist or access denied - will be created by Terraform
            pass

    print(
        f"\n  GuardDuty Detectors: {imported_count} imported, {skipped_count} already in state"
    )


def sync_cloudtrail_kms_resources(config: dict, state_resources: set):
    """Sync CloudTrail KMS keys and aliases into Terraform state.

    Handles:
    - module.kms_cloudtrail[0] - KMS key for CloudTrail S3 bucket (log_archive account)
    - module.cloudtrail[0] - KMS key for CloudWatch Logs (management account)
    """
    print("\n=== Syncing CloudTrail KMS Resources ===\n")

    resource_prefix = config["resource_prefix"]
    primary_region = config.get("primary_region", "us-east-1")

    # Get account IDs from tfvars
    account_ids = get_account_ids_from_tfvars()

    imported_count = 0
    skipped_count = 0

    # 1. CloudTrail S3 KMS key (module.kms_cloudtrail) - in log_archive account
    if account_ids["log_archive"]:
        session = get_cross_account_session(account_ids["log_archive"], primary_region)
        if session:
            kms_client = session.client("kms")
            kms_alias_name = f"alias/{resource_prefix}-cloudtrail"
            key_tf_address = "module.kms_cloudtrail[0].aws_kms_key.main"
            alias_tf_address = "module.kms_cloudtrail[0].aws_kms_alias.main"

            key_in_state = resource_exists_in_state(key_tf_address, state_resources)
            alias_in_state = resource_exists_in_state(alias_tf_address, state_resources)

            try:
                key_response = kms_client.describe_key(KeyId=kms_alias_name)
                kms_key_id = key_response["KeyMetadata"]["KeyId"]

                if not key_in_state:
                    print(f"  Importing {key_tf_address}...")
                    success, output = run_terraform_cmd(
                        ["import", key_tf_address, kms_key_id]
                    )
                    if success:
                        print("    Imported successfully")
                        imported_count += 1
                    elif "Resource already managed" in output:
                        skipped_count += 1
                    else:
                        print(f"    Import failed: {output[:200]}")
                else:
                    skipped_count += 1

                if not alias_in_state:
                    print(f"  Importing {alias_tf_address}...")
                    success, output = run_terraform_cmd(
                        ["import", alias_tf_address, kms_alias_name]
                    )
                    if success:
                        print("    Imported successfully")
                        imported_count += 1
                    elif "Resource already managed" in output:
                        skipped_count += 1
                    else:
                        print(f"    Import failed: {output[:200]}")
                else:
                    skipped_count += 1

            except ClientError as e:
                if e.response["Error"]["Code"] == "NotFoundException":
                    print(f"  KMS key {kms_alias_name} not found - will be created")

    # 2. CloudWatch Logs KMS key (module.cloudtrail) - in management account
    kms_client = boto3.client("kms", region_name=primary_region)
    kms_alias_name = f"alias/{resource_prefix}-cloudtrail-cloudwatch-logs"
    key_tf_address = "module.cloudtrail[0].aws_kms_key.cloudwatch_logs"
    alias_tf_address = "module.cloudtrail[0].aws_kms_alias.cloudwatch_logs"

    key_in_state = resource_exists_in_state(key_tf_address, state_resources)
    alias_in_state = resource_exists_in_state(alias_tf_address, state_resources)

    try:
        key_response = kms_client.describe_key(KeyId=kms_alias_name)
        kms_key_id = key_response["KeyMetadata"]["KeyId"]

        if not key_in_state:
            print(f"  Importing {key_tf_address}...")
            success, output = run_terraform_cmd(["import", key_tf_address, kms_key_id])
            if success:
                print("    Imported successfully")
                imported_count += 1
            elif "Resource already managed" in output:
                skipped_count += 1
            else:
                print(f"    Import failed: {output[:200]}")
        else:
            skipped_count += 1

        if not alias_in_state:
            print(f"  Importing {alias_tf_address}...")
            success, output = run_terraform_cmd(
                ["import", alias_tf_address, kms_alias_name]
            )
            if success:
                print("    Imported successfully")
                imported_count += 1
            elif "Resource already managed" in output:
                skipped_count += 1
            else:
                print(f"    Import failed: {output[:200]}")
        else:
            skipped_count += 1

    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            print(f"  KMS key {kms_alias_name} not found - will be created")

    print(
        f"\n  CloudTrail KMS: {imported_count} imported, {skipped_count} already in state"
    )


def sync_config_kms_resources(config: dict, state_resources: set):
    """Sync Config KMS keys and aliases into Terraform state.

    Handles module.kms_config[0] - KMS key for AWS Config (log_archive account)
    """
    print("\n=== Syncing Config KMS Resources ===\n")

    resource_prefix = config["resource_prefix"]
    primary_region = config.get("primary_region", "us-east-1")

    # Get account IDs from tfvars
    account_ids = get_account_ids_from_tfvars()

    imported_count = 0
    skipped_count = 0

    if account_ids["log_archive"]:
        session = get_cross_account_session(account_ids["log_archive"], primary_region)
        if session:
            kms_client = session.client("kms")
            kms_alias_name = f"alias/{resource_prefix}-config"
            key_tf_address = "module.kms_config[0].aws_kms_key.main"
            alias_tf_address = "module.kms_config[0].aws_kms_alias.main"

            key_in_state = resource_exists_in_state(key_tf_address, state_resources)
            alias_in_state = resource_exists_in_state(alias_tf_address, state_resources)

            try:
                key_response = kms_client.describe_key(KeyId=kms_alias_name)
                kms_key_id = key_response["KeyMetadata"]["KeyId"]

                if not key_in_state:
                    print(f"  Importing {key_tf_address}...")
                    success, output = run_terraform_cmd(
                        ["import", key_tf_address, kms_key_id]
                    )
                    if success:
                        print("    Imported successfully")
                        imported_count += 1
                    elif "Resource already managed" in output:
                        skipped_count += 1
                    else:
                        print(f"    Import failed: {output[:200]}")
                else:
                    skipped_count += 1

                if not alias_in_state:
                    print(f"  Importing {alias_tf_address}...")
                    success, output = run_terraform_cmd(
                        ["import", alias_tf_address, kms_alias_name]
                    )
                    if success:
                        print("    Imported successfully")
                        imported_count += 1
                    elif "Resource already managed" in output:
                        skipped_count += 1
                    else:
                        print(f"    Import failed: {output[:200]}")
                else:
                    skipped_count += 1

            except ClientError as e:
                if e.response["Error"]["Code"] == "NotFoundException":
                    print(f"  KMS key {kms_alias_name} not found - will be created")

    print(
        f"\n  Config KMS: {imported_count} imported, {skipped_count} already in state"
    )


def sync_s3_buckets(config: dict, state_resources: set):
    """Sync S3 buckets into Terraform state.

    Handles:
    - module.cloudtrail[0].module.bucket - CloudTrail logs bucket
    - module.config[0].module.bucket - Config data bucket
    """
    print("\n=== Syncing S3 Buckets ===\n")

    resource_prefix = config["resource_prefix"]
    primary_region = config.get("primary_region", "us-east-1")

    # Get account IDs from tfvars
    account_ids = get_account_ids_from_tfvars()

    imported_count = 0
    skipped_count = 0

    if not account_ids["log_archive"]:
        print("  No log_archive account ID found, skipping")
        return

    session = get_cross_account_session(account_ids["log_archive"], primary_region)
    if not session:
        print("  Could not get cross-account session, skipping")
        return

    s3_client = session.client("s3")

    # Define buckets to sync
    buckets = [
        (
            f"{resource_prefix}-cloudtrail-logs-{account_ids['log_archive']}",
            "module.cloudtrail[0].module.bucket.aws_s3_bucket.main",
        ),
        (
            f"{resource_prefix}-config-{account_ids['log_archive']}",
            "module.config[0].module.bucket.aws_s3_bucket.main",
        ),
    ]

    for bucket_name, tf_address in buckets:
        if resource_exists_in_state(tf_address, state_resources):
            skipped_count += 1
            continue

        # Check if bucket exists
        try:
            s3_client.head_bucket(Bucket=bucket_name)

            print(f"  Importing {tf_address}...")
            success, output = run_terraform_cmd(["import", tf_address, bucket_name])
            if success:
                print("    Imported successfully")
                imported_count += 1
            elif "Resource already managed" in output:
                skipped_count += 1
            else:
                print(f"    Import failed: {output[:200]}")

        except ClientError:
            # Bucket doesn't exist - will be created by Terraform
            pass

    print(
        f"\n  S3 Buckets: {imported_count} imported, {skipped_count} already in state"
    )


def sync_ssm_kms_resources(
    config: dict, management_account_id: str, state_resources: set
):
    """Sync SSM KMS keys and aliases into Terraform state.

    Handles orphaned KMS resources that may exist from previous failed runs.
    Checks all accounts (management, log_archive, audit) and all regions.
    """
    print("\n=== Syncing SSM KMS Resources ===\n")

    resource_prefix = config["resource_prefix"]

    # Get account IDs from tfvars
    account_ids = get_account_ids_from_tfvars()
    if not account_ids["management"]:
        account_ids["management"] = management_account_id

    # Define account types and their module prefixes
    account_types = [
        ("mgmt", account_ids["management"], None),  # None = use default session
        ("log_archive", account_ids["log_archive"], account_ids["log_archive"]),
        ("audit", account_ids["audit"], account_ids["audit"]),
    ]

    imported_count = 0
    skipped_count = 0

    for account_prefix, account_id, assume_account_id in account_types:
        if not account_id:
            print(f"  {account_prefix}: No account ID found, skipping")
            continue

        for region in ALL_REGIONS:
            region_suffix = region_to_module_suffix(region)
            kms_alias_name = f"alias/{resource_prefix}-ssm-logs-{region}"

            # Terraform addresses
            key_tf_address = (
                f"module.ssm_{account_prefix}_{region_suffix}[0].aws_kms_key.ssm_logs"
            )
            alias_tf_address = (
                f"module.ssm_{account_prefix}_{region_suffix}[0].aws_kms_alias.ssm_logs"
            )

            # Skip if both already in state
            key_in_state = resource_exists_in_state(key_tf_address, state_resources)
            alias_in_state = resource_exists_in_state(alias_tf_address, state_resources)

            if key_in_state and alias_in_state:
                skipped_count += 2
                continue

            # Get session for this account/region
            if assume_account_id:
                session = get_cross_account_session(assume_account_id, region)
                if not session:
                    continue
                kms_client = session.client("kms")
            else:
                kms_client = boto3.client("kms", region_name=region)

            # Check if KMS alias exists in AWS
            try:
                key_response = kms_client.describe_key(KeyId=kms_alias_name)
                kms_key_id = key_response["KeyMetadata"]["KeyId"]

                # Import KMS key if not in state
                if not key_in_state:
                    print(f"  Importing {key_tf_address}...")
                    success, output = run_terraform_cmd(
                        ["import", key_tf_address, kms_key_id]
                    )
                    if success:
                        print("    Imported successfully")
                        imported_count += 1
                    elif "Resource already managed" in output:
                        print("    Already in state")
                        skipped_count += 1
                    else:
                        print(f"    Import failed: {output[:200]}")

                # Import KMS alias if not in state
                if not alias_in_state:
                    print(f"  Importing {alias_tf_address}...")
                    success, output = run_terraform_cmd(
                        ["import", alias_tf_address, kms_alias_name]
                    )
                    if success:
                        print("    Imported successfully")
                        imported_count += 1
                    elif "Resource already managed" in output:
                        print("    Already in state")
                        skipped_count += 1
                    else:
                        print(f"    Import failed: {output[:200]}")

            except ClientError as e:
                if e.response["Error"]["Code"] == "NotFoundException":
                    # KMS key/alias doesn't exist - will be created by Terraform
                    pass
                else:
                    # Other error - skip this resource
                    pass

    print(
        f"\n  SSM KMS Resources: {imported_count} imported, {skipped_count} already in state"
    )


def main():
    """Main state sync function."""
    print("=" * 50)
    print("  Terraform State Sync")
    print("=" * 50)

    # Load config
    config = load_config()

    # Get current account
    sts_client = boto3.client("sts")
    account_id = sts_client.get_caller_identity()["Account"]
    print(f"\nAccount: {account_id}")

    # Get current state resources (used by multiple sync functions)
    state_resources = get_state_resources()

    # Sync bootstrap resources (KMS key, alias, S3 bucket)
    sync_bootstrap_resources(config, account_id)

    # Sync shared accounts (log_archive, audit)
    sync_accounts(config, state_resources)

    # Sync service KMS resources
    sync_cloudtrail_kms_resources(config, state_resources)
    sync_config_kms_resources(config, state_resources)

    # Sync S3 buckets
    sync_s3_buckets(config, state_resources)

    # Sync organization resources
    sync_organizational_units(config, state_resources)
    sync_delegated_admins(config, state_resources)

    # Sync IAM Service Linked Roles
    sync_service_linked_roles(config, state_resources)

    # Sync Security Hub accounts
    sync_securityhub_accounts(config, account_id, state_resources)

    # Remove organization from state if discovered as external (prevents deletion)
    remove_organization_from_state_if_external(state_resources)

    # Remove Config resources from state when Control Tower manages Config
    cleanup_config_resources_if_external(config, state_resources)

    # Remove old Inspector enabler resources (replaced by regional modules)
    cleanup_old_inspector_enablers(state_resources)

    # Sync GuardDuty delegated admin (management account)
    sync_guardduty_org_admin(config, state_resources)

    # Sync GuardDuty org config (audit account)
    sync_guardduty_org_config(config, state_resources)

    # Sync GuardDuty detectors
    sync_guardduty_detectors(config, account_id, state_resources)

    # Sync SSM resources (handles orphaned resources from failed runs)
    sync_ssm_kms_resources(config, account_id, state_resources)
    sync_ssm_log_groups(config, account_id, state_resources)

    print("\n" + "=" * 50)
    print("  State Sync Complete")
    print("=" * 50 + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
