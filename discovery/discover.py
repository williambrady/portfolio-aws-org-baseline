#!/usr/bin/env python3
"""
Discovery script for AWS Organization baseline.
Inspects the current state of AWS Organizations and outputs variables for Terraform.
"""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional, TypedDict

import boto3
import yaml
from botocore.exceptions import ClientError

# Import local module using importlib to avoid E402 lint errors
_ct_spec = importlib.util.spec_from_file_location(
    "control_tower_regions", Path(__file__).parent / "control_tower_regions.py"
)
_ct_module = importlib.util.module_from_spec(_ct_spec)
_ct_spec.loader.exec_module(_ct_module)
detect_control_tower = _ct_module.detect_control_tower
ct_run_plan = _ct_module.run_plan


class AccountInfo(TypedDict):
    """Type definition for AWS account information."""

    id: str
    name: str
    email: str
    status: str


class SharedAccounts(TypedDict):
    """Type definition for shared accounts discovery result."""

    log_archive: Optional[AccountInfo]
    audit: Optional[AccountInfo]
    security_tooling: Optional[AccountInfo]


def check_terraform_state_for_resource(resource_address: str) -> bool:
    """Check if a resource exists in Terraform state.

    Returns True if the resource is in state, False otherwise.
    """
    try:
        # nosemgrep: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
        result = subprocess.run(  # nosec B607 - runs in controlled Docker environment
            ["terraform", "state", "list"],
            capture_output=True,
            text=True,
            cwd="/work/terraform",
        )
        if result.returncode == 0:
            resources = set(
                line.strip()
                for line in result.stdout.strip().split("\n")
                if line.strip()
            )
            return resource_address in resources
    except Exception:
        pass
    return False


def load_config() -> dict:
    """Load configuration from config.yaml with environment variable overrides.

    Environment variables that can override config.yaml values:
    - VPC_BLOCK_MODE: Overrides vpc_block_public_access.mode (ingress, bidirectional, disabled)
    """
    config_path = Path("/work/config.yaml")
    if not config_path.exists():
        print("Warning: config.yaml not found, using defaults")
        config = {"primary_region": "us-east-1", "resource_prefix": "org-baseline"}
    else:
        with open(config_path) as f:
            config = yaml.safe_load(f)

    # Validate required fields
    if not config.get("resource_prefix"):
        raise ValueError("resource_prefix is required in config.yaml")

    if os.environ.get("VPC_BLOCK_MODE"):
        if "vpc_block_public_access" not in config:
            config["vpc_block_public_access"] = {}
        config["vpc_block_public_access"]["mode"] = os.environ["VPC_BLOCK_MODE"]
        print(
            f"  [env override] vpc_block_public_access.mode = {config['vpc_block_public_access']['mode']}"
        )

    return config


def discover_organization(org_client) -> dict:
    """Discover AWS Organization details.

    The organization_exists flag controls whether Terraform creates the organization:
    - False: Terraform will create/manage the organization
    - True: Terraform will skip creation (brownfield scenario)

    Logic:
    - If org exists in AWS AND is in Terraform state → False (Terraform manages it)
    - If org exists in AWS AND NOT in state → True (brownfield, don't recreate)
    - If org doesn't exist → False (Terraform will create it)
    """
    result = {
        "organization_exists": False,
        "organization_id": "",
        "organization_arn": "",
        "master_account_id": "",
        "feature_set": "",
    }

    try:
        org = org_client.describe_organization()["Organization"]
        result["organization_id"] = org["Id"]
        result["organization_arn"] = org["Arn"]
        result["master_account_id"] = org["MasterAccountId"]
        result["feature_set"] = org["FeatureSet"]
        print(f"  Organization ID: {org['Id']}")
        print(f"  Master Account: {org['MasterAccountId']}")
        print(f"  Feature Set: {org['FeatureSet']}")

        # Check if organization is managed by Terraform
        org_in_state = check_terraform_state_for_resource(
            "module.organization.aws_organizations_organization.main[0]"
        )

        if org_in_state:
            # Terraform created and manages this org - keep managing it
            result["organization_exists"] = False
            print("  Managed by: Terraform (in state)")
        else:
            # Org exists but not in state - brownfield scenario
            result["organization_exists"] = True
            print("  Managed by: External (not in Terraform state)")

    except ClientError as e:
        if e.response["Error"]["Code"] == "AWSOrganizationsNotInUseException":
            print("  No organization exists - will be created")
        else:
            raise

    return result


def discover_organizational_units(org_client, root_id: str) -> list:
    """Discover all organizational units."""
    ous = []

    def get_ous_recursive(parent_id: str, parent_path: str = ""):
        try:
            paginator = org_client.get_paginator("list_organizational_units_for_parent")
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page["OrganizationalUnits"]:
                    ou_path = (
                        f"{parent_path}/{ou['Name']}" if parent_path else ou["Name"]
                    )
                    ous.append(
                        {
                            "id": ou["Id"],
                            "name": ou["Name"],
                            "arn": ou["Arn"],
                            "path": ou_path,
                        }
                    )
                    print(f"    {ou_path} ({ou['Id']})")
                    get_ous_recursive(ou["Id"], ou_path)
        except ClientError:
            pass

    get_ous_recursive(root_id)
    return ous


def discover_accounts(org_client) -> list:
    """Discover all accounts in the organization."""
    accounts = []

    try:
        paginator = org_client.get_paginator("list_accounts")
        for page in paginator.paginate():
            for account in page["Accounts"]:
                accounts.append(
                    {
                        "id": account["Id"],
                        "name": account["Name"],
                        "email": account["Email"],
                        "status": account["Status"],
                        "joined_method": account["JoinedMethod"],
                    }
                )
                status_icon = "+" if account["Status"] == "ACTIVE" else "x"
                print(f"    [{status_icon}] {account['Name']} ({account['Id']})")
    except ClientError:
        pass

    return accounts


def discover_delegated_admins(org_client) -> dict:
    """Discover delegated administrator accounts per service."""
    delegated_admins = {}

    services = [
        "securityhub.amazonaws.com",
        "config.amazonaws.com",
        "access-analyzer.amazonaws.com",
        "inspector2.amazonaws.com",
        "guardduty.amazonaws.com",
    ]

    for service in services:
        try:
            response = org_client.list_delegated_administrators(
                ServicePrincipal=service
            )
            admins = response.get("DelegatedAdministrators", [])
            if admins:
                delegated_admins[service] = [a["Id"] for a in admins]
                print(f"    {service}: {', '.join(delegated_admins[service])}")
        except ClientError:
            pass

    return delegated_admins


def discover_organization_trail(primary_region: str, resource_prefix: str) -> dict:
    """Discover existing organization CloudTrail trail.

    Returns information about any existing organization trail that is NOT managed
    by this baseline. Trails matching our naming pattern ({resource_prefix}-organization-trail)
    are excluded since they are managed by Terraform.
    """
    result = {
        "organization_trail_exists": False,
        "organization_trail_name": "",
        "organization_trail_arn": "",
    }

    # Our managed trail name
    managed_trail_name = f"{resource_prefix}-organization-trail"

    try:
        cloudtrail_client = boto3.client("cloudtrail", region_name=primary_region)
        response = cloudtrail_client.describe_trails(includeShadowTrails=False)

        for trail in response.get("trailList", []):
            # Check if this is an organization trail
            if trail.get("IsOrganizationTrail", False):
                trail_name = trail.get("Name", "")
                # Skip trails that match our managed naming pattern
                if trail_name == managed_trail_name:
                    print(
                        f"    Found: {trail_name} (managed by this baseline, ignoring)"
                    )
                    continue
                result["organization_trail_exists"] = True
                result["organization_trail_name"] = trail_name
                result["organization_trail_arn"] = trail.get("TrailARN", "")
                print(f"    Found: {trail_name} (external organization trail)")
                print(f"    ARN: {trail.get('TrailARN')}")
                break

    except ClientError as e:
        print(f"    Warning: Could not describe trails: {e}")

    return result


def discover_inspector_org_config(primary_region: str, audit_account_id: str) -> dict:
    """Discover existing Inspector organization configuration.

    Returns information about Inspector organization status:
    - Whether Inspector is enabled organization-wide
    - The delegated admin account ID
    - Whether auto-enable is configured

    If Inspector is already enabled with the expected delegated admin (audit account),
    we set inspector_org_exists=True to avoid conflicts.
    """
    result = {
        "inspector_org_exists": False,
        "inspector_delegated_admin": "",
        "inspector_auto_enable_ec2": False,
        "inspector_auto_enable_ecr": False,
        "inspector_auto_enable_lambda": False,
        "inspector_auto_enable_lambda_code": False,
    }

    try:
        inspector_client = boto3.client("inspector2", region_name=primary_region)

        # Check delegated admin status
        try:
            response = inspector_client.list_delegated_admin_accounts()
            admins = response.get("delegatedAdminAccounts", [])
            if admins:
                admin = admins[0]
                result["inspector_delegated_admin"] = admin.get("accountId", "")
                status = admin.get("status", "")
                if status in ["ENABLED", "ENABLE_IN_PROGRESS"]:
                    result["inspector_org_exists"] = True
                    print(
                        f"    Delegated Admin: {result['inspector_delegated_admin']} (status: {status})"
                    )

                    # If we have a delegated admin, check organization configuration
                    # Need to assume role into audit account to check org config
                    if result["inspector_delegated_admin"] == audit_account_id:
                        try:
                            sts_client = boto3.client("sts", region_name=primary_region)
                            assumed = sts_client.assume_role(
                                RoleArn=f"arn:aws:iam::{audit_account_id}:role/OrganizationAccountAccessRole",
                                RoleSessionName="inspector-discovery",
                            )
                            creds = assumed["Credentials"]
                            audit_inspector = boto3.client(
                                "inspector2",
                                region_name=primary_region,
                                aws_access_key_id=creds["AccessKeyId"],
                                aws_secret_access_key=creds["SecretAccessKey"],
                                aws_session_token=creds["SessionToken"],
                            )

                            # Get organization configuration
                            org_config = (
                                audit_inspector.describe_organization_configuration()
                            )
                            auto_enable = org_config.get("autoEnable", {})
                            result["inspector_auto_enable_ec2"] = auto_enable.get(
                                "ec2", False
                            )
                            result["inspector_auto_enable_ecr"] = auto_enable.get(
                                "ecr", False
                            )
                            result["inspector_auto_enable_lambda"] = auto_enable.get(
                                "lambda", False
                            )
                            result["inspector_auto_enable_lambda_code"] = (
                                auto_enable.get("lambdaCode", False)
                            )

                            enabled = []
                            if result["inspector_auto_enable_ec2"]:
                                enabled.append("EC2")
                            if result["inspector_auto_enable_ecr"]:
                                enabled.append("ECR")
                            if result["inspector_auto_enable_lambda"]:
                                enabled.append("Lambda")
                            if result["inspector_auto_enable_lambda_code"]:
                                enabled.append("LambdaCode")
                            if enabled:
                                print(f"    Auto-enable: {', '.join(enabled)}")
                            else:
                                print("    Auto-enable: None configured")
                        except ClientError as e:
                            print(
                                f"    Warning: Could not check org config from audit account: {e}"
                            )
                else:
                    print(
                        f"    Delegated Admin: {result['inspector_delegated_admin']} (status: {status} - not active)"
                    )
            else:
                print("    Delegated Admin: None configured")
        except ClientError as e:
            if "AccessDenied" not in str(e):
                print(f"    Warning: Could not list delegated admins: {e}")

    except ClientError as e:
        print(f"    Warning: Could not check Inspector status: {e}")

    return result


def discover_guardduty_org_config(primary_region: str, audit_account_id: str) -> dict:
    """Discover existing GuardDuty organization configuration.

    Returns information about GuardDuty organization status:
    - Whether GuardDuty is enabled organization-wide
    - The delegated admin account ID
    - Whether auto-enable is configured

    If GuardDuty is already enabled with the expected delegated admin (audit account),
    we set guardduty_org_exists=True to avoid conflicts.
    """
    result = {
        "guardduty_org_exists": False,
        "guardduty_delegated_admin": "",
        "guardduty_auto_enable": False,
        "guardduty_s3_protection": False,
        "guardduty_eks_protection": False,
        "guardduty_malware_protection": False,
    }

    try:
        # Check delegated admin status using Organizations API (more reliable)
        org_client = boto3.client("organizations", region_name=primary_region)
        try:
            response = org_client.list_delegated_administrators(
                ServicePrincipal="guardduty.amazonaws.com"
            )
            admins = response.get("DelegatedAdministrators", [])
            if admins:
                result["guardduty_delegated_admin"] = admins[0]["Id"]
                result["guardduty_org_exists"] = True
                print(f"    Delegated Admin: {result['guardduty_delegated_admin']}")

                # If we have a delegated admin, check organization configuration
                if result["guardduty_delegated_admin"] == audit_account_id:
                    try:
                        sts_client = boto3.client("sts", region_name=primary_region)
                        assumed = sts_client.assume_role(
                            RoleArn=f"arn:aws:iam::{audit_account_id}:role/OrganizationAccountAccessRole",
                            RoleSessionName="guardduty-discovery",
                        )
                        creds = assumed["Credentials"]
                        audit_guardduty = boto3.client(
                            "guardduty",
                            region_name=primary_region,
                            aws_access_key_id=creds["AccessKeyId"],
                            aws_secret_access_key=creds["SecretAccessKey"],
                            aws_session_token=creds["SessionToken"],
                        )

                        # Get detector ID in audit account
                        detectors = audit_guardduty.list_detectors()
                        if detectors.get("DetectorIds"):
                            detector_id = detectors["DetectorIds"][0]

                            # Get organization configuration
                            org_config = (
                                audit_guardduty.describe_organization_configuration(
                                    DetectorId=detector_id
                                )
                            )
                            result["guardduty_auto_enable"] = (
                                org_config.get("AutoEnable", False)
                                or org_config.get("AutoEnableOrganizationMembers", "")
                                == "ALL"
                            )

                            # Check data sources
                            datasources = org_config.get("DataSources", {})
                            s3_logs = datasources.get("S3Logs", {})
                            result["guardduty_s3_protection"] = s3_logs.get(
                                "AutoEnable", False
                            )

                            kubernetes = datasources.get("Kubernetes", {})
                            audit_logs = kubernetes.get("AuditLogs", {})
                            result["guardduty_eks_protection"] = audit_logs.get(
                                "AutoEnable", False
                            )

                            malware = datasources.get("MalwareProtection", {})
                            scan_ec2 = malware.get("ScanEc2InstanceWithFindings", {})
                            ebs = scan_ec2.get("EbsVolumes", {})
                            result["guardduty_malware_protection"] = ebs.get(
                                "AutoEnable", False
                            )

                            enabled = []
                            if result["guardduty_auto_enable"]:
                                enabled.append("AutoEnable=ALL")
                            if result["guardduty_s3_protection"]:
                                enabled.append("S3")
                            if result["guardduty_eks_protection"]:
                                enabled.append("EKS")
                            if result["guardduty_malware_protection"]:
                                enabled.append("Malware")
                            if enabled:
                                print(f"    Protection plans: {', '.join(enabled)}")
                            else:
                                print("    Protection plans: None auto-enabled")
                    except ClientError as e:
                        print(
                            f"    Warning: Could not check org config from audit account: {e}"
                        )
            else:
                print("    Delegated Admin: None configured")
        except ClientError as e:
            if "AccessDenied" not in str(e):
                print(f"    Warning: Could not list delegated admins: {e}")

    except ClientError as e:
        print(f"    Warning: Could not check GuardDuty status: {e}")

    return result


def discover_security_hub_org_config(
    primary_region: str, audit_account_id: str
) -> dict:
    """Discover existing Security Hub organization configuration.

    Returns information about Security Hub organization status:
    - Whether Security Hub is enabled organization-wide
    - The delegated admin account ID
    - Configuration policy status

    If Security Hub is already enabled with the expected delegated admin (audit account),
    we set securityhub_org_exists=True to avoid conflicts.
    """
    result = {
        "securityhub_org_exists": False,
        "securityhub_delegated_admin": "",
        "securityhub_auto_enable": False,
        "securityhub_auto_enable_standards": False,
        "securityhub_configuration_type": "",  # CENTRAL or LOCAL
    }

    try:
        # Check delegated admin status using Organizations API
        org_client = boto3.client("organizations", region_name=primary_region)
        try:
            response = org_client.list_delegated_administrators(
                ServicePrincipal="securityhub.amazonaws.com"
            )
            admins = response.get("DelegatedAdministrators", [])
            if admins:
                result["securityhub_delegated_admin"] = admins[0]["Id"]
                result["securityhub_org_exists"] = True
                print(f"    Delegated Admin: {result['securityhub_delegated_admin']}")

                # If we have a delegated admin, check organization configuration
                if result["securityhub_delegated_admin"] == audit_account_id:
                    try:
                        sts_client = boto3.client("sts", region_name=primary_region)
                        assumed = sts_client.assume_role(
                            RoleArn=f"arn:aws:iam::{audit_account_id}:role/OrganizationAccountAccessRole",
                            RoleSessionName="securityhub-discovery",
                        )
                        creds = assumed["Credentials"]
                        audit_securityhub = boto3.client(
                            "securityhub",
                            region_name=primary_region,
                            aws_access_key_id=creds["AccessKeyId"],
                            aws_secret_access_key=creds["SecretAccessKey"],
                            aws_session_token=creds["SessionToken"],
                        )

                        # Get organization configuration
                        try:
                            org_config = (
                                audit_securityhub.describe_organization_configuration()
                            )
                            result["securityhub_auto_enable"] = org_config.get(
                                "AutoEnable", False
                            )
                            result["securityhub_auto_enable_standards"] = (
                                org_config.get("AutoEnableStandards", "") == "DEFAULT"
                            )
                            result["securityhub_configuration_type"] = org_config.get(
                                "OrganizationConfiguration", {}
                            ).get("ConfigurationType", "LOCAL")

                            config_info = []
                            if result["securityhub_auto_enable"]:
                                config_info.append("AutoEnable")
                            if result["securityhub_auto_enable_standards"]:
                                config_info.append("AutoEnableStandards")
                            if result["securityhub_configuration_type"]:
                                config_info.append(
                                    f"Type={result['securityhub_configuration_type']}"
                                )
                            if config_info:
                                print(f"    Configuration: {', '.join(config_info)}")
                        except ClientError as e:
                            if "not subscribed" in str(e).lower():
                                print(
                                    "    Note: Security Hub not enabled in audit account"
                                )
                            else:
                                print(
                                    f"    Warning: Could not describe org config: {e}"
                                )
                    except ClientError as e:
                        print(
                            f"    Warning: Could not check org config from audit account: {e}"
                        )
            else:
                print("    Delegated Admin: None configured")
        except ClientError as e:
            if "AccessDenied" not in str(e):
                print(f"    Warning: Could not list delegated admins: {e}")

    except ClientError as e:
        print(f"    Warning: Could not check Security Hub status: {e}")

    return result


def discover_kms_keys(
    primary_region: str, resource_prefix: str, log_archive_account_id: str
) -> dict:
    """Discover existing KMS keys that match our naming pattern.

    Checks for KMS keys that would be created by the baseline:
    - {resource_prefix}-tfstate-key (management account)
    - {resource_prefix}-cloudtrail-key (log-archive account)
    - {resource_prefix}-config-key (log-archive account)
    """
    result = {
        "kms_tfstate_exists": False,
        "kms_tfstate_arn": "",
        "kms_cloudtrail_exists": False,
        "kms_cloudtrail_arn": "",
        "kms_config_exists": False,
        "kms_config_arn": "",
    }

    # Check management account for tfstate key
    try:
        kms_client = boto3.client("kms", region_name=primary_region)
        paginator = kms_client.get_paginator("list_aliases")
        for page in paginator.paginate():
            for alias in page.get("Aliases", []):
                alias_name = alias.get("AliasName", "")
                if alias_name == f"alias/{resource_prefix}-tfstate-key":
                    result["kms_tfstate_exists"] = True
                    result["kms_tfstate_arn"] = alias.get("TargetKeyId", "")
                    # Get full ARN
                    try:
                        key_info = kms_client.describe_key(KeyId=alias["TargetKeyId"])
                        result["kms_tfstate_arn"] = key_info["KeyMetadata"]["Arn"]
                        print(f"    tfstate key: {result['kms_tfstate_arn']}")
                    except ClientError:
                        pass
                    break
    except ClientError as e:
        print(f"    Warning: Could not check KMS keys in management account: {e}")

    # Check log-archive account for cloudtrail and config keys
    if log_archive_account_id:
        try:
            sts_client = boto3.client("sts", region_name=primary_region)
            assumed = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{log_archive_account_id}:role/OrganizationAccountAccessRole",
                RoleSessionName="kms-discovery",
            )
            creds = assumed["Credentials"]
            log_kms_client = boto3.client(
                "kms",
                region_name=primary_region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )

            paginator = log_kms_client.get_paginator("list_aliases")
            for page in paginator.paginate():
                for alias in page.get("Aliases", []):
                    alias_name = alias.get("AliasName", "")
                    if alias_name == f"alias/{resource_prefix}-cloudtrail-key":
                        result["kms_cloudtrail_exists"] = True
                        try:
                            key_info = log_kms_client.describe_key(
                                KeyId=alias["TargetKeyId"]
                            )
                            result["kms_cloudtrail_arn"] = key_info["KeyMetadata"][
                                "Arn"
                            ]
                            print(f"    cloudtrail key: {result['kms_cloudtrail_arn']}")
                        except ClientError:
                            pass
                    elif alias_name == f"alias/{resource_prefix}-config-key":
                        result["kms_config_exists"] = True
                        try:
                            key_info = log_kms_client.describe_key(
                                KeyId=alias["TargetKeyId"]
                            )
                            result["kms_config_arn"] = key_info["KeyMetadata"]["Arn"]
                            print(f"    config key: {result['kms_config_arn']}")
                        except ClientError:
                            pass
        except ClientError as e:
            print(f"    Warning: Could not check KMS keys in log-archive account: {e}")

    if not any(
        [
            result["kms_tfstate_exists"],
            result["kms_cloudtrail_exists"],
            result["kms_config_exists"],
        ]
    ):
        print("    (no baseline KMS keys found)")

    return result


def discover_config_recorders(
    primary_region: str,
    mgmt_account_id: str,
    log_archive_account_id: str,
    audit_account_id: str,
) -> dict:
    """Discover Config recorder status in core accounts.

    Checks Config recorder status in:
    - Management account
    - Log-archive account
    - Audit account

    Returns status for primary region (other regions checked during post-deployment).
    """
    result = {
        "config_recorder_mgmt_exists": False,
        "config_recorder_mgmt_recording": False,
        "config_recorder_log_archive_exists": False,
        "config_recorder_log_archive_recording": False,
        "config_recorder_audit_exists": False,
        "config_recorder_audit_recording": False,
    }

    def check_config_recorder(config_client, account_name):
        """Check if Config recorder exists and is recording."""
        try:
            recorders = config_client.describe_configuration_recorders()
            if recorders.get("ConfigurationRecorders"):
                recorder_name = recorders["ConfigurationRecorders"][0].get("name", "")
                # Check status
                status_response = config_client.describe_configuration_recorder_status()
                statuses = status_response.get("ConfigurationRecordersStatus", [])
                is_recording = any(s.get("recording", False) for s in statuses)
                return True, is_recording, recorder_name
        except ClientError:
            pass
        return False, False, ""

    # Check management account
    try:
        config_client = boto3.client("config", region_name=primary_region)
        exists, recording, name = check_config_recorder(config_client, "management")
        result["config_recorder_mgmt_exists"] = exists
        result["config_recorder_mgmt_recording"] = recording
        if exists:
            status = "recording" if recording else "stopped"
            print(f"    Management: {name} ({status})")
    except ClientError as e:
        print(f"    Warning: Could not check Config in management account: {e}")

    # Check log-archive account
    if log_archive_account_id:
        try:
            sts_client = boto3.client("sts", region_name=primary_region)
            assumed = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{log_archive_account_id}:role/OrganizationAccountAccessRole",
                RoleSessionName="config-discovery",
            )
            creds = assumed["Credentials"]
            log_config_client = boto3.client(
                "config",
                region_name=primary_region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
            exists, recording, name = check_config_recorder(
                log_config_client, "log-archive"
            )
            result["config_recorder_log_archive_exists"] = exists
            result["config_recorder_log_archive_recording"] = recording
            if exists:
                status = "recording" if recording else "stopped"
                print(f"    Log Archive: {name} ({status})")
        except ClientError as e:
            print(f"    Warning: Could not check Config in log-archive account: {e}")

    # Check audit account
    if audit_account_id:
        try:
            sts_client = boto3.client("sts", region_name=primary_region)
            assumed = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{audit_account_id}:role/OrganizationAccountAccessRole",
                RoleSessionName="config-discovery",
            )
            creds = assumed["Credentials"]
            audit_config_client = boto3.client(
                "config",
                region_name=primary_region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
            exists, recording, name = check_config_recorder(
                audit_config_client, "audit"
            )
            result["config_recorder_audit_exists"] = exists
            result["config_recorder_audit_recording"] = recording
            if exists:
                status = "recording" if recording else "stopped"
                print(f"    Audit: {name} ({status})")
        except ClientError as e:
            print(f"    Warning: Could not check Config in audit account: {e}")

    if not any(
        [
            result["config_recorder_mgmt_exists"],
            result["config_recorder_log_archive_exists"],
            result["config_recorder_audit_exists"],
        ]
    ):
        print("    (no Config recorders found in core accounts)")

    return result


def discover_vpc_block_public_access(primary_region: str, mgmt_account_id: str) -> dict:
    """Discover current VPC block public access settings.

    Checks the current VPC block public access mode in the management account
    for the primary region.
    """
    result = {
        "vpc_block_current_mode": "",
        "vpc_block_enabled": False,
    }

    try:
        ec2_client = boto3.client("ec2", region_name=primary_region)
        response = ec2_client.describe_vpc_block_public_access_options()
        options = response.get("VpcBlockPublicAccessOptions", {})

        state = options.get("InternetGatewayBlockMode", "")
        if state:
            result["vpc_block_enabled"] = state != "off"
            if state == "block-ingress":
                result["vpc_block_current_mode"] = "ingress"
            elif state == "block-bidirectional":
                result["vpc_block_current_mode"] = "bidirectional"
            else:
                result["vpc_block_current_mode"] = "disabled"
            print(
                f"    Current mode: {result['vpc_block_current_mode']} (AWS state: {state})"
            )
        else:
            print("    VPC block public access: not configured")
    except ClientError as e:
        if "InvalidParameterValue" in str(e) or "UnsupportedOperation" in str(e):
            print("    VPC block public access: not available in this region")
        else:
            print(f"    Warning: Could not check VPC block public access: {e}")

    return result


def discover_ec2_defaults(primary_region: str) -> dict:
    """Discover current EC2/EBS default settings.

    Checks:
    - EBS encryption by default
    - EBS snapshot public access block
    - IMDSv2 default settings
    """
    result = {
        "ebs_encryption_enabled": False,
        "ebs_snapshot_block_enabled": False,
        "imdsv2_required": False,
    }

    try:
        ec2_client = boto3.client("ec2", region_name=primary_region)

        # Check EBS encryption by default
        try:
            response = ec2_client.get_ebs_encryption_by_default()
            result["ebs_encryption_enabled"] = response.get(
                "EbsEncryptionByDefault", False
            )
        except ClientError:
            pass

        # Check EBS snapshot public access block
        try:
            response = ec2_client.get_snapshot_block_public_access_state()
            state = response.get("State", "")
            result["ebs_snapshot_block_enabled"] = state in [
                "block-all-sharing",
                "block-new-sharing",
            ]
        except ClientError:
            pass

        # Check IMDS defaults
        try:
            response = ec2_client.get_instance_metadata_defaults()
            defaults = response.get("AccountLevel", {})
            http_tokens = defaults.get("HttpTokens", "")
            result["imdsv2_required"] = http_tokens == "required"
        except ClientError:
            pass

        enabled = []
        if result["ebs_encryption_enabled"]:
            enabled.append("EBS-encryption")
        if result["ebs_snapshot_block_enabled"]:
            enabled.append("snapshot-block")
        if result["imdsv2_required"]:
            enabled.append("IMDSv2-required")

        if enabled:
            print(f"    Enabled: {', '.join(enabled)}")
        else:
            print("    No EC2 defaults configured")

    except ClientError as e:
        print(f"    Warning: Could not check EC2 defaults: {e}")

    return result


def discover_ssm_settings(primary_region: str) -> dict:
    """Discover current SSM settings.

    Checks:
    - SSM document public sharing block
    """
    result = {
        "ssm_public_sharing_blocked": False,
    }

    try:
        ssm_client = boto3.client("ssm", region_name=primary_region)

        # Check public sharing settings
        try:
            response = ssm_client.get_service_setting(
                SettingId="/ssm/documents/console/public-sharing-permission"
            )
            value = response.get("ServiceSetting", {}).get("SettingValue", "")
            result["ssm_public_sharing_blocked"] = value == "Disable"
            if result["ssm_public_sharing_blocked"]:
                print("    Public document sharing: blocked")
            else:
                print("    Public document sharing: allowed")
        except ClientError as e:
            if "ServiceSettingNotFound" in str(e):
                print(
                    "    Public document sharing: not configured (defaults to allowed)"
                )
            else:
                print(f"    Warning: Could not check SSM settings: {e}")

    except ClientError as e:
        print(f"    Warning: Could not check SSM settings: {e}")

    return result


def discover_organization_config(
    primary_region: str, resource_prefix: str, audit_account_id: str = ""
) -> dict:
    """Discover existing organization-level AWS Config aggregator.

    Returns information about any existing organization Config aggregator that is NOT
    managed by this baseline. Aggregators matching our naming pattern are excluded.

    Checks both the management account and the audit account (if provided), since
    Control Tower creates the aggregator in the delegated admin (audit) account.

    Control Tower creates:
    - aws-controltower-ConfigAggregatorForOrganizations (aggregator in audit account)
    - Config recorders in all accounts via StackSets
    - SCPs preventing modification of Config recorders
    """
    result = {
        "organization_config_exists": False,
        "organization_config_aggregator_name": "",
        "organization_config_aggregator_arn": "",
    }

    # Our managed aggregator name
    managed_aggregator_name = f"{resource_prefix}-config-aggregator"

    def check_aggregators(config_client, account_label: str) -> bool:
        """Check for organization aggregators in a given account. Returns True if found."""
        try:
            response = config_client.describe_configuration_aggregators()

            for aggregator in response.get("ConfigurationAggregators", []):
                # Check if this is an organization aggregator
                org_source = aggregator.get("OrganizationAggregationSource")
                if org_source and org_source.get("AllAwsRegions", False):
                    aggregator_name = aggregator.get("ConfigurationAggregatorName", "")
                    # Skip aggregators that match our managed naming pattern
                    if aggregator_name == managed_aggregator_name:
                        print(
                            f"    Found: {aggregator_name} (managed by this baseline, ignoring)"
                        )
                        continue
                    result["organization_config_exists"] = True
                    result["organization_config_aggregator_name"] = aggregator_name
                    result["organization_config_aggregator_arn"] = aggregator.get(
                        "ConfigurationAggregatorArn", ""
                    )
                    print(f"    Found: {aggregator_name} (in {account_label})")
                    print(f"    ARN: {aggregator.get('ConfigurationAggregatorArn')}")
                    return True
        except ClientError as e:
            print(
                f"    Warning: Could not describe config aggregators in {account_label}: {e}"
            )
        return False

    # Check management account first
    config_client = boto3.client("config", region_name=primary_region)
    if check_aggregators(config_client, "management account"):
        return result

    # Check audit account if provided and no aggregator found in management
    if audit_account_id:
        try:
            sts_client = boto3.client("sts", region_name=primary_region)
            assumed = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{audit_account_id}:role/OrganizationAccountAccessRole",
                RoleSessionName="config-aggregator-discovery",
            )
            creds = assumed["Credentials"]
            audit_config_client = boto3.client(
                "config",
                region_name=primary_region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
            check_aggregators(audit_config_client, "audit account")
        except ClientError as e:
            print(
                f"    Warning: Could not check audit account for config aggregators: {e}"
            )

    return result


def get_accounts_in_ou(org_client, ou_id: str) -> list:
    """Get list of account IDs in a specific OU."""
    account_ids = []
    try:
        paginator = org_client.get_paginator("list_accounts_for_parent")
        for page in paginator.paginate(ParentId=ou_id):
            for account in page["Accounts"]:
                if account["Status"] == "ACTIVE":
                    account_ids.append(account["Id"])
    except ClientError:
        pass
    return account_ids


def fuzzy_match_account_type(account_name: str) -> str:
    """Fuzzy match account name to determine account type.

    Returns: "log_archive", "audit", "security_tooling", or "" if no match.

    Matching rules (case-insensitive, checked in priority order):
    - "audit" in name -> audit
    - "log" in name -> log_archive
    - "security" and "tool" in name -> security_tooling
    """
    name_lower = account_name.lower()

    # Check for audit first (matches: "audit", "Audit", "security-audit", etc.)
    if "audit" in name_lower:
        return "audit"

    # Check for log archive (matches: "log-archive", "LogArchive", "log_archive", "logs", etc.)
    if "log" in name_lower:
        return "log_archive"

    # Check for security tooling (matches: "security-tooling", "SecurityTooling", etc.)
    if "security" in name_lower and "tool" in name_lower:
        return "security_tooling"

    return ""


def discover_shared_accounts(
    accounts: list, config: dict, org_client=None, security_ou_id: str = ""
) -> SharedAccounts:
    """Identify shared accounts from config with fuzzy matching fallback.

    Matching strategy:
    1. Exact name match from config (highest priority)
    2. If Security OU exists and has accounts, use fuzzy matching on those accounts
    3. Fall back to fuzzy matching on all accounts
    """
    shared = {
        "log_archive": None,
        "audit": None,
        "security_tooling": None,
    }

    shared_config = config.get("shared_accounts", {})

    # Build lookup by account ID
    accounts_by_id = {a["id"]: a for a in accounts}

    # Step 1: Try exact name match from config
    for account in accounts:
        if shared_config.get("log_archive", {}).get("name") == account["name"]:
            shared["log_archive"] = account
            print(f"    Log Archive: {account['name']} ({account['id']}) [exact match]")
        elif shared_config.get("audit", {}).get("name") == account["name"]:
            shared["audit"] = account
            print(f"    Audit: {account['name']} ({account['id']}) [exact match]")
        elif shared_config.get("security_tooling", {}).get("name") == account["name"]:
            shared["security_tooling"] = account
            print(
                f"    Security Tooling: {account['name']} ({account['id']}) [exact match]"
            )

    # Step 2: If we're missing accounts and have a Security OU, try fuzzy matching there first
    missing = [k for k, v in shared.items() if v is None and k != "security_tooling"]

    if missing and security_ou_id and org_client:
        security_ou_accounts = get_accounts_in_ou(org_client, security_ou_id)
        candidate_accounts = [
            accounts_by_id[aid] for aid in security_ou_accounts if aid in accounts_by_id
        ]

        for account in candidate_accounts:
            account_type = fuzzy_match_account_type(account["name"])
            if (
                account_type
                and account_type in missing
                and shared[account_type] is None
            ):
                shared[account_type] = account
                print(
                    f"    {account_type.replace('_', ' ').title()}: {account['name']} ({account['id']}) [fuzzy match in Security OU]"
                )
                missing.remove(account_type)

    # Step 3: Fall back to fuzzy matching on all accounts if still missing
    if missing:
        for account in accounts:
            account_type = fuzzy_match_account_type(account["name"])
            if (
                account_type
                and account_type in missing
                and shared[account_type] is None
            ):
                shared[account_type] = account
                print(
                    f"    {account_type.replace('_', ' ').title()}: {account['name']} ({account['id']}) [fuzzy match]"
                )
                missing.remove(account_type)

    return shared


def get_root_id(org_client) -> str:
    """Get the organization root ID."""
    try:
        roots = org_client.list_roots()["Roots"]
        if roots:
            return roots[0]["Id"]
    except ClientError:
        pass
    return ""


def main():
    """Main discovery function."""
    print("=" * 50)
    print("  AWS Organization Discovery")
    print("=" * 50)
    print("")

    # Load config
    config = load_config()
    resource_prefix = config["resource_prefix"]
    primary_region = config.get("primary_region", "us-east-1")

    # Create clients
    org_client = boto3.client("organizations", region_name=primary_region)
    sts_client = boto3.client("sts", region_name=primary_region)

    # Get current account info
    caller = sts_client.get_caller_identity()
    current_account_id = caller["Account"]
    print(f"Current Account: {current_account_id}")
    print("")

    # Discover organization
    print("Organization:")
    org_info = discover_organization(org_client)
    print("")

    # Initialize discovery results
    discovery = {
        "current_account_id": current_account_id,
        "resource_prefix": resource_prefix,
        "primary_region": primary_region,
        **org_info,
        "organizational_units": [],
        "accounts": [],
        "delegated_admins": {},
        "shared_accounts": {
            "log_archive_account_id": "",
            "audit_account_id": "",
            "security_tooling_account_id": "",
        },
    }

    if org_info["organization_exists"]:
        root_id = get_root_id(org_client)

        # Discover OUs
        print("Organizational Units:")
        if root_id:
            discovery["organizational_units"] = discover_organizational_units(
                org_client, root_id
            )
        if not discovery["organizational_units"]:
            print("    (none)")
        print("")

        # Discover accounts
        print("Accounts:")
        discovery["accounts"] = discover_accounts(org_client)
        if not discovery["accounts"]:
            print("    (none)")
        print("")

        # Discover delegated admins
        print("Delegated Administrators:")
        discovery["delegated_admins"] = discover_delegated_admins(org_client)
        if not discovery["delegated_admins"]:
            print("    (none)")
        print("")

        # Find Security OU ID for fuzzy matching
        security_ou_name = config.get("security_ou_name", "Security")
        security_ou_id = ""
        for ou in discovery["organizational_units"]:
            if ou["name"].lower() == security_ou_name.lower():
                security_ou_id = ou["id"]
                break

        # Identify shared accounts
        print("Shared Accounts:")
        shared = discover_shared_accounts(
            discovery["accounts"], config, org_client, security_ou_id
        )
        log_archive = shared["log_archive"]
        audit = shared["audit"]
        security_tooling = shared["security_tooling"]
        if log_archive is not None:
            discovery["shared_accounts"]["log_archive_account_id"] = log_archive["id"]
        if audit is not None:
            discovery["shared_accounts"]["audit_account_id"] = audit["id"]
        if security_tooling is not None:
            discovery["shared_accounts"]["security_tooling_account_id"] = (
                security_tooling["id"]
            )
        if not any(shared.values()):
            print("    (none identified)")
        print("")

    # Discover existing organization CloudTrail (runs regardless of org state)
    print("Organization CloudTrail:")
    cloudtrail_info = discover_organization_trail(primary_region, resource_prefix)
    discovery["organization_trail_exists"] = cloudtrail_info[
        "organization_trail_exists"
    ]
    discovery["organization_trail_name"] = cloudtrail_info["organization_trail_name"]
    discovery["organization_trail_arn"] = cloudtrail_info["organization_trail_arn"]
    if not cloudtrail_info["organization_trail_exists"]:
        print("    (none found - will be created)")
    print("")

    # Discover existing organization Config aggregator (runs regardless of org state)
    # Check both management and audit accounts since Control Tower puts the aggregator in audit
    print("Organization Config:")
    audit_account_for_config = discovery["shared_accounts"].get("audit_account_id", "")
    config_info = discover_organization_config(
        primary_region, resource_prefix, audit_account_for_config
    )
    discovery["organization_config_exists"] = config_info["organization_config_exists"]
    discovery["organization_config_aggregator_name"] = config_info[
        "organization_config_aggregator_name"
    ]
    discovery["organization_config_aggregator_arn"] = config_info[
        "organization_config_aggregator_arn"
    ]
    if not config_info["organization_config_exists"]:
        print("    (none found - will be created)")
    print("")

    # Discover Control Tower Landing Zone
    print("Control Tower:")
    ct_info = detect_control_tower(primary_region)
    discovery["control_tower_exists"] = ct_info["control_tower_exists"]
    discovery["landing_zone_arn"] = ct_info.get("landing_zone_arn", "")
    discovery["governed_regions"] = ct_info.get("governed_regions", [])

    if ct_info["control_tower_exists"]:
        print(f"    Found: Landing Zone v{ct_info['landing_zone_version']}")
        print(f"    Status: {ct_info['landing_zone_status']}")
        print(f"    Governed regions: {len(ct_info['governed_regions'])}")

        # Run plan to show what regions would change
        ct_run_plan(primary_region)
    else:
        print("    (not detected)")
    print("")

    # Get audit account ID for security service discovery
    audit_account_id = discovery["shared_accounts"].get("audit_account_id", "")

    # Discover Inspector organization configuration
    print("Inspector Organization:")
    if audit_account_id:
        inspector_info = discover_inspector_org_config(primary_region, audit_account_id)
        discovery["inspector_org_exists"] = inspector_info["inspector_org_exists"]
        discovery["inspector_delegated_admin"] = inspector_info[
            "inspector_delegated_admin"
        ]
        discovery["inspector_auto_enable_ec2"] = inspector_info[
            "inspector_auto_enable_ec2"
        ]
        discovery["inspector_auto_enable_ecr"] = inspector_info[
            "inspector_auto_enable_ecr"
        ]
        discovery["inspector_auto_enable_lambda"] = inspector_info[
            "inspector_auto_enable_lambda"
        ]
        discovery["inspector_auto_enable_lambda_code"] = inspector_info[
            "inspector_auto_enable_lambda_code"
        ]
        if not inspector_info["inspector_org_exists"]:
            print("    (not configured - will be set up)")
    else:
        print("    (skipped - audit account not identified)")
        discovery["inspector_org_exists"] = False
        discovery["inspector_delegated_admin"] = ""
    print("")

    # Discover GuardDuty organization configuration
    print("GuardDuty Organization:")
    if audit_account_id:
        guardduty_info = discover_guardduty_org_config(primary_region, audit_account_id)
        discovery["guardduty_org_exists"] = guardduty_info["guardduty_org_exists"]
        discovery["guardduty_delegated_admin"] = guardduty_info[
            "guardduty_delegated_admin"
        ]
        discovery["guardduty_auto_enable"] = guardduty_info["guardduty_auto_enable"]
        discovery["guardduty_s3_protection"] = guardduty_info["guardduty_s3_protection"]
        discovery["guardduty_eks_protection"] = guardduty_info[
            "guardduty_eks_protection"
        ]
        discovery["guardduty_malware_protection"] = guardduty_info[
            "guardduty_malware_protection"
        ]
        if not guardduty_info["guardduty_org_exists"]:
            print("    (not configured - will be set up)")
    else:
        print("    (skipped - audit account not identified)")
        discovery["guardduty_org_exists"] = False
        discovery["guardduty_delegated_admin"] = ""
    print("")

    # Discover Security Hub organization configuration
    print("Security Hub Organization:")
    if audit_account_id:
        securityhub_info = discover_security_hub_org_config(
            primary_region, audit_account_id
        )
        discovery["securityhub_org_exists"] = securityhub_info["securityhub_org_exists"]
        discovery["securityhub_delegated_admin"] = securityhub_info[
            "securityhub_delegated_admin"
        ]
        discovery["securityhub_auto_enable"] = securityhub_info[
            "securityhub_auto_enable"
        ]
        discovery["securityhub_auto_enable_standards"] = securityhub_info[
            "securityhub_auto_enable_standards"
        ]
        discovery["securityhub_configuration_type"] = securityhub_info[
            "securityhub_configuration_type"
        ]
        if not securityhub_info["securityhub_org_exists"]:
            print("    (not configured - will be set up)")
    else:
        print("    (skipped - audit account not identified)")
        discovery["securityhub_org_exists"] = False
        discovery["securityhub_delegated_admin"] = ""
    print("")

    # Get account IDs for Priority 2 discovery
    log_archive_account_id = discovery["shared_accounts"].get(
        "log_archive_account_id", ""
    )
    mgmt_account_id = current_account_id

    # Discover KMS keys
    print("KMS Keys:")
    kms_info = discover_kms_keys(
        primary_region, resource_prefix, log_archive_account_id
    )
    discovery["kms_tfstate_exists"] = kms_info["kms_tfstate_exists"]
    discovery["kms_tfstate_arn"] = kms_info["kms_tfstate_arn"]
    discovery["kms_cloudtrail_exists"] = kms_info["kms_cloudtrail_exists"]
    discovery["kms_cloudtrail_arn"] = kms_info["kms_cloudtrail_arn"]
    discovery["kms_config_exists"] = kms_info["kms_config_exists"]
    discovery["kms_config_arn"] = kms_info["kms_config_arn"]
    print("")

    # Discover Config recorder status in core accounts
    print("Config Recorders (primary region):")
    config_recorder_info = discover_config_recorders(
        primary_region, mgmt_account_id, log_archive_account_id, audit_account_id
    )
    discovery["config_recorder_mgmt_exists"] = config_recorder_info[
        "config_recorder_mgmt_exists"
    ]
    discovery["config_recorder_mgmt_recording"] = config_recorder_info[
        "config_recorder_mgmt_recording"
    ]
    discovery["config_recorder_log_archive_exists"] = config_recorder_info[
        "config_recorder_log_archive_exists"
    ]
    discovery["config_recorder_log_archive_recording"] = config_recorder_info[
        "config_recorder_log_archive_recording"
    ]
    discovery["config_recorder_audit_exists"] = config_recorder_info[
        "config_recorder_audit_exists"
    ]
    discovery["config_recorder_audit_recording"] = config_recorder_info[
        "config_recorder_audit_recording"
    ]
    print("")

    # Discover VPC block public access settings
    print("VPC Block Public Access:")
    vpc_info = discover_vpc_block_public_access(primary_region, mgmt_account_id)
    discovery["vpc_block_current_mode"] = vpc_info["vpc_block_current_mode"]
    discovery["vpc_block_enabled"] = vpc_info["vpc_block_enabled"]
    print("")

    # Discover EC2/EBS defaults
    print("EC2/EBS Defaults:")
    ec2_info = discover_ec2_defaults(primary_region)
    discovery["ebs_encryption_enabled"] = ec2_info["ebs_encryption_enabled"]
    discovery["ebs_snapshot_block_enabled"] = ec2_info["ebs_snapshot_block_enabled"]
    discovery["imdsv2_required"] = ec2_info["imdsv2_required"]
    print("")

    # Discover SSM settings
    print("SSM Settings:")
    ssm_info = discover_ssm_settings(primary_region)
    discovery["ssm_public_sharing_blocked"] = ssm_info["ssm_public_sharing_blocked"]
    print("")

    # Get root ID for OUs
    root_id = ""
    if org_info["organization_exists"]:
        root_id = get_root_id(org_client)
        discovery["root_id"] = root_id

    # Extract Security Hub config
    security_hub_config = config.get("security_hub", {})
    securityhub_standards = security_hub_config.get("standards", ["aws-foundational"])
    securityhub_disabled_controls = security_hub_config.get("disabled_controls", [])

    # Extract Organizational Unit config
    organizational_units = config.get(
        "organizational_units",
        [
            {"name": "Security", "children": []},
            {
                "name": "Workloads",
                "children": [
                    {"name": "Production", "children": []},
                    {"name": "NonProduction", "children": []},
                ],
            },
            {"name": "Unmanaged", "children": []},
        ],
    )

    # Normalize OU config - ensure children key exists
    def normalize_ou(ou):
        return {
            "name": ou.get("name"),
            "children": [normalize_ou(child) for child in ou.get("children", [])],
        }

    organizational_units = [normalize_ou(ou) for ou in organizational_units]

    # Security OU name for account placement
    security_ou_name = config.get("security_ou_name", "Security")

    # Extract VPC block public access config
    vpc_config = config.get("vpc_block_public_access", {})
    vpc_block_public_access_mode = vpc_config.get("mode", "ingress")

    # Extract shared account config
    shared_accounts_config = config.get("shared_accounts", {})
    log_archive_config = shared_accounts_config.get("log_archive", {})
    audit_config = shared_accounts_config.get("audit", {})
    security_tooling_config = shared_accounts_config.get("security_tooling", {})

    # Get account names
    log_archive_name = log_archive_config.get("name", "log-archive")
    audit_name = audit_config.get("name", "audit")
    security_tooling_name = security_tooling_config.get("name", "")

    # Get emails from config (may be empty if accounts already exist)
    log_archive_email = log_archive_config.get("email", "")
    audit_email = audit_config.get("email", "")
    security_tooling_email = security_tooling_config.get("email", "")

    # Build lookup of discovered accounts by ID for email auto-detection
    discovered_accounts_by_id = {a["id"]: a for a in discovery["accounts"]}

    # Auto-detect emails from discovered accounts if not specified in config
    log_archive_email_source = "config"
    audit_email_source = "config"
    security_tooling_email_source = "config"

    if not log_archive_email and discovery["shared_accounts"]["log_archive_account_id"]:
        account = discovered_accounts_by_id.get(
            discovery["shared_accounts"]["log_archive_account_id"]
        )
        if account and account.get("email"):
            log_archive_email = account["email"]
            log_archive_email_source = "discovered"

    if not audit_email and discovery["shared_accounts"]["audit_account_id"]:
        account = discovered_accounts_by_id.get(
            discovery["shared_accounts"]["audit_account_id"]
        )
        if account and account.get("email"):
            audit_email = account["email"]
            audit_email_source = "discovered"

    if (
        not security_tooling_email
        and discovery["shared_accounts"]["security_tooling_account_id"]
    ):
        account = discovered_accounts_by_id.get(
            discovery["shared_accounts"]["security_tooling_account_id"]
        )
        if account and account.get("email"):
            security_tooling_email = account["email"]
            security_tooling_email_source = "discovered"

    # Validate required emails (only for accounts that will be created)
    if (
        not discovery["shared_accounts"]["log_archive_account_id"]
        and not log_archive_email
    ):
        raise ValueError(
            "shared_accounts.log_archive.email is required in config.yaml (account does not exist)"
        )
    if not discovery["shared_accounts"]["audit_account_id"] and not audit_email:
        raise ValueError(
            "shared_accounts.audit.email is required in config.yaml (account does not exist)"
        )

    # Display account emails with source
    print("Account Emails:")
    print(f"    Log Archive: {log_archive_email} [{log_archive_email_source}]")
    print(f"    Audit: {audit_email} [{audit_email_source}]")
    if security_tooling_email:
        print(
            f"    Security Tooling: {security_tooling_email} [{security_tooling_email_source}]"
        )
    print("")

    # Write bootstrap.auto.tfvars.json
    tfvars = {
        "resource_prefix": resource_prefix,
        "primary_region": primary_region,
        "organization_exists": discovery["organization_exists"],
        "organization_id": discovery["organization_id"],
        "master_account_id": discovery["master_account_id"],
        "root_id": root_id,
        # Account names and emails from config
        "log_archive_account_name": log_archive_name,
        "log_archive_account_email": log_archive_email,
        "log_archive_account_id": discovery["shared_accounts"][
            "log_archive_account_id"
        ],
        "audit_account_name": audit_name,
        "audit_account_email": audit_email,
        "audit_account_id": discovery["shared_accounts"]["audit_account_id"],
        "security_tooling_account_name": security_tooling_name,
        "security_tooling_account_email": security_tooling_email,
        "security_tooling_account_id": discovery["shared_accounts"][
            "security_tooling_account_id"
        ],
        # Security Hub config
        "securityhub_standards": securityhub_standards,
        "securityhub_disabled_controls": securityhub_disabled_controls,
        # OU config
        "organizational_units": organizational_units,
        "security_ou_name": security_ou_name,
        # Custom tags from config (filter out empty values)
        "custom_tags": {k: v for k, v in config.get("tags", {}).items() if v},
        # VPC block public access config
        "vpc_block_public_access_mode": vpc_block_public_access_mode,
        # Control Tower discovery
        "control_tower_exists": discovery.get("control_tower_exists", False),
        # CloudTrail discovery
        "organization_trail_exists": discovery.get("organization_trail_exists", False),
        # Config discovery
        "organization_config_exists": discovery.get(
            "organization_config_exists", False
        ),
        # Inspector discovery
        "inspector_org_exists": discovery.get("inspector_org_exists", False),
        "inspector_delegated_admin": discovery.get("inspector_delegated_admin", ""),
        # GuardDuty discovery
        "guardduty_org_exists": discovery.get("guardduty_org_exists", False),
        "guardduty_delegated_admin": discovery.get("guardduty_delegated_admin", ""),
        # Security Hub discovery
        "securityhub_org_exists": discovery.get("securityhub_org_exists", False),
        "securityhub_discovered_delegated_admin": discovery.get(
            "securityhub_delegated_admin", ""
        ),
    }

    # Alternate contacts config - validate if enabled
    alternate_contacts_config = config.get("alternate_contacts", {})
    enable_alternate_contacts = alternate_contacts_config.get(
        "enable_alternate_contacts", False
    )
    billing_contact = alternate_contacts_config.get("billing_contact")
    operations_contact = alternate_contacts_config.get("operations_contact")
    security_contact = alternate_contacts_config.get("security_contact")

    if enable_alternate_contacts:
        missing_contacts = []
        if not billing_contact:
            missing_contacts.append("billing_contact")
        if not operations_contact:
            missing_contacts.append("operations_contact")
        if not security_contact:
            missing_contacts.append("security_contact")
        if missing_contacts:
            raise ValueError(
                f"alternate_contacts.enable_alternate_contacts is true but the following "
                f"contacts are missing in config.yaml: {', '.join(missing_contacts)}"
            )

    tfvars["enable_alternate_contacts"] = enable_alternate_contacts
    tfvars["billing_contact"] = billing_contact
    tfvars["operations_contact"] = operations_contact
    tfvars["security_contact"] = security_contact

    tfvars_path = Path("/work/terraform/bootstrap.auto.tfvars.json")
    with open(tfvars_path, "w") as f:
        json.dump(tfvars, f, indent=2)
    print(f"Written: {tfvars_path}")

    # Also write full discovery for reference
    discovery_path = Path("/work/terraform/discovery.json")
    with open(discovery_path, "w") as f:
        json.dump(discovery, f, indent=2, default=str)
    print(f"Written: {discovery_path}")

    print("")
    print("Discovery complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
