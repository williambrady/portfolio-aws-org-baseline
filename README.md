# portfolio-aws-org-baseline

Setup a secure AWS Organization baseline with discovery-driven Terraform deployment.

## Overview

portfolio-aws-org-baseline bootstraps secure baseline configurations for AWS Organizations. It creates the organization structure, shared accounts, and configures security services using Terraform and Python/Boto3.

## Features

### Organization Structure
- **AWS Organization** - Creates organization with feature set "ALL"
- **Organizational Units** - Configurable hierarchy (supports 3 levels of nesting)
- **Shared Accounts** - log-archive, audit, security-tooling (optional)

### Security Services
- **CloudTrail** - Organization trail with KMS encryption, logs to log-archive account
- **AWS Config** - Config recorders in all regions for all accounts, aggregator in audit account
- **Security Hub** - Delegated admin, finding aggregation, configurable standards
- **AWS Inspector** - Organization-wide vulnerability scanning in all regions (EC2, ECR, Lambda, Lambda Code) with per-region delegated admin and auto-enable configuration
- **GuardDuty** - Threat detection in all regions with organization-wide auto-enable:
  - S3 protection, K8s audit logs, malware protection
  - Lambda Network Logs (GuardDuty.6)
  - RDS Login Events (GuardDuty.9)
  - Runtime Monitoring (EKS, ECS Fargate, EC2 agent management)
- **IAM Password Policy** - Enforced across all accounts (24 char min, complexity, 24 password history)
- **SSM Settings** - Block public sharing, CloudWatch logging for Automation with KMS encryption (1 year retention)
- **EC2 Defaults** - EBS encryption, block snapshot public access, IMDSv2 required
- **S3 Account Public Access Block** - Block public access for all S3 buckets at account level
- **VPC Block Public Access** - Configurable internet gateway blocking (ingress, bidirectional, or disabled)
- **Delegated Administrators** - Security Hub, GuardDuty, AWS Config, IAM Access Analyzer, Inspector

### Infrastructure Modules
- **KMS** - Centralized key management for all services
- **S3** - Reusable bucket module with access logging support
- **S3 Access Logs** - Dedicated buckets for S3 access logging

### Control Tower Integration
- **Automatic Detection** - Detects existing Control Tower Landing Zones
- **CloudTrail/Config Skip** - Automatically skips CloudTrail and Config modules when Control Tower manages them
- **Region Governance** - Extends Control Tower governance to all available AWS regions

### Post-Deployment Automation
- **Deployment Verification** - Verifies organization, OUs, accounts, and delegated admins
- **Default VPC Cleanup** - Removes default VPCs across all accounts and regions
- **Config Member Account Enablement** - Enables and validates AWS Config in all member accounts

## Prerequisites

- **Docker** - Required for running the baseline
- **AWS CLI** - Configured with a profile for the management account
- **AWS Credentials** - Administrative access to the management account (OrganizationsFullAccess, IAMFullAccess, etc.)

For detailed information about each deployment phase, see [STEPS.md](STEPS.md).

## Quick Start

### 1. Configure

Edit `config.yaml` with your settings:

```yaml
# Required: Prefix for all resource names (S3 buckets, KMS keys, etc.)
resource_prefix: "myorg"

# Required: Primary AWS region for state bucket and finding aggregation
primary_region: "us-east-1"

# Shared account configuration
# Email is required only if accounts don't exist yet
# For existing accounts, email is auto-detected from AWS Organizations
shared_accounts:
  log_archive:
    name: "Log Archive"
    email: "aws+log-archive@example.com"  # Optional if account exists
  audit:
    name: "Audit"
    email: "aws+audit@example.com"        # Optional if account exists
```

### 2. Plan

```bash
AWS_PROFILE=management-account make plan
```

### 3. Apply

```bash
AWS_PROFILE=management-account make apply
```

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `make discover` | Discover current AWS state without changes |
| `make plan` | Discovery + Terraform plan (preview changes) |
| `make apply` | Discovery + Terraform apply + post-deployment tasks |
| `make destroy` | Destroy all managed resources (use with caution) |
| `make shell` | Open interactive shell in container for debugging |

### Examples

```bash
# Preview changes for a new organization
AWS_PROFILE=mgmt make plan

# Apply baseline to management account
AWS_PROFILE=mgmt make apply

# Apply with VPC public access blocking disabled
AWS_PROFILE=mgmt VPC_BLOCK_MODE=disabled make apply

# Apply with bidirectional VPC blocking (most restrictive)
AWS_PROFILE=mgmt VPC_BLOCK_MODE=bidirectional make apply

# Debug: open shell in container
AWS_PROFILE=mgmt make shell
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_PROFILE` | AWS profile for management account | *Required* |
| `VPC_BLOCK_MODE` | VPC public access mode | `ingress` |

**VPC_BLOCK_MODE options:**
- `ingress` - Block inbound internet, allow outbound (recommended)
- `bidirectional` - Block both inbound and outbound (most restrictive)
- `disabled` - No VPC blocking (least secure)

## Configuration Reference

Edit `config.yaml` to customize the baseline:

```yaml
# REQUIRED: Prefix for all AWS resource names
# Used for: S3 buckets, KMS keys, CloudTrail, etc.
# Example resources: {prefix}-tfstate-{account_id}, {prefix}-cloudtrail-logs
resource_prefix: "myorg"

# REQUIRED: Primary AWS region
# - Terraform state bucket location
# - Security Hub finding aggregation region
# - Config aggregator region
primary_region: "us-east-1"

# Shared account configuration
# Accounts are created in the Security OU
shared_accounts:
  log_archive:
    name: "Log Archive"           # Account name in AWS
    email: "aws+logs@example.com" # Required only for new accounts

  audit:
    name: "Audit"
    email: "aws+audit@example.com" # Required only for new accounts

  # Optional: Security tooling account
  # security_tooling:
  #   name: "Security Tooling"
  #   email: "aws+security@example.com"

# Note: For existing accounts, email can be omitted - it will be
# auto-detected from AWS Organizations during discovery

# Custom tags applied to all resources
tags:
  owner: "platform-team"
  contact: "platform@example.com"

# Organizational Unit structure (supports 3 levels of nesting)
organizational_units:
  - name: Security      # Shared accounts placed here
  - name: Production
  - name: Non-Production
  - name: Sandbox
    children:
      - name: Dev
      - name: Test

# VPC Block Public Access configuration
vpc_block_public_access:
  mode: "ingress"  # ingress | bidirectional | disabled

# Security Hub standards to enable
security_hub:
  standards:
    - aws-foundational  # AWS Foundational Security Best Practices
    - cis-1.4          # CIS AWS Foundations Benchmark v1.4.0
    - nist-800-53      # NIST 800-53 Rev. 5
    # - pci-dss        # PCI DSS v3.2.1 (optional)
```

### Brownfield Deployments

For existing AWS Organizations, the discovery process automatically:
- Detects existing organization and root ID
- Finds existing log-archive and audit accounts by name matching
- **Auto-detects email addresses** from discovered accounts (no need to specify in config.yaml)
- Identifies existing OUs to avoid duplicates
- Detects Control Tower and skips CloudTrail/Config if managed by CT
- Imports existing resources into Terraform state

**Email Auto-Detection:** When accounts already exist in AWS Organizations, you can omit the `email` field in config.yaml. The discovery script will retrieve the email from AWS and display its source:

```
Account Emails:
    Log Archive: aws+logs@example.com [discovered]
    Audit: aws+audit@example.com [discovered]
```

If accounts don't exist yet, email is required in config.yaml to create them.

## Project Structure

```
portfolio-aws-org-baseline/
├── entrypoint.sh           # Main orchestration script
├── config.yaml             # Configuration file
├── requirements.txt        # Python dependencies
├── discovery/
│   ├── discover.py         # AWS discovery script
│   ├── state_sync.py       # Terraform state synchronization
│   └── control_tower_regions.py  # Control Tower region governance
├── post-deployment/
│   ├── verify.py           # Deployment verification
│   ├── cleanup-default-vpcs.py
│   └── enable-config-member-accounts.py  # Config enablement for member accounts
├── terraform/
│   ├── main.tf             # Root module orchestration
│   ├── variables.tf        # Variable definitions
│   ├── outputs.tf          # Output definitions
│   ├── providers.tf        # Provider configurations
│   ├── versions.tf         # Version constraints
│   ├── guardduty-regional.tf  # GuardDuty multi-region deployment
│   ├── inspector-regional.tf  # Inspector multi-region deployment
│   └── modules/
│       ├── kms/            # KMS key management
│       ├── s3/             # Reusable S3 bucket
│       ├── s3-tfstate/     # Terraform state bucket
│       ├── organization/   # AWS Org, OUs, delegated admins
│       ├── accounts/       # Shared accounts
│       ├── security-hub/   # Security Hub configuration
│       ├── cloudtrail/     # Organization CloudTrail
│       ├── config/         # AWS Config recorders/aggregator
│       ├── config-recorder/ # Single-region Config recorder module
│       ├── inspector/      # AWS Inspector base module
│       ├── inspector-org/  # Per-region Inspector delegated admin
│       ├── inspector-enabler/ # Single-region Inspector enabler
│       ├── inspector-org-config/ # Per-region Inspector org configuration
│       ├── guardduty-org/  # Per-region GuardDuty delegated admin
│       ├── guardduty-enabler/ # Single-region GuardDuty enabler
│       ├── guardduty-org-config/ # Per-region GuardDuty org configuration
│       ├── iam-password-policy/  # IAM password policy
│       ├── s3-account-public-access-block/ # S3 account public access block
│       ├── ssm-settings/   # SSM settings (public sharing block, CloudWatch logging)
│       ├── ec2-defaults/   # EC2/EBS security defaults
│       └── vpc-defaults/   # VPC block public access
├── Dockerfile
└── Makefile
```

## State Management

- Terraform state stored in S3: `{resource_prefix}-tfstate-{account_id}/organization/terraform.tfstate`
- State bucket created automatically on first run with:
  - KMS encryption (dedicated key with alias `{resource_prefix}-tfstate`)
  - Versioning enabled
  - SSL enforcement
  - Public access blocked

## Resources Created

### Organization
- AWS Organization (feature set: ALL)
- Organizational Units (configurable via config.yaml)
- Shared Accounts in Security OU

### KMS Keys
- **tfstate** - Terraform state bucket encryption (management account)
- **cloudtrail** - CloudTrail log encryption (log-archive account)
- **config** - AWS Config data encryption (log-archive account)

### S3 Buckets
- **tfstate** - Terraform state with versioning and encryption
- **access-logs** - S3 access logging (per account)
- **cloudtrail-logs** - CloudTrail logs with lifecycle policies
- **config** - AWS Config snapshots with lifecycle policies

### Security Services
- **CloudTrail**: Organization trail, multi-region, S3 bucket with KMS encryption
- **AWS Config**: Recorders in all 17 regions for management/log-archive/audit accounts, aggregator in audit
- **Security Hub**: Delegated admin, finding aggregator, standards subscriptions
- **AWS Inspector**:
  - Delegated admin configured per-region (17 regions)
  - EC2/ECR/Lambda scanning enabled in all regions
  - Lambda Code scanning in supported regions
  - Auto-enable configured for new member accounts
- **GuardDuty**:
  - Delegated admin configured per-region (17 regions)
  - Detectors enabled in all 17 regions for all accounts
  - Organization auto-enable set to ALL
  - Protection plans: S3, K8s audit logs, malware protection
  - Lambda Network Logs enabled (GuardDuty.6)
  - RDS Login Events enabled (GuardDuty.9)
  - Runtime Monitoring with EKS/ECS/EC2 agent management
- **IAM Password Policy**: 24 char minimum, uppercase/lowercase/numbers/symbols required, 24 password history, admin reset on expiry
- **SSM Settings**: Public sharing blocked, CloudWatch logging for Automation enabled with KMS encryption and 365-day retention in all 17 regions for all accounts
- **EC2 Defaults**: EBS encryption by default (alias/aws/ebs), block EBS snapshot public access, IMDSv2 required with 2-hop limit
- **S3 Account Public Access Block**: Block public ACLs, policies, and bucket access at account level for all 3 accounts
- **VPC Block Public Access**: Internet gateway blocking at VPC level (configurable: ingress, bidirectional, or disabled) in all 17 regions for all 3 accounts
- **Delegated Administrators**: Security Hub, GuardDuty, Config, Access Analyzer, Inspector

## Module Details

### KMS Module
Centralized KMS key creation with configurable policies:
- Service principal access (CloudTrail, Config, etc.)
- Cross-account access
- Organization-wide access

### S3 Module
Reusable S3 bucket with security best practices:
- KMS encryption
- Versioning
- SSL enforcement
- Access logging (with `is_access_logging_bucket` option)
- Configurable lifecycle rules
- Custom bucket policies

### Inspector Module
Organization-wide vulnerability scanning with a multi-module architecture:

**Module Structure:**
| Module | Account | Purpose |
|--------|---------|---------|
| `inspector-org` | Management | Designate delegated admin (per-region) |
| `inspector-enabler` | All accounts | Enable Inspector scanning |
| `inspector-org-config` | Delegated Admin | Configure auto-enable settings |

**Important:** Inspector's delegated admin is **regional**, not global. The `EnableDelegatedAdminAccount` API must be called in each region where Inspector organization features are needed.

**Features:**
- EC2 instance scanning
- ECR container image scanning
- Lambda function scanning
- Lambda code scanning (supported regions only - not us-west-1, ca-central-1, etc.)
- Automatic Security Hub integration
- Auto-enable for new member accounts

### GuardDuty Module
Threat detection with organization-wide configuration:

**Module Structure:**
| Module | Account | Purpose |
|--------|---------|---------|
| `guardduty-org` | Management | Designate delegated admin (per-region) |
| `guardduty-enabler` | Delegated Admin | Enable GuardDuty detector |
| `guardduty-org-config` | Delegated Admin | Configure auto-enable and protection plans |

**Protection Plans (auto-enabled for all members):**
- S3 Data Events protection
- Kubernetes Audit Logs
- Malware Protection (EBS scanning)
- Lambda Network Logs (GuardDuty.6)
- RDS Login Events (GuardDuty.9)
- Runtime Monitoring with:
  - EKS Addon Management
  - ECS Fargate Agent Management
  - EC2 Agent Management

### IAM Password Policy Module
Account-level password policy:
- Minimum 24 characters
- Uppercase, lowercase, numbers, symbols required
- 24 password history (no reuse)
- 90 day maximum age
- Admin must reset expired passwords

## Post-Deployment Tasks

After Terraform successfully applies the baseline configuration, the system automatically runs post-deployment tasks:

### Deployment Verification

Verifies organization structure, OUs, accounts, and delegated administrators are configured correctly.

### Inspector Member Enrollment

**Purpose:** Enrolls all organization member accounts as Inspector members under the delegated administrator.

**Why This Exists:** While Terraform configures auto-enable for new accounts, existing accounts need to be explicitly associated with the delegated administrator.

**Process:**
1. Assumes role into the delegated admin (audit) account
2. Fetches all active organization accounts
3. Compares against existing Inspector members
4. Enrolls any accounts not already members

**Example output:**
```
Inspector Member Enrollment
==================================================
Running from account: 123456789012
Inspector delegated admin: 987654321098
Assuming role into audit account...
  Successfully assumed OrganizationAccountAccessRole

Accounts to enroll (5):
  + 111111111111 - Log Archive
  + 222222222222 - Workload-Dev
  + 333333333333 - Workload-Prod

Enrolling accounts...
  Enrolling 111111111111 (Log Archive)... OK
  Enrolling 222222222222 (Workload-Dev)... OK
  Enrolling 333333333333 (Workload-Prod)... OK

Enrollment complete: 5/5 accounts enrolled
```

### GuardDuty Verification

**Purpose:** Validates GuardDuty organization configuration across all 17 regions.

**Checks:**
- GuardDuty service access enabled in Organizations
- Delegated administrator correctly configured in all regions
- Organization auto-enable configuration applied
- Detectors enabled in management, log-archive, and audit accounts

### Default VPC Cleanup

**Purpose:** Removes default VPCs across all accounts in the organization and all active AWS regions as a security best practice.

**Process:**
1. Enumerates all active accounts in the organization
2. Assumes `OrganizationAccountAccessRole` in each account
3. Identifies default VPCs in each region
4. Safely deletes VPC components in order:
   - Detaches and deletes Internet Gateways
   - Deletes Subnets
   - Deletes Security Groups (non-default)
   - Deletes Route Tables (non-main)
   - Deletes Network ACLs (non-default)
   - Deletes the VPC itself

**Dependency Handling:** If default VPCs contain running instances or other active resources, they are marked as "skipped" (not failed). The baseline deployment succeeds, and skipped VPCs can be cleaned up in follow-up processes after dependencies are removed.

**Example output:**
```
Processing Production Account (123456789012)...
  Deleted default VPCs in: us-west-2, eu-west-1
  Skipped (has dependencies): us-east-1

==================================================
  Summary
==================================================
  Accounts processed: 5
  Default VPCs deleted: 75
  Skipped (dependencies): 3
  Errors: 0

Completed! 3 VPC(s) skipped due to active dependencies.
These will be cleaned up in follow-up processes.
```

### Config Member Account Enablement

**Purpose:** Enables AWS Config recorders in all member accounts (those not managed by Terraform) and ensures they deliver to the centralized S3 bucket with proper encryption.

**Why This Exists:** Terraform manages Config for the three core accounts (management, log-archive, audit). Member accounts need Config enabled separately, and existing accounts may have misconfigured recorders pointing to local buckets.

**Process:**
1. Enumerates all active accounts in the organization
2. Excludes accounts managed by Terraform (management, audit, log-archive)
3. Assumes `OrganizationAccountAccessRole` in each member account
4. Creates Config service-linked role if needed
5. For each region, validates existing Config configuration:
   - **Creates** recorder/channel if not present
   - **Updates** recorder if not using the Service-Linked Role
   - **Updates** delivery channel if pointing to wrong S3 bucket or missing KMS
   - **Skips** regions already correctly configured

**Configuration Validation:**
| Setting | Expected Value |
|---------|----------------|
| IAM Role | `AWSServiceRoleForConfig` (Service-Linked Role) |
| S3 Bucket | Central Config bucket in log-archive account |
| KMS Key | Central Config KMS key |

**Dry-Run Mode:** During `make plan`, the script runs in dry-run mode showing what changes would be made without applying them.

**Example output:**
```
Processing Workload-Dev (444444444444)...
  Would create service-linked role
  Would enable Config in: 15 regions
  Would update Config in: 2 regions
    - us-west-2: Wrong S3 bucket: local-bucket (expected central-bucket)
    - us-west-2: Wrong KMS key: None

============================================================
  Dry Run Summary
============================================================
  Member accounts processed: 5
  Service-linked roles to create: 3
  Regions to enable: 75
  Regions to update (misconfigured): 10
  Regions already correct: 0

Issues that would be fixed:
  - Wrong S3 bucket: local-bucket (expected central-bucket) (8 regions)
  - Wrong KMS key: None (10 regions)
  - Wrong IAM role: arn:aws:iam::xxx:role/CustomRole (expected SLR) (2 regions)

Dry run complete - 85 region(s) would be changed.
```

**Control Tower Environments:** If Control Tower is managing Config, the script detects this and exits gracefully - no action needed as member accounts are automatically enrolled by Control Tower.

## Utility Scripts

The `scripts/` directory contains utility scripts for diagnostics and testing:

### test-guardduty-org-config.py

Tests GuardDuty organization configuration API access from different accounts to verify which account (management or delegated admin) can call specific APIs.

**Usage:**
```bash
python3 scripts/test-guardduty-org-config.py --profile <management-account-profile> --region us-east-1
```

**Tests performed:**
- `ListOrganizationAdminAccounts` - from both accounts
- `DescribeOrganizationConfiguration` - from both accounts
- `UpdateOrganizationConfiguration` - from both accounts
- `UpdateOrganizationConfiguration` (feature) - from both accounts

**Expected results:**
| API | Management Account | Delegated Admin |
|-----|-------------------|-----------------|
| `ListOrganizationAdminAccounts` | SUCCESS | FAILED |
| `DescribeOrganizationConfiguration` | FAILED | SUCCESS |
| `UpdateOrganizationConfiguration` | FAILED | SUCCESS |

This confirms that `aws_guardduty_organization_configuration` and `aws_guardduty_organization_configuration_feature` Terraform resources must use delegated admin account providers.
