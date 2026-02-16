# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AWS Organization baseline deployment using Terraform wrapped in Docker. Implements discovery-driven deployments for multi-account AWS Organizations.

**Stack:** Terraform (infrastructure), Python (discovery/verification), Bash (orchestration), Docker (distribution)

## Architecture

### Core Principles

1. **Terraform as State Owner** - Single source of truth for all AWS infrastructure state
2. **Config-Driven** - `config.yaml` in project root defines organization specification
3. **Discovery-Driven** - Python discovers existing resources before Terraform runs
4. **Idempotent Operations** - All deployments safe to retry
5. **Modular Design** - Reusable Terraform modules for each service

### Data Flow

```
config.yaml → discover.py → bootstrap.auto.tfvars.json → state_sync.py → Terraform → AWS
```

### Account Types

- **Management Account** - AWS Organization root, runs Terraform
- **Log Archive Account** - Centralized logging (CloudTrail S3, Config)
- **Audit Account** - Security services delegated admin (Security Hub, Config aggregator, Inspector)

## Directory Structure

```
portfolio-aws-org-baseline/
├── entrypoint.sh           # Main orchestration script
├── config.yaml             # Organization configuration
├── requirements.txt        # Python dependencies
├── discovery/
│   ├── discover.py         # AWS discovery, generates tfvars
│   ├── state_sync.py       # Terraform state synchronization
│   └── control_tower_regions.py  # Control Tower region governance helper
├── post-deployment/
│   ├── verify.py           # Core deployment verification
│   ├── verify-regional-security.py  # Regional security settings verification
│   ├── verify-security-hub.py       # Security Hub configuration verification
│   ├── verify-config-recorders.py   # Config recorder verification
│   ├── cleanup-default-vpcs.py
│   └── enable-config-member-accounts.py  # Config enablement for member accounts
├── terraform/
│   ├── main.tf             # Root module - orchestrates child modules
│   ├── variables.tf        # Variable definitions
│   ├── outputs.tf          # Output definitions
│   ├── providers.tf        # Provider configurations (default, log_archive, audit)
│   ├── versions.tf         # Terraform/provider version constraints
│   └── modules/
│       ├── kms/                  # Reusable KMS key with configurable policies
│       ├── s3/                   # Reusable S3 bucket with access logging
│       ├── s3-tfstate/           # Terraform state bucket
│       ├── organization/         # AWS Org, OUs, delegated admins
│       ├── accounts/             # Shared accounts (log-archive, audit)
│       ├── security-hub/         # Security Hub org configuration
│       ├── cloudtrail/           # Organization CloudTrail
│       ├── config/               # AWS Config recorders/aggregator
│       ├── config-recorder/      # Single-region Config recorder module
│       ├── inspector/            # AWS Inspector org configuration
│       ├── inspector-enabler/    # Single-region Inspector enabler
│       ├── guardduty-org/        # GuardDuty delegated admin (config managed by portfolio-aws-org-guardduty)
│       ├── iam-password-policy/  # IAM password policy
│       ├── s3-account-public-access-block/ # S3 account public access block
│       ├── ssm-settings/         # SSM public sharing block
│       ├── ec2-defaults/         # EC2/EBS security defaults
│       └── vpc-defaults/         # VPC block public access
├── Dockerfile
└── Makefile
```

## Commands

All code runs inside Docker containers. Use the Makefile:

```bash
# Build Docker image
make build

# Discover current AWS state
AWS_PROFILE=my-profile make discover

# Show Terraform plan
AWS_PROFILE=my-profile make plan

# Apply configuration
AWS_PROFILE=my-profile make apply

# Open interactive shell
AWS_PROFILE=my-profile make shell
```

### Environment Variable Overrides

Override `config.yaml` values at runtime without modifying the file:

```bash
# Override VPC block public access mode
AWS_PROFILE=my-profile VPC_BLOCK_MODE=disabled make apply
```

| Variable | Description | Valid Values |
|----------|-------------|--------------|
| `VPC_BLOCK_MODE` | Override `vpc_block_public_access.mode` | `ingress`, `bidirectional`, `disabled` |

## Configuration

Edit `config.yaml` to customize:

- `resource_prefix` - Prefix for all resource names (S3 buckets, KMS keys, etc.). **Required.**
- `primary_region` - Primary AWS region (findings consolidated here)
- `tags` - Custom tags applied to all resources (e.g., owner, contact)
- `shared_accounts` - Log archive and audit account details. Email is required only for new accounts; existing accounts auto-detect email from AWS.
- `organizational_units` - OU hierarchy (supports 3 levels of nesting)
- `security_hub` - Standards and central configuration settings:
  - `standards` - List of standards to enable (aws-foundational, cis-1.2, cis-1.4, nist-800-53, pci-dss)
  - `disabled_controls` - List of control IDs to disable organization-wide (e.g., S3.15, CloudFormation.4)
- `vpc_block_public_access` - VPC internet gateway blocking mode (ingress, bidirectional, disabled)

Security services (Security Hub, Config, Inspector) aggregate findings from all regions to `primary_region`.

### Account Discovery

The discovery process identifies existing shared accounts using a tiered matching strategy:

1. **Exact match** - Account name matches `shared_accounts.*.name` in config.yaml
2. **Fuzzy match in Security OU** - Case-insensitive keyword matching for accounts in the Security OU
3. **Fuzzy match all accounts** - Falls back to matching across all organization accounts

Fuzzy matching keywords (checked in priority order):
- `audit` → Audit account
- `log` → Log Archive account
- `security` + `tool` → Security Tooling account

Example matches:
| Account Name | Detected As |
|--------------|-------------|
| `audit` | Audit |
| `SecurityAudit` | Audit |
| `log-archive` | Log Archive |
| `CentralLogs` | Log Archive |

### Email Auto-Detection

When shared accounts already exist in AWS Organizations, the discovery script automatically retrieves their email addresses. This allows you to omit the `email` field in config.yaml for brownfield deployments.

**Behavior:**
- If account exists in AWS AND email is omitted in config → email auto-detected from AWS Organizations
- If account exists in AWS AND email is specified in config → config value is used
- If account doesn't exist AND email is omitted → error (email required to create account)

**Discovery output shows the source:**
```
Account Emails:
    Log Archive: aws+logs@example.com [discovered]
    Audit: aws+audit@example.com [config]
```

**Minimal brownfield config.yaml** (accounts already exist):
```yaml
resource_prefix: "myorg"
primary_region: "us-east-1"
shared_accounts:
  log_archive:
    name: "Log Archive"    # Email auto-detected
  audit:
    name: "Audit"          # Email auto-detected
```

### CloudTrail Discovery

The discovery process detects existing organization CloudTrail trails to avoid creating duplicates. This is essential for Control Tower environments where `aws-controltower-BaselineCloudTrail` already exists.

**Behavior:**
- If an organization trail is detected, the CloudTrail module is skipped entirely
- Related resources (KMS key, S3 bucket, CloudWatch Log Group) are also skipped
- Other security services (Config, Security Hub, Inspector) continue to deploy normally

**Detection output example:**
```
Organization CloudTrail:
    Found: aws-controltower-BaselineCloudTrail (organization trail)
    ARN: arn:aws:cloudtrail:us-east-1:123456789012:trail/aws-controltower-BaselineCloudTrail
```

### Config Discovery

The discovery process detects existing organization-level AWS Config aggregators to avoid conflicts. This is essential for Control Tower environments where `aws-controltower-ConfigAggregatorForOrganizations` already exists.

**Behavior:**
- If an organization Config aggregator is detected, the Config module is skipped entirely
- Related resources (KMS key, S3 bucket, Config recorders, service linked roles) are also skipped
- Other security services (CloudTrail, Security Hub, Inspector) continue to deploy normally

**Detection output example:**
```
Organization Config:
    Found: aws-controltower-ConfigAggregatorForOrganizations (organization aggregator)
    ARN: arn:aws:config:us-east-1:123456789012:config-aggregator/aws-controltower-ConfigAggregatorForOrganizations
```

### Control Tower Discovery

The discovery process explicitly detects Control Tower Landing Zones using the `list_landing_zones()` and `get_landing_zone()` APIs.

**Behavior:**
- When Control Tower is detected, CloudTrail and Config modules are explicitly skipped
- The `control_tower_exists` flag is set in addition to `organization_trail_exists` and `organization_config_exists`
- Control Tower region governance is checked and can be extended to all available regions

**Detection output example:**
```
Control Tower:
    Found: Landing Zone v3.3
    Status: ACTIVE
    Governed regions: 4
```

### Control Tower Region Governance

When Control Tower is detected, the baseline can automatically extend governance to all available AWS regions.

**Workflow:**
- **Phase 1 (Discovery)**: Shows diff of regions that would be added to governance
- **Phase 1.5 (Apply only)**: Calls `update_landing_zone()` to add missing regions

**Plan mode output example:**
```
Control Tower Regions:
    Landing Zone: arn:aws:controltower:us-east-1:123456789012:landingzone/...
    Version: 3.3
    Status: ACTIVE
    Drift: IN_SYNC

  ~ Control Tower governed regions

    Currently governed (4):
      us-east-1
      us-east-2
      us-west-1
      us-west-2

    Regions to add (13):
      + ap-northeast-1
      + ap-southeast-1
      ...
```

**Apply mode**: Initiates Landing Zone update (non-blocking, 15-30+ minute operation).

## Credential Handling

- **Local:** Mount `~/.aws` into container and set `AWS_PROFILE` environment variable
- **ECS:** IAM roles assumed by container
- AWS credentials are never stored in the image

## Module Architecture

### Provider Aliases
Cross-account modules use provider aliases:
- `aws` - Management account (default)
- `aws.log_archive` - Log archive account
- `aws.audit` - Audit account

Regional providers exist for all 17 AWS regions for each account (e.g., `aws.us_west_2`, `aws.log_archive_eu_west_1`, `aws.audit_ap_southeast_1`). This enables multi-region Config recorder deployment.

Modules declare required aliases via `configuration_aliases` in their `terraform` block.

### Module Dependencies
```
kms_tfstate ─────────────────────────────────────────┐
                                                     ↓
organization_base → accounts → organization ──→ All service modules
                                                     ↑
kms_cloudtrail, kms_config ──────────────────────────┘
```

### Key Modules

**KMS Module** - Creates KMS keys with configurable policies:
- Service principal access
- Cross-account access
- Organization-wide access

**S3 Module** - Creates S3 buckets with:
- KMS encryption
- Access logging (`is_access_logging_bucket` prevents circular logging)
- Lifecycle rules
- Custom bucket policies

**CloudTrail Module** - Organization-wide CloudTrail:
- Multi-region trail with S3 logging to log-archive account
- CloudWatch Logs integration with dedicated KMS key
- CloudWatch Log Group with 365-day retention
- IAM role for CloudTrail to CloudWatch Logs delivery
- Automatically skipped if an organization trail already exists (e.g., Control Tower)

**Inspector Module** - Organization-wide vulnerability scanning:
- Delegated admin configuration and member associations
- LAMBDA_CODE only enabled in supported regions (not us-west-1)
- Auto-enables for new accounts

**Inspector Enabler Module** - Single-region Inspector enablement:
- Enables Inspector with EC2, ECR, LAMBDA, LAMBDA_CODE scanning
- LAMBDA_CODE excluded in unsupported regions
- Used by `inspector-regional.tf` to enable in all 17 regions for all 3 accounts

**GuardDuty Org Module** - GuardDuty delegated admin registration:
- Designates audit account as delegated administrator per region
- GuardDuty detector enablement, org config, and protection plans managed by `portfolio-aws-org-guardduty`

**Config Recorder Module** - Single-region Config recorder:
- Reusable module for deploying Config recorder in any region
- Used by `config-regional.tf` to deploy recorders in all 17 regions for all 3 accounts
- Delivers to centralized S3 bucket with KMS encryption

**SSM Settings Module** - Single-region SSM configuration:
- Blocks public sharing of SSM documents
- Enables CloudWatch logging for SSM Automation (SSM.6 compliance)
- Creates KMS key for CloudWatch log encryption
- CloudWatch Log Group with 365-day retention
- Used by `ssm-regional.tf` to deploy settings in all 17 regions for all 3 accounts

**EC2 Defaults Module** - Single-region EC2/EBS security defaults:
- EBS encryption by default using alias/aws/ebs key
- Block public access to EBS snapshots
- IMDSv2 required, 2-hop limit, instance tags enabled
- Used by `ec2-regional.tf` to deploy defaults in all 17 regions for all 3 accounts

**VPC Defaults Module** - Single-region VPC block public access:
- Blocks internet gateway access at the VPC level
- Modes: ingress (blocks inbound), bidirectional (blocks both), disabled
- Used by `vpc-regional.tf` to deploy in all 17 regions for all 3 accounts

## Post-Deployment Scripts

### cleanup-default-vpcs.py

Removes default VPCs across all accounts in the organization and all regions.

**Behavior:**
- Assumes `OrganizationAccountAccessRole` in each member account
- Uses management account credentials directly for the management account itself
- Deletes VPC components in dependency order (IGWs, subnets, security groups, route tables, NACLs, then VPC)

**Dependency Handling:**
- VPCs with active dependencies (running instances, EFS mounts, etc.) are marked as "skipped" rather than "failed"
- The script returns exit code 0 when only skipped (no real failures), allowing the baseline deployment to succeed
- Skipped VPCs can be cleaned up in follow-up processes after dependencies are removed

### enable-config-member-accounts.py

Enables and validates AWS Config recorders in all member accounts (accounts not managed by Terraform).

**Purpose:**
- Terraform manages Config recorders for core accounts (management, audit, log-archive)
- This script enables Config in all other member accounts, delivering to the same centralized S3 bucket
- Validates existing Config configurations and updates them if misconfigured
- The organization Config aggregator in the audit account automatically collects data from all accounts

**Behavior:**
- Assumes `OrganizationAccountAccessRole` in each member account
- Creates Config service-linked role if it doesn't exist
- For each region, checks existing Config configuration and:
  - **Creates** recorder/channel if not present
  - **Updates** recorder if not using the Service-Linked Role
  - **Updates** delivery channel if pointing to wrong S3 bucket or missing KMS encryption
  - **Skips** regions already correctly configured
- Delivers configuration snapshots to the centralized S3 bucket in log-archive account
- Uses KMS encryption with the Config KMS key
- Only records global resources (IAM) in the primary region to avoid duplicates

**Usage:**
```bash
# Dry run - preview what would be enabled/updated (runs automatically during make plan)
AWS_PROFILE=mgmt make plan

# Or manually:
AWS_PROFILE=mgmt make shell
python /work/post-deployment/enable-config-member-accounts.py --dry-run

# Apply - enable/update Config (runs automatically during make apply)
AWS_PROFILE=mgmt make apply
```

**Idempotent:** Safe to re-run; only changes misconfigured or missing settings.

**Smart Update Logic:**
The script validates existing Config configurations against expected settings:
- **IAM Role**: Must use `AWSServiceRoleForConfig` (Service-Linked Role)
- **S3 Bucket**: Must deliver to the central Config bucket in log-archive account
- **KMS Key**: Must use the central Config KMS key for encryption

**Dry-run output example:**
```
Processing Workload-Dev (444444444444)...
  Would create service-linked role
  Would enable Config in: 15 regions
  Would update Config in: 2 regions
    - us-west-2: Wrong S3 bucket: local-config-bucket (expected central-config-bucket)
    - us-west-2: Wrong KMS key: None

Dry Run Summary
  Member accounts processed: 5
  Service-linked roles to create: 3
  Regions to enable: 75
  Regions to update (misconfigured): 10
  Regions already correct: 0

Issues that would be fixed:
  - Wrong S3 bucket: local-config-bucket (expected central-config-bucket) (8 regions)
  - Wrong KMS key: None (10 regions)
  - Wrong IAM role: arn:aws:iam::xxx:role/CustomRole (expected SLR) (2 regions)
```

**Control Tower Environments:**
If Control Tower is managing Config, the script detects this and exits gracefully - no action needed as member accounts are automatically enrolled by Control Tower.

### verify.py

Core deployment verification script that validates organization-level resources.

**Checks Performed:**
- Organization exists with ALL features enabled
- Organizational Units match configuration
- Shared accounts (log-archive, audit) exist and are active
- Delegated administrators configured for security services
- Organization CloudTrail is active and logging
- KMS keys exist and are enabled (tfstate, cloudtrail, config)
- S3 buckets exist with correct configuration (versioning, encryption, public access)
- IAM password policies are configured correctly
- S3 account-level public access blocks are enabled

### verify-regional-security.py

Validates regional security settings across all 17 regions and 3 core accounts.

**Checks Performed:**
- Inspector enablement (EC2, ECR, Lambda scanning)
- EC2/EBS defaults (encryption by default, IMDSv2 required, snapshot public access blocked)
- VPC block public access settings match configuration
- SSM document public sharing is blocked

**Usage:**
```bash
AWS_PROFILE=mgmt make shell
python /work/post-deployment/verify-regional-security.py
```

### verify-security-hub.py

Validates Security Hub organization configuration.

**Checks Performed:**
- Delegated administrator is correctly set to audit account
- Organization configuration type (CENTRAL vs LOCAL)
- Enabled standards match configuration
- Disabled controls match configuration
- Member accounts are enrolled

**Usage:**
```bash
AWS_PROFILE=mgmt make shell
python /work/post-deployment/verify-security-hub.py
```

### verify-config-recorders.py

Validates AWS Config recorders across all regions and accounts.

**Checks Performed:**
- Config recorders exist and are recording
- Delivery channels point to correct central S3 bucket
- Service-linked role is used (not custom role)
- Config aggregator exists in audit account

**Control Tower:** Automatically detects Control Tower and exits gracefully.

**Usage:**
```bash
AWS_PROFILE=mgmt make shell
python /work/post-deployment/verify-config-recorders.py
```

## Testing

Test against a fresh AWS account:
```bash
AWS_PROFILE=test-profile make build
AWS_PROFILE=test-profile make plan
AWS_PROFILE=test-profile make apply
```

## Rules

- **No Claude Attribution** - Do not mention Claude, AI, or any AI assistant in commit messages, documentation, or code comments. Commits should appear as standard developer commits without AI attribution or "Generated with Claude" footers.
- **Use python3** - Always use `python3` instead of `python` when executing Python scripts from the command line.
- **Run pre-commit before pushing** - Always run `pre-commit run --all-files` before pushing changes to GitHub. Fix any issues found before pushing.

## Reference

See [STEPS.md](STEPS.md) for detailed deployment phases and [README.md](README.md) for complete documentation.
