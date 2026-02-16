# Deployment Steps

This document describes the exact steps that occur when using `portfolio-aws-org-baseline` to deploy baseline security configurations to an AWS Organization.

## Prerequisites

Before running the tool, ensure:
- AWS credentials are configured (via environment variables or mounted `~/.aws` directory)
- Docker is installed and running
- `config.yaml` is customized for your environment
- You have administrative access to the AWS Organization management account

## Execution Flow

### Step 0: Credential Validation

1. Verify AWS credentials are valid using `aws sts get-caller-identity`
2. Retrieve and display the target AWS account ID (management account)
3. Load configuration from `config.yaml`:
   - `primary_region` - Primary AWS region for state and aggregation
   - `resource_prefix` - Prefix for all resource names
   - `vpc_block_public_access.mode` - VPC blocking mode (can be overridden via `VPC_BLOCK_MODE` env var)

### Step 1: State Bucket Setup

Creates or validates the Terraform state bucket (`{prefix}-tfstate-{account_id}`):

1. **Check if state bucket exists**
2. **If bucket doesn't exist:**
   - Create KMS key for state bucket encryption
   - Create KMS key alias (`alias/{prefix}-tfstate`)
   - Enable KMS key rotation
   - Create S3 bucket in primary region
   - Enable versioning
   - Configure KMS encryption with bucket keys
   - Block all public access
   - Add bucket policy for SSL/TLS enforcement
3. **If bucket exists but lacks KMS encryption:**
   - Create or retrieve KMS key
   - Upgrade bucket to KMS encryption

---

## Phase 1: Discovery

The discovery script (`discovery/discover.py`) inspects the current state of the AWS Organization:

### Organization Discovery
- Check if AWS Organization exists
- Retrieve organization ID, ARN, and feature set
- Identify management account ID
- Determine if organization is managed by Terraform or brownfield

### Organizational Units Discovery
- List all existing OUs in the organization
- Build OU hierarchy (supports 3 levels of nesting)
- Match configured OUs against existing OUs
- Identify OUs to create vs. import

### Shared Accounts Discovery
- Search for existing log-archive account by name
- Search for existing audit account by name
- Auto-detect email addresses from discovered accounts
- Identify accounts to create vs. import

### Control Tower Detection
- Check for Control Tower Landing Zone
- Detect Control Tower-managed CloudTrail
- Detect Control Tower-managed AWS Config
- Set flags to skip services managed by Control Tower

### Service Discovery
For each of the 17 target regions:

**AWS Config:**
- Check for existing Config recorders
- Identify central Config aggregator

**Security Hub:**
- Check if Security Hub is enabled
- Identify delegated administrator
- List enabled security standards

**Inspector:**
- Check if Inspector is enabled
- Identify delegated administrator
- Get auto-enable configuration

### Output
- Generate `discovery.json` with discovered state
- Generate `bootstrap.auto.tfvars.json` for Terraform
- Variables inform Terraform about existing resources to avoid conflicts

---

## Phase 1.5: Control Tower Region Governance (Conditional)

Only runs during `apply` if Control Tower is detected.

1. **Detect governed regions** from Control Tower Landing Zone
2. **Identify ungoverned regions** that need to be added
3. **Extend governance** to all 17 target regions
4. Ensures Control Tower manages all regions for consistent security posture

---

## Phase 2: Terraform Init

### Initialization
1. Clear any stale local Terraform state (`.terraform/`)
2. Initialize Terraform with S3 backend configuration:
   - Bucket: `{prefix}-tfstate-{account_id}`
   - Key: `organization/terraform.tfstate`
   - Region: Primary region from config
   - Encryption: Enabled

### State Synchronization
1. Run `state_sync.py` to import existing resources into Terraform state
2. Import bootstrap resources (state bucket, KMS keys)
3. Import discovered AWS resources:
   - Organization (if exists but not in state)
   - Organizational Units
   - Shared accounts (log-archive, audit)
4. Prevents Terraform from trying to recreate existing resources

---

## Phase 3: Terraform Plan/Apply

### Resource Creation/Updates

Terraform creates or updates the following resources:

**Organization Structure:**
- AWS Organization (feature set: ALL)
- Organizational Units (configurable hierarchy, up to 3 levels)
- Shared Accounts in Security OU:
  - Log Archive account
  - Audit account
  - Security Tooling account (optional)

**KMS Keys (in appropriate accounts):**
| Key | Account | Purpose |
|-----|---------|---------|
| `{prefix}-tfstate` | Management | Terraform state encryption |
| `{prefix}-cloudtrail` | Log Archive | CloudTrail log encryption |
| `{prefix}-config` | Log Archive | Config snapshot encryption |

**S3 Buckets:**
| Bucket | Account | Purpose |
|--------|---------|---------|
| `{prefix}-tfstate-{id}` | Management | Terraform state |
| `{prefix}-access-logs-{id}` | Each account | S3 access logging |
| `{prefix}-cloudtrail-{id}` | Log Archive | CloudTrail logs |
| `{prefix}-config-{id}` | Log Archive | Config snapshots |

**Security Services (Organization-Wide):**

| Service | Configuration |
|---------|---------------|
| CloudTrail | Organization trail, multi-region, KMS encryption, logs to log-archive |
| AWS Config | Recorders in all 17 regions for core accounts, aggregator in audit |
| Security Hub | Delegated admin, finding aggregation, configurable standards |
| GuardDuty | Delegated admin per-region (config managed by portfolio-aws-org-guardduty) |
| Inspector | Delegated admin per-region, EC2/ECR/Lambda/Lambda Code scanning |

**Account-Level Controls (All 3 Core Accounts):**

| Control | Configuration |
|---------|---------------|
| IAM Password Policy | 24 char min, complexity, 24 password history |
| S3 Account Public Access Block | Block all public access |
| SSM Settings | Block public sharing, CloudWatch logging with KMS |
| EC2 Defaults | EBS encryption, snapshot blocking, IMDSv2 required |
| VPC Block Public Access | Configurable mode (ingress/bidirectional/disabled) |

**Delegated Administrators (in Audit Account):**
- Security Hub
- GuardDuty
- AWS Config
- IAM Access Analyzer
- Inspector

---

## Phase 4: Post-Deployment

Only runs when `apply` action is used.

### Deployment Verification (`verify.py`)

1. **Organization Verification**
   - Verify organization exists with correct feature set
   - Validate master account ID matches

2. **OU Verification**
   - Verify all configured OUs exist
   - Check OU hierarchy matches configuration

3. **Account Verification**
   - Verify shared accounts exist (log-archive, audit)
   - Validate accounts are in correct OUs

4. **Delegated Admin Verification**
   - Verify delegated administrators are configured
   - Check each service has correct delegated admin

### Default VPC Cleanup (`cleanup-default-vpcs.py`)

**Purpose:** Removes default VPCs across all accounts in the organization and all 17 regions.

**Process:**
1. Enumerate all active accounts in the organization
2. Assume `OrganizationAccountAccessRole` in each account
3. For each region with a default VPC:
   - Detach and delete Internet Gateways
   - Delete all Subnets
   - Delete non-default Security Groups
   - Delete non-main Route Tables
   - Delete non-default Network ACLs
   - Delete the VPC

**Dependency Handling:** VPCs with running instances are marked as "skipped" and can be cleaned up later.

### AWS Config Enablement (`enable-config-member-accounts.py`)

**Purpose:** Enables AWS Config recorders in all member accounts with centralized delivery.

**Process:**
1. Enumerate all active accounts (excluding management, audit, log-archive)
2. Assume `OrganizationAccountAccessRole` in each member account
3. Create Config service-linked role if needed
4. For each of 17 regions:
   - Create recorder/channel if not present
   - Update recorder if not using Service-Linked Role
   - Update delivery channel if pointing to wrong S3 bucket or missing KMS

**Configuration Applied:**
| Setting | Value |
|---------|-------|
| IAM Role | `AWSServiceRoleForConfig` (Service-Linked Role) |
| S3 Bucket | Central Config bucket in log-archive account |
| KMS Key | Central Config KMS key |

**Control Tower Mode:** If Control Tower is detected, only configures the management account (CT manages all others).

### Inspector Member Enrollment (`enroll-inspector-members.py`)

**Purpose:** Enrolls all organization member accounts as Inspector members.

**Process:**
1. Assume role into the delegated admin (audit) account
2. Fetch all active organization accounts
3. Compare against existing Inspector members
4. Enroll any accounts not already members

**Note:** While Terraform configures auto-enable for new accounts, existing accounts need explicit enrollment.

---

## Phase 5: Summary

1. Output Terraform `organization_summary` as JSON
2. Display completion message
3. Show key outputs:
   - Organization ID
   - Shared account IDs
   - Delegated admin configurations

---

## Command Reference

| Command | Description |
|---------|-------------|
| `discover` | Run discovery only, output current state |
| `plan` | Run discovery + Terraform plan (no changes) + post-deployment preview |
| `apply` | Full deployment (discovery + apply + post-deployment) |
| `destroy` | Tear down all managed resources (use with caution) |
| `shell` | Open interactive shell in container for debugging |

## State Management

- Terraform state stored in: `s3://{prefix}-tfstate-{account_id}/organization/terraform.tfstate`
- State bucket created automatically on first run
- State includes all managed resources across all regions and accounts
- State sync ensures brownfield resources are imported before apply

## Security Controls Summary

All S3 buckets created by this tool include:

| Control | Description |
|---------|-------------|
| KMS Encryption | Dedicated KMS key per bucket with automatic rotation |
| Public Access Block | All public access blocked at bucket level |
| SSL/TLS Enforcement | Bucket policy denies non-SSL requests |
| Versioning | Enabled for object recovery |
| Access Logging | Buckets log to dedicated access logging bucket |
| Lifecycle Policies | Configurable transitions and expirations |

## Multi-Account Architecture

```
Management Account
├── AWS Organization
├── CloudTrail (organization trail)
├── State bucket
└── Delegates admin to Audit Account

Log Archive Account
├── CloudTrail logs bucket (KMS encrypted)
├── Config snapshots bucket (KMS encrypted)
└── Centralized logging destination

Audit Account (Delegated Admin)
├── Security Hub aggregator
├── Inspector organization configuration
├── Config aggregator
└── IAM Access Analyzer

Member Accounts
├── AWS Config (delivers to central bucket)
├── Security Hub (findings to aggregator)
├── GuardDuty (managed by portfolio-aws-org-guardduty)
├── Inspector (managed by org config)
└── Account-level security controls
```

## Brownfield vs Greenfield

**Greenfield (New Organization):**
- Creates AWS Organization from scratch
- Creates all OUs and shared accounts
- Full Terraform management

**Brownfield (Existing Organization):**
- Discovers existing organization structure
- Auto-detects shared accounts by name
- Imports existing resources into Terraform state
- Applies baseline controls without recreating resources
- Detects and respects Control Tower management
