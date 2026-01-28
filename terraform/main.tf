# AWS Organization Baseline - Root Module
# Orchestrates all child modules for complete organization baseline deployment
#
# DEPLOYMENT PHASES:
# - Phase 1 (fresh org): Creates organization, OUs, and accounts
# - Phase 2 (accounts exist): Creates all cross-account resources (run after discovery finds accounts)

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------
# Local Values
# -----------------------------------------------------------------------------

locals {
  # Account IDs from discovery (for provider configuration - known at plan time)
  # These are populated by the discovery script when accounts already exist
  log_archive_account_id = var.log_archive_account_id
  audit_account_id       = var.audit_account_id

  # Whether accounts exist (from discovery) - controls cross-account resource creation
  # On first run for a fresh org, these will be empty and cross-account resources will be skipped
  accounts_exist = var.log_archive_account_id != "" && var.audit_account_id != ""

  # Whether to create CloudTrail - skip if Control Tower is detected or an organization trail already exists
  create_cloudtrail = local.accounts_exist && !var.control_tower_exists && !var.organization_trail_exists

  # Whether to create Config - skip if Control Tower is detected or an organization Config aggregator already exists
  create_config = local.accounts_exist && !var.control_tower_exists && !var.organization_config_exists

  common_tags = merge(
    {
      ManagedBy = "portfolio-aws-org-baseline"
    },
    var.custom_tags
  )
}

# -----------------------------------------------------------------------------
# KMS Keys
# Centralized KMS key management for all services
# -----------------------------------------------------------------------------

# KMS key for Terraform state bucket (management account)
module "kms_tfstate" {
  source = "./modules/kms"

  alias_name  = "${var.resource_prefix}-tfstate"
  description = "KMS key for Terraform state bucket encryption"
  common_tags = local.common_tags
}

# KMS key for CloudTrail (log archive account) - only when creating CloudTrail
module "kms_cloudtrail" {
  source = "./modules/kms"
  count  = local.create_cloudtrail ? 1 : 0

  providers = {
    aws = aws.log_archive
  }

  alias_name         = "${var.resource_prefix}-cloudtrail"
  description        = "KMS key for CloudTrail log encryption"
  service_principals = ["cloudtrail.amazonaws.com"]
  service_principal_actions = [
    "kms:GenerateDataKey*",
    "kms:DescribeKey"
  ]
  additional_account_ids = [data.aws_caller_identity.current.account_id]
  additional_policy_statements = [
    {
      Sid    = "AllowCloudTrailEncryptionContext"
      Effect = "Allow"
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      }
      Action = [
        "kms:GenerateDataKey*"
      ]
      Resource = "*"
      Condition = {
        StringLike = {
          "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
        }
      }
    }
  ]
  common_tags = local.common_tags
}

# KMS key for AWS Config (log archive account) - only when accounts exist
module "kms_config" {
  source = "./modules/kms"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive
  }

  alias_name                = "${var.resource_prefix}-config"
  description               = "KMS key for AWS Config data encryption"
  service_principals        = ["config.amazonaws.com"]
  allow_organization_access = true
  organization_id           = module.organization.organization_id
  common_tags               = local.common_tags
}

# -----------------------------------------------------------------------------
# Access Logging Buckets
# Centralized buckets for S3 access logs
# -----------------------------------------------------------------------------

# Access logging bucket for management account buckets (e.g., tfstate)
module "s3_access_logs" {
  source = "./modules/s3"

  bucket_name              = "${var.resource_prefix}-access-logs-${data.aws_caller_identity.current.account_id}"
  kms_key_arn              = module.kms_tfstate.key_arn
  versioning_enabled       = true
  enforce_ssl              = true
  is_access_logging_bucket = true # Prevents logging to itself

  lifecycle_rules = [
    {
      id     = "access-logs-lifecycle"
      status = "Enabled"
      transitions = [
        { days = 30, storage_class = "STANDARD_IA" },
        { days = 90, storage_class = "GLACIER" }
      ]
      expiration_days = 365
    }
  ]

  common_tags = local.common_tags
}

# Access logging bucket for log archive account - created when accounts exist
# Uses CloudTrail KMS key if available, Config KMS key if available, otherwise SSE-S3
module "s3_access_logs_log_archive" {
  source = "./modules/s3"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive
  }

  bucket_name              = "${var.resource_prefix}-access-logs-${local.log_archive_account_id}"
  kms_key_arn              = local.create_cloudtrail ? module.kms_cloudtrail[0].key_arn : (local.create_config ? module.kms_config[0].key_arn : null)
  versioning_enabled       = true
  enforce_ssl              = true
  is_access_logging_bucket = true # Prevents logging to itself

  lifecycle_rules = [
    {
      id     = "access-logs-lifecycle"
      status = "Enabled"
      transitions = [
        { days = 30, storage_class = "STANDARD_IA" },
        { days = 90, storage_class = "GLACIER" }
      ]
      expiration_days = 365
    }
  ]

  common_tags = local.common_tags
}

# -----------------------------------------------------------------------------
# Organization Module
# Creates AWS Organization, OUs, and delegated administrators
# -----------------------------------------------------------------------------

module "organization" {
  source = "./modules/organization"

  organization_exists     = var.organization_exists
  root_id                 = var.root_id
  organizational_units    = var.organizational_units
  security_ou_name        = var.security_ou_name
  audit_account_id        = local.audit_account_id
  create_delegated_admins = local.accounts_exist
}

# -----------------------------------------------------------------------------
# Accounts Module
# Creates shared accounts (log-archive, audit, security-tooling)
# Note: Uses security_ou_id from the organization module's OU output
# -----------------------------------------------------------------------------

module "accounts" {
  source = "./modules/accounts"

  security_ou_id = module.organization.security_ou_id

  log_archive_account_name  = var.log_archive_account_name
  log_archive_account_email = var.log_archive_account_email

  audit_account_name  = var.audit_account_name
  audit_account_email = var.audit_account_email

  security_tooling_account_name  = var.security_tooling_account_name
  security_tooling_account_email = var.security_tooling_account_email

  common_tags = local.common_tags
}

# -----------------------------------------------------------------------------
# S3 Terraform State Module
# -----------------------------------------------------------------------------

module "s3_tfstate" {
  source = "./modules/s3-tfstate"

  resource_prefix        = var.resource_prefix
  account_id             = data.aws_caller_identity.current.account_id
  kms_key_arn            = module.kms_tfstate.key_arn
  access_logging_enabled = true
  access_logging_bucket  = module.s3_access_logs.bucket_id
  common_tags            = local.common_tags
}

# -----------------------------------------------------------------------------
# Security Hub Module - only when accounts exist
# -----------------------------------------------------------------------------

module "security_hub" {
  source = "./modules/security-hub"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws       = aws
    aws.audit = aws.audit
  }

  resource_prefix  = var.resource_prefix
  primary_region   = var.primary_region
  root_id          = module.organization.root_id
  audit_account_id = local.audit_account_id

  standards         = var.securityhub_standards
  disabled_controls = var.securityhub_disabled_controls
}

# -----------------------------------------------------------------------------
# CloudTrail Module - only when accounts exist and no organization trail exists
# Skipped for Control Tower environments which have aws-controltower-BaselineCloudTrail
# -----------------------------------------------------------------------------

module "cloudtrail" {
  source = "./modules/cloudtrail"
  count  = local.create_cloudtrail ? 1 : 0

  providers = {
    aws             = aws
    aws.log_archive = aws.log_archive
  }

  resource_prefix        = var.resource_prefix
  primary_region         = var.primary_region
  management_account_id  = data.aws_caller_identity.current.account_id
  log_archive_account_id = local.log_archive_account_id
  kms_key_arn            = module.kms_cloudtrail[0].key_arn
  access_logging_enabled = true
  access_logging_bucket  = module.s3_access_logs_log_archive[0].bucket_id

  common_tags = local.common_tags
}

# -----------------------------------------------------------------------------
# AWS Config Module - only when accounts exist and no org-level Config exists
# -----------------------------------------------------------------------------

module "config" {
  source = "./modules/config"
  count  = local.create_config ? 1 : 0

  providers = {
    aws             = aws
    aws.log_archive = aws.log_archive
    aws.audit       = aws.audit
  }

  resource_prefix        = var.resource_prefix
  organization_id        = module.organization.organization_id
  log_archive_account_id = local.log_archive_account_id
  kms_key_arn            = module.kms_config[0].key_arn
  access_logging_enabled = true
  access_logging_bucket  = module.s3_access_logs_log_archive[0].bucket_id

  common_tags = local.common_tags
}

# -----------------------------------------------------------------------------
# IAM Password Policy
# Applied to all accounts for consistent security baseline
# -----------------------------------------------------------------------------

# Management account password policy
module "iam_password_policy_management" {
  source = "./modules/iam-password-policy"

  minimum_password_length   = 24
  require_uppercase         = true
  require_lowercase         = true
  require_numbers           = true
  require_symbols           = true
  password_reuse_prevention = 24
  hard_expiry               = true
}

# Log archive account password policy - only when accounts exist
module "iam_password_policy_log_archive" {
  source = "./modules/iam-password-policy"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive
  }

  minimum_password_length   = 24
  require_uppercase         = true
  require_lowercase         = true
  require_numbers           = true
  require_symbols           = true
  password_reuse_prevention = 24
  hard_expiry               = true
}

# Audit account password policy - only when accounts exist
module "iam_password_policy_audit" {
  source = "./modules/iam-password-policy"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit
  }

  minimum_password_length   = 24
  require_uppercase         = true
  require_lowercase         = true
  require_numbers           = true
  require_symbols           = true
  password_reuse_prevention = 24
  hard_expiry               = true
}

# -----------------------------------------------------------------------------
# S3 Account Public Access Block
# Blocks public access for all S3 buckets at the account level
# -----------------------------------------------------------------------------

# Management account S3 public access block
module "s3_account_public_access_block_management" {
  source = "./modules/s3-account-public-access-block"
}

# Log archive account S3 public access block - only when accounts exist
module "s3_account_public_access_block_log_archive" {
  source = "./modules/s3-account-public-access-block"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive
  }
}

# Audit account S3 public access block - only when accounts exist
module "s3_account_public_access_block_audit" {
  source = "./modules/s3-account-public-access-block"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit
  }
}

# -----------------------------------------------------------------------------
# AWS Inspector Module - only when accounts exist
# Organization-wide vulnerability scanning with Security Hub integration
# -----------------------------------------------------------------------------

module "inspector" {
  source = "./modules/inspector"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws       = aws
    aws.audit = aws.audit
  }

  audit_account_id = local.audit_account_id

  # Note: Organization auto-enable configuration is now handled regionally
  # via the inspector-org-config module called from inspector-regional.tf.
  # Member associations are NOT managed in Terraform - existing accounts
  # are enrolled via post-deployment/enroll-inspector-members.py
}
