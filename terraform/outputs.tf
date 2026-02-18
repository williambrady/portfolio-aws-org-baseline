# Outputs for AWS Organization Baseline

# -----------------------------------------------------------------------------
# Organization
# -----------------------------------------------------------------------------

output "organization_id" {
  description = "The AWS Organization ID"
  value       = module.organization.organization_id
}

output "organization_arn" {
  description = "The AWS Organization ARN"
  value       = module.organization.organization_arn
}

output "organization_root_id" {
  description = "The ID of the organization root"
  value       = module.organization.root_id
}

output "management_account_id" {
  description = "The management account ID"
  value       = module.organization.master_account_id
}

# -----------------------------------------------------------------------------
# Organizational Units
# -----------------------------------------------------------------------------

output "organizational_units" {
  description = "Map of all organizational units by path"
  value       = module.organization.organizational_units
}

output "security_ou_id" {
  description = "The Security OU ID (where shared accounts are placed)"
  value       = module.organization.security_ou_id
}

# -----------------------------------------------------------------------------
# Shared Accounts
# -----------------------------------------------------------------------------

output "log_archive_account_id" {
  description = "The log archive account ID"
  value       = module.accounts.log_archive_account_id
}

output "audit_account_id" {
  description = "The audit account ID"
  value       = module.accounts.audit_account_id
}

output "security_tooling_account_id" {
  description = "The security tooling account ID (if created)"
  value       = module.accounts.security_tooling_account_id
}

# -----------------------------------------------------------------------------
# S3 Terraform State
# -----------------------------------------------------------------------------

output "tfstate_bucket_name" {
  description = "The name of the Terraform state bucket"
  value       = module.s3_tfstate.bucket_name
}

output "tfstate_bucket_arn" {
  description = "The ARN of the Terraform state bucket"
  value       = module.s3_tfstate.bucket_arn
}

# -----------------------------------------------------------------------------
# KMS Keys
# -----------------------------------------------------------------------------

output "kms_tfstate_key_arn" {
  description = "The KMS key ARN for Terraform state encryption"
  value       = module.kms_tfstate.key_arn
}

output "kms_cloudtrail_key_arn" {
  description = "The KMS key ARN for CloudTrail encryption"
  value       = length(module.kms_cloudtrail) > 0 ? module.kms_cloudtrail[0].key_arn : null
}

output "kms_config_key_arn" {
  description = "The KMS key ARN for Config encryption"
  value       = length(module.kms_config) > 0 ? module.kms_config[0].key_arn : null
}

output "kms_access_logs_key_arn" {
  description = "The KMS key ARN for access logs bucket encryption"
  value       = module.kms_access_logs.key_arn
}

output "kms_deployment_artifacts_key_arn" {
  description = "The KMS key ARN for deployment artifacts bucket encryption"
  value       = module.kms_deployment_artifacts.key_arn
}

# -----------------------------------------------------------------------------
# Deployment Artifacts
# -----------------------------------------------------------------------------

output "deployment_artifacts_bucket_name" {
  description = "The name of the deployment artifacts bucket"
  value       = module.s3_deployment_artifacts.bucket_id
}

output "deployment_artifacts_bucket_arn" {
  description = "The ARN of the deployment artifacts bucket"
  value       = module.s3_deployment_artifacts.bucket_arn
}

# -----------------------------------------------------------------------------
# Security Hub (conditional - only when accounts exist)
# -----------------------------------------------------------------------------

output "securityhub_aggregation_region" {
  description = "The region where Security Hub findings are aggregated"
  value       = length(module.security_hub) > 0 ? module.security_hub[0].aggregation_region : null
}

output "securityhub_admin_account" {
  description = "The Security Hub delegated administrator account ID"
  value       = length(module.security_hub) > 0 ? module.security_hub[0].admin_account_id : null
}

output "securityhub_standards_enabled" {
  description = "List of Security Hub standards enabled"
  value       = length(module.security_hub) > 0 ? module.security_hub[0].standards_enabled : []
}

output "securityhub_configuration_policy_id" {
  description = "The ID of the central Security Hub configuration policy (if enabled)"
  value       = length(module.security_hub) > 0 ? module.security_hub[0].configuration_policy_id : null
}

output "securityhub_configuration_policy_arn" {
  description = "The ARN of the central Security Hub configuration policy"
  value       = length(module.security_hub) > 0 ? module.security_hub[0].configuration_policy_arn : null
}

# -----------------------------------------------------------------------------
# CloudTrail (conditional - only when accounts exist)
# -----------------------------------------------------------------------------

output "cloudtrail_name" {
  description = "The name of the organization CloudTrail"
  value       = length(module.cloudtrail) > 0 ? module.cloudtrail[0].trail_name : null
}

output "cloudtrail_arn" {
  description = "The ARN of the organization CloudTrail"
  value       = length(module.cloudtrail) > 0 ? module.cloudtrail[0].trail_arn : null
}

output "cloudtrail_s3_bucket" {
  description = "The S3 bucket for CloudTrail logs"
  value       = length(module.cloudtrail) > 0 ? module.cloudtrail[0].s3_bucket_name : null
}

output "cloudtrail_kms_key_arn" {
  description = "The KMS key ARN for CloudTrail encryption"
  value       = length(module.kms_cloudtrail) > 0 ? module.kms_cloudtrail[0].key_arn : null
}

# -----------------------------------------------------------------------------
# AWS Config (conditional - only when accounts exist)
# -----------------------------------------------------------------------------

output "config_s3_bucket" {
  description = "The S3 bucket for AWS Config data"
  value       = length(module.config) > 0 ? module.config[0].s3_bucket_name : null
}

output "config_kms_key_arn" {
  description = "The KMS key ARN for Config encryption"
  value       = length(module.kms_config) > 0 ? module.kms_config[0].key_arn : null
}

output "config_recorder_management" {
  description = "The name of the Config recorder in the management account"
  value       = length(module.config) > 0 ? module.config[0].recorder_management_name : null
}

output "config_recorder_log_archive" {
  description = "The name of the Config recorder in the log archive account"
  value       = length(module.config) > 0 ? module.config[0].recorder_log_archive_name : null
}

output "config_recorder_audit" {
  description = "The name of the Config recorder in the audit account"
  value       = length(module.config) > 0 ? module.config[0].recorder_audit_name : null
}

output "config_aggregator_name" {
  description = "The name of the Config aggregator"
  value       = length(module.config) > 0 ? module.config[0].aggregator_name : null
}

# -----------------------------------------------------------------------------
# IAM Password Policy
# -----------------------------------------------------------------------------

output "iam_password_policy" {
  description = "IAM password policy configuration applied to all accounts"
  value = {
    minimum_password_length   = module.iam_password_policy_management.minimum_password_length
    password_reuse_prevention = module.iam_password_policy_management.password_reuse_prevention
    hard_expiry               = module.iam_password_policy_management.hard_expiry
  }
}

# -----------------------------------------------------------------------------
# AWS Inspector (conditional - only when accounts exist)
# -----------------------------------------------------------------------------

output "inspector_delegated_admin" {
  description = "The Inspector delegated administrator account ID"
  value       = length(module.inspector) > 0 ? module.inspector[0].audit_account_id : null
}

# Note: Inspector resource types and auto-enable configuration are now handled
# regionally via the inspector-org-config module in inspector-regional.tf.

# -----------------------------------------------------------------------------
# SSM Parameter Store
# -----------------------------------------------------------------------------

output "org_config_ssm_parameter_name" {
  description = "SSM parameter path containing org-baseline config for cross-project consumption"
  value       = length(aws_ssm_parameter.org_config) > 0 ? aws_ssm_parameter.org_config[0].name : null
}

output "org_config_kms_key_arn" {
  description = "The KMS key ARN for SSM org-config parameter encryption"
  value       = module.kms_org_config.key_arn
}

# -----------------------------------------------------------------------------
# Deployment Status
# -----------------------------------------------------------------------------

output "accounts_exist" {
  description = "Whether shared accounts exist (determines if cross-account resources are deployed)"
  value       = local.accounts_exist
}

output "phase" {
  description = "Current deployment phase (1 = org/accounts only, 2 = full deployment)"
  value       = local.accounts_exist ? 2 : 1
}

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------

output "organization_summary" {
  description = "Summary of the organization baseline deployment"
  value = {
    deployment_phase     = local.accounts_exist ? "Phase 2 - Full deployment" : "Phase 1 - Organization and accounts only"
    organization_id      = module.organization.organization_id
    management_account   = module.organization.master_account_id
    log_archive_account  = module.accounts.log_archive_account_id
    audit_account        = module.accounts.audit_account_id
    organizational_units = module.organization.organizational_units
    security_hub = local.accounts_exist ? {
      admin_account        = module.security_hub[0].admin_account_id
      aggregation_region   = module.security_hub[0].aggregation_region
      standards            = module.security_hub[0].standards_enabled
      configuration_policy = module.security_hub[0].configuration_policy_id
    } : null
    cloudtrail = local.create_cloudtrail ? {
      name      = module.cloudtrail[0].trail_name
      s3_bucket = module.cloudtrail[0].s3_bucket_name
      kms_key   = module.kms_cloudtrail[0].key_arn
    } : null
    config = local.create_config ? {
      recorder_management  = module.config[0].recorder_management_name
      recorder_log_archive = module.config[0].recorder_log_archive_name
      recorder_audit       = module.config[0].recorder_audit_name
      aggregator_name      = module.config[0].aggregator_name
      s3_bucket            = module.config[0].s3_bucket_name
      kms_key              = module.kms_config[0].key_arn
    } : null
    kms_keys = {
      tfstate              = module.kms_tfstate.key_arn
      access_logs          = module.kms_access_logs.key_arn
      deployment_artifacts = module.kms_deployment_artifacts.key_arn
      cloudtrail           = length(module.kms_cloudtrail) > 0 ? module.kms_cloudtrail[0].key_arn : null
      config               = length(module.kms_config) > 0 ? module.kms_config[0].key_arn : null
      org_config           = module.kms_org_config.key_arn
    }
    deployment_log_group = aws_cloudwatch_log_group.deployments.name
    iam_password_policy = {
      minimum_length      = module.iam_password_policy_management.minimum_password_length
      reuse_prevention    = module.iam_password_policy_management.password_reuse_prevention
      hard_expiry         = module.iam_password_policy_management.hard_expiry
      applied_to_accounts = local.accounts_exist ? ["management", "log_archive", "audit"] : ["management"]
    }
    inspector = local.accounts_exist ? {
      delegated_admin = module.inspector[0].audit_account_id
      # Note: Delegated admin is enabled per-region via inspector-org module
      # Auto-enable configuration is handled regionally via inspector-org-config
    } : null
  }
}
