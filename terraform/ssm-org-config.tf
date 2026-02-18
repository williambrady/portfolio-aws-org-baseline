# -----------------------------------------------------------------------------
# SSM Parameter Store - Organization Configuration
# Publishes org-baseline configuration for cross-project consumption
# (e.g., portfolio-aws-org-guardduty reads this to auto-discover account IDs)
# -----------------------------------------------------------------------------

# KMS key for SSM org-config parameter encryption (management account)
module "kms_org_config" {
  source = "./modules/kms"

  alias_name  = "${var.resource_prefix}-org-config"
  description = "KMS key for SSM org-config parameter encryption"
  common_tags = local.common_tags
}

resource "aws_ssm_parameter" "org_config" {
  count = local.accounts_exist ? 1 : 0

  name   = "/${var.resource_prefix}/org-baseline/config"
  type   = "SecureString"
  key_id = module.kms_org_config.key_arn
  value = jsonencode({
    resource_prefix        = var.resource_prefix
    primary_region         = var.primary_region
    management_account_id  = data.aws_caller_identity.current.account_id
    audit_account_id       = module.accounts.audit_account_id
    log_archive_account_id = module.accounts.log_archive_account_id
    organization_id        = module.organization.organization_id
    tfstate_bucket_name    = module.s3_tfstate.bucket_name
    tags                   = var.custom_tags
  })

  tags = merge(local.common_tags, {
    Name = "${var.resource_prefix}-org-config"
  })
}
