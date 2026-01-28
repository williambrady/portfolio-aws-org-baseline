# SSM Settings - Multi-Region Deployment
# Deploys SSM settings in all regions for all accounts:
# - Blocks public sharing of SSM documents
# - Enables CloudWatch logging for SSM Automation with KMS encryption

# =============================================================================
# Management Account - SSM Settings
# =============================================================================

module "ssm_mgmt_us_east_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws
  }
}

module "ssm_mgmt_us_east_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.us_east_2
  }
}

module "ssm_mgmt_us_west_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.us_west_1
  }
}

module "ssm_mgmt_us_west_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.us_west_2
  }
}

module "ssm_mgmt_eu_west_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.eu_west_1
  }
}

module "ssm_mgmt_eu_west_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.eu_west_2
  }
}

module "ssm_mgmt_eu_west_3" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.eu_west_3
  }
}

module "ssm_mgmt_eu_central_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.eu_central_1
  }
}

module "ssm_mgmt_eu_north_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.eu_north_1
  }
}

module "ssm_mgmt_ap_southeast_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.ap_southeast_1
  }
}

module "ssm_mgmt_ap_southeast_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.ap_southeast_2
  }
}

module "ssm_mgmt_ap_northeast_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.ap_northeast_1
  }
}

module "ssm_mgmt_ap_northeast_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.ap_northeast_2
  }
}

module "ssm_mgmt_ap_northeast_3" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.ap_northeast_3
  }
}

module "ssm_mgmt_ap_south_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.ap_south_1
  }
}

module "ssm_mgmt_ca_central_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.ca_central_1
  }
}

module "ssm_mgmt_sa_east_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.sa_east_1
  }
}

# =============================================================================
# Log Archive Account - SSM Settings
# =============================================================================

module "ssm_log_archive_us_east_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive
  }
}

module "ssm_log_archive_us_east_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_us_east_2
  }
}

module "ssm_log_archive_us_west_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_us_west_1
  }
}

module "ssm_log_archive_us_west_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_us_west_2
  }
}

module "ssm_log_archive_eu_west_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_eu_west_1
  }
}

module "ssm_log_archive_eu_west_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_eu_west_2
  }
}

module "ssm_log_archive_eu_west_3" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_eu_west_3
  }
}

module "ssm_log_archive_eu_central_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_eu_central_1
  }
}

module "ssm_log_archive_eu_north_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_eu_north_1
  }
}

module "ssm_log_archive_ap_southeast_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_ap_southeast_1
  }
}

module "ssm_log_archive_ap_southeast_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_ap_southeast_2
  }
}

module "ssm_log_archive_ap_northeast_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_ap_northeast_1
  }
}

module "ssm_log_archive_ap_northeast_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_ap_northeast_2
  }
}

module "ssm_log_archive_ap_northeast_3" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_ap_northeast_3
  }
}

module "ssm_log_archive_ap_south_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_ap_south_1
  }
}

module "ssm_log_archive_ca_central_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_ca_central_1
  }
}

module "ssm_log_archive_sa_east_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.log_archive_sa_east_1
  }
}

# =============================================================================
# Audit Account - SSM Settings
# =============================================================================

module "ssm_audit_us_east_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit
  }
}

module "ssm_audit_us_east_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_us_east_2
  }
}

module "ssm_audit_us_west_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_us_west_1
  }
}

module "ssm_audit_us_west_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_us_west_2
  }
}

module "ssm_audit_eu_west_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_eu_west_1
  }
}

module "ssm_audit_eu_west_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_eu_west_2
  }
}

module "ssm_audit_eu_west_3" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_eu_west_3
  }
}

module "ssm_audit_eu_central_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_eu_central_1
  }
}

module "ssm_audit_eu_north_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_eu_north_1
  }
}

module "ssm_audit_ap_southeast_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_ap_southeast_1
  }
}

module "ssm_audit_ap_southeast_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_ap_southeast_2
  }
}

module "ssm_audit_ap_northeast_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_ap_northeast_1
  }
}

module "ssm_audit_ap_northeast_2" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_ap_northeast_2
  }
}

module "ssm_audit_ap_northeast_3" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_ap_northeast_3
  }
}

module "ssm_audit_ap_south_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_ap_south_1
  }
}

module "ssm_audit_ca_central_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_ca_central_1
  }
}

module "ssm_audit_sa_east_1" {
  source = "./modules/ssm-settings"
  count  = local.accounts_exist ? 1 : 0

  resource_prefix = var.resource_prefix

  providers = {
    aws = aws.audit_sa_east_1
  }
}
