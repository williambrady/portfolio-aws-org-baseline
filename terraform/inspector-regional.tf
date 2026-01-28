# Inspector - Multi-Region Deployment
# Enables Inspector in all regions for all accounts
# - EC2, ECR, LAMBDA scanning in all regions
# - LAMBDA_CODE scanning in supported regions (not us-west-1, ca-central-1, etc.)
#
# Architecture (dependency order):
# 1. inspector_org_*: Designates delegated admin per region (from management account)
# 2. inspector_audit_*: Enable Inspector in audit account (delegated admin must have Inspector enabled)
# 3. inspector_org_config_*: Configure auto-enable per region (requires Inspector enabled in audit)
# 4. inspector_mgmt_*/inspector_log_archive_*: Enable Inspector in other accounts
#
# NOTE: Inspector's delegated admin is REGIONAL, not global. The EnableDelegatedAdminAccount
# API must be called in each region where Inspector organization features are needed.

# =============================================================================
# Inspector Organization Configuration
# The UpdateOrganizationConfiguration API must be called from the delegated
# admin (audit account), not the management account.
# =============================================================================
locals {
  enable_inspector_org_config = true
}

# =============================================================================
# Inspector Delegated Administrator (Management Account)
# =============================================================================
# Designates audit account as Inspector delegated administrator.
# MUST run from management account context. Must be done PER REGION.

module "inspector_org_us_east_1" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_us_east_2" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.us_east_2
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_us_west_1" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.us_west_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_us_west_2" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.us_west_2
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_eu_west_1" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_west_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_eu_west_2" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_west_2
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_eu_west_3" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_west_3
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_eu_central_1" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_central_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_eu_north_1" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_north_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_ap_southeast_1" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_southeast_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_ap_southeast_2" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_southeast_2
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_ap_northeast_1" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_northeast_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_ap_northeast_2" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_northeast_2
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_ap_northeast_3" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_northeast_3
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_ap_south_1" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_south_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_ca_central_1" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ca_central_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "inspector_org_sa_east_1" {
  source = "./modules/inspector-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.sa_east_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

# =============================================================================
# Audit Account - Inspector (MUST RUN AFTER DELEGATED ADMIN)
# =============================================================================
# Inspector must be enabled in the audit account (delegated admin) in each region
# BEFORE the organization configuration can be set for that region.

module "inspector_audit_us_east_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit
  }

  depends_on = [module.inspector_org_us_east_1]
}

module "inspector_audit_us_east_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_us_east_2
  }

  depends_on = [module.inspector_org_us_east_2]
}

module "inspector_audit_us_west_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_us_west_1
  }

  depends_on = [module.inspector_org_us_west_1]
}

module "inspector_audit_us_west_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_us_west_2
  }

  depends_on = [module.inspector_org_us_west_2]
}

module "inspector_audit_eu_west_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_1
  }

  depends_on = [module.inspector_org_eu_west_1]
}

module "inspector_audit_eu_west_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_2
  }

  depends_on = [module.inspector_org_eu_west_2]
}

module "inspector_audit_eu_west_3" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_3
  }

  depends_on = [module.inspector_org_eu_west_3]
}

module "inspector_audit_eu_central_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_central_1
  }

  depends_on = [module.inspector_org_eu_central_1]
}

module "inspector_audit_eu_north_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_north_1
  }

  depends_on = [module.inspector_org_eu_north_1]
}

module "inspector_audit_ap_southeast_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_southeast_1
  }

  depends_on = [module.inspector_org_ap_southeast_1]
}

module "inspector_audit_ap_southeast_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_southeast_2
  }

  depends_on = [module.inspector_org_ap_southeast_2]
}

module "inspector_audit_ap_northeast_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_1
  }

  depends_on = [module.inspector_org_ap_northeast_1]
}

module "inspector_audit_ap_northeast_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_2
  }

  depends_on = [module.inspector_org_ap_northeast_2]
}

module "inspector_audit_ap_northeast_3" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_3
  }

  depends_on = [module.inspector_org_ap_northeast_3]
}

module "inspector_audit_ap_south_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_south_1
  }

  depends_on = [module.inspector_org_ap_south_1]
}

module "inspector_audit_ca_central_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ca_central_1
  }

  depends_on = [module.inspector_org_ca_central_1]
}

module "inspector_audit_sa_east_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_sa_east_1
  }

  depends_on = [module.inspector_org_sa_east_1]
}

# =============================================================================
# Inspector Organization Configuration (Audit Account - Delegated Admin)
# =============================================================================
# Configures auto-enable settings for member accounts in each region.
# MUST run from AUDIT account (delegated admin) which has permissions to
# call UpdateOrganizationConfiguration for the organization.
# Requires Inspector to be enabled in the audit account first.

module "inspector_org_config_us_east_1" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit
    time = time
  }

  depends_on = [module.inspector_audit_us_east_1]
}

module "inspector_org_config_us_east_2" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_us_east_2
    time = time
  }

  depends_on = [module.inspector_audit_us_east_2]
}

module "inspector_org_config_us_west_1" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_us_west_1
    time = time
  }

  depends_on = [module.inspector_audit_us_west_1]
}

module "inspector_org_config_us_west_2" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_us_west_2
    time = time
  }

  depends_on = [module.inspector_audit_us_west_2]
}

module "inspector_org_config_eu_west_1" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_eu_west_1
    time = time
  }

  depends_on = [module.inspector_audit_eu_west_1]
}

module "inspector_org_config_eu_west_2" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_eu_west_2
    time = time
  }

  depends_on = [module.inspector_audit_eu_west_2]
}

module "inspector_org_config_eu_west_3" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_eu_west_3
    time = time
  }

  depends_on = [module.inspector_audit_eu_west_3]
}

module "inspector_org_config_eu_central_1" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_eu_central_1
    time = time
  }

  depends_on = [module.inspector_audit_eu_central_1]
}

module "inspector_org_config_eu_north_1" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_eu_north_1
    time = time
  }

  depends_on = [module.inspector_audit_eu_north_1]
}

module "inspector_org_config_ap_southeast_1" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_ap_southeast_1
    time = time
  }

  depends_on = [module.inspector_audit_ap_southeast_1]
}

module "inspector_org_config_ap_southeast_2" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_ap_southeast_2
    time = time
  }

  depends_on = [module.inspector_audit_ap_southeast_2]
}

module "inspector_org_config_ap_northeast_1" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_ap_northeast_1
    time = time
  }

  depends_on = [module.inspector_audit_ap_northeast_1]
}

module "inspector_org_config_ap_northeast_2" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_ap_northeast_2
    time = time
  }

  depends_on = [module.inspector_audit_ap_northeast_2]
}

module "inspector_org_config_ap_northeast_3" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_ap_northeast_3
    time = time
  }

  depends_on = [module.inspector_audit_ap_northeast_3]
}

module "inspector_org_config_ap_south_1" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_ap_south_1
    time = time
  }

  depends_on = [module.inspector_audit_ap_south_1]
}

module "inspector_org_config_ca_central_1" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_ca_central_1
    time = time
  }

  depends_on = [module.inspector_audit_ca_central_1]
}

module "inspector_org_config_sa_east_1" {
  source = "./modules/inspector-org-config"
  count  = local.enable_inspector_org_config && local.accounts_exist ? 1 : 0

  providers = {
    aws  = aws.audit_sa_east_1
    time = time
  }

  depends_on = [module.inspector_audit_sa_east_1]
}

# =============================================================================
# Management Account - Inspector
# =============================================================================

module "inspector_mgmt_us_east_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws
  }

  depends_on = [module.inspector_org_config_us_east_1]
}

module "inspector_mgmt_us_east_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.us_east_2
  }

  depends_on = [module.inspector_org_config_us_east_2]
}

module "inspector_mgmt_us_west_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.us_west_1
  }

  depends_on = [module.inspector_org_config_us_west_1]
}

module "inspector_mgmt_us_west_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.us_west_2
  }

  depends_on = [module.inspector_org_config_us_west_2]
}

module "inspector_mgmt_eu_west_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_west_1
  }

  depends_on = [module.inspector_org_config_eu_west_1]
}

module "inspector_mgmt_eu_west_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_west_2
  }

  depends_on = [module.inspector_org_config_eu_west_2]
}

module "inspector_mgmt_eu_west_3" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_west_3
  }

  depends_on = [module.inspector_org_config_eu_west_3]
}

module "inspector_mgmt_eu_central_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_central_1
  }

  depends_on = [module.inspector_org_config_eu_central_1]
}

module "inspector_mgmt_eu_north_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_north_1
  }

  depends_on = [module.inspector_org_config_eu_north_1]
}

module "inspector_mgmt_ap_southeast_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_southeast_1
  }

  depends_on = [module.inspector_org_config_ap_southeast_1]
}

module "inspector_mgmt_ap_southeast_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_southeast_2
  }

  depends_on = [module.inspector_org_config_ap_southeast_2]
}

module "inspector_mgmt_ap_northeast_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_northeast_1
  }

  depends_on = [module.inspector_org_config_ap_northeast_1]
}

module "inspector_mgmt_ap_northeast_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_northeast_2
  }

  depends_on = [module.inspector_org_config_ap_northeast_2]
}

module "inspector_mgmt_ap_northeast_3" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_northeast_3
  }

  depends_on = [module.inspector_org_config_ap_northeast_3]
}

module "inspector_mgmt_ap_south_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_south_1
  }

  depends_on = [module.inspector_org_config_ap_south_1]
}

module "inspector_mgmt_ca_central_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ca_central_1
  }

  depends_on = [module.inspector_org_config_ca_central_1]
}

module "inspector_mgmt_sa_east_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.sa_east_1
  }

  depends_on = [module.inspector_org_config_sa_east_1]
}

# =============================================================================
# Log Archive Account - Inspector
# =============================================================================

module "inspector_log_archive_us_east_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive
  }

  depends_on = [module.inspector_org_config_us_east_1]
}

module "inspector_log_archive_us_east_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_us_east_2
  }

  depends_on = [module.inspector_org_config_us_east_2]
}

module "inspector_log_archive_us_west_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_us_west_1
  }

  depends_on = [module.inspector_org_config_us_west_1]
}

module "inspector_log_archive_us_west_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_us_west_2
  }

  depends_on = [module.inspector_org_config_us_west_2]
}

module "inspector_log_archive_eu_west_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_west_1
  }

  depends_on = [module.inspector_org_config_eu_west_1]
}

module "inspector_log_archive_eu_west_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_west_2
  }

  depends_on = [module.inspector_org_config_eu_west_2]
}

module "inspector_log_archive_eu_west_3" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_west_3
  }

  depends_on = [module.inspector_org_config_eu_west_3]
}

module "inspector_log_archive_eu_central_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_central_1
  }

  depends_on = [module.inspector_org_config_eu_central_1]
}

module "inspector_log_archive_eu_north_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_north_1
  }

  depends_on = [module.inspector_org_config_eu_north_1]
}

module "inspector_log_archive_ap_southeast_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_southeast_1
  }

  depends_on = [module.inspector_org_config_ap_southeast_1]
}

module "inspector_log_archive_ap_southeast_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_southeast_2
  }

  depends_on = [module.inspector_org_config_ap_southeast_2]
}

module "inspector_log_archive_ap_northeast_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_northeast_1
  }

  depends_on = [module.inspector_org_config_ap_northeast_1]
}

module "inspector_log_archive_ap_northeast_2" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_northeast_2
  }

  depends_on = [module.inspector_org_config_ap_northeast_2]
}

module "inspector_log_archive_ap_northeast_3" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_northeast_3
  }

  depends_on = [module.inspector_org_config_ap_northeast_3]
}

module "inspector_log_archive_ap_south_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_south_1
  }

  depends_on = [module.inspector_org_config_ap_south_1]
}

module "inspector_log_archive_ca_central_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_ca_central_1
  }

  depends_on = [module.inspector_org_config_ca_central_1]
}

module "inspector_log_archive_sa_east_1" {
  source = "./modules/inspector-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_sa_east_1
  }

  depends_on = [module.inspector_org_config_sa_east_1]
}
