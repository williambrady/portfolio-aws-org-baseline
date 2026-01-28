# GuardDuty - Multi-Region Deployment
# Enables GuardDuty organization configuration across all regions
#
# Architecture:
# - guardduty-org module: Called from management account to designate delegated admin
# - guardduty-enabler module: Called for audit account only (delegated admin needs detector)
# - guardduty-org-config module: Called from audit account to configure auto-enable
#
# Member accounts (including management and log_archive) are automatically enrolled
# by the organization configuration with auto_enable_organization_members = "ALL".
# Only the audit account (delegated admin) needs an explicit detector.

# =============================================================================
# GuardDuty Delegated Administrator (Management Account)
# =============================================================================
# Designates audit account as GuardDuty delegated administrator.
# MUST run from management account context.

module "guardduty_org_us_east_1" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_us_east_2" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.us_east_2
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_us_west_1" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.us_west_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_us_west_2" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.us_west_2
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_eu_west_1" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_west_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_eu_west_2" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_west_2
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_eu_west_3" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_west_3
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_eu_central_1" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_central_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_eu_north_1" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_north_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_ap_southeast_1" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_southeast_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_ap_southeast_2" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_southeast_2
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_ap_northeast_1" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_northeast_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_ap_northeast_2" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_northeast_2
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_ap_northeast_3" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_northeast_3
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_ap_south_1" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_south_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_ca_central_1" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ca_central_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

module "guardduty_org_sa_east_1" {
  source = "./modules/guardduty-org"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.sa_east_1
  }

  audit_account_id = local.audit_account_id

  depends_on = [module.organization]
}

# =============================================================================
# Audit Account - GuardDuty Detectors (Delegated Admin)
# =============================================================================
# The audit account needs an explicit detector as the delegated administrator.
# This detector is referenced by the org-config module's data source.

module "guardduty_audit_us_east_1" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit
  }

  depends_on = [module.guardduty_org_us_east_1]
}

module "guardduty_audit_us_east_2" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_us_east_2
  }

  depends_on = [module.guardduty_org_us_east_2]
}

module "guardduty_audit_us_west_1" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_us_west_1
  }

  depends_on = [module.guardduty_org_us_west_1]
}

module "guardduty_audit_us_west_2" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_us_west_2
  }

  depends_on = [module.guardduty_org_us_west_2]
}

module "guardduty_audit_eu_west_1" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_1
  }

  depends_on = [module.guardduty_org_eu_west_1]
}

module "guardduty_audit_eu_west_2" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_2
  }

  depends_on = [module.guardduty_org_eu_west_2]
}

module "guardduty_audit_eu_west_3" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_3
  }

  depends_on = [module.guardduty_org_eu_west_3]
}

module "guardduty_audit_eu_central_1" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_central_1
  }

  depends_on = [module.guardduty_org_eu_central_1]
}

module "guardduty_audit_eu_north_1" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_north_1
  }

  depends_on = [module.guardduty_org_eu_north_1]
}

module "guardduty_audit_ap_southeast_1" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_southeast_1
  }

  depends_on = [module.guardduty_org_ap_southeast_1]
}

module "guardduty_audit_ap_southeast_2" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_southeast_2
  }

  depends_on = [module.guardduty_org_ap_southeast_2]
}

module "guardduty_audit_ap_northeast_1" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_1
  }

  depends_on = [module.guardduty_org_ap_northeast_1]
}

module "guardduty_audit_ap_northeast_2" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_2
  }

  depends_on = [module.guardduty_org_ap_northeast_2]
}

module "guardduty_audit_ap_northeast_3" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_3
  }

  depends_on = [module.guardduty_org_ap_northeast_3]
}

module "guardduty_audit_ap_south_1" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_south_1
  }

  depends_on = [module.guardduty_org_ap_south_1]
}

module "guardduty_audit_ca_central_1" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ca_central_1
  }

  depends_on = [module.guardduty_org_ca_central_1]
}

module "guardduty_audit_sa_east_1" {
  source = "./modules/guardduty-enabler"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_sa_east_1
  }

  depends_on = [module.guardduty_org_sa_east_1]
}

# =============================================================================
# Wait for GuardDuty Delegated Admin Propagation
# =============================================================================
# AWS needs time to propagate the delegated admin status across all regions
# before the org configuration can be applied from the audit account.

resource "time_sleep" "guardduty_delegated_admin_propagation" {
  count = local.accounts_exist ? 1 : 0

  create_duration = "180s"

  depends_on = [
    module.guardduty_org_us_east_1,
    module.guardduty_org_us_east_2,
    module.guardduty_org_us_west_1,
    module.guardduty_org_us_west_2,
    module.guardduty_org_eu_west_1,
    module.guardduty_org_eu_west_2,
    module.guardduty_org_eu_west_3,
    module.guardduty_org_eu_central_1,
    module.guardduty_org_eu_north_1,
    module.guardduty_org_ap_southeast_1,
    module.guardduty_org_ap_southeast_2,
    module.guardduty_org_ap_northeast_1,
    module.guardduty_org_ap_northeast_2,
    module.guardduty_org_ap_northeast_3,
    module.guardduty_org_ap_south_1,
    module.guardduty_org_ca_central_1,
    module.guardduty_org_sa_east_1,
  ]
}

# =============================================================================
# GuardDuty Organization Configuration (Audit Account - Delegated Admin)
# =============================================================================
# Configures auto-enable and protection plan settings for all member accounts.
# MUST run from AUDIT account (delegated admin) using the audit account's
# detector ID. The delegated admin has permissions to call
# UpdateOrganizationConfiguration for the organization.

module "guardduty_org_config_us_east_1" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_us_east_1]
}

module "guardduty_org_config_us_east_2" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_us_east_2
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_us_east_2]
}

module "guardduty_org_config_us_west_1" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_us_west_1
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_us_west_1]
}

module "guardduty_org_config_us_west_2" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_us_west_2
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_us_west_2]
}

module "guardduty_org_config_eu_west_1" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_1
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_eu_west_1]
}

module "guardduty_org_config_eu_west_2" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_2
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_eu_west_2]
}

module "guardduty_org_config_eu_west_3" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_3
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_eu_west_3]
}

module "guardduty_org_config_eu_central_1" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_central_1
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_eu_central_1]
}

module "guardduty_org_config_eu_north_1" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_north_1
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_eu_north_1]
}

module "guardduty_org_config_ap_southeast_1" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_southeast_1
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_ap_southeast_1]
}

module "guardduty_org_config_ap_southeast_2" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_southeast_2
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_ap_southeast_2]
}

module "guardduty_org_config_ap_northeast_1" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_1
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_ap_northeast_1]
}

module "guardduty_org_config_ap_northeast_2" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_2
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_ap_northeast_2]
}

module "guardduty_org_config_ap_northeast_3" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_3
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_ap_northeast_3]
}

module "guardduty_org_config_ap_south_1" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_south_1
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_ap_south_1]
}

module "guardduty_org_config_ca_central_1" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ca_central_1
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_ca_central_1]
}

module "guardduty_org_config_sa_east_1" {
  source = "./modules/guardduty-org-config"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_sa_east_1
  }

  depends_on = [time_sleep.guardduty_delegated_admin_propagation, module.guardduty_audit_sa_east_1]
}

# =============================================================================
# Note: Management and Log Archive GuardDuty Detectors
# =============================================================================
# These detectors are managed by the organization configuration with
# auto_enable_organization_members = "ALL". If migrating from a previous
# version that had explicit detector modules, run the following to remove
# them from state (they cannot be deleted via API while enrolled in org):
#
# make shell
# cd terraform
# for region in us_east_1 us_east_2 us_west_1 us_west_2 eu_west_1 eu_west_2 eu_west_3 \
#               eu_central_1 eu_north_1 ap_southeast_1 ap_southeast_2 ap_northeast_1 \
#               ap_northeast_2 ap_northeast_3 ap_south_1 ca_central_1 sa_east_1; do
#   terraform state rm "module.guardduty_mgmt_${region}[0].aws_guardduty_detector.main"
#   terraform state rm "module.guardduty_log_archive_${region}[0].aws_guardduty_detector.main"
# done
