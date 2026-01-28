# EC2 Defaults - Multi-Region Deployment
# Deploys EC2 security defaults in all regions for all accounts
# - EBS encryption by default with alias/aws/ebs key
# - Block public access to EBS snapshots
# - IMDSv2 required, 2 hop limit, instance tags enabled

# =============================================================================
# Management Account - EC2 Defaults
# =============================================================================

module "ec2_mgmt_us_east_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws
  }
}

module "ec2_mgmt_us_east_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.us_east_2
  }
}

module "ec2_mgmt_us_west_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.us_west_1
  }
}

module "ec2_mgmt_us_west_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.us_west_2
  }
}

module "ec2_mgmt_eu_west_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_west_1
  }
}

module "ec2_mgmt_eu_west_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_west_2
  }
}

module "ec2_mgmt_eu_west_3" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_west_3
  }
}

module "ec2_mgmt_eu_central_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_central_1
  }
}

module "ec2_mgmt_eu_north_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.eu_north_1
  }
}

module "ec2_mgmt_ap_southeast_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_southeast_1
  }
}

module "ec2_mgmt_ap_southeast_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_southeast_2
  }
}

module "ec2_mgmt_ap_northeast_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_northeast_1
  }
}

module "ec2_mgmt_ap_northeast_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_northeast_2
  }
}

module "ec2_mgmt_ap_northeast_3" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_northeast_3
  }
}

module "ec2_mgmt_ap_south_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ap_south_1
  }
}

module "ec2_mgmt_ca_central_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.ca_central_1
  }
}

module "ec2_mgmt_sa_east_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.sa_east_1
  }
}

# =============================================================================
# Log Archive Account - EC2 Defaults
# =============================================================================

module "ec2_log_archive_us_east_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive
  }
}

module "ec2_log_archive_us_east_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_us_east_2
  }
}

module "ec2_log_archive_us_west_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_us_west_1
  }
}

module "ec2_log_archive_us_west_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_us_west_2
  }
}

module "ec2_log_archive_eu_west_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_west_1
  }
}

module "ec2_log_archive_eu_west_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_west_2
  }
}

module "ec2_log_archive_eu_west_3" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_west_3
  }
}

module "ec2_log_archive_eu_central_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_central_1
  }
}

module "ec2_log_archive_eu_north_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_north_1
  }
}

module "ec2_log_archive_ap_southeast_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_southeast_1
  }
}

module "ec2_log_archive_ap_southeast_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_southeast_2
  }
}

module "ec2_log_archive_ap_northeast_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_northeast_1
  }
}

module "ec2_log_archive_ap_northeast_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_northeast_2
  }
}

module "ec2_log_archive_ap_northeast_3" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_northeast_3
  }
}

module "ec2_log_archive_ap_south_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_south_1
  }
}

module "ec2_log_archive_ca_central_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_ca_central_1
  }
}

module "ec2_log_archive_sa_east_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.log_archive_sa_east_1
  }
}

# =============================================================================
# Audit Account - EC2 Defaults
# =============================================================================

module "ec2_audit_us_east_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit
  }
}

module "ec2_audit_us_east_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_us_east_2
  }
}

module "ec2_audit_us_west_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_us_west_1
  }
}

module "ec2_audit_us_west_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_us_west_2
  }
}

module "ec2_audit_eu_west_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_1
  }
}

module "ec2_audit_eu_west_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_2
  }
}

module "ec2_audit_eu_west_3" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_3
  }
}

module "ec2_audit_eu_central_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_central_1
  }
}

module "ec2_audit_eu_north_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_eu_north_1
  }
}

module "ec2_audit_ap_southeast_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_southeast_1
  }
}

module "ec2_audit_ap_southeast_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_southeast_2
  }
}

module "ec2_audit_ap_northeast_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_1
  }
}

module "ec2_audit_ap_northeast_2" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_2
  }
}

module "ec2_audit_ap_northeast_3" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_3
  }
}

module "ec2_audit_ap_south_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ap_south_1
  }
}

module "ec2_audit_ca_central_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_ca_central_1
  }
}

module "ec2_audit_sa_east_1" {
  source = "./modules/ec2-defaults"
  count  = local.accounts_exist ? 1 : 0

  providers = {
    aws = aws.audit_sa_east_1
  }
}
