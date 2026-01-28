# VPC Defaults - Multi-Region Deployment
# Deploys VPC block public access settings in all regions for all accounts

# =============================================================================
# Management Account - VPC Defaults
# =============================================================================

module "vpc_mgmt_us_east_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws
  }
}

module "vpc_mgmt_us_east_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.us_east_2
  }
}

module "vpc_mgmt_us_west_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.us_west_1
  }
}

module "vpc_mgmt_us_west_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.us_west_2
  }
}

module "vpc_mgmt_eu_west_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.eu_west_1
  }
}

module "vpc_mgmt_eu_west_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.eu_west_2
  }
}

module "vpc_mgmt_eu_west_3" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.eu_west_3
  }
}

module "vpc_mgmt_eu_central_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.eu_central_1
  }
}

module "vpc_mgmt_eu_north_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.eu_north_1
  }
}

module "vpc_mgmt_ap_southeast_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.ap_southeast_1
  }
}

module "vpc_mgmt_ap_southeast_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.ap_southeast_2
  }
}

module "vpc_mgmt_ap_northeast_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.ap_northeast_1
  }
}

module "vpc_mgmt_ap_northeast_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.ap_northeast_2
  }
}

module "vpc_mgmt_ap_northeast_3" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.ap_northeast_3
  }
}

module "vpc_mgmt_ap_south_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.ap_south_1
  }
}

module "vpc_mgmt_ca_central_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.ca_central_1
  }
}

module "vpc_mgmt_sa_east_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.sa_east_1
  }
}

# =============================================================================
# Log Archive Account - VPC Defaults
# =============================================================================

module "vpc_log_archive_us_east_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive
  }
}

module "vpc_log_archive_us_east_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_us_east_2
  }
}

module "vpc_log_archive_us_west_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_us_west_1
  }
}

module "vpc_log_archive_us_west_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_us_west_2
  }
}

module "vpc_log_archive_eu_west_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_eu_west_1
  }
}

module "vpc_log_archive_eu_west_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_eu_west_2
  }
}

module "vpc_log_archive_eu_west_3" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_eu_west_3
  }
}

module "vpc_log_archive_eu_central_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_eu_central_1
  }
}

module "vpc_log_archive_eu_north_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_eu_north_1
  }
}

module "vpc_log_archive_ap_southeast_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_ap_southeast_1
  }
}

module "vpc_log_archive_ap_southeast_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_ap_southeast_2
  }
}

module "vpc_log_archive_ap_northeast_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_ap_northeast_1
  }
}

module "vpc_log_archive_ap_northeast_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_ap_northeast_2
  }
}

module "vpc_log_archive_ap_northeast_3" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_ap_northeast_3
  }
}

module "vpc_log_archive_ap_south_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_ap_south_1
  }
}

module "vpc_log_archive_ca_central_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_ca_central_1
  }
}

module "vpc_log_archive_sa_east_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.log_archive_sa_east_1
  }
}

# =============================================================================
# Audit Account - VPC Defaults
# =============================================================================

module "vpc_audit_us_east_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit
  }
}

module "vpc_audit_us_east_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_us_east_2
  }
}

module "vpc_audit_us_west_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_us_west_1
  }
}

module "vpc_audit_us_west_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_us_west_2
  }
}

module "vpc_audit_eu_west_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_eu_west_1
  }
}

module "vpc_audit_eu_west_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_eu_west_2
  }
}

module "vpc_audit_eu_west_3" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_eu_west_3
  }
}

module "vpc_audit_eu_central_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_eu_central_1
  }
}

module "vpc_audit_eu_north_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_eu_north_1
  }
}

module "vpc_audit_ap_southeast_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_ap_southeast_1
  }
}

module "vpc_audit_ap_southeast_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_ap_southeast_2
  }
}

module "vpc_audit_ap_northeast_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_ap_northeast_1
  }
}

module "vpc_audit_ap_northeast_2" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_ap_northeast_2
  }
}

module "vpc_audit_ap_northeast_3" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_ap_northeast_3
  }
}

module "vpc_audit_ap_south_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_ap_south_1
  }
}

module "vpc_audit_ca_central_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_ca_central_1
  }
}

module "vpc_audit_sa_east_1" {
  source = "./modules/vpc-defaults"
  count  = local.accounts_exist ? 1 : 0

  vpc_block_public_access_mode = var.vpc_block_public_access_mode

  providers = {
    aws = aws.audit_sa_east_1
  }
}
