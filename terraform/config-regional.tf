# AWS Config Regional Deployment
# Deploys Config recorders in all regions for all accounts
# Primary region (us-east-1) is handled by the main config module
# Skipped when organization Config aggregator exists (e.g., Control Tower)

# -----------------------------------------------------------------------------
# Local Values
# -----------------------------------------------------------------------------

locals {
  config_recorder_name    = "${var.resource_prefix}-config-recorder"
  config_delivery_channel = "${var.resource_prefix}-config-delivery"
  config_bucket_name      = local.create_config ? "${var.resource_prefix}-config-${module.accounts.log_archive_account_id}" : ""
  config_kms_key_arn      = local.create_config ? module.kms_config[0].key_arn : ""
}

# =============================================================================
# MANAGEMENT ACCOUNT - Regional Config Recorders
# =============================================================================

module "config_mgmt_us_east_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.us_east_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_us_west_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.us_west_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_us_west_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.us_west_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_eu_west_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.eu_west_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_eu_west_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.eu_west_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_eu_west_3" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.eu_west_3
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_eu_central_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.eu_central_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_eu_north_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.eu_north_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_ap_southeast_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.ap_southeast_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_ap_southeast_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.ap_southeast_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_ap_northeast_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.ap_northeast_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_ap_northeast_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.ap_northeast_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_ap_northeast_3" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.ap_northeast_3
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_ap_south_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.ap_south_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_ca_central_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.ca_central_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_mgmt_sa_east_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.sa_east_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

# =============================================================================
# LOG ARCHIVE ACCOUNT - Regional Config Recorders
# =============================================================================

module "config_log_archive_us_east_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_us_east_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_us_west_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_us_west_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_us_west_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_us_west_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_eu_west_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_west_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_eu_west_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_west_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_eu_west_3" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_west_3
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_eu_central_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_central_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_eu_north_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_eu_north_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_ap_southeast_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_southeast_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_ap_southeast_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_southeast_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_ap_northeast_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_northeast_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_ap_northeast_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_northeast_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_ap_northeast_3" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_northeast_3
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_ap_south_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_ap_south_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_ca_central_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_ca_central_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_log_archive_sa_east_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.log_archive_sa_east_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

# =============================================================================
# AUDIT ACCOUNT - Regional Config Recorders
# =============================================================================

module "config_audit_us_east_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_us_east_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_us_west_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_us_west_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_us_west_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_us_west_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_eu_west_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_eu_west_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_eu_west_3" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_eu_west_3
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_eu_central_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_eu_central_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_eu_north_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_eu_north_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_ap_southeast_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_ap_southeast_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_ap_southeast_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_ap_southeast_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_ap_northeast_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_ap_northeast_2" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_2
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_ap_northeast_3" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_ap_northeast_3
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_ap_south_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_ap_south_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_ca_central_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_ca_central_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}

module "config_audit_sa_east_1" {
  source = "./modules/config-recorder"
  count  = local.create_config ? 1 : 0

  providers = {
    aws = aws.audit_sa_east_1
  }

  recorder_name            = local.config_recorder_name
  delivery_channel_name    = local.config_delivery_channel
  s3_bucket_name           = local.config_bucket_name
  kms_key_arn              = local.config_kms_key_arn
  include_global_resources = false

  depends_on = [module.config]
}
