# AWS Config Module
# Manages AWS Config recorders for all accounts and organization aggregator
# Uses the S3 module for consistent bucket creation

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.0"
      configuration_aliases = [aws.log_archive, aws.audit]
    }
  }
}

# -----------------------------------------------------------------------------
# S3 Bucket for Config Data
# -----------------------------------------------------------------------------

module "bucket" {
  source = "../s3"

  providers = {
    aws = aws.log_archive
  }

  bucket_name        = "${var.resource_prefix}-config-${var.log_archive_account_id}"
  kms_key_arn        = var.kms_key_arn
  versioning_enabled = true
  enforce_ssl        = true

  # Access logging configuration
  access_logging_enabled = var.access_logging_enabled
  access_logging_bucket  = var.access_logging_bucket
  access_logging_prefix  = "config/"

  # Config-specific bucket policy
  bucket_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::${var.resource_prefix}-config-${var.log_archive_account_id}"
        Condition = {
          StringEquals = {
            "aws:SourceOrgID" = var.organization_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketExistenceCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:ListBucket"
        Resource = "arn:aws:s3:::${var.resource_prefix}-config-${var.log_archive_account_id}"
        Condition = {
          StringEquals = {
            "aws:SourceOrgID" = var.organization_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${var.resource_prefix}-config-${var.log_archive_account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"    = "bucket-owner-full-control"
            "aws:SourceOrgID" = var.organization_id
          }
        }
      },
      {
        Sid       = "DenyNonSSL"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:aws:s3:::${var.resource_prefix}-config-${var.log_archive_account_id}",
          "arn:aws:s3:::${var.resource_prefix}-config-${var.log_archive_account_id}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })

  # Lifecycle rules for config data retention
  lifecycle_rules = [
    {
      id     = "config-lifecycle"
      status = "Enabled"
      transitions = [
        { days = 30, storage_class = "STANDARD_IA" },
        { days = 90, storage_class = "GLACIER" }
      ]
      expiration_days = 2555 # ~7 years
    }
  ]

  common_tags = var.common_tags
}

# -----------------------------------------------------------------------------
# Service-Linked Roles for Config
# -----------------------------------------------------------------------------

resource "aws_iam_service_linked_role" "config_management" {
  aws_service_name = "config.amazonaws.com"
}

resource "aws_iam_service_linked_role" "config_log_archive" {
  provider = aws.log_archive

  aws_service_name = "config.amazonaws.com"
}

resource "aws_iam_service_linked_role" "config_audit" {
  provider = aws.audit

  aws_service_name = "config.amazonaws.com"
}

# -----------------------------------------------------------------------------
# Management Account Config
# -----------------------------------------------------------------------------

resource "aws_config_configuration_recorder" "management" {
  name     = "${var.resource_prefix}-config-recorder"
  role_arn = aws_iam_service_linked_role.config_management.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_delivery_channel" "management" {
  name           = "${var.resource_prefix}-config-delivery"
  s3_bucket_name = module.bucket.bucket_id
  s3_kms_key_arn = var.kms_key_arn

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.management]
}

resource "aws_config_configuration_recorder_status" "management" {
  name       = aws_config_configuration_recorder.management.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.management]
}

# -----------------------------------------------------------------------------
# Log Archive Account Config
# -----------------------------------------------------------------------------

resource "aws_config_configuration_recorder" "log_archive" {
  provider = aws.log_archive

  name     = "${var.resource_prefix}-config-recorder"
  role_arn = aws_iam_service_linked_role.config_log_archive.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true # Record IAM resources for this account
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_delivery_channel" "log_archive" {
  provider = aws.log_archive

  name           = "${var.resource_prefix}-config-delivery"
  s3_bucket_name = module.bucket.bucket_id
  s3_kms_key_arn = var.kms_key_arn

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.log_archive]
}

resource "aws_config_configuration_recorder_status" "log_archive" {
  provider = aws.log_archive

  name       = aws_config_configuration_recorder.log_archive.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.log_archive]
}

# -----------------------------------------------------------------------------
# Audit Account Config
# -----------------------------------------------------------------------------

resource "aws_config_configuration_recorder" "audit" {
  provider = aws.audit

  name     = "${var.resource_prefix}-config-recorder"
  role_arn = aws_iam_service_linked_role.config_audit.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true # Record IAM resources for this account
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_delivery_channel" "audit" {
  provider = aws.audit

  name           = "${var.resource_prefix}-config-delivery"
  s3_bucket_name = module.bucket.bucket_id
  s3_kms_key_arn = var.kms_key_arn

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.audit]
}

resource "aws_config_configuration_recorder_status" "audit" {
  provider = aws.audit

  name       = aws_config_configuration_recorder.audit.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.audit]
}

# -----------------------------------------------------------------------------
# Config Aggregator (Audit Account)
# -----------------------------------------------------------------------------

resource "aws_config_configuration_aggregator" "organization" {
  provider = aws.audit

  name = "${var.resource_prefix}-config-aggregator"

  organization_aggregation_source {
    all_regions = true
    role_arn    = aws_iam_service_linked_role.config_audit.arn
  }

  tags = merge(var.common_tags, {
    Name = "${var.resource_prefix}-config-aggregator"
  })
}
