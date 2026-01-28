# CloudTrail Module
# Manages Organization CloudTrail with S3 and CloudWatch Logs logging
# Uses the S3 and KMS modules for consistent resource creation

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.0"
      configuration_aliases = [aws.log_archive]
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
    }
  }
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# -----------------------------------------------------------------------------
# S3 Bucket for CloudTrail Logs
# -----------------------------------------------------------------------------

module "bucket" {
  source = "../s3"

  providers = {
    aws = aws.log_archive
  }

  bucket_name        = "${var.resource_prefix}-cloudtrail-logs-${var.log_archive_account_id}"
  kms_key_arn        = var.kms_key_arn
  versioning_enabled = true
  enforce_ssl        = true

  # Access logging configuration
  access_logging_enabled = var.access_logging_enabled
  access_logging_bucket  = var.access_logging_bucket
  access_logging_prefix  = "cloudtrail/"

  # CloudTrail-specific bucket policy
  bucket_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::${var.resource_prefix}-cloudtrail-logs-${var.log_archive_account_id}"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.primary_region}:${var.management_account_id}:trail/${var.resource_prefix}-organization-trail"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${var.resource_prefix}-cloudtrail-logs-${var.log_archive_account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.primary_region}:${var.management_account_id}:trail/${var.resource_prefix}-organization-trail"
          }
        }
      },
      {
        Sid       = "DenyNonSSL"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:aws:s3:::${var.resource_prefix}-cloudtrail-logs-${var.log_archive_account_id}",
          "arn:aws:s3:::${var.resource_prefix}-cloudtrail-logs-${var.log_archive_account_id}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })

  # Lifecycle rules for log retention
  lifecycle_rules = [
    {
      id     = "cloudtrail-lifecycle"
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

# Wait for S3 bucket policy to propagate before creating CloudTrail
# AWS needs time to propagate bucket policies across regions
resource "time_sleep" "wait_for_bucket_policy" {
  depends_on = [module.bucket]

  create_duration = "30s"
}

# -----------------------------------------------------------------------------
# KMS Key for CloudWatch Logs
# -----------------------------------------------------------------------------

resource "aws_kms_key" "cloudwatch_logs" {
  description             = "KMS key for CloudTrail CloudWatch Logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMPolicies"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*"
          }
        }
      }
    ]
  })

  tags = merge(var.common_tags, {
    Name = "${var.resource_prefix}-cloudtrail-cloudwatch-logs"
  })
}

resource "aws_kms_alias" "cloudwatch_logs" {
  name          = "alias/${var.resource_prefix}-cloudtrail-cloudwatch-logs"
  target_key_id = aws_kms_key.cloudwatch_logs.key_id
}

# -----------------------------------------------------------------------------
# CloudWatch Log Group for CloudTrail
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/${var.resource_prefix}/cloudtrail"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.cloudwatch_logs.arn

  tags = merge(var.common_tags, {
    Name = "${var.resource_prefix}-cloudtrail-logs"
  })
}

# -----------------------------------------------------------------------------
# IAM Role for CloudTrail to CloudWatch Logs
# -----------------------------------------------------------------------------

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "${var.resource_prefix}-cloudtrail-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudTrailAssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(var.common_tags, {
    Name = "${var.resource_prefix}-cloudtrail-cloudwatch-role"
  })
}

# trivy:ignore:AVD-AWS-0057 Wildcard required for CloudWatch Logs - :* suffix targets log streams within the specific log group only
resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "${var.resource_prefix}-cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLogGroupCreation"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Organization CloudTrail
# -----------------------------------------------------------------------------

# checkov:skip=CKV_AWS_252:SNS topic not configured - no consumption pipeline established yet
resource "aws_cloudtrail" "organization" {
  name                          = "${var.resource_prefix}-organization-trail"
  s3_bucket_name                = module.bucket.bucket_id
  is_organization_trail         = true
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = var.kms_key_arn

  # CloudWatch Logs integration
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  tags = merge(var.common_tags, {
    Name = "${var.resource_prefix}-organization-trail"
  })

  depends_on = [time_sleep.wait_for_bucket_policy]
}
