# S3 Terraform State Bucket Module
# Manages the S3 bucket for Terraform state storage using the S3 module

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# S3 Bucket for Terraform State
# -----------------------------------------------------------------------------

module "bucket" {
  source = "../s3"

  bucket_name        = "${var.resource_prefix}-tfstate-${var.account_id}"
  kms_key_arn        = var.kms_key_arn
  versioning_enabled = true
  enforce_ssl        = true

  # Access logging configuration
  access_logging_enabled = var.access_logging_enabled
  access_logging_bucket  = var.access_logging_bucket
  access_logging_prefix  = "tfstate/"

  common_tags = var.common_tags
}
