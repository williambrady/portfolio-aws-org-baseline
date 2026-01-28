# S3 Account Public Access Block Module
# Blocks public access for all S3 buckets at the account level

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------
# S3 Account Public Access Block
# -----------------------------------------------------------------------------

resource "aws_s3_account_public_access_block" "main" {
  account_id = data.aws_caller_identity.current.account_id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
