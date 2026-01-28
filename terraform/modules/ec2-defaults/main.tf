# AWS EC2 Defaults Module
# Configures secure EC2 defaults for a single region

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
data "aws_region" "current" {}

# Get the AWS managed EBS KMS key
data "aws_kms_alias" "ebs" {
  name = "alias/aws/ebs"
}

# -----------------------------------------------------------------------------
# EBS Encryption Settings
# -----------------------------------------------------------------------------

# Enable EBS encryption by default for all new volumes
resource "aws_ebs_encryption_by_default" "enabled" {
  enabled = true
}

# Set default KMS key for EBS encryption
resource "aws_ebs_default_kms_key" "ebs" {
  key_arn = data.aws_kms_alias.ebs.target_key_arn

  depends_on = [aws_ebs_encryption_by_default.enabled]
}

# Block public access to EBS snapshots
resource "aws_ebs_snapshot_block_public_access" "enabled" {
  state = "block-all-sharing"
}

# -----------------------------------------------------------------------------
# Instance Metadata Service (IMDS) Defaults
# -----------------------------------------------------------------------------

# Configure IMDS defaults for all new instances
resource "aws_ec2_instance_metadata_defaults" "secure" {
  http_tokens                 = "required" # IMDSv2 only (no IMDSv1)
  http_put_response_hop_limit = 2          # Allow 2 hops for containers
  instance_metadata_tags      = "enabled"  # Enable access to instance tags

  depends_on = [
    aws_ebs_encryption_by_default.enabled,
    aws_ebs_snapshot_block_public_access.enabled
  ]
}
