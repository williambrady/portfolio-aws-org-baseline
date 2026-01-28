# AWS Inspector Organization Configuration Module
# Configures organization-wide auto-enable settings for Inspector
#
# IMPORTANT: This module must be called from the AUDIT account context
# (the delegated administrator). The delegated admin has permissions to
# call UpdateOrganizationConfiguration for the organization.
#
# This module is regional - call it once per region.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
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

data "aws_region" "current" {}

# -----------------------------------------------------------------------------
# Local Values
# -----------------------------------------------------------------------------

locals {
  # Regions where LAMBDA_CODE scanning is supported
  # https://docs.aws.amazon.com/inspector/latest/user/inspector_regions.html
  lambda_code_supported_regions = [
    "us-east-1",
    "us-east-2",
    "us-west-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-north-1",
  ]

  # Check if current region supports LAMBDA_CODE
  lambda_code_enabled = contains(local.lambda_code_supported_regions, data.aws_region.current.name)
}

# -----------------------------------------------------------------------------
# Organization Configuration
# -----------------------------------------------------------------------------

# Wait for Inspector to be fully enabled before configuring organization settings
# This resource should only be created after the inspector_audit_* enabler completes
# The additional wait ensures AWS has propagated the enabler changes
resource "time_sleep" "wait_before_org_config" {
  create_duration = "15s"
}

# Configure Inspector organization-wide auto-enable settings
# This MUST be called from the audit account (delegated admin) in each region.
resource "aws_inspector2_organization_configuration" "main" {
  depends_on = [time_sleep.wait_before_org_config]

  auto_enable {
    ec2         = true
    ecr         = true
    lambda      = true
    lambda_code = local.lambda_code_enabled
  }
}
