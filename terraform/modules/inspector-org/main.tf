# AWS Inspector Organization Module - Delegated Admin Setup
# Designates the audit account as the Inspector delegated administrator
#
# IMPORTANT: This module must be called from the MANAGEMENT account context.
# The delegated administrator registration requires management account permissions.
#
# This module is REGIONAL - call it once per region.
# Unlike some services, Inspector's delegated admin must be enabled in each
# region where you want to use Inspector organization features.

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

data "aws_region" "current" {}

# -----------------------------------------------------------------------------
# Delegated Administrator
# -----------------------------------------------------------------------------

# Designate audit account as the Inspector delegated administrator for this region
# This is called from the management account
resource "aws_inspector2_delegated_admin_account" "main" {
  account_id = var.audit_account_id
}
