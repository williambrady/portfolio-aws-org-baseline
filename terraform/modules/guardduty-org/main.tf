# AWS GuardDuty Organization Module - Delegated Admin Setup
# Designates the audit account as the GuardDuty delegated administrator
#
# IMPORTANT: This module must be called from the MANAGEMENT account context.
# The delegated administrator registration requires management account permissions.
#
# This module is regional - call it once per region.
#
# NOTE: Organization configuration (auto-enable settings) must be configured
# from the AUDIT account (delegated admin) - see guardduty-org-config module.

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

# Designate audit account as the GuardDuty delegated administrator
# This is called from the management account
resource "aws_guardduty_organization_admin_account" "main" {
  admin_account_id = var.audit_account_id

  lifecycle {
    ignore_changes = [admin_account_id]
  }
}
