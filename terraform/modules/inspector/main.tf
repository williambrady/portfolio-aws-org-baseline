# AWS Inspector Module
# Manages Inspector organization-level setup
#
# Note: Delegated administrator designation is now handled REGIONALLY via the
# inspector-org module called from inspector-regional.tf.
# This is because Inspector's EnableDelegatedAdminAccount API is regional,
# unlike some other services that have a global delegated admin.
#
# Organization configuration is also handled regionally via the
# inspector-org-config module called from inspector-regional.tf.
# This ensures auto-enable works in all regions, not just the primary region.
#
# This module is kept for backwards compatibility but no longer creates
# any resources. The audit_account_id variable is still required for
# the regional modules.

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.0"
      configuration_aliases = [aws.audit]
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
    }
  }
}

# -----------------------------------------------------------------------------
# Delegated Administrator
# -----------------------------------------------------------------------------
# NOTE: Delegated admin setup has moved to the inspector-org module
# which is called per-region in inspector-regional.tf.
# Inspector requires regional delegated admin setup, not global.

# -----------------------------------------------------------------------------
# Member Association
# -----------------------------------------------------------------------------
# Member accounts are NOT managed in Terraform state because:
# 1. auto_enable = true handles NEW accounts automatically when they join the org
# 2. Existing accounts are enrolled via post-deployment script:
#    post-deployment/enroll-inspector-members.py
#
# This avoids state drift when accounts join/leave the organization.
# The post-deployment script enrolls all existing member accounts
# (including management and log_archive) across all regions.
