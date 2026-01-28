# Security Hub Module
# Manages Security Hub organization-wide configuration with CENTRAL mode

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
# Local Values
# -----------------------------------------------------------------------------

locals {
  # Standard ARNs for central configuration policy (region-specific format required)
  securityhub_policy_standards_arns = {
    "aws-foundational" = "arn:aws:securityhub:${var.primary_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
    "cis-1.2"          = "arn:aws:securityhub:${var.primary_region}::standards/cis-aws-foundations-benchmark/v/1.2.0"
    "cis-1.4"          = "arn:aws:securityhub:${var.primary_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
    "nist-800-53"      = "arn:aws:securityhub:${var.primary_region}::standards/nist-800-53/v/5.0.0"
    "pci-dss"          = "arn:aws:securityhub:${var.primary_region}::standards/pci-dss/v/3.2.1"
  }
}

# -----------------------------------------------------------------------------
# Security Hub Accounts
# -----------------------------------------------------------------------------

# Enable Security Hub in the management account
resource "aws_securityhub_account" "management" {
  enable_default_standards = false
  auto_enable_controls     = true
}

# Enable Security Hub in the audit account (delegated admin)
resource "aws_securityhub_account" "audit" {
  provider = aws.audit

  enable_default_standards = false
  auto_enable_controls     = true
}

# -----------------------------------------------------------------------------
# Organization Admin
# -----------------------------------------------------------------------------

# Security Hub Organization Admin (enables org-wide management)
resource "aws_securityhub_organization_admin_account" "main" {
  admin_account_id = var.audit_account_id

  depends_on = [aws_securityhub_account.management, aws_securityhub_account.audit]
}

# -----------------------------------------------------------------------------
# Organization Sync Wait
# -----------------------------------------------------------------------------

# Wait for AWS to sync organization data to Security Hub
# Required before CENTRAL configuration mode can be enabled
resource "time_sleep" "wait_for_org_sync" {
  depends_on = [aws_securityhub_organization_admin_account.main]

  create_duration = "15m"
}

# -----------------------------------------------------------------------------
# Finding Aggregator (must be created before CENTRAL mode)
# -----------------------------------------------------------------------------

# Security Hub Finding Aggregator - consolidates findings from all regions
# Must be created BEFORE enabling CENTRAL configuration mode
resource "aws_securityhub_finding_aggregator" "main" {
  provider = aws.audit

  linking_mode = "ALL_REGIONS"

  depends_on = [time_sleep.wait_for_org_sync]
}

# Wait for finding aggregator to be fully configured before enabling CENTRAL mode
resource "time_sleep" "wait_for_finding_aggregator" {
  depends_on = [aws_securityhub_finding_aggregator.main]

  create_duration = "30s"
}

# -----------------------------------------------------------------------------
# Organization Configuration (CENTRAL mode)
# -----------------------------------------------------------------------------

# Security Hub Organization Configuration - always uses CENTRAL mode
# CENTRAL mode enables organization-wide configuration policies
resource "aws_securityhub_organization_configuration" "main" {
  provider = aws.audit

  # With CENTRAL configuration, auto_enable must be false - the central policy
  # associated to the org root controls which accounts have Security Hub enabled
  auto_enable           = false
  auto_enable_standards = "NONE"

  organization_configuration {
    configuration_type = "CENTRAL"
  }

  depends_on = [time_sleep.wait_for_finding_aggregator]
}

# -----------------------------------------------------------------------------
# Central Configuration Policy
# -----------------------------------------------------------------------------

# Central Configuration Policy - applies to entire organization
resource "aws_securityhub_configuration_policy" "main" {
  provider = aws.audit

  name        = "${var.resource_prefix}-security-policy"
  description = "Central security configuration policy for ${var.resource_prefix} organization"

  configuration_policy {
    service_enabled = true

    enabled_standard_arns = [
      for std in var.standards : local.securityhub_policy_standards_arns[std]
    ]

    dynamic "security_controls_configuration" {
      for_each = length(var.disabled_controls) > 0 ? [1] : []
      content {
        disabled_control_identifiers = var.disabled_controls
      }
    }
  }

  depends_on = [aws_securityhub_organization_configuration.main]
}

# Associate the central policy with the organization root
resource "aws_securityhub_configuration_policy_association" "root" {
  provider = aws.audit

  target_id = var.root_id
  policy_id = aws_securityhub_configuration_policy.main.id

  depends_on = [aws_securityhub_configuration_policy.main]
}
