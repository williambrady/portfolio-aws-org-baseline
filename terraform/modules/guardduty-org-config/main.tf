# AWS GuardDuty Organization Configuration Module
# Configures organization-wide auto-enable settings for GuardDuty
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
  }
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "aws_region" "current" {}

# Get the current account's detector (audit account when called correctly)
data "aws_guardduty_detector" "current" {}

# -----------------------------------------------------------------------------
# Organization Configuration
# -----------------------------------------------------------------------------

# Configure GuardDuty organization-wide auto-enable settings
# This MUST be called from the audit account (delegated admin) using the
# audit account's detector ID.
#
# Note: Individual features are configured via aws_guardduty_organization_configuration_feature
# resources below, which support "ALL" (all accounts) vs just "NEW" (new accounts only).
# The datasources block here is kept minimal as features are managed separately.
resource "aws_guardduty_organization_configuration" "main" {
  auto_enable_organization_members = "ALL"
  detector_id                      = data.aws_guardduty_detector.current.id
}

# -----------------------------------------------------------------------------
# S3 Protection Organization Feature
# -----------------------------------------------------------------------------
# Enables S3 data event analysis for all member accounts.
# Detects suspicious activities in S3 buckets.

resource "aws_guardduty_organization_configuration_feature" "s3_data_events" {
  detector_id = data.aws_guardduty_detector.current.id
  name        = "S3_DATA_EVENTS"
  auto_enable = "ALL"

  depends_on = [aws_guardduty_organization_configuration.main]
}

# -----------------------------------------------------------------------------
# EKS Audit Log Monitoring Organization Feature
# -----------------------------------------------------------------------------
# Enables EKS audit log analysis for all member accounts.
# Detects suspicious activities in EKS clusters.

resource "aws_guardduty_organization_configuration_feature" "eks_audit_logs" {
  detector_id = data.aws_guardduty_detector.current.id
  name        = "EKS_AUDIT_LOGS"
  auto_enable = "ALL"

  depends_on = [aws_guardduty_organization_configuration.main]
}

# -----------------------------------------------------------------------------
# Malware Protection for EC2 Organization Feature
# -----------------------------------------------------------------------------
# Enables EBS malware scanning for all member accounts.
# Scans EBS volumes when GuardDuty detects suspicious behavior.

resource "aws_guardduty_organization_configuration_feature" "ebs_malware_protection" {
  detector_id = data.aws_guardduty_detector.current.id
  name        = "EBS_MALWARE_PROTECTION"
  auto_enable = "ALL"

  depends_on = [aws_guardduty_organization_configuration.main]
}

# -----------------------------------------------------------------------------
# Runtime Monitoring Organization Feature
# -----------------------------------------------------------------------------

resource "aws_guardduty_organization_configuration_feature" "runtime_monitoring" {
  detector_id = data.aws_guardduty_detector.current.id
  name        = "RUNTIME_MONITORING"
  auto_enable = "ALL"

  additional_configuration {
    name        = "EKS_ADDON_MANAGEMENT"
    auto_enable = "ALL"
  }

  additional_configuration {
    name        = "ECS_FARGATE_AGENT_MANAGEMENT"
    auto_enable = "ALL"
  }

  additional_configuration {
    name        = "EC2_AGENT_MANAGEMENT"
    auto_enable = "ALL"
  }

  depends_on = [aws_guardduty_organization_configuration.main]

  # AWS API returns additional_configuration blocks in arbitrary order, causing
  # perpetual replacement cycles. Ignore changes since configuration is correct.
  # Ref: AWS provider compares by position, not by name.
  lifecycle {
    ignore_changes = [additional_configuration]
  }
}

# -----------------------------------------------------------------------------
# Lambda Protection Organization Feature (GuardDuty.6)
# -----------------------------------------------------------------------------
# Enables Lambda Network Activity Monitoring for all member accounts.
# Detects suspicious network activity from Lambda functions.

resource "aws_guardduty_organization_configuration_feature" "lambda_network_logs" {
  detector_id = data.aws_guardduty_detector.current.id
  name        = "LAMBDA_NETWORK_LOGS"
  auto_enable = "ALL"

  depends_on = [aws_guardduty_organization_configuration.main]
}

# -----------------------------------------------------------------------------
# RDS Protection Organization Feature (GuardDuty.9)
# -----------------------------------------------------------------------------
# Enables RDS Login Activity Monitoring for all member accounts.
# Detects anomalous login behavior to RDS databases.

resource "aws_guardduty_organization_configuration_feature" "rds_login_events" {
  detector_id = data.aws_guardduty_detector.current.id
  name        = "RDS_LOGIN_EVENTS"
  auto_enable = "ALL"

  depends_on = [aws_guardduty_organization_configuration.main]
}
