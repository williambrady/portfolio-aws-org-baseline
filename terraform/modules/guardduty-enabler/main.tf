# AWS GuardDuty Enabler Module
# Enables GuardDuty in a single region for a single account

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
# GuardDuty Detector
# -----------------------------------------------------------------------------

# checkov:skip=CKV2_AWS_3:GuardDuty is enabled per-region via this enabler module pattern
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
}

# -----------------------------------------------------------------------------
# Detector Features
# -----------------------------------------------------------------------------
# These features are enabled on the detector level for the audit account.
# The organization-wide configuration (guardduty-org-config) enables them for
# all member accounts automatically.

# Lambda Protection (GuardDuty.6)
# Monitors Lambda function network activity for suspicious behavior
resource "aws_guardduty_detector_feature" "lambda_network_logs" {
  detector_id = aws_guardduty_detector.main.id
  name        = "LAMBDA_NETWORK_LOGS"
  status      = "ENABLED"
}

# RDS Protection (GuardDuty.9)
# Monitors RDS login activity for anomalous behavior
resource "aws_guardduty_detector_feature" "rds_login_events" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RDS_LOGIN_EVENTS"
  status      = "ENABLED"
}

# Note: Runtime Monitoring is configured organization-wide via guardduty-org-config module.
# Member accounts cannot individually manage this feature when a delegated admin exists.
