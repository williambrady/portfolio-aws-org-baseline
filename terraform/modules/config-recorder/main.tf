# AWS Config Recorder Module
# Creates a Config recorder and delivery channel in a single region

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

# -----------------------------------------------------------------------------
# Service-Linked Role
# -----------------------------------------------------------------------------

resource "aws_iam_service_linked_role" "config" {
  count = var.create_service_linked_role ? 1 : 0

  aws_service_name = "config.amazonaws.com"
}

# -----------------------------------------------------------------------------
# Config Recorder
# -----------------------------------------------------------------------------

# checkov:skip=CKV_AWS_346:Global resources recorded only in home region to avoid duplication
resource "aws_config_configuration_recorder" "main" {
  name     = var.recorder_name
  role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

  recording_group {
    all_supported                 = true
    include_global_resource_types = var.include_global_resources
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

# -----------------------------------------------------------------------------
# Delivery Channel
# -----------------------------------------------------------------------------

resource "aws_config_delivery_channel" "main" {
  name           = var.delivery_channel_name
  s3_bucket_name = var.s3_bucket_name
  s3_key_prefix  = var.s3_key_prefix
  s3_kms_key_arn = var.kms_key_arn

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# -----------------------------------------------------------------------------
# Recorder Status (Start Recording)
# -----------------------------------------------------------------------------

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}
