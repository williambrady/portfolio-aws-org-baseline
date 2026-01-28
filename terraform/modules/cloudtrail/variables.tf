# Variables for CloudTrail Module

variable "resource_prefix" {
  description = "Prefix for resource naming"
  type        = string
}

variable "primary_region" {
  description = "Primary AWS region"
  type        = string
}

variable "management_account_id" {
  description = "Management account ID"
  type        = string
}

variable "log_archive_account_id" {
  description = "Log archive account ID"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for CloudTrail encryption"
  type        = string
}

variable "access_logging_enabled" {
  description = "Enable access logging for the CloudTrail bucket"
  type        = bool
  default     = true
}

variable "access_logging_bucket" {
  description = "Target bucket for access logs"
  type        = string
  default     = ""
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}
