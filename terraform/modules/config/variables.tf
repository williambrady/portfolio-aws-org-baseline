# Variables for AWS Config Module

variable "resource_prefix" {
  description = "Prefix for resource naming"
  type        = string
}

variable "organization_id" {
  description = "AWS Organization ID"
  type        = string
}

variable "log_archive_account_id" {
  description = "Log archive account ID"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for Config encryption"
  type        = string
}

variable "access_logging_enabled" {
  description = "Enable access logging for the Config bucket"
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
