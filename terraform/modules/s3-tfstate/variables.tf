# Variables for S3 Terraform State Module

variable "resource_prefix" {
  description = "Prefix for resource naming"
  type        = string
}

variable "account_id" {
  description = "AWS account ID for bucket naming"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the KMS key for bucket encryption"
  type        = string
}

variable "access_logging_enabled" {
  description = "Enable access logging for the state bucket"
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
