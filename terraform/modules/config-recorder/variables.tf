# Variables for Config Recorder Module

variable "recorder_name" {
  description = "Name for the Config recorder"
  type        = string
}

variable "delivery_channel_name" {
  description = "Name for the delivery channel"
  type        = string
}

variable "s3_bucket_name" {
  description = "S3 bucket name for Config data delivery"
  type        = string
}

variable "s3_key_prefix" {
  description = "S3 key prefix for Config data (optional)"
  type        = string
  default     = ""
}

variable "kms_key_arn" {
  description = "KMS key ARN for encrypting Config data"
  type        = string
  default     = null
}

variable "include_global_resources" {
  description = "Whether to include global resources (should only be true in one region per account)"
  type        = bool
  default     = false
}

variable "create_service_linked_role" {
  description = "Whether to create the Config service-linked role (should only be true once per account)"
  type        = bool
  default     = false
}
