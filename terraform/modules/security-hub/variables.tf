# Variables for Security Hub Module

variable "resource_prefix" {
  description = "Prefix for resource naming"
  type        = string
}

variable "root_id" {
  description = "Organization root ID for policy association"
  type        = string
}

variable "management_account_id" {
  description = "Management account ID"
  type        = string
}

variable "audit_account_id" {
  description = "Audit account ID (delegated admin)"
  type        = string
}

variable "log_archive_account_id" {
  description = "Log archive account ID"
  type        = string
}

variable "primary_region" {
  description = "Primary AWS region for aggregation"
  type        = string
}

variable "standards" {
  description = "List of Security Hub standards to enable (aws-foundational, cis-1.2, cis-1.4, nist-800-53, pci-dss)"
  type        = list(string)
  default     = ["aws-foundational"]
}

variable "disabled_controls" {
  description = "List of Security Hub control IDs to disable organization-wide (e.g., S3.15, CloudFormation.4)"
  type        = list(string)
  default     = []
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}
