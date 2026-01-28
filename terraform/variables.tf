# Variables for AWS Organization Baseline

# -----------------------------------------------------------------------------
# Organization Configuration
# -----------------------------------------------------------------------------

variable "resource_prefix" {
  description = "Prefix for all resource names (S3 buckets, KMS keys, etc.)"
  type        = string
}

variable "primary_region" {
  description = "Primary AWS region"
  type        = string
  default     = "us-east-1"
}

# -----------------------------------------------------------------------------
# Discovery Variables (populated by discover.py)
# -----------------------------------------------------------------------------

variable "organization_exists" {
  description = "Whether an organization already exists"
  type        = bool
  default     = false
}

variable "root_id" {
  description = "Organization root ID (from discovery)"
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Shared Account Configuration
# -----------------------------------------------------------------------------

variable "log_archive_account_name" {
  description = "Name for the log archive account"
  type        = string
  default     = "log-archive"
}

variable "log_archive_account_email" {
  description = "Email for the log archive account"
  type        = string
}

variable "log_archive_account_id" {
  description = "Existing log archive account ID (from discovery)"
  type        = string
  default     = ""
}

variable "audit_account_name" {
  description = "Name for the audit account"
  type        = string
  default     = "audit"
}

variable "audit_account_email" {
  description = "Email for the audit account"
  type        = string
}

variable "audit_account_id" {
  description = "Existing audit account ID (from discovery)"
  type        = string
  default     = ""
}

variable "security_tooling_account_name" {
  description = "Name for the security tooling account (optional)"
  type        = string
  default     = ""
}

variable "security_tooling_account_email" {
  description = "Email for the security tooling account (optional)"
  type        = string
  default     = ""
}

variable "security_tooling_account_id" {
  description = "Existing security tooling account ID (from discovery)"
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Security Hub Configuration
# -----------------------------------------------------------------------------

variable "securityhub_standards" {
  description = "List of Security Hub standards to enable (aws-foundational, cis-1.2, cis-1.4, nist-800-53, pci-dss)"
  type        = list(string)
  default     = ["aws-foundational"]
}

variable "securityhub_disabled_controls" {
  description = "List of Security Hub control IDs to disable organization-wide (e.g., S3.15, CloudFormation.4)"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Organizational Unit Configuration
# -----------------------------------------------------------------------------

variable "organizational_units" {
  description = "List of organizational units to create. Each OU can have nested children."
  type = list(object({
    name = string
    children = optional(list(object({
      name = string
      children = optional(list(object({
        name = string
      })), [])
    })), [])
  }))
  default = [
    {
      name     = "Security"
      children = []
    },
    {
      name = "Workloads"
      children = [
        { name = "Production", children = [] },
        { name = "NonProduction", children = [] }
      ]
    },
    {
      name     = "Unmanaged"
      children = []
    }
  ]
}

variable "security_ou_name" {
  description = "Name of the Security OU where shared accounts are placed"
  type        = string
  default     = "Security"
}

# -----------------------------------------------------------------------------
# Custom Tags
# -----------------------------------------------------------------------------

variable "custom_tags" {
  description = "Custom tags to apply to all resources (from config.yaml tags section)"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# VPC Block Public Access Configuration
# -----------------------------------------------------------------------------

variable "vpc_block_public_access_mode" {
  description = "VPC block public access mode: ingress, bidirectional, or disabled"
  type        = string
  default     = "ingress"

  validation {
    condition     = contains(["ingress", "bidirectional", "disabled"], var.vpc_block_public_access_mode)
    error_message = "vpc_block_public_access_mode must be one of: ingress, bidirectional, disabled"
  }
}

# -----------------------------------------------------------------------------
# Control Tower Configuration
# -----------------------------------------------------------------------------

variable "control_tower_exists" {
  description = "Whether Control Tower Landing Zone is detected (from discovery). When true, CloudTrail and Config modules are skipped as Control Tower manages these."
  type        = bool
  default     = false
}

# -----------------------------------------------------------------------------
# CloudTrail Configuration
# -----------------------------------------------------------------------------

variable "organization_trail_exists" {
  description = "Whether an organization CloudTrail trail already exists (from discovery). When true, CloudTrail module is skipped."
  type        = bool
  default     = false
}

# -----------------------------------------------------------------------------
# Config Configuration
# -----------------------------------------------------------------------------

variable "organization_config_exists" {
  description = "Whether an organization Config aggregator already exists (from discovery). When true, Config module is skipped."
  type        = bool
  default     = false
}
