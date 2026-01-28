# Variables for Accounts Module

variable "security_ou_id" {
  description = "Security OU ID where accounts are placed"
  type        = string
}

# Log Archive Account
variable "log_archive_account_name" {
  description = "Name for the log archive account"
  type        = string
  default     = "log-archive"
}

variable "log_archive_account_email" {
  description = "Email for the log archive account"
  type        = string
}

# Audit Account
variable "audit_account_name" {
  description = "Name for the audit account"
  type        = string
  default     = "audit"
}

variable "audit_account_email" {
  description = "Email for the audit account"
  type        = string
}

# Security Tooling Account (Optional)
variable "security_tooling_account_name" {
  description = "Name for the security tooling account (optional, set empty to skip)"
  type        = string
  default     = ""
}

variable "security_tooling_account_email" {
  description = "Email for the security tooling account (optional)"
  type        = string
  default     = ""
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}
