# Variables for Organization Module

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

variable "organizational_units" {
  description = "List of organizational units to create with nested children"
  type = list(object({
    name = string
    children = optional(list(object({
      name = string
      children = optional(list(object({
        name = string
      })), [])
    })), [])
  }))
  default = []
}

variable "security_ou_name" {
  description = "Name of the Security OU where shared accounts are placed"
  type        = string
  default     = "Security"
}

variable "audit_account_id" {
  description = "Audit account ID for delegated administrator setup"
  type        = string
  default     = ""
}

variable "create_delegated_admins" {
  description = "Whether to create delegated administrator resources (set to true after accounts exist)"
  type        = bool
  default     = false
}
