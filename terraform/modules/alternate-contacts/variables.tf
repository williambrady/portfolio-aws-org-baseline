variable "enable_alternate_contacts" {
  description = "Whether to enable alternate contacts"
  type        = bool
  default     = true
}

variable "account_id" {
  description = "The AWS account ID to set alternate contacts for. If null, uses the current account."
  type        = string
  default     = null
}

variable "billing_contact" {
  description = "Billing alternate contact details"
  type = object({
    name  = string
    title = string
    email = string
    phone = string
  })
}

variable "operations_contact" {
  description = "Operations alternate contact details"
  type = object({
    name  = string
    title = string
    email = string
    phone = string
  })
}

variable "security_contact" {
  description = "Security alternate contact details"
  type = object({
    name  = string
    title = string
    email = string
    phone = string
  })
}
