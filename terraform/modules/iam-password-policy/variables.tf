# Variables for IAM Password Policy Module

variable "minimum_password_length" {
  description = "Minimum length for IAM user passwords"
  type        = number
  default     = 16
}

variable "require_uppercase" {
  description = "Require at least one uppercase letter"
  type        = bool
  default     = true
}

variable "require_lowercase" {
  description = "Require at least one lowercase letter"
  type        = bool
  default     = true
}

variable "require_numbers" {
  description = "Require at least one number"
  type        = bool
  default     = true
}

variable "require_symbols" {
  description = "Require at least one special character"
  type        = bool
  default     = true
}

variable "allow_users_to_change_password" {
  description = "Allow IAM users to change their own password"
  type        = bool
  default     = true
}

variable "max_password_age" {
  description = "Maximum age in days before password expires (0 = never expires)"
  type        = number
  default     = 90
}

variable "password_reuse_prevention" {
  description = "Number of previous passwords that cannot be reused"
  type        = number
  default     = 24
}

variable "hard_expiry" {
  description = "Prevent users from setting a new password after expiry (admin must reset)"
  type        = bool
  default     = true
}
