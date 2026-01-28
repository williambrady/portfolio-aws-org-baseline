# Variables for VPC Defaults Module

variable "vpc_block_public_access_mode" {
  description = "VPC block public access mode: ingress, bidirectional, or disabled"
  type        = string
  default     = "ingress"

  validation {
    condition     = contains(["ingress", "bidirectional", "disabled"], var.vpc_block_public_access_mode)
    error_message = "vpc_block_public_access_mode must be one of: ingress, bidirectional, disabled"
  }
}
