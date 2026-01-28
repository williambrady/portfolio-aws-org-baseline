# Variables for AWS Inspector Module

variable "audit_account_id" {
  description = "The audit account ID (delegated administrator)"
  type        = string
}

# Note: Scanning configuration (EC2, ECR, Lambda, Lambda Code) is now handled
# regionally via the inspector-org-config module called from inspector-regional.tf.
