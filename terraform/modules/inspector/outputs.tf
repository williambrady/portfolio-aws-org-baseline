# Outputs for AWS Inspector Module

output "audit_account_id" {
  description = "The audit account ID (delegated admin) for Inspector"
  value       = var.audit_account_id
}

# Note: Delegated admin setup has moved to inspector-org module (per-region).
# Organization auto-enable configuration is handled by inspector-org-config module.
