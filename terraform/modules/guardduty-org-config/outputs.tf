# Outputs for GuardDuty Organization Configuration Module

output "detector_id" {
  description = "GuardDuty detector ID in the audit account (delegated admin)"
  value       = data.aws_guardduty_detector.current.id
}

output "region" {
  description = "AWS region where this module is deployed"
  value       = data.aws_region.current.name
}

output "auto_enable_members" {
  description = "Auto-enable setting for organization members"
  value       = aws_guardduty_organization_configuration.main.auto_enable_organization_members
}
