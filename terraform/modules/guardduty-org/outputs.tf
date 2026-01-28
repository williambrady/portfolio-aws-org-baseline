# Outputs for GuardDuty Organization Module (Delegated Admin)

output "delegated_admin_account_id" {
  description = "Account ID of the GuardDuty delegated administrator"
  value       = aws_guardduty_organization_admin_account.main.admin_account_id
}

output "region" {
  description = "AWS region where this module is deployed"
  value       = data.aws_region.current.name
}
