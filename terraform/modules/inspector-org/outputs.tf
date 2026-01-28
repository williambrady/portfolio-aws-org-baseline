# Outputs for Inspector Organization Module

output "delegated_admin_account_id" {
  description = "Account ID of the Inspector delegated administrator"
  value       = aws_inspector2_delegated_admin_account.main.account_id
}

output "region" {
  description = "AWS region where this module is deployed"
  value       = data.aws_region.current.name
}
