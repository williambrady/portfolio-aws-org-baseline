# Outputs for Security Hub Module

output "admin_account_id" {
  description = "The Security Hub delegated administrator account ID"
  value       = aws_securityhub_organization_admin_account.main.admin_account_id
}

output "aggregation_region" {
  description = "The region where Security Hub findings are aggregated"
  value       = var.primary_region
}

output "standards_enabled" {
  description = "List of Security Hub standards enabled"
  value       = var.standards
}

output "configuration_policy_id" {
  description = "The ID of the central Security Hub configuration policy"
  value       = aws_securityhub_configuration_policy.main.id
}

output "configuration_policy_arn" {
  description = "The ARN of the central Security Hub configuration policy"
  value       = aws_securityhub_configuration_policy.main.arn
}
