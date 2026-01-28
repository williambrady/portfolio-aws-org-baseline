# Outputs for Accounts Module

output "log_archive_account_id" {
  description = "The log archive account ID"
  value       = aws_organizations_account.log_archive.id
}

output "log_archive_account_arn" {
  description = "The log archive account ARN"
  value       = aws_organizations_account.log_archive.arn
}

output "audit_account_id" {
  description = "The audit account ID"
  value       = aws_organizations_account.audit.id
}

output "audit_account_arn" {
  description = "The audit account ARN"
  value       = aws_organizations_account.audit.arn
}

output "security_tooling_account_id" {
  description = "The security tooling account ID (if created)"
  value       = length(aws_organizations_account.security_tooling) > 0 ? aws_organizations_account.security_tooling[0].id : ""
}

output "security_tooling_account_arn" {
  description = "The security tooling account ARN (if created)"
  value       = length(aws_organizations_account.security_tooling) > 0 ? aws_organizations_account.security_tooling[0].arn : ""
}
