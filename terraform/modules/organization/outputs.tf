# Outputs for Organization Module

output "organization_id" {
  description = "The AWS Organization ID"
  value       = data.aws_organizations_organization.current.id
}

output "organization_arn" {
  description = "The AWS Organization ARN"
  value       = data.aws_organizations_organization.current.arn
}

output "root_id" {
  description = "The ID of the organization root"
  value       = local.root_id
}

output "master_account_id" {
  description = "The management account ID"
  value       = data.aws_organizations_organization.current.master_account_id
}

output "security_ou_id" {
  description = "The Security OU ID (where shared accounts are placed)"
  value       = try(aws_organizations_organizational_unit.level1[var.security_ou_name].id, "")
}

output "organizational_units" {
  description = "Map of all organizational units by path"
  value = merge(
    { for k, v in aws_organizations_organizational_unit.level1 : k => v.id },
    { for k, v in aws_organizations_organizational_unit.level2 : k => v.id },
    { for k, v in aws_organizations_organizational_unit.level3 : k => v.id }
  )
}

output "delegated_admin_securityhub" {
  description = "Security Hub delegated administrator resource"
  value       = length(aws_organizations_delegated_administrator.securityhub) > 0 ? aws_organizations_delegated_administrator.securityhub[0] : null
}

output "delegated_admin_config" {
  description = "Config delegated administrator resource"
  value       = length(aws_organizations_delegated_administrator.config) > 0 ? aws_organizations_delegated_administrator.config[0] : null
}

output "delegated_admin_access_analyzer" {
  description = "Access Analyzer delegated administrator resource"
  value       = length(aws_organizations_delegated_administrator.access_analyzer) > 0 ? aws_organizations_delegated_administrator.access_analyzer[0] : null
}
