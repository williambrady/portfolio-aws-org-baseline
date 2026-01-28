# Outputs for Inspector Enabler Module

output "enabled" {
  description = "Whether Inspector was enabled (waits for propagation)"
  value       = time_sleep.wait_for_enabler.id != "" ? true : true
}

output "resource_types" {
  description = "Resource types that are enabled"
  value       = local.all_resource_types
}

output "region" {
  description = "The region where Inspector is enabled"
  value       = data.aws_region.current.name
}

output "account_id" {
  description = "The account ID where Inspector is enabled"
  value       = data.aws_caller_identity.current.account_id
}
