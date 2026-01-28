# Outputs for VPC Defaults Module

output "internet_gateway_block_mode" {
  description = "VPC internet gateway block mode setting (null if disabled)"
  value       = length(aws_vpc_block_public_access_options.block_public_access) > 0 ? aws_vpc_block_public_access_options.block_public_access[0].internet_gateway_block_mode : null
}

output "vpc_block_public_access_id" {
  description = "ID of the VPC block public access configuration (null if disabled)"
  value       = length(aws_vpc_block_public_access_options.block_public_access) > 0 ? aws_vpc_block_public_access_options.block_public_access[0].id : null
}

output "vpc_block_public_access_enabled" {
  description = "Whether VPC block public access is enabled"
  value       = var.vpc_block_public_access_mode != "disabled"
}

output "region" {
  description = "The region where this setting is applied"
  value       = data.aws_region.current.name
}

output "account_id" {
  description = "The account ID where this setting is applied"
  value       = data.aws_caller_identity.current.account_id
}
