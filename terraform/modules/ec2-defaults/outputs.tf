# Outputs for EC2 Defaults Module

output "ebs_encryption_enabled" {
  description = "Whether EBS encryption by default is enabled"
  value       = aws_ebs_encryption_by_default.enabled.enabled
}

output "ebs_default_kms_key_arn" {
  description = "Default KMS key ARN for EBS encryption"
  value       = aws_ebs_default_kms_key.ebs.key_arn
}

output "ebs_snapshot_block_public_access_state" {
  description = "State of EBS snapshot block public access"
  value       = aws_ebs_snapshot_block_public_access.enabled.state
}

output "imds_http_tokens" {
  description = "IMDS HTTP tokens requirement (required = IMDSv2 only)"
  value       = aws_ec2_instance_metadata_defaults.secure.http_tokens
}

output "imds_hop_limit" {
  description = "IMDS HTTP PUT response hop limit"
  value       = aws_ec2_instance_metadata_defaults.secure.http_put_response_hop_limit
}

output "imds_instance_tags_enabled" {
  description = "Whether instance metadata tags are enabled"
  value       = aws_ec2_instance_metadata_defaults.secure.instance_metadata_tags
}

output "region" {
  description = "The region where these defaults are applied"
  value       = data.aws_region.current.name
}

output "account_id" {
  description = "The account ID where these defaults are applied"
  value       = data.aws_caller_identity.current.account_id
}
