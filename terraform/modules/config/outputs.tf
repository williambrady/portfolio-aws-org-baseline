# Outputs for AWS Config Module

output "s3_bucket_name" {
  description = "The S3 bucket name for AWS Config data"
  value       = module.bucket.bucket_id
}

output "s3_bucket_arn" {
  description = "The S3 bucket ARN for AWS Config data"
  value       = module.bucket.bucket_arn
}

output "recorder_management_name" {
  description = "The name of the Config recorder in the management account"
  value       = aws_config_configuration_recorder.management.name
}

output "recorder_log_archive_name" {
  description = "The name of the Config recorder in the log archive account"
  value       = aws_config_configuration_recorder.log_archive.name
}

output "recorder_audit_name" {
  description = "The name of the Config recorder in the audit account"
  value       = aws_config_configuration_recorder.audit.name
}

output "aggregator_name" {
  description = "The name of the Config aggregator"
  value       = aws_config_configuration_aggregator.organization.name
}

output "aggregator_arn" {
  description = "The ARN of the Config aggregator"
  value       = aws_config_configuration_aggregator.organization.arn
}
