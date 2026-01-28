# Outputs for CloudTrail Module

output "trail_name" {
  description = "The name of the organization CloudTrail"
  value       = aws_cloudtrail.organization.name
}

output "trail_arn" {
  description = "The ARN of the organization CloudTrail"
  value       = aws_cloudtrail.organization.arn
}

output "s3_bucket_name" {
  description = "The S3 bucket name for CloudTrail logs"
  value       = module.bucket.bucket_id
}

output "s3_bucket_arn" {
  description = "The S3 bucket ARN for CloudTrail logs"
  value       = module.bucket.bucket_arn
}

output "cloudwatch_log_group_name" {
  description = "The CloudWatch Log Group name for CloudTrail"
  value       = aws_cloudwatch_log_group.cloudtrail.name
}

output "cloudwatch_log_group_arn" {
  description = "The CloudWatch Log Group ARN for CloudTrail"
  value       = aws_cloudwatch_log_group.cloudtrail.arn
}

output "cloudwatch_kms_key_arn" {
  description = "The KMS key ARN for CloudTrail CloudWatch Logs"
  value       = aws_kms_key.cloudwatch_logs.arn
}

output "cloudwatch_iam_role_arn" {
  description = "The IAM role ARN for CloudTrail to CloudWatch Logs"
  value       = aws_iam_role.cloudtrail_cloudwatch.arn
}
