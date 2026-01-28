# Outputs for S3 Terraform State Module

output "bucket_name" {
  description = "Name of the Terraform state bucket"
  value       = module.bucket.bucket_id
}

output "bucket_arn" {
  description = "ARN of the Terraform state bucket"
  value       = module.bucket.bucket_arn
}
