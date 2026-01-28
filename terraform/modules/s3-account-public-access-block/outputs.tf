# Outputs for S3 Account Public Access Block Module

output "account_id" {
  description = "The AWS account ID where public access block is configured"
  value       = data.aws_caller_identity.current.account_id
}

output "block_public_acls" {
  description = "Whether public ACLs are blocked"
  value       = aws_s3_account_public_access_block.main.block_public_acls
}

output "block_public_policy" {
  description = "Whether public bucket policies are blocked"
  value       = aws_s3_account_public_access_block.main.block_public_policy
}

output "ignore_public_acls" {
  description = "Whether public ACLs are ignored"
  value       = aws_s3_account_public_access_block.main.ignore_public_acls
}

output "restrict_public_buckets" {
  description = "Whether public buckets are restricted"
  value       = aws_s3_account_public_access_block.main.restrict_public_buckets
}
