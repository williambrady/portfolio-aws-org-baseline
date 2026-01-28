# Outputs for IAM Password Policy Module

output "expire_passwords" {
  description = "Whether passwords expire"
  value       = aws_iam_account_password_policy.main.expire_passwords
}

output "minimum_password_length" {
  description = "Minimum password length configured"
  value       = aws_iam_account_password_policy.main.minimum_password_length
}

output "password_reuse_prevention" {
  description = "Number of passwords prevented from reuse"
  value       = aws_iam_account_password_policy.main.password_reuse_prevention
}

output "hard_expiry" {
  description = "Whether admin must reset expired passwords"
  value       = aws_iam_account_password_policy.main.hard_expiry
}
