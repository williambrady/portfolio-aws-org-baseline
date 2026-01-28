# Shared Accounts Module
# Manages log-archive, audit, and security-tooling accounts

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Log Archive Account
# -----------------------------------------------------------------------------

resource "aws_organizations_account" "log_archive" {
  name      = var.log_archive_account_name
  email     = var.log_archive_account_email
  parent_id = var.security_ou_id

  iam_user_access_to_billing = "DENY"

  tags = merge(var.common_tags, {
    AccountType = "log-archive"
  })

  lifecycle {
    ignore_changes = [
      iam_user_access_to_billing,
      email, # Email can't be changed after creation
      name,  # Name changes require trusted access with AWS Account Management
    ]
  }
}

# -----------------------------------------------------------------------------
# Audit Account
# -----------------------------------------------------------------------------

resource "aws_organizations_account" "audit" {
  name      = var.audit_account_name
  email     = var.audit_account_email
  parent_id = var.security_ou_id

  iam_user_access_to_billing = "DENY"

  tags = merge(var.common_tags, {
    AccountType = "audit"
  })

  lifecycle {
    ignore_changes = [
      iam_user_access_to_billing,
      email, # Email can't be changed after creation
      name,  # Name changes require trusted access with AWS Account Management
    ]
  }
}

# -----------------------------------------------------------------------------
# Security Tooling Account (Optional)
# -----------------------------------------------------------------------------

resource "aws_organizations_account" "security_tooling" {
  count = var.security_tooling_account_name != "" ? 1 : 0

  name      = var.security_tooling_account_name
  email     = var.security_tooling_account_email
  parent_id = var.security_ou_id

  iam_user_access_to_billing = "DENY"

  tags = merge(var.common_tags, {
    AccountType = "security-tooling"
  })

  lifecycle {
    ignore_changes = [
      iam_user_access_to_billing,
      email, # Email can't be changed after creation
      name,  # Name changes require trusted access with AWS Account Management
    ]
  }
}
