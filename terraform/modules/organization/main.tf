# AWS Organization Module
# Manages AWS Organization, OUs, root access, and delegated administrators

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

# -----------------------------------------------------------------------------
# AWS Organization
# -----------------------------------------------------------------------------

resource "aws_organizations_organization" "main" {
  count = var.organization_exists ? 0 : 1

  aws_service_access_principals = [
    "access-analyzer.amazonaws.com",
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "guardduty.amazonaws.com",
    "iam.amazonaws.com",
    "inspector2.amazonaws.com",
    "malware-protection.guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "sso.amazonaws.com",
  ]

  feature_set = "ALL"
}

# Get organization details (works for both new and existing orgs)
data "aws_organizations_organization" "current" {
  depends_on = [aws_organizations_organization.main]
}

# -----------------------------------------------------------------------------
# Service Access Enablement (for existing organizations)
# When organization_exists = true, we need to explicitly enable service access
# -----------------------------------------------------------------------------

resource "null_resource" "enable_service_access" {
  count = var.organization_exists && var.create_delegated_admins ? 1 : 0

  provisioner "local-exec" {
    command = <<-EOT
      for service in access-analyzer.amazonaws.com cloudtrail.amazonaws.com config.amazonaws.com guardduty.amazonaws.com inspector2.amazonaws.com malware-protection.guardduty.amazonaws.com securityhub.amazonaws.com; do
        aws organizations enable-aws-service-access --service-principal $service 2>/dev/null || true
      done
    EOT
  }
}

# -----------------------------------------------------------------------------
# Local Values
# -----------------------------------------------------------------------------

locals {
  # Organization root ID - use discovered value or fall back to data source
  root_id = var.root_id != "" ? var.root_id : data.aws_organizations_organization.current.roots[0].id

  # Level 1 OUs (directly under root)
  level1_ous = { for ou in var.organizational_units : ou.name => ou }

  # Level 2 OUs (children of level 1)
  level2_ous = merge([
    for parent in var.organizational_units : {
      for child in parent.children : "${parent.name}/${child.name}" => {
        name        = child.name
        parent_name = parent.name
        children    = child.children
      }
    }
  ]...)

  # Level 3 OUs (children of level 2)
  level3_ous = merge([
    for parent_key, parent in local.level2_ous : {
      for child in parent.children : "${parent_key}/${child.name}" => {
        name       = child.name
        parent_key = parent_key
      }
    }
  ]...)
}

# -----------------------------------------------------------------------------
# Centralized Root Access Management
# -----------------------------------------------------------------------------

# Enable trusted access for IAM in Organizations (required for centralized root access)
resource "null_resource" "enable_iam_trusted_access" {
  provisioner "local-exec" {
    command = "aws organizations enable-aws-service-access --service-principal iam.amazonaws.com || true"
  }

  triggers = {
    always_run = "1"
  }
}

# Enable centralized root access for member accounts
resource "aws_iam_organizations_features" "root_access" {
  enabled_features = [
    "RootCredentialsManagement",
    "RootSessions",
  ]

  depends_on = [null_resource.enable_iam_trusted_access]
}

# -----------------------------------------------------------------------------
# Organizational Units (Dynamic)
# -----------------------------------------------------------------------------

# Level 1 OUs (under root)
resource "aws_organizations_organizational_unit" "level1" {
  for_each = local.level1_ous

  name      = each.value.name
  parent_id = local.root_id
}

# Level 2 OUs (under level 1)
resource "aws_organizations_organizational_unit" "level2" {
  for_each = local.level2_ous

  name      = each.value.name
  parent_id = aws_organizations_organizational_unit.level1[each.value.parent_name].id
}

# Level 3 OUs (under level 2)
resource "aws_organizations_organizational_unit" "level3" {
  for_each = local.level3_ous

  name      = each.value.name
  parent_id = aws_organizations_organizational_unit.level2[each.value.parent_key].id
}

# -----------------------------------------------------------------------------
# Delegated Administrators
# -----------------------------------------------------------------------------

resource "aws_organizations_delegated_administrator" "securityhub" {
  count = var.create_delegated_admins ? 1 : 0

  account_id        = var.audit_account_id
  service_principal = "securityhub.amazonaws.com"

  depends_on = [null_resource.enable_service_access]
}

resource "aws_organizations_delegated_administrator" "config" {
  count = var.create_delegated_admins ? 1 : 0

  account_id        = var.audit_account_id
  service_principal = "config.amazonaws.com"

  depends_on = [null_resource.enable_service_access]
}

resource "aws_organizations_delegated_administrator" "access_analyzer" {
  count = var.create_delegated_admins ? 1 : 0

  account_id        = var.audit_account_id
  service_principal = "access-analyzer.amazonaws.com"

  depends_on = [null_resource.enable_service_access]
}

resource "aws_organizations_delegated_administrator" "inspector" {
  count = var.create_delegated_admins ? 1 : 0

  account_id        = var.audit_account_id
  service_principal = "inspector2.amazonaws.com"

  depends_on = [null_resource.enable_service_access]
}
