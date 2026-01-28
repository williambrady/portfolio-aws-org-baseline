# Provider Configurations
# Includes regional providers for multi-region Config deployment

# -----------------------------------------------------------------------------
# Management Account Providers
# -----------------------------------------------------------------------------

provider "aws" {
  region = var.primary_region
}

provider "aws" {
  alias  = "us_east_2"
  region = "us-east-2"
}

provider "aws" {
  alias  = "us_west_1"
  region = "us-west-1"
}

provider "aws" {
  alias  = "us_west_2"
  region = "us-west-2"
}

provider "aws" {
  alias  = "eu_west_1"
  region = "eu-west-1"
}

provider "aws" {
  alias  = "eu_west_2"
  region = "eu-west-2"
}

provider "aws" {
  alias  = "eu_west_3"
  region = "eu-west-3"
}

provider "aws" {
  alias  = "eu_central_1"
  region = "eu-central-1"
}

provider "aws" {
  alias  = "eu_north_1"
  region = "eu-north-1"
}

provider "aws" {
  alias  = "ap_southeast_1"
  region = "ap-southeast-1"
}

provider "aws" {
  alias  = "ap_southeast_2"
  region = "ap-southeast-2"
}

provider "aws" {
  alias  = "ap_northeast_1"
  region = "ap-northeast-1"
}

provider "aws" {
  alias  = "ap_northeast_2"
  region = "ap-northeast-2"
}

provider "aws" {
  alias  = "ap_northeast_3"
  region = "ap-northeast-3"
}

provider "aws" {
  alias  = "ap_south_1"
  region = "ap-south-1"
}

provider "aws" {
  alias  = "ca_central_1"
  region = "ca-central-1"
}

provider "aws" {
  alias  = "sa_east_1"
  region = "sa-east-1"
}

# -----------------------------------------------------------------------------
# Log Archive Account Providers
# -----------------------------------------------------------------------------

provider "aws" {
  alias  = "log_archive"
  region = var.primary_region

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_us_east_2"
  region = "us-east-2"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_us_west_1"
  region = "us-west-1"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_us_west_2"
  region = "us-west-2"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_eu_west_1"
  region = "eu-west-1"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_eu_west_2"
  region = "eu-west-2"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_eu_west_3"
  region = "eu-west-3"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_eu_central_1"
  region = "eu-central-1"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_eu_north_1"
  region = "eu-north-1"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_ap_southeast_1"
  region = "ap-southeast-1"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_ap_southeast_2"
  region = "ap-southeast-2"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_ap_northeast_1"
  region = "ap-northeast-1"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_ap_northeast_2"
  region = "ap-northeast-2"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_ap_northeast_3"
  region = "ap-northeast-3"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_ap_south_1"
  region = "ap-south-1"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_ca_central_1"
  region = "ca-central-1"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "log_archive_sa_east_1"
  region = "sa-east-1"

  dynamic "assume_role" {
    for_each = local.log_archive_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.log_archive_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

# -----------------------------------------------------------------------------
# Audit Account Providers
# -----------------------------------------------------------------------------

provider "aws" {
  alias  = "audit"
  region = var.primary_region

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_us_east_2"
  region = "us-east-2"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_us_west_1"
  region = "us-west-1"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_us_west_2"
  region = "us-west-2"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_eu_west_1"
  region = "eu-west-1"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_eu_west_2"
  region = "eu-west-2"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_eu_west_3"
  region = "eu-west-3"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_eu_central_1"
  region = "eu-central-1"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_eu_north_1"
  region = "eu-north-1"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_ap_southeast_1"
  region = "ap-southeast-1"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_ap_southeast_2"
  region = "ap-southeast-2"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_ap_northeast_1"
  region = "ap-northeast-1"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_ap_northeast_2"
  region = "ap-northeast-2"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_ap_northeast_3"
  region = "ap-northeast-3"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_ap_south_1"
  region = "ap-south-1"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_ca_central_1"
  region = "ca-central-1"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}

provider "aws" {
  alias  = "audit_sa_east_1"
  region = "sa-east-1"

  dynamic "assume_role" {
    for_each = local.audit_account_id != "" ? [1] : []
    content {
      role_arn = "arn:aws:iam::${local.audit_account_id}:role/OrganizationAccountAccessRole"
    }
  }
}
