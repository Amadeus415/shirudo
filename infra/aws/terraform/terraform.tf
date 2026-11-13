terraform {
  # Supply the state bucket and its region to `terraform init` with
  # `-backend-config`.
  backend "s3" {
    key          = ".terraform/terraform.state"
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.45"
    }
  }

  required_version = "~> 1.15"
}

