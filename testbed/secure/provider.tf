# Emulator only. Every endpoint is pinned to the local Moto server and the keys are Moto dummies.
# Pinned to 4.67.0: with 5.x the Go SDK sends a short CloudTrail X-Amz-Target that Moto 5.2.6 answers with 404.
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "4.67.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "testing"
  secret_key                  = "testing"
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  skip_region_validation      = true

  endpoints {
    acm            = "http://localhost:5000"
    cloudtrail     = "http://localhost:5000"
    ec2            = "http://localhost:5000"
    iam            = "http://localhost:5000"
    kms            = "http://localhost:5000"
    rds            = "http://localhost:5000"
    s3             = "http://localhost:5000"
    secretsmanager = "http://localhost:5000"
    sts            = "http://localhost:5000"
  }
}
