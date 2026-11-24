# Deliberately insecure sample for the Item 8 tool runs. Never apply it.
# Stand-in until the Lane B testbed exists; seeded issues are listed in fixtures/recorded/README.md.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "public_data" {
  bucket = "assay-sample-public-data"
}

resource "aws_s3_bucket_acl" "public_data" {
  bucket = aws_s3_bucket.public_data.id
  acl    = "public-read"
}

resource "aws_s3_bucket" "private_logs" {
  bucket = "assay-sample-private-logs"
}

resource "aws_s3_bucket_public_access_block" "private_logs" {
  bucket                  = aws_s3_bucket.private_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "private_logs" {
  bucket = aws_s3_bucket.private_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.good.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "private_logs" {
  bucket = aws_s3_bucket.private_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "private_logs" {
  bucket        = aws_s3_bucket.private_logs.id
  target_bucket = aws_s3_bucket.private_logs.id
  target_prefix = "self/"
}

resource "aws_security_group" "open_admin" {
  name        = "open-admin"
  description = "Sample group with admin ports open"
  vpc_id      = "vpc-0sample"

  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "rdp"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "plain" {
  availability_zone = "us-east-1a"
  size              = 8
  encrypted         = false
}

resource "aws_db_instance" "public_db" {
  identifier          = "assay-sample-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "app"
  password            = var.db_password
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}

variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_iam_policy" "star" {
  name = "assay-sample-star"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_kms_key" "no_rotation" {
  description         = "Sample key without rotation"
  enable_key_rotation = false
}

resource "aws_kms_key" "good" {
  description         = "Sample key with rotation"
  enable_key_rotation = true
}

resource "aws_cloudtrail" "single_region" {
  name                       = "assay-sample-trail"
  s3_bucket_name             = aws_s3_bucket.private_logs.id
  is_multi_region_trail      = false
  enable_log_file_validation = false
}
