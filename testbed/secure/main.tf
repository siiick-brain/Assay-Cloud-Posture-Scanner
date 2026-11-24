# Secure testbed. Same shape as ../insecure with every seeded issue fixed, so a scan finds nothing.

locals {
  prefix  = "assay-secure"
  account = "123456789012"
}

resource "aws_kms_key" "data" {
  description             = "Testbed key with rotation"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  tags                    = { Name = "${local.prefix}-key", criticality = "high", data_sensitivity = "restricted" }
}

resource "aws_s3_bucket" "logs" {
  bucket = "${local.prefix}-logs"
  tags   = { criticality = "low", data_sensitivity = "internal" }
}

resource "aws_s3_bucket_acl" "logs" {
  bucket = aws_s3_bucket.logs.id
  acl    = "log-delivery-write"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "logs" {
  bucket        = aws_s3_bucket.logs.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "self/"
  depends_on    = [aws_s3_bucket_acl.logs]
}

resource "aws_s3_bucket" "data" {
  bucket = "${local.prefix}-data"
  tags   = { criticality = "high", data_sensitivity = "confidential" }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "data/"
  depends_on    = [aws_s3_bucket_logging.logs]
}

resource "aws_s3_bucket" "trail" {
  bucket = "${local.prefix}-trail"
  tags   = { criticality = "high", data_sensitivity = "internal" }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "trail" {
  bucket        = aws_s3_bucket.trail.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "trail/"
  depends_on    = [aws_s3_bucket_logging.logs]
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "TrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
      },
      {
        Sid       = "TrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${local.account}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "${local.prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true
  depends_on                    = [aws_s3_bucket_policy.trail]
}

resource "aws_vpc" "main" {
  cidr_block = "10.20.0.0/16"
  tags       = { Name = "${local.prefix}-vpc", criticality = "medium", data_sensitivity = "internal" }
}

resource "aws_security_group" "app" {
  name        = "${local.prefix}-app"
  description = "Testbed group reachable from inside the VPC only"
  vpc_id      = aws_vpc.main.id
  tags        = { criticality = "high", data_sensitivity = "confidential" }

  ingress {
    description = "HTTPS from the VPC"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["10.20.0.0/16"]
  }
}

resource "aws_ebs_encryption_by_default" "on" {
  enabled = true
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = true
  kms_key_id        = aws_kms_key.data.arn
  tags              = { Name = "${local.prefix}-data", criticality = "high", data_sensitivity = "confidential" }
}

resource "aws_iam_policy" "read_data" {
  name = "${local.prefix}-read-data"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
    }]
  })
  tags = { criticality = "medium", data_sensitivity = "internal" }
}

resource "aws_iam_group" "readers" {
  name = "${local.prefix}-readers"
}

resource "aws_iam_group_policy_attachment" "read_data" {
  group      = aws_iam_group.readers.name
  policy_arn = aws_iam_policy.read_data.arn
}

# No console password and no long-lived access key, so neither user check applies.
resource "aws_iam_user" "svc" {
  name = "${local.prefix}-svc"
  tags = { criticality = "medium", data_sensitivity = "internal" }
}

resource "aws_iam_user_group_membership" "svc" {
  user   = aws_iam_user.svc.name
  groups = [aws_iam_group.readers.name]
}

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}
