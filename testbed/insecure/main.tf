# Insecure testbed. Each seeded issue is listed in ../ground-truth.yaml.

locals {
  prefix = "assay-insecure"
}

# Log target for the buckets that are meant to pass the logging check.
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

# Seeded: public-read ACL and no Block Public Access.
resource "aws_s3_bucket" "public" {
  bucket = "${local.prefix}-public"
  tags   = { criticality = "high", data_sensitivity = "confidential" }
}

resource "aws_s3_bucket_acl" "public" {
  bucket = aws_s3_bucket.public.id
  acl    = "public-read"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "public" {
  bucket = aws_s3_bucket.public.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "public" {
  bucket = aws_s3_bucket.public.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "public" {
  bucket        = aws_s3_bucket.public.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "public/"
  depends_on    = [aws_s3_bucket_logging.logs]
}

# Seeded: no default encryption, no versioning and no access logging.
resource "aws_s3_bucket" "unencrypted" {
  bucket = "${local.prefix}-unencrypted"
  tags   = { criticality = "medium", data_sensitivity = "restricted" }
}

resource "aws_s3_bucket_public_access_block" "unencrypted" {
  bucket                  = aws_s3_bucket.unencrypted.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_vpc" "main" {
  cidr_block = "10.10.0.0/16"
  tags       = { Name = "${local.prefix}-vpc", criticality = "medium", data_sensitivity = "internal" }
}

# Seeded: SSH and PostgreSQL open to the whole internet.
resource "aws_security_group" "open" {
  name        = "${local.prefix}-open"
  description = "Testbed group open to the internet"
  vpc_id      = aws_vpc.main.id
  tags        = { criticality = "high", data_sensitivity = "confidential" }

  ingress {
    description = "SSH from anywhere"
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "PostgreSQL from anywhere"
    protocol    = "tcp"
    from_port   = 5432
    to_port     = 5432
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Seeded: unencrypted volume.
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = false
  tags              = { Name = "${local.prefix}-data", criticality = "high", data_sensitivity = "confidential" }
}

# Seeded: wildcard action on wildcard resource.
resource "aws_iam_policy" "admin_wildcard" {
  name = "${local.prefix}-admin-wildcard"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
  tags = { criticality = "high", data_sensitivity = "internal" }
}

# Seeded: service-wide action wildcard.
resource "aws_iam_policy" "s3_wildcard" {
  name = "${local.prefix}-s3-wildcard"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "*" }]
  })
  tags = { criticality = "medium", data_sensitivity = "internal" }
}

# The group has no members, so the policies count as attached without touching the user checks.
resource "aws_iam_group" "ops" {
  name = "${local.prefix}-ops"
}

resource "aws_iam_group_policy_attachment" "admin_wildcard" {
  group      = aws_iam_group.ops.name
  policy_arn = aws_iam_policy.admin_wildcard.arn
}

resource "aws_iam_group_policy_attachment" "s3_wildcard" {
  group      = aws_iam_group.ops.name
  policy_arn = aws_iam_policy.s3_wildcard.arn
}

# Seeded: console password without MFA and an active access key that ages past 90 days.
resource "aws_iam_user" "dev" {
  name = "${local.prefix}-dev"
  tags = { criticality = "high", data_sensitivity = "confidential" }
}

resource "aws_iam_user_login_profile" "dev" {
  user                    = aws_iam_user.dev.name
  password_reset_required = false
}

resource "aws_iam_access_key" "dev" {
  user = aws_iam_user.dev.name
}

# Seeded: customer managed key without rotation.
resource "aws_kms_key" "data" {
  description             = "Testbed key without rotation"
  enable_key_rotation     = false
  deletion_window_in_days = 7
  tags                    = { Name = "${local.prefix}-key", criticality = "high", data_sensitivity = "restricted" }
}

# Account-level gaps seeded by omission: no CloudTrail trail, no password policy and
# EBS encryption by default left off.
