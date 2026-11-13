provider "aws" {
  region = var.region
  default_tags {
    tags = var.tags
  }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnet" "subnet" {
  vpc_id            = data.aws_vpc.default.id
  availability_zone = var.availability_zone
}

data "aws_ami" "bpf_next_ubuntu" {
  most_recent = true

  owners = ["self"]

  filter {
    name   = "name"
    values = ["shirudo-target-ubuntu-*"]
  }

  filter {
    name   = "tag:ShirudoRole"
    values = ["target"]
  }

  filter {
    name   = "tpm-support"
    values = ["v2.0"]
  }
}

resource "aws_security_group" "target" {
  name   = "shirudo-target"
  vpc_id = data.aws_vpc.default.id
}

resource "aws_vpc_security_group_egress_rule" "allow_any_outbound" {
  security_group_id = aws_security_group.target.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Allow all egress traffic"
}

resource "aws_instance" "ubuntu_bpf_next" {
  ami                         = data.aws_ami.bpf_next_ubuntu.id
  instance_type               = "t3.large"
  subnet_id                   = data.aws_subnet.subnet.id
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.target.name
  vpc_security_group_ids      = [aws_security_group.target.id]

  metadata_options {
    http_endpoint          = "enabled"
    http_tokens            = "required"
    instance_metadata_tags = "enabled"
  }

  tags = {
    Name = "ubuntu_bpf_next"
    role = "target"
  }
}

resource "aws_iam_role" "target" {
  name = "shirudo-target"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ssm_audit" {
  count = var.ssm_audit_bucket != "" ? 1 : 0

  name = "shirudo-ssm-audit"
  role = aws_iam_role.target.name
  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:PutObjectTagging",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
        ]
        Effect = "Allow"

        Resource = [
          "arn:aws:s3:::${var.ssm_audit_bucket}",
          "arn:aws:s3:::${var.ssm_audit_bucket}/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.target.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "target" {
  name = "shirudo-target"
  role = aws_iam_role.target.name
}
