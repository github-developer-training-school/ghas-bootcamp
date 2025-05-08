terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# S3 bucket
resource "aws_s3_bucket" "example" {
  bucket = "my-example-bucket-123"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

# EC2 instance
resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"  # Amazon Linux 2 AMI
  instance_type = "t2.micro"
  
  tags = {
    Name = "example-instance"
  }
}

# Security Group
resource "aws_security_group" "example" {
  name        = "example-security-group"
  description = "Example security group"
  vpc_id      = aws_vpc.example.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "example-security-group"
  }
}

# VPC
resource "aws_vpc" "example" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "example-vpc"
  }
}

# Subnet
resource "aws_subnet" "example" {
  vpc_id            = aws_vpc.example.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-west-2a"

  tags = {
    Name = "example-subnet"
  }
}

# Network ACL
resource "aws_network_acl" "example" {
  vpc_id = aws_vpc.example.id

  egress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 65535
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 65535
  }

  tags = {
    Name = "example-network-acl"
  }
}

# Launch Template
resource "aws_launch_template" "example" {
  name_prefix   = "example"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  network_interfaces {
    associate_public_ip_address = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "example-instance"
    }
  }
} 