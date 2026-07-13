terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "aws_instance" "elevpn_server" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.elevpn_server_security_group_id]
  key_name               = var.key_name

  tags = {
    Name      = "elevpn-server"
    ManagedBy = "Terraform"
  }
}

resource "aws_instance" "elevpn_client" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.elevpn_client_security_group_id]
  key_name               = var.key_name

  tags = {
    Name      = "elevpn-client"
    ManagedBy = "Terraform"
  }
}