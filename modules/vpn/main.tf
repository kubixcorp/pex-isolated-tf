terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }
}

provider "aws" {
  alias  = "virginia"
  region = "us-east-1"
}

provider "aws" {
  alias  = "oregon"
  region = "us-west-2"
}

resource "aws_vpn_gateway" "this" {
  vpc_id = var.vpc_id

  tags = {
    Name = "main-vpn-gateway"
  }
}


output "vpn_gateway_id" {
  value = aws_vpn_gateway.this.id
}
