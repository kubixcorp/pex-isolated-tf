
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }
}

provider "aws" {
  alias  = "current"
  region = var.region
}

resource "aws_ec2_transit_gateway" "this" {
  tags = {
    Name = "transit-gateway"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "this" {
  vpc_id             = var.vpc_id
  subnet_ids         = var.subnet_ids
  transit_gateway_id = aws_ec2_transit_gateway.this.id
  tags = {
    Name = "transit-gateway-attachment"
  }
}

output "tgw_id" {
  value = aws_ec2_transit_gateway.this.id
}

output "attachment_id" {
  value = aws_ec2_transit_gateway_vpc_attachment.this.id
}
