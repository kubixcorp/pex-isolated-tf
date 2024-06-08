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
  #provider = aws[var.region == "us-east-1" ? "virginia" : "oregon"]
  #provider = aws.virginia
  description = "TGW in ${var.region}"
  tags = {
    Name = "main-tgw"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "this" {
  #provider = aws[var.region == "us-east-1" ? "virginia" : "oregon"]
  #provider = aws.oregon
  transit_gateway_id = aws_ec2_transit_gateway.this.id
  subnet_ids         = var.subnet_ids
  vpc_id             = var.vpc_id

  tags = {
    Name = "main-tgw-attachment"
  }
}

output "tgw_id" {
  value = aws_ec2_transit_gateway.this.id
}

output "attachment_id" {
  value = aws_ec2_transit_gateway_vpc_attachment.this.id
}
