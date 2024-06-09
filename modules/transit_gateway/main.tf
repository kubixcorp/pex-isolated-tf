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

resource "aws_ec2_transit_gateway_vpc_attachment" "this" {
  provider            = aws.current
  vpc_id              = var.vpc_id
  subnet_ids          = var.subnet_ids
  transit_gateway_id  = var.tgw_id
  tags = {
    Name = "transit-gateway-attachment"
  }
}

resource "null_resource" "delete_attachment_before_tgw" {
  depends_on = [
    aws_ec2_transit_gateway_vpc_attachment.this
  ]

  provisioner "local-exec" {
    command = "terraform destroy -target aws_ec2_transit_gateway_vpc_attachment.this"
  }
}

resource "aws_ec2_transit_gateway" "this" {
  provider = aws.current
  description = "Transit Gateway for region"
  tags = {
    Name = "transit-gateway"
  }

  depends_on = [null_resource.delete_attachment_before_tgw]
}

output "attachment_id" {
  value = aws_ec2_transit_gateway_vpc_attachment.this.id
}