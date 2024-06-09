terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
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

  depends_on = [
    aws_ec2_transit_gateway.this,
  ]
}

output "attachment_id" {
  value = aws_ec2_transit_gateway_vpc_attachment.this.id
}