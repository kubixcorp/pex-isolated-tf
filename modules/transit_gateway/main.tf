terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "this" {
  provider           = aws
  vpc_id             = var.vpc_id
  subnet_ids         = var.subnet_ids
  transit_gateway_id = var.tgw_id
  tags = {
    Name = "transit-gateway-attachment"
  }
}

