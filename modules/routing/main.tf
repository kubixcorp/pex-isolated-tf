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

resource "aws_ec2_transit_gateway_route_table" "this" {
  provider           = aws.current
  transit_gateway_id = var.transit_gateway_id
}

resource "aws_ec2_transit_gateway_route_table_association" "association" {
  provider                       = aws.current
  transit_gateway_attachment_id  = var.transit_gateway_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this.id

  lifecycle {
    ignore_changes = [transit_gateway_route_table_id]
  }
}

resource "aws_ec2_transit_gateway_route_table_propagation" "propagation" {
  provider                       = aws.current
  transit_gateway_attachment_id  = var.transit_gateway_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this.id
}

resource "aws_ec2_transit_gateway_route" "to_peer" {
  provider                       = aws.current
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this.id
  destination_cidr_block         = "10.1.0.0/16"
  transit_gateway_attachment_id  = var.peer_attachment_id

  lifecycle {
    ignore_changes = [transit_gateway_route_table_id]
  }
}

resource "aws_ec2_transit_gateway_route" "from_peer" {
  provider                       = aws.current
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this.id
  destination_cidr_block         = "10.0.0.0/16"
  transit_gateway_attachment_id  = var.peer_transit_gateway_id

  lifecycle {
    ignore_changes = [transit_gateway_route_table_id]
  }
}