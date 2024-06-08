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

resource "aws_ec2_transit_gateway_route_table" "this" {
  transit_gateway_id = var.transit_gateway_id
  tags = {
    Name = "transit-gateway-route-table"
  }
}

resource "aws_ec2_transit_gateway_route_table_association" "association" {
  transit_gateway_attachment_id = var.transit_gateway_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this.id
}

resource "aws_ec2_transit_gateway_route" "to_peer" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this.id
  destination_cidr_block         = "10.1.0.0/16" # Cambia según sea necesario
  transit_gateway_attachment_id  = var.peer_attachment_id
}

resource "aws_ec2_transit_gateway_route" "from_peer" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this.id
  destination_cidr_block         = "10.0.0.0/16" # Cambia según sea necesario
  transit_gateway_attachment_id  = var.peer_transit_gateway_id
}
