terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }
}

resource "aws_ec2_transit_gateway_route_table" "this" {
  transit_gateway_id = var.transit_gateway_id
  tags = {
    Name = "transit-gateway-route-table"
  }
}

resource "aws_ec2_transit_gateway_route" "this" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this.id
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = var.transit_gateway_attachment_id
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
