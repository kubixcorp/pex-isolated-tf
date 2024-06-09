terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }
}

provider "aws" {
  alias   = "virginia"
  region  = "us-east-1"
  profile = var.aws_profile
}

provider "aws" {
  alias   = "oregon"
  region  = "us-west-2"
  profile = var.aws_profile
}

# Crear los VPCs y Subnets
module "vpc_virginia" {
  source = "./modules/vpc"
  providers = {
    aws = aws.virginia
  }
  region               = var.vpc_virginia_region
  vpc_cidr             = var.vpc_virginia_cidr
  public_subnet_cidrs  = var.vpc_virginia_public_subnets
  private_subnet_cidrs = var.vpc_virginia_private_subnets
  availability_zones   = var.vpc_virginia_azs
}

module "vpc_oregon" {
  source = "./modules/vpc"
  providers = {
    aws = aws.oregon
  }
  region               = var.vpc_oregon_region
  vpc_cidr             = var.vpc_oregon_cidr
  public_subnet_cidrs  = var.vpc_oregon_public_subnets
  private_subnet_cidrs = var.vpc_oregon_private_subnets
  availability_zones   = var.vpc_oregon_azs
}

# Crear los Transit Gateways después de los VPCs y Subnets
resource "aws_ec2_transit_gateway" "virginia" {
  provider = aws.virginia
  description = "Transit Gateway for Virginia region"
  tags = {
    Name = "transit-gateway-virginia"
  }
}

resource "aws_ec2_transit_gateway" "oregon" {
  provider = aws.oregon
  description = "Transit Gateway for Oregon region"
  tags = {
    Name = "transit-gateway-oregon"
  }
}

# Crear las asociaciones de Transit Gateway y rutas después de los Transit Gateways
module "transit_gateway_virginia" {
  source = "./modules/transit_gateway"
  providers = {
    aws = aws.virginia
  }
  region     = var.vpc_virginia_region
  vpc_id     = module.vpc_virginia.vpc_id
  subnet_ids = module.vpc_virginia.public_subnets
  tgw_id     = aws_ec2_transit_gateway.virginia.id
}

module "transit_gateway_oregon" {
  source = "./modules/transit_gateway"
  providers = {
    aws = aws.oregon
  }
  region     = var.vpc_oregon_region
  vpc_id     = module.vpc_oregon.vpc_id
  subnet_ids = module.vpc_oregon.public_subnets
  tgw_id     = aws_ec2_transit_gateway.oregon.id
}

module "routing_virginia" {
  source = "./modules/routing"
  providers = {
    aws = aws.virginia
  }
  region                        = var.vpc_virginia_region
  transit_gateway_id            = aws_ec2_transit_gateway.virginia.id
  transit_gateway_attachment_id = module.transit_gateway_virginia.attachment_id
  peer_transit_gateway_id       = aws_ec2_transit_gateway.oregon.id
  peer_attachment_id            = module.transit_gateway_oregon.attachment_id
}

module "routing_oregon" {
  source = "./modules/routing"
  providers = {
    aws = aws.oregon
  }
  region                        = var.vpc_oregon_region
  transit_gateway_id            = aws_ec2_transit_gateway.oregon.id
  transit_gateway_attachment_id = module.transit_gateway_oregon.attachment_id
  peer_transit_gateway_id       = aws_ec2_transit_gateway.virginia.id
  peer_attachment_id            = module.transit_gateway_virginia.attachment_id
}