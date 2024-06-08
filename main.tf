terraform {
  required_version = ">= 1.2.0"
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
  profile = "fmoralesIsolated"
}

provider "aws" {
  alias   = "oregon"
  region  = "us-west-2"
  profile = "fmoralesIsolated"
}

module "vpc_virginia" {
  source = "./modules/vpc"
  providers = {
    aws = aws.virginia
  }
  vpc_cidr             = "10.0.0.0/16"
  public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnet_cidrs = ["10.0.3.0/24", "10.0.4.0/24"]
  availability_zones   = ["us-east-1a", "us-east-1b"]
}

module "vpc_oregon" {
  source = "./modules/vpc"
  providers = {
    aws = aws.oregon
  }
  vpc_cidr             = "10.1.0.0/16"
  public_subnet_cidrs  = ["10.1.1.0/24", "10.1.2.0/24"]
  private_subnet_cidrs = ["10.1.3.0/24", "10.1.4.0/24"]
  availability_zones   = ["us-west-2a", "us-west-2b"]
}

module "transit_gateway_virginia" {
  source = "./modules/transit_gateway"
  providers = {
    aws = aws.virginia
  }
  region     = "us-east-1"
  vpc_id     = module.vpc_virginia.vpc_id
  subnet_ids = module.vpc_virginia.public_subnets
}

module "transit_gateway_oregon" {
  source = "./modules/transit_gateway"
  providers = {
    aws = aws.oregon
  }
  region     = "us-west-2"
  vpc_id     = module.vpc_oregon.vpc_id
  subnet_ids = module.vpc_oregon.public_subnets
}

module "routing_virginia" {
  source = "./modules/routing"
  providers = {
    aws = aws.virginia
  }
  transit_gateway_id_virginia            = module.transit_gateway_virginia.tgw_id
  transit_gateway_attachment_id_virginia = module.transit_gateway_virginia.attachment_id
  transit_gateway_id_oregon              = module.transit_gateway_oregon.tgw_id
  transit_gateway_attachment_id_oregon   = module.transit_gateway_oregon.attachment_id
}

module "routing_oregon" {
  source = "./modules/routing"
  providers = {
    aws = aws.oregon
  }
  transit_gateway_id_virginia            = module.transit_gateway_virginia.tgw_id
  transit_gateway_attachment_id_virginia = module.transit_gateway_virginia.attachment_id
  transit_gateway_id_oregon              = module.transit_gateway_oregon.tgw_id
  transit_gateway_attachment_id_oregon   = module.transit_gateway_oregon.attachment_id
}

module "vpn_virginia" {
  source = "./modules/vpn"
  providers = {
    aws = aws.virginia
  }
  vpc_id            = module.vpc_virginia.vpc_id
  tgw_id            = module.transit_gateway_virginia.tgw_id
  tgw_attachment_id = module.transit_gateway_virginia.attachment_id
}

module "vpn_oregon" {
  source = "./modules/vpn"
  providers = {
    aws = aws.oregon
  }
  vpc_id            = module.vpc_oregon.vpc_id
  tgw_id            = module.transit_gateway_oregon.tgw_id
  tgw_attachment_id = module.transit_gateway_oregon.attachment_id
}
