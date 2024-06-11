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
  region  = var.vpc_virginia_region
  profile = var.aws_profile
}

provider "aws" {
  alias   = "oregon"
  region  = var.vpc_oregon_region
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
  provider    = aws.virginia
  description = "Transit Gateway for Virginia region"
  tags = {
    Name = "transit-gateway-virginia"
  }
}

resource "aws_ec2_transit_gateway" "oregon" {
  provider    = aws.oregon
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

# Crear ALBs después de los VPCs y Subnets
module "alb_virginia" {
  source = "./modules/alb"
  providers = {
    aws = aws.virginia
  }
  name                   = "alb-virginia"
  internal               = false
  security_groups        = [aws_security_group.alb_sg_virginia.id]
  subnets                = module.vpc_virginia.public_subnets
  enable_deletion_protection = false
  target_group_name      = "tg-virginia"
  target_group_port      = 80
  vpc_id                 = module.vpc_virginia.vpc_id
  certificate_arn        = var.certificate_arn_virginia
  tags = {
    Name = "ALB Virginia"
  }
}

module "alb_oregon" {
  source = "./modules/alb"
  providers = {
    aws = aws.oregon
  }
  name                   = "alb-oregon"
  internal               = false
  security_groups        = [aws_security_group.alb_sg_oregon.id]
  subnets                = module.vpc_oregon.public_subnets
  enable_deletion_protection = false
  target_group_name      = "tg-oregon"
  target_group_port      = 80
  vpc_id                 = module.vpc_oregon.vpc_id
  certificate_arn        = var.certificate_arn_oregon
  tags = {
    Name = "ALB Oregon"
  }
}

# Crear los Security Groups
resource "aws_security_group" "alb_sg_virginia" {
  provider = aws.virginia
  vpc_id   = module.vpc_virginia.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ALB Security Group Virginia"
  }
}

resource "aws_security_group" "alb_sg_oregon" {
  provider = aws.oregon
  vpc_id   = module.vpc_oregon.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ALB Security Group Oregon"
  }
}

resource "aws_security_group" "instance_sg_virginia" {
  provider = aws.virginia
  vpc_id   = module.vpc_virginia.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Instance Security Group Virginia"
  }
}

resource "aws_security_group" "instance_sg_oregon" {
  provider = aws.oregon
  vpc_id   = module.vpc_oregon.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Instance Security Group Oregon"
  }
}

# Crear instancias EC2 usando el nuevo módulo
module "web_instance_virginia" {
  source = "./modules/ec2"
  providers = {
    aws = aws.virginia
  }
  ami                  = "ami-04e8b3e527208c8cf"
  instance_type        = "t2.micro"
  subnet_id            = module.vpc_virginia.public_subnets[0]
  key_name             = "BaseKeyAcces"
  security_group_ids   = [aws_security_group.instance_sg_virginia.id]
  user_data            = <<-EOF
                          #!/bin/bash
                          echo "Hello, World from Virginia!" > /var/www/html/index.html
                          yum install -y httpd
                          systemctl start httpd
                          systemctl enable httpd
                          EOF
  tags = {
    Name = "WebInstanceVirginia"
  }
  depends_on = [aws_security_group.instance_sg_virginia]
}

module "web_instance_oregon" {
  source = "./modules/ec2"
  providers = {
    aws = aws.oregon
  }
  ami                  = "ami-0676a735c5f8e67c4"
  instance_type        = "t2.micro"
  subnet_id            = module.vpc_oregon.public_subnets[0]
  key_name             = "BaseKeyAcces"
  security_group_ids   = [aws_security_group.instance_sg_oregon.id]
  user_data            = <<-EOF
                          #!/bin/bash
                          echo "Hello, World from Oregon!" > /var/www/html/index.html
                          yum install -y httpd
                          systemctl start httpd
                          systemctl enable httpd
                          EOF
  tags = {
    Name = "WebInstanceOregon"
  }
  depends_on = [aws_security_group.instance_sg_oregon]
}
