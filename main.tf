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

# Agregar el balanceador de carga de tipo aplicación (ALB) en Virginia
resource "aws_security_group" "alb_sg_virginia" {
  provider    = aws.virginia
  name_prefix = "alb-sg"
  description = "Security group for ALB in Virginia"
  vpc_id      = module.vpc_virginia.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

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
}

resource "aws_security_group" "alb_sg_oregon" {
  provider    = aws.oregon
  name_prefix = "alb-sg"
  description = "Security group for ALB in Oregon"
  vpc_id      = module.vpc_oregon.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

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
}

module "alb_virginia" {
  source = "./modules/alb"
  providers = {
    aws = aws.virginia
  }

  name                       = "my-alb-virginia"
  internal                   = false
  security_groups            = [aws_security_group.alb_sg_virginia.id]
  subnets                    = module.vpc_virginia.public_subnets
  enable_deletion_protection = false
  tags                       = { Environment = "production" }
  target_group_name          = "my-target-group-virginia"
  target_group_port          = 80
  vpc_id                     = module.vpc_virginia.vpc_id
  certificate_arn            = var.certificate_arn_virginia
}

module "alb_oregon" {
  source = "./modules/alb"
  providers = {
    aws = aws.oregon
  }

  name                       = "my-alb-oregon"
  internal                   = false
  security_groups            = [aws_security_group.alb_sg_oregon.id]
  subnets                    = module.vpc_oregon.public_subnets
  enable_deletion_protection = false
  tags                       = { Environment = "production" }
  target_group_name          = "my-target-group-oregon"
  target_group_port          = 80
  vpc_id                     = module.vpc_oregon.vpc_id
  certificate_arn            = var.certificate_arn_oregon
}

# Grupo de seguridad para instancias en Virginia
resource "aws_security_group" "instance_sg_virginia" {
  provider    = aws.virginia
  name_prefix = "instance-sg"
  description = "Security group for instances in Virginia"
  vpc_id      = module.vpc_virginia.vpc_id

  # Permitir tráfico HTTP desde el ALB
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  # Permitir tráfico HTTPS desde el ALB (si es necesario)
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  # Regla de salida para todo el tráfico
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Grupo de seguridad para instancias en Oregón
resource "aws_security_group" "instance_sg_oregon" {
  provider    = aws.oregon
  name_prefix = "instance-sg"
  description = "Security group for instances in Oregon"
  vpc_id      = module.vpc_oregon.vpc_id

  # Permitir tráfico HTTP desde el ALB
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  # Permitir tráfico HTTPS desde el ALB (si es necesario)
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  # Regla de salida para todo el tráfico
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Instancia web simple en Virginia
resource "aws_instance" "web_instance_virginia" {
  provider = aws.virginia
  ami           = "ami-04e8b3e527208c8cf" # AMI de Amazon Linux 2 para us-east-1
  instance_type = "t2.micro"
  subnet_id     = module.vpc_virginia.public_subnets[0]

  vpc_security_group_ids = [aws_security_group.instance_sg_virginia.id]

  user_data = <<-EOF
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

# Instancia web simple en Oregón
resource "aws_instance" "web_instance_oregon" {
  provider = aws.oregon
  ami           = "ami-0676a735c5f8e67c4" # AMI de Amazon Linux 2 para us-west-2
  instance_type = "t2.micro"
  subnet_id     = module.vpc_oregon.public_subnets[0]

  vpc_security_group_ids = [aws_security_group.instance_sg_oregon.id]

  user_data = <<-EOF
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
