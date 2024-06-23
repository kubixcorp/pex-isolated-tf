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
  //private_subnet_cidrs = var.vpc_virginia_private_subnets
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
  //private_subnet_cidrs = var.vpc_oregon_private_subnets
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

data "aws_elb_service_account" "main" {}
# Crear el bucket de S3 para los logs del ALB
resource "aws_s3_bucket" "alb_logs_virginia" {
  provider      = aws.virginia
  bucket        = "alb-logs-isolated-virginia"
  force_destroy = true
  tags = {
    Name = "ALB Logs Bucket Virginia"
  }
}

resource "aws_s3_bucket" "alb_logs_oregon" {
  provider      = aws.oregon
  bucket        = "alb-logs-isolated-oregon"
  force_destroy = true
  tags = {
    Name = "ALB Logs Bucket Oregon"
  }
}

resource "aws_s3_bucket_policy" "alb_logs_virginia_policy" {
  provider = aws.virginia
  bucket   = aws_s3_bucket.alb_logs_virginia.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::127311923021:root"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs_virginia.arn}/*"
      },
      {
        Effect = "Allow"
        Principal = {
          AWS = data.aws_elb_service_account.main.arn
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs_virginia.arn}/*"
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "alb_logs_oregon_policy" {
  provider = aws.oregon
  bucket   = aws_s3_bucket.alb_logs_oregon.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::127311923021:root"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs_oregon.arn}/*"
      }
    ]
  })
}
# Crear ALBs después de los VPCs y Subnets
module "alb_virginia" {
  source = "./modules/alb"
  providers = {
    aws = aws.virginia
  }
  name                       = "alb-virginia"
  internal                   = false
  security_groups = [aws_security_group.alb_sg_virginia.id]
  subnets                    = module.vpc_virginia.public_subnets
  enable_deletion_protection = false
  target_group_name          = "tg-virginia"
  target_group_port          = 80
  vpc_id                     = module.vpc_virginia.vpc_id
  certificate_arn            = var.certificate_arn_virginia
  access_logs_bucket         = aws_s3_bucket.alb_logs_virginia.bucket
  tags = {
    Name = "ALB Virginia"
  }
}

module "alb_oregon" {
  source = "./modules/alb"
  providers = {
    aws = aws.oregon
  }
  name                       = "alb-oregon"
  internal                   = false
  security_groups = [aws_security_group.alb_sg_oregon.id]
  subnets                    = module.vpc_oregon.public_subnets
  enable_deletion_protection = false
  target_group_name          = "tg-oregon"
  target_group_port          = 80
  vpc_id                     = module.vpc_oregon.vpc_id
  certificate_arn            = var.certificate_arn_oregon
  access_logs_bucket         = aws_s3_bucket.alb_logs_oregon.bucket
  tags = {
    Name = "ALB Oregon"
  }
}

# Crear los Security Groups
resource "aws_security_group" "alb_sg_virginia" {
  provider = aws.virginia
  vpc_id   = module.vpc_virginia.vpc_id

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
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
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
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
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
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
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
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
  ami           = "ami-04e8b3e527208c8cf"
  instance_type = "t2.micro"
  subnet_id     = module.vpc_virginia.public_subnets[0]
  key_name      = "BaseKeyAcces"
  security_group_ids = [aws_security_group.instance_sg_virginia.id]
  user_data = templatefile("${path.module}/scripts/web_instance_data.sh", {
    region = "Virginia"
  })
  tags = {
    Name = "WebInstanceVirginia"
  }
  depends_on = [aws_security_group.instance_sg_virginia]
}

resource "aws_lb_target_group_attachment" "virginia" {
  provider         = aws.virginia
  target_group_arn = module.alb_virginia.target_group_arn
  target_id        = module.web_instance_virginia.instance_id
  port             = 80
}

module "web_instance_oregon" {
  source = "./modules/ec2"
  providers = {
    aws = aws.oregon
  }
  ami           = "ami-0676a735c5f8e67c4"
  instance_type = "t2.micro"
  subnet_id     = module.vpc_oregon.public_subnets[0]
  key_name      = "BaseKeyAcces"
  security_group_ids = [aws_security_group.instance_sg_oregon.id]
  user_data = templatefile("${path.module}/scripts/web_instance_data.sh", {
    region = "Oregon"
  })
  tags = {
    Name = "WebInstanceOregon"
  }
  depends_on = [aws_security_group.instance_sg_oregon]
}

resource "aws_lb_target_group_attachment" "oregon" {
  provider         = aws.oregon
  target_group_arn = module.alb_oregon.target_group_arn
  target_id        = module.web_instance_oregon.instance_id
  port             = 80
}
