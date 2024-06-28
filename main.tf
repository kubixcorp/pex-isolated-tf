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

provider "aws" {
  alias   = "route53"
  region  = var.vpc_virginia_region
  profile = var.aws_profile_route53
}
# VPCs, Subnets
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
# Transit Gateways, VPCs, Subnets
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
# Transit Gateway and route
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
# BucketS3  logs to ALB
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
          AWS = data.aws_elb_service_account.main.arn
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs_oregon.arn}/*"
      }
    ]
  })
}

resource "aws_wafv2_ip_set" "allowed_ips_virginia" {
  provider           = aws.virginia
  name               = "allowed-ips-virginia"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.allowed_ips
}

resource "aws_wafv2_ip_set" "allowed_ips_oregon" {
  provider           = aws.oregon
  name               = "allowed-ips-oregon"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.allowed_ips
}

resource "aws_wafv2_web_acl" "web_acl_virginia" {
  provider    = aws.virginia
  name        = "alb-web-acl-virginia"
  scope       = "REGIONAL"
  description = "Web ACL to allow specific IPs"

  default_action {
    block {}
  }

  rule {
    name     = "allow-specific-ips-virginia"
    priority = 1

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.allowed_ips_virginia.arn
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "allow-specific-ips-virginia"
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "web-acl-metrics-virginia"
    sampled_requests_enabled   = true
  }
  depends_on = [aws_wafv2_ip_set.allowed_ips_virginia]
}

resource "aws_wafv2_web_acl" "web_acl_oregon" {
  provider    = aws.oregon
  name        = "alb-web-acl-oregon"
  scope       = "REGIONAL"
  description = "Web ACL to allow specific IPs"

  default_action {
    block {}
  }

  rule {
    name     = "allow-specific-ips-oregon"
    priority = 1

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.allowed_ips_oregon.arn
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "allow-specific-ips-oregon"
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "web-acl-metrics-oregon"
    sampled_requests_enabled   = true
  }
  depends_on = [aws_wafv2_ip_set.allowed_ips_oregon]
}

module "alb_virginia" {
  source = "./modules/alb"
  providers = {
    aws = aws.virginia
  }
  name                       = "alb-virginia"
  internal                   = false
  security_groups            = [aws_security_group.alb_sg_virginia.id]
  subnets                    = module.vpc_virginia.public_subnets
  enable_deletion_protection = false
  target_group_name          = "tg-virginia"
  target_group_port          = 80
  vpc_id                     = module.vpc_virginia.vpc_id
  certificate_arn            = var.certificate_arn_virginia
  access_logs_bucket         = aws_s3_bucket.alb_logs_virginia.bucket
  enable_access_logs         = true
  tags = {
    Name = "ALB Virginia"
  }
  depends_on = [aws_wafv2_web_acl.web_acl_virginia]

}

resource "aws_wafv2_web_acl_association" "web_acl_association_virginia" {
  provider     = aws.virginia
  resource_arn = module.alb_virginia.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.web_acl_virginia.arn
  depends_on   = [module.alb_virginia, aws_wafv2_web_acl.web_acl_virginia]
}

module "alb_oregon" {
  source = "./modules/alb"
  providers = {
    aws = aws.oregon
  }
  name                       = "alb-oregon"
  internal                   = false
  security_groups            = [aws_security_group.alb_sg_oregon.id]
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
  depends_on = [aws_wafv2_web_acl.web_acl_oregon]
}

resource "aws_wafv2_web_acl_association" "web_acl_association_oregon" {
  provider     = aws.oregon
  resource_arn = module.alb_oregon.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.web_acl_oregon.arn
  depends_on   = [module.alb_oregon, aws_wafv2_web_acl.web_acl_oregon]
}
/* Security Groups */
resource "aws_security_group" "alb_sg_virginia" {
  provider    = aws.virginia
  name        = "alb_sg_virginia"
  description = "ALB Security Group Virginia"
  vpc_id      = module.vpc_virginia.vpc_id

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
  provider    = aws.oregon
  name        = "alb_sg_oregon"
  description = "ALB Security Group Oregon"
  vpc_id      = module.vpc_oregon.vpc_id

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
/* IAM Role and Instance Profile */
resource "aws_iam_role" "ssm_role" {
  provider = aws.virginia
  name     = "ssm_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action = "sts:AssumeRole",
        Sid    = "AllowEC2AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_attach" {
  provider   = aws.virginia
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm_instance_profile" {
  provider = aws.virginia
  name     = "my_ssm_instance_profile"
  role     = aws_iam_role.ssm_role.name
}
/* IAM Role and Instance Profile */
/* Instances Bastion Virginia */
resource "aws_security_group" "bastion_sg_virginia" {
  provider    = aws.virginia
  name        = "bastion_sg_virginia"
  description = "Allow SSH traffic"
  vpc_id      = module.vpc_virginia.vpc_id

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
    Name = "Bastion SG Virginia"
  }
}

resource "aws_instance" "bastion_virginia" {
  provider               = aws.virginia
  ami                    = "ami-04e8b3e527208c8cf"
  instance_type          = "t2.micro"
  subnet_id              = module.vpc_virginia.public_subnets[0]
  key_name               = "BaseKeyAcces"
  vpc_security_group_ids = [aws_security_group.bastion_sg_virginia.id]
  user_data = templatefile("${path.module}/scripts/bastion_utils.sh", {
    region = "Virginia"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  tags = {
    Name = "Bastion Virginia"
  }
  depends_on = [aws_security_group.bastion_sg_virginia, aws_iam_instance_profile.ssm_instance_profile]
}
/* Instances Bastion Virginia */
/* Instances Bastion Oregon */
resource "aws_security_group" "bastion_sg_oregon" {
  provider    = aws.oregon
  name        = "oregon_sg_virginia"
  description = "Allow SSH traffic"
  vpc_id      = module.vpc_oregon.vpc_id

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
    Name = "Bastion SG Oregon"
  }
}

resource "aws_instance" "bastion_oregon" {
  provider               = aws.oregon
  ami                    = "ami-0676a735c5f8e67c4"
  instance_type          = "t2.micro"
  subnet_id              = module.vpc_oregon.public_subnets[0]
  key_name               = "BaseKeyAcces"
  vpc_security_group_ids = [aws_security_group.bastion_sg_oregon.id]
  user_data = templatefile("${path.module}/scripts/bastion_utils.sh", {
    region = "Oregon"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  tags = {
    Name = "Bastion Oregon"
  }
  depends_on = [aws_security_group.bastion_sg_oregon, aws_iam_instance_profile.ssm_instance_profile]
}
/* Instances Bastion Oregon */
/* GitLab Virginia */
resource "aws_security_group" "gitlab_sg_virginia" {
  provider    = aws.virginia
  name        = "gitlab_sg_virginia"
  description = "Allow HTTP, HTTPS and SSH traffic"
  vpc_id      = module.vpc_virginia.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "GitLab SG Virginia"
  }
}

resource "aws_instance" "gitlab_virginia" {
  provider               = aws.virginia
  ami                    = "ami-0c2926c986c7eb348"
  instance_type          = "c5.xlarge"
  key_name               = "BaseKeyAcces"
  subnet_id              = module.vpc_virginia.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.gitlab_sg_virginia.id]
  user_data = templatefile("${path.module}/scripts/gitlab_utils.sh", {
    region = "Virginia"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  root_block_device {
    volume_type = "gp3"
    volume_size = 40
  }

  tags = {
    Name = "GitLab Virginia"
  }
  depends_on = [aws_security_group.gitlab_sg_virginia, aws_iam_instance_profile.ssm_instance_profile]
}

resource "aws_lb_target_group" "gitlab_tg_virginia" {
  name     = "gitlab-tg-virginia"
  provider = aws.virginia
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_virginia.vpc_id
  health_check {
    path     = "/users/sign_in"
    interval = 30
    timeout  = 5
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "gitlab_rule_virginia" {
  provider     = aws.virginia
  tags         = { Name = "gitlab_rule_virginia" }
  listener_arn = module.alb_virginia.alb_listener_https_arn
  priority     = 20

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gitlab_tg_virginia.arn
  }

  condition {
    host_header {
      values = ["gitlab.isolated-virginia.kubixcorp.com"]
    }
  }
}

resource "aws_lb_target_group_attachment" "gitlab_attachment_virginia" {
  provider         = aws.virginia
  target_group_arn = aws_lb_target_group.gitlab_tg_virginia.arn
  target_id        = aws_instance.gitlab_virginia.id
  port             = 80
  depends_on       = [aws_lb_target_group.gitlab_tg_virginia, aws_instance.gitlab_virginia]
}

resource "aws_route53_record" "gitlab_dns_virginia" {
  provider = aws.route53
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "gitlab.isolated-virginia.kubixcorp.com"
  type     = "A"
  alias {
    name                   = module.alb_virginia.alb_dns_name
    zone_id                = module.alb_virginia.alb_zone_id
    evaluate_target_health = true
  }
}
/* GitLab Virginia */
/* GitLab Oregon */
resource "aws_security_group" "gitlab_sg_oregon" {
  provider    = aws.oregon
  name        = "gitlab_sg_oregon"
  description = "Allow HTTP, HTTPS and SSH traffic"
  vpc_id      = module.vpc_oregon.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "GitLab SG Oregon"
  }
}

resource "aws_instance" "gitlab_oregon" {
  provider               = aws.oregon
  ami                    = "ami-0e6cc701211a663f2"
  instance_type          = "c5.xlarge"
  key_name               = "BaseKeyAcces"
  subnet_id              = module.vpc_oregon.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.gitlab_sg_oregon.id]
  user_data = templatefile("${path.module}/scripts/gitlab_utils.sh", {
    region = "Oregon"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  root_block_device {
    volume_type = "gp3"
    volume_size = 40
  }

  tags = {
    Name = "GitLab Oregon"
  }
  depends_on = [aws_security_group.gitlab_sg_oregon, aws_iam_instance_profile.ssm_instance_profile]
}

resource "aws_lb_target_group" "gitlab_tg_oregon" {
  name     = "gitlab-tg-oregon"
  provider = aws.oregon
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_oregon.vpc_id
  health_check {
    path     = "/users/sign_in"
    interval = 30
    timeout  = 5
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "gitlab_rule_oregon" {
  provider     = aws.oregon
  tags         = { Name = "gitlab_rule_oregon" }
  listener_arn = module.alb_oregon.alb_listener_https_arn
  priority     = 20

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gitlab_tg_oregon.arn
  }

  condition {
    host_header {
      values = ["gitlab.isolated-oregon.kubixcorp.com"]
    }
  }
}

resource "aws_lb_target_group_attachment" "gitlab_attachment_oregon" {
  provider         = aws.oregon
  target_group_arn = aws_lb_target_group.gitlab_tg_oregon.arn
  target_id        = aws_instance.gitlab_oregon.id
  port             = 80
  depends_on       = [aws_lb_target_group.gitlab_tg_oregon, aws_instance.gitlab_oregon]
}

resource "aws_route53_record" "gitlab_dns_oregon" {
  provider = aws.route53
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "gitlab.isolated-oregon.kubixcorp.com"
  type     = "A"
  alias {
    name                   = module.alb_oregon.alb_dns_name
    zone_id                = module.alb_oregon.alb_zone_id
    evaluate_target_health = true
  }
}
/* GitLab Oregon */
/* Jasper Virginia */
resource "aws_security_group" "jasper_sg_virginia" {
  provider    = aws.virginia
  name        = "jasper_sg_virginia"
  description = "Allow HTTP, HTTPS and SSH traffic"
  vpc_id      = module.vpc_virginia.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "Jasper SG Virginia"
  }
}

resource "aws_instance" "jasper_virginia" {
  provider               = aws.virginia
  ami                    = "ami-04e8b3e527208c8cf"
  instance_type          = "c5.xlarge"
  key_name               = "BaseKeyAcces"
  subnet_id              = module.vpc_virginia.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.jasper_sg_virginia.id]
  user_data = templatefile("${path.module}/scripts/jasper_utils.sh", {
    region = "Virginia"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  root_block_device {
    volume_type = "gp3"
    volume_size = 40
  }

  tags = {
    Name = "Jasper Virginia"
  }
  depends_on = [aws_security_group.jasper_sg_virginia, aws_iam_instance_profile.ssm_instance_profile]
}

resource "aws_lb_target_group" "jasper_tg_virginia" {
  name     = "jasper-tg-virginia"
  provider = aws.virginia
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_virginia.vpc_id
  health_check {
    port = "88"
    path     = "/"
    interval = 30
    timeout  = 5
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "jasper_rule_virginia" {
  provider     = aws.virginia
  tags         = { Name = "jasper_rule_virginia" }
  listener_arn = module.alb_virginia.alb_listener_https_arn
  priority     = 19

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.jasper_tg_virginia.arn
  }

  condition {
    host_header {
      values = ["reports.isolated-virginia.kubixcorp.com"]
    }
  }
}

resource "aws_lb_target_group_attachment" "jasper_attachment_virginia" {
  provider         = aws.virginia
  target_group_arn = aws_lb_target_group.jasper_tg_virginia.arn
  target_id        = aws_instance.jasper_virginia.id
  port             = 80
  depends_on       = [aws_lb_target_group.jasper_tg_virginia, aws_instance.jasper_virginia]
}

resource "aws_route53_record" "jasper_dns_virginia" {
  provider = aws.route53
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "reports.isolated-virginia.kubixcorp.com"
  type     = "A"
  alias {
    name                   = module.alb_virginia.alb_dns_name
    zone_id                = module.alb_virginia.alb_zone_id
    evaluate_target_health = true
  }
}
/* Jasper Virginia */
/* Jasper Oregon */
resource "aws_security_group" "jasper_sg_oregon" {
  provider    = aws.oregon
  name        = "jasper_sg_oregon"
  description = "Allow HTTP, HTTPS and SSH traffic"
  vpc_id      = module.vpc_oregon.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "Jasper SG Oregon"
  }
}

resource "aws_instance" "jasper_oregon" {
  provider               = aws.oregon
  ami                    = "ami-0676a735c5f8e67c4"
  instance_type          = "c5.xlarge"
  key_name               = "BaseKeyAcces"
  subnet_id              = module.vpc_oregon.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.jasper_sg_oregon.id]
  user_data = templatefile("${path.module}/scripts/jasper_utils.sh", {
    region = "Oregon"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  root_block_device {
    volume_type = "gp3"
    volume_size = 40
  }

  tags = {
    Name = "Jasper Oregon"
  }
  depends_on = [aws_security_group.jasper_sg_oregon, aws_iam_instance_profile.ssm_instance_profile]
}

resource "aws_lb_target_group" "jasper_tg_oregon" {
  name     = "jasper-tg-oregon"
  provider = aws.oregon
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_oregon.vpc_id
  health_check {
    port = "88"
    path     = "/"
    interval = 30
    timeout  = 5
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "jasper_rule_oregon" {
  provider     = aws.oregon
  tags         = { Name = "jasper_rule_oregon" }
  listener_arn = module.alb_oregon.alb_listener_https_arn
  priority     = 19

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.jasper_tg_oregon.arn
  }

  condition {
    host_header {
      values = ["reports.isolated-oregon.kubixcorp.com"]
    }
  }
}

resource "aws_lb_target_group_attachment" "jasper_attachment_oregon" {
  provider         = aws.oregon
  target_group_arn = aws_lb_target_group.jasper_tg_oregon.arn
  target_id        = aws_instance.jasper_oregon.id
  port             = 80
  depends_on       = [aws_lb_target_group.jasper_tg_oregon, aws_instance.jasper_oregon]
}

resource "aws_route53_record" "jasper_dns_oregon" {
  provider = aws.route53
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "reports.isolated-oregon.kubixcorp.com"
  type     = "A"
  alias {
    name                   = module.alb_oregon.alb_dns_name
    zone_id                = module.alb_oregon.alb_zone_id
    evaluate_target_health = true
  }
}
/* Jasper Oregon */
/* Pentaho Virginia */
resource "aws_security_group" "pentaho_sg_virginia" {
  provider    = aws.virginia
  name        = "pentaho_sg_virginia"
  description = "Allow HTTP, HTTPS and SSH traffic"
  vpc_id      = module.vpc_virginia.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "Pentaho SG Virginia"
  }
}

resource "aws_instance" "pentaho_virginia" {
  provider               = aws.virginia
  ami                    = "ami-04e8b3e527208c8cf"
  instance_type          = "c5.xlarge"
  key_name               = "BaseKeyAcces"
  subnet_id              = module.vpc_virginia.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.pentaho_sg_virginia.id]
  user_data = templatefile("${path.module}/scripts/pentaho_utils.sh", {
    region = "Virginia"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  root_block_device {
    volume_type = "gp3"
    volume_size = 40
  }

  tags = {
    Name = "Pentaho Virginia"
  }
  depends_on = [aws_security_group.pentaho_sg_virginia, aws_iam_instance_profile.ssm_instance_profile]
}

resource "aws_lb_target_group" "pentaho_tg_virginia" {
  name     = "pentaho-tg-virginia"
  provider = aws.virginia
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_virginia.vpc_id
  health_check {
    port = "88"
    path     = "/"
    interval = 30
    timeout  = 5
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "pentaho_rule_virginia" {
  provider     = aws.virginia
  tags         = { Name = "pentaho_rule_virginia" }
  listener_arn = module.alb_virginia.alb_listener_https_arn
  priority     = 18

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.pentaho_tg_virginia.arn
  }

  condition {
    host_header {
      values = ["pentaho.isolated-virginia.kubixcorp.com"]
    }
  }
}

resource "aws_lb_target_group_attachment" "pentaho_attachment_virginia" {
  provider         = aws.virginia
  target_group_arn = aws_lb_target_group.pentaho_tg_virginia.arn
  target_id        = aws_instance.pentaho_virginia.id
  port             = 80
  depends_on       = [aws_lb_target_group.pentaho_tg_virginia, aws_instance.pentaho_virginia]
}

resource "aws_route53_record" "pentaho_dns_virginia" {
  provider = aws.route53
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "pentaho.isolated-virginia.kubixcorp.com"
  type     = "A"
  alias {
    name                   = module.alb_virginia.alb_dns_name
    zone_id                = module.alb_virginia.alb_zone_id
    evaluate_target_health = true
  }
}
/* Pentaho Virginia */
/* Pentaho Oregon */
resource "aws_security_group" "pentaho_sg_oregon" {
  provider    = aws.oregon
  name        = "pentaho_sg_oregon"
  description = "Allow HTTP, HTTPS and SSH traffic"
  vpc_id      = module.vpc_oregon.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "Pentaho SG Oregon"
  }
}

resource "aws_instance" "pentaho_oregon" {
  provider               = aws.oregon
  ami                    = "ami-0676a735c5f8e67c4"
  instance_type          = "c5.xlarge"
  key_name               = "BaseKeyAcces"
  subnet_id              = module.vpc_oregon.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.pentaho_sg_oregon.id]
  user_data = templatefile("${path.module}/scripts/pentaho_utils.sh", {
    region = "Oregon"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  root_block_device {
    volume_type = "gp3"
    volume_size = 40
  }

  tags = {
    Name = "Pentaho Oregon"
  }
  depends_on = [aws_security_group.pentaho_sg_oregon, aws_iam_instance_profile.ssm_instance_profile]
}

resource "aws_lb_target_group" "pentaho_tg_oregon" {
  name     = "pentaho-tg-oregon"
  provider = aws.oregon
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_oregon.vpc_id
  health_check {
    port = "88"
    path     = "/"
    interval = 30
    timeout  = 5
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "pentaho_rule_oregon" {
  provider     = aws.oregon
  tags         = { Name = "pentaho_rule_oregon" }
  listener_arn = module.alb_oregon.alb_listener_https_arn
  priority     = 18

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.pentaho_tg_oregon.arn
  }

  condition {
    host_header {
      values = ["pentaho.isolated-oregon.kubixcorp.com"]
    }
  }
}

resource "aws_lb_target_group_attachment" "pentaho_attachment_oregon" {
  provider         = aws.oregon
  target_group_arn = aws_lb_target_group.pentaho_tg_oregon.arn
  target_id        = aws_instance.pentaho_oregon.id
  port             = 80
  depends_on       = [aws_lb_target_group.pentaho_tg_oregon, aws_instance.pentaho_oregon]
}

resource "aws_route53_record" "pentaho_dns_oregon" {
  provider = aws.route53
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "pentaho.isolated-oregon.kubixcorp.com"
  type     = "A"
  alias {
    name                   = module.alb_oregon.alb_dns_name
    zone_id                = module.alb_oregon.alb_zone_id
    evaluate_target_health = true
  }
}
/* Pentaho Oregon */
/* SonarQube Virginia */
resource "aws_security_group" "sonarqube_sg_virginia" {
  provider    = aws.virginia
  name        = "sonarqube_sg_virginia"
  description = "Allow HTTP, HTTPS and SSH traffic"
  vpc_id      = module.vpc_virginia.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "SonarQube SG Virginia"
  }
}

resource "aws_instance" "sonarqube_virginia" {
  provider               = aws.virginia
  ami                    = "ami-04e8b3e527208c8cf"
  instance_type          = "c5.xlarge"
  key_name               = "BaseKeyAcces"
  subnet_id              = module.vpc_virginia.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.sonarqube_sg_virginia.id]
  user_data = templatefile("${path.module}/scripts/sonarqube_utils.sh", {
    region = "Virginia"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  root_block_device {
    volume_type = "gp3"
    volume_size = 40
  }

  tags = {
    Name = "SonarQube Virginia"
  }
  depends_on = [aws_security_group.sonarqube_sg_virginia, aws_iam_instance_profile.ssm_instance_profile]
}

resource "aws_lb_target_group" "sonarqube_tg_virginia" {
  name     = "sonarqube-tg-virginia"
  provider = aws.virginia
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_virginia.vpc_id
  health_check {
    port = "88"
    path     = "/"
    interval = 30
    timeout  = 5
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "sonarqube_rule_virginia" {
  provider     = aws.virginia
  tags         = { Name = "sonarqube_rule_virginia" }
  listener_arn = module.alb_virginia.alb_listener_https_arn
  priority     = 17

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.sonarqube_tg_virginia.arn
  }

  condition {
    host_header {
      values = ["sonarqube.isolated-virginia.kubixcorp.com"]
    }
  }
}

resource "aws_lb_target_group_attachment" "sonarqube_attachment_virginia" {
  provider         = aws.virginia
  target_group_arn = aws_lb_target_group.sonarqube_tg_virginia.arn
  target_id        = aws_instance.sonarqube_virginia.id
  port             = 80
  depends_on       = [aws_lb_target_group.sonarqube_tg_virginia, aws_instance.sonarqube_virginia]
}

resource "aws_route53_record" "sonarqube_dns_virginia" {
  provider = aws.route53
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "sonarqube.isolated-virginia.kubixcorp.com"
  type     = "A"
  alias {
    name                   = module.alb_virginia.alb_dns_name
    zone_id                = module.alb_virginia.alb_zone_id
    evaluate_target_health = true
  }
}
/* SonarQube Virginia */
/* SonarQube Oregon */
resource "aws_security_group" "sonarqube_sg_oregon" {
  provider    = aws.oregon
  name        = "sonarqube_sg_oregon"
  description = "Allow HTTP, HTTPS and SSH traffic"
  vpc_id      = module.vpc_oregon.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "SonarQube SG Oregon"
  }
}

resource "aws_instance" "sonarqube_oregon" {
  provider               = aws.oregon
  ami                    = "ami-0676a735c5f8e67c4"
  instance_type          = "c5.xlarge"
  key_name               = "BaseKeyAcces"
  subnet_id              = module.vpc_oregon.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.sonarqube_sg_oregon.id]
  user_data = templatefile("${path.module}/scripts/sonarqube_utils.sh", {
    region = "Oregon"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  root_block_device {
    volume_type = "gp3"
    volume_size = 40
  }

  tags = {
    Name = "SonarQube Oregon"
  }
  depends_on = [aws_security_group.sonarqube_sg_oregon, aws_iam_instance_profile.ssm_instance_profile]
}

resource "aws_lb_target_group" "sonarqube_tg_oregon" {
  name     = "sonarqube-tg-oregon"
  provider = aws.oregon
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_oregon.vpc_id
  health_check {
    port = "88"
    path     = "/"
    interval = 30
    timeout  = 5
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "sonarqube_rule_oregon" {
  provider     = aws.oregon
  tags         = { Name = "sonarqube_rule_oregon" }
  listener_arn = module.alb_oregon.alb_listener_https_arn
  priority     = 17

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.sonarqube_tg_oregon.arn
  }

  condition {
    host_header {
      values = ["sonarqube.isolated-oregon.kubixcorp.com"]
    }
  }
}

resource "aws_lb_target_group_attachment" "sonarqube_attachment_oregon" {
  provider         = aws.oregon
  target_group_arn = aws_lb_target_group.sonarqube_tg_oregon.arn
  target_id        = aws_instance.sonarqube_oregon.id
  port             = 80
  depends_on       = [aws_lb_target_group.sonarqube_tg_oregon, aws_instance.sonarqube_oregon]
}

resource "aws_route53_record" "sonarqube_dns_oregon" {
  provider = aws.route53
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "sonarqube.isolated-oregon.kubixcorp.com"
  type     = "A"
  alias {
    name                   = module.alb_oregon.alb_dns_name
    zone_id                = module.alb_oregon.alb_zone_id
    evaluate_target_health = true
  }
}
/* SonarQube Oregon */
/* Monitor Virginia */
resource "aws_security_group" "monitor_sg_virginia" {
  provider    = aws.virginia
  name        = "monitor_sg_virginia"
  description = "Allow HTTP, HTTPS and SSH traffic"
  vpc_id      = module.vpc_virginia.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "Monitor SG Virginia"
  }
}

resource "aws_instance" "monitor_virginia" {
  provider               = aws.virginia
  ami                    = "ami-09634e8f6f4163b0e"
  instance_type          = "c5.xlarge"
  key_name               = "BaseKeyAcces"
  subnet_id              = module.vpc_virginia.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.monitor_sg_virginia.id]
  user_data = templatefile("${path.module}/scripts/monitor_utils.sh", {
    region = "Virginia"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  root_block_device {
    volume_type = "gp3"
    volume_size = 40
  }

  tags = {
    Name = "Monitor Virginia"
  }
  depends_on = [aws_security_group.monitor_sg_virginia, aws_iam_instance_profile.ssm_instance_profile]
}

resource "aws_lb_target_group" "monitor_tg_virginia" {
  name     = "monitor-tg-virginia"
  provider = aws.virginia
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_virginia.vpc_id
  health_check {
    port = "88"
    path     = "/"
    interval = 30
    timeout  = 5
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "monitor_rule_virginia" {
  provider     = aws.virginia
  tags         = { Name = "monitor_rule_virginia" }
  listener_arn = module.alb_virginia.alb_listener_https_arn
  priority     = 16

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.monitor_tg_virginia.arn
  }

  condition {
    host_header {
      values = ["monitor.isolated-virginia.kubixcorp.com"]
    }
  }
}

resource "aws_lb_target_group_attachment" "monitor_attachment_virginia" {
  provider         = aws.virginia
  target_group_arn = aws_lb_target_group.monitor_tg_virginia.arn
  target_id        = aws_instance.monitor_virginia.id
  port             = 80
  depends_on       = [aws_lb_target_group.monitor_tg_virginia, aws_instance.monitor_virginia]
}

resource "aws_route53_record" "monitor_dns_virginia" {
  provider = aws.route53
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "monitor.isolated-virginia.kubixcorp.com"
  type     = "A"
  alias {
    name                   = module.alb_virginia.alb_dns_name
    zone_id                = module.alb_virginia.alb_zone_id
    evaluate_target_health = true
  }
}
/* Monitor Virginia */
/* Monitor Oregon */
resource "aws_security_group" "monitor_sg_oregon" {
  provider    = aws.oregon
  name        = "monitor_sg_oregon"
  description = "Allow HTTP, HTTPS and SSH traffic"
  vpc_id      = module.vpc_oregon.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "Monitor SG Oregon"
  }
}

resource "aws_instance" "monitor_oregon" {
  provider               = aws.oregon
  ami                    = "ami-0fff21d6d6b6003b0"
  instance_type          = "c5.xlarge"
  key_name               = "BaseKeyAcces"
  subnet_id              = module.vpc_oregon.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.monitor_sg_oregon.id]
  user_data = templatefile("${path.module}/scripts/monitor_utils.sh", {
    region = "Oregon"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  root_block_device {
    volume_type = "gp3"
    volume_size = 40
  }

  tags = {
    Name = "Monitor Oregon"
  }
  depends_on = [aws_security_group.monitor_sg_oregon, aws_iam_instance_profile.ssm_instance_profile]
}

resource "aws_lb_target_group" "monitor_tg_oregon" {
  name     = "monitor-tg-oregon"
  provider = aws.oregon
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_oregon.vpc_id
  health_check {
    port = "88"
    path     = "/"
    interval = 30
    timeout  = 5
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "monitor_rule_oregon" {
  provider     = aws.oregon
  tags         = { Name = "monitor_rule_oregon" }
  listener_arn = module.alb_oregon.alb_listener_https_arn
  priority     = 16

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.monitor_tg_oregon.arn
  }

  condition {
    host_header {
      values = ["monitor.isolated-oregon.kubixcorp.com"]
    }
  }
}

resource "aws_lb_target_group_attachment" "monitor_attachment_oregon" {
  provider         = aws.oregon
  target_group_arn = aws_lb_target_group.monitor_tg_oregon.arn
  target_id        = aws_instance.monitor_oregon.id
  port             = 80
  depends_on       = [aws_lb_target_group.monitor_tg_oregon, aws_instance.monitor_oregon]
}

resource "aws_route53_record" "monitor_dns_oregon" {
  provider = aws.route53
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "monitor.isolated-oregon.kubixcorp.com"
  type     = "A"
  alias {
    name                   = module.alb_oregon.alb_dns_name
    zone_id                = module.alb_oregon.alb_zone_id
    evaluate_target_health = true
  }
}
/* Monitor Oregon */
/* OpenVPN Virginia */
resource "aws_security_group" "openvpn_sg_virginia" {
  provider    = aws.virginia
  name        = "openvpn_sg_virginia"
  description = "Allow HTTP, HTTPS and SSH traffic"
  vpc_id      = module.vpc_virginia.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "OpenVPN SG Virginia"
  }
}

resource "aws_instance" "openvpn_virginia" {
  provider               = aws.virginia
  ami                    = "ami-095f86ec226de8b8e"
  instance_type          = "c5.xlarge"
  key_name               = "BaseKeyAcces"
  subnet_id              = module.vpc_virginia.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.openvpn_sg_virginia.id]
  user_data = templatefile("${path.module}/scripts/openvpn_utils.sh", {
    region = "Virginia"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  root_block_device {
    volume_type = "gp3"
    volume_size = 40
  }

  tags = {
    Name = "OpenVPN Virginia"
  }
  depends_on = [aws_security_group.openvpn_sg_virginia, aws_iam_instance_profile.ssm_instance_profile]
}

resource "aws_lb_target_group" "openvpn_tg_virginia" {
  name     = "openvpn-tg-virginia"
  provider = aws.virginia
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_virginia.vpc_id
  health_check {
    port = "88"
    path     = "/"
    interval = 30
    timeout  = 5
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "openvpn_rule_virginia" {
  provider     = aws.virginia
  tags         = { Name = "openvpn_rule_virginia" }
  listener_arn = module.alb_virginia.alb_listener_https_arn
  priority     = 15

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.openvpn_tg_virginia.arn
  }

  condition {
    host_header {
      values = ["openvpn.isolated-virginia.kubixcorp.com"]
    }
  }
}

resource "aws_lb_target_group_attachment" "openvpn_attachment_virginia" {
  provider         = aws.virginia
  target_group_arn = aws_lb_target_group.openvpn_tg_virginia.arn
  target_id        = aws_instance.openvpn_virginia.id
  port             = 80
  depends_on       = [aws_lb_target_group.openvpn_tg_virginia, aws_instance.openvpn_virginia]
}

resource "aws_route53_record" "openvpn_dns_virginia" {
  provider = aws.route53
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "openvpn.isolated-virginia.kubixcorp.com"
  type     = "A"
  alias {
    name                   = module.alb_virginia.alb_dns_name
    zone_id                = module.alb_virginia.alb_zone_id
    evaluate_target_health = true
  }
}
/* OpenVPN Virginia */
/* OpenVPN Oregon */
resource "aws_security_group" "openvpn_sg_oregon" {
  provider    = aws.oregon
  name        = "openvpn_sg_oregon"
  description = "Allow HTTP, HTTPS and SSH traffic"
  vpc_id      = module.vpc_oregon.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "OpenVPN SG Oregon"
  }
}

resource "aws_instance" "openvpn_oregon" {
  provider               = aws.oregon
  ami                    = "ami-0ad3f99eafc4c44f4"
  instance_type          = "c5.xlarge"
  key_name               = "BaseKeyAcces"
  subnet_id              = module.vpc_oregon.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.openvpn_sg_oregon.id]
  user_data = templatefile("${path.module}/scripts/openvpn_utils.sh", {
    region = "Oregon"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  root_block_device {
    volume_type = "gp3"
    volume_size = 40
  }

  tags = {
    Name = "OpenVPN Oregon"
  }
  depends_on = [aws_security_group.openvpn_sg_oregon, aws_iam_instance_profile.ssm_instance_profile]
}

resource "aws_lb_target_group" "openvpn_tg_oregon" {
  name     = "openvpn-tg-oregon"
  provider = aws.oregon
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_oregon.vpc_id
  health_check {
    port = "88"
    path     = "/"
    interval = 30
    timeout  = 5
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "openvpn_rule_oregon" {
  provider     = aws.oregon
  tags         = { Name = "openvpn_rule_oregon" }
  listener_arn = module.alb_oregon.alb_listener_https_arn
  priority     = 15

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.openvpn_tg_oregon.arn
  }

  condition {
    host_header {
      values = ["openvpn.isolated-oregon.kubixcorp.com"]
    }
  }
}

resource "aws_lb_target_group_attachment" "openvpn_attachment_oregon" {
  provider         = aws.oregon
  target_group_arn = aws_lb_target_group.openvpn_tg_oregon.arn
  target_id        = aws_instance.openvpn_oregon.id
  port             = 80
  depends_on       = [aws_lb_target_group.openvpn_tg_oregon, aws_instance.openvpn_oregon]
}

resource "aws_route53_record" "openvpn_dns_oregon" {
  provider = aws.route53
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "openvpn.isolated-oregon.kubixcorp.com"
  type     = "A"
  alias {
    name                   = module.alb_oregon.alb_dns_name
    zone_id                = module.alb_oregon.alb_zone_id
    evaluate_target_health = true
  }
}
/* OpenVPN Oregon */

/* Tickets Virginia */
resource "aws_security_group" "tickets_sg_virginia" {
  provider    = aws.virginia
  name        = "tickets_sg_virginia"
  description = "Allow HTTP, HTTPS and SSH traffic"
  vpc_id      = module.vpc_virginia.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_virginia.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "Tickets SG Virginia"
  }
}

resource "aws_instance" "tickets_virginia" {
  provider               = aws.virginia
  ami                    = "ami-04e8b3e527208c8cf"
  instance_type          = "c5.xlarge"
  key_name               = "BaseKeyAcces"
  subnet_id              = module.vpc_virginia.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.tickets_sg_virginia.id]
  user_data = templatefile("${path.module}/scripts/tickets_utils.sh", {
    region = "Virginia"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  root_block_device {
    volume_type = "gp3"
    volume_size = 40
  }

  tags = {
    Name = "Tickets Virginia"
  }
  depends_on = [aws_security_group.tickets_sg_virginia, aws_iam_instance_profile.ssm_instance_profile]
}

resource "aws_lb_target_group" "tickets_tg_virginia" {
  name     = "tickets-tg-virginia"
  provider = aws.virginia
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_virginia.vpc_id
  health_check {
    port = "88"
    path     = "/"
    interval = 30
    timeout  = 5
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "tickets_rule_virginia" {
  provider     = aws.virginia
  tags         = { Name = "tickets_rule_virginia" }
  listener_arn = module.alb_virginia.alb_listener_https_arn
  priority     = 14

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tickets_tg_virginia.arn
  }

  condition {
    host_header {
      values = ["tickets.isolated-virginia.kubixcorp.com"]
    }
  }
}

resource "aws_lb_target_group_attachment" "tickets_attachment_virginia" {
  provider         = aws.virginia
  target_group_arn = aws_lb_target_group.tickets_tg_virginia.arn
  target_id        = aws_instance.tickets_virginia.id
  port             = 80
  depends_on       = [aws_lb_target_group.tickets_tg_virginia, aws_instance.tickets_virginia]
}

resource "aws_route53_record" "tickets_dns_virginia" {
  provider = aws.route53
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "tickets.isolated-virginia.kubixcorp.com"
  type     = "A"
  alias {
    name                   = module.alb_virginia.alb_dns_name
    zone_id                = module.alb_virginia.alb_zone_id
    evaluate_target_health = true
  }
}
/* Tickets Virginia */
/* Tickets Oregon */
resource "aws_security_group" "tickets_sg_oregon" {
  provider    = aws.oregon
  name        = "tickets_sg_oregon"
  description = "Allow HTTP, HTTPS and SSH traffic"
  vpc_id      = module.vpc_oregon.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    //cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg_oregon.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "Tickets SG Oregon"
  }
}

resource "aws_instance" "tickets_oregon" {
  provider               = aws.oregon
  ami                    = "ami-0676a735c5f8e67c4"
  instance_type          = "c5.xlarge"
  key_name               = "BaseKeyAcces"
  subnet_id              = module.vpc_oregon.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.tickets_sg_oregon.id]
  user_data = templatefile("${path.module}/scripts/tickets_utils.sh", {
    region = "Oregon"
  })
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  root_block_device {
    volume_type = "gp3"
    volume_size = 40
  }

  tags = {
    Name = "Tickets Oregon"
  }
  depends_on = [aws_security_group.tickets_sg_oregon, aws_iam_instance_profile.ssm_instance_profile]
}

resource "aws_lb_target_group" "tickets_tg_oregon" {
  name     = "tickets-tg-oregon"
  provider = aws.oregon
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc_oregon.vpc_id
  health_check {
    port = "88"
    path     = "/"
    interval = 30
    timeout  = 5
    matcher  = "200"
  }
}

resource "aws_lb_listener_rule" "tickets_rule_oregon" {
  provider     = aws.oregon
  tags         = { Name = "tickets_rule_oregon" }
  listener_arn = module.alb_oregon.alb_listener_https_arn
  priority     = 14

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tickets_tg_oregon.arn
  }

  condition {
    host_header {
      values = ["tickets.isolated-oregon.kubixcorp.com"]
    }
  }
}

resource "aws_lb_target_group_attachment" "tickets_attachment_oregon" {
  provider         = aws.oregon
  target_group_arn = aws_lb_target_group.tickets_tg_oregon.arn
  target_id        = aws_instance.tickets_oregon.id
  port             = 80
  depends_on       = [aws_lb_target_group.tickets_tg_oregon, aws_instance.tickets_oregon]
}

resource "aws_route53_record" "tickets_dns_oregon" {
  provider = aws.route53
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "tickets.isolated-oregon.kubixcorp.com"
  type     = "A"
  alias {
    name                   = module.alb_oregon.alb_dns_name
    zone_id                = module.alb_oregon.alb_zone_id
    evaluate_target_health = true
  }
}
/* Tickets Oregon */
