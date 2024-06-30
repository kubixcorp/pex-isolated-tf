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
  name                       = "ALB-Main-Virginia"
  internal                   = false
  security_groups = [aws_security_group.alb_sg_virginia.id]
  subnets                    = module.vpc_virginia.public_subnets
  enable_deletion_protection = false
  target_group_name          = "Main-TGroup-virginia"
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
  depends_on = [module.alb_virginia, aws_wafv2_web_acl.web_acl_virginia]
}

module "alb_oregon" {
  source = "./modules/alb"
  providers = {
    aws = aws.oregon
  }
  name                       = "ALB-Main-Oregon"
  internal                   = false
  security_groups = [aws_security_group.alb_sg_oregon.id]
  subnets                    = module.vpc_oregon.public_subnets
  enable_deletion_protection = false
  target_group_name          = "Main-TGroup-oregon"
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
  depends_on = [module.alb_oregon, aws_wafv2_web_acl.web_acl_oregon]
}
/* Security Groups */
resource "aws_security_group" "alb_sg_virginia" {
  provider    = aws.virginia
  name        = "alb_sg_virginia"
  description = "ALB Security Group Virginia"
  vpc_id      = module.vpc_virginia.vpc_id

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
  provider    = aws.oregon
  name        = "alb_sg_oregon"
  description = "ALB Security Group Oregon"
  vpc_id      = module.vpc_oregon.vpc_id

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
    from_port = 22
    to_port   = 22
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
    Name = "Bastion SG Virginia"
  }
}

resource "aws_instance" "bastion_virginia" {
  provider      = aws.virginia
  ami           = "ami-04e8b3e527208c8cf"
  instance_type = "t2.micro"
  subnet_id     = module.vpc_virginia.public_subnets[0]
  key_name      = "BaseKeyAcces"
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
    from_port = 22
    to_port   = 22
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
    Name = "Bastion SG Oregon"
  }
}

resource "aws_instance" "bastion_oregon" {
  provider      = aws.oregon
  ami           = "ami-0676a735c5f8e67c4"
  instance_type = "t2.micro"
  subnet_id     = module.vpc_oregon.public_subnets[0]
  key_name      = "BaseKeyAcces"
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








/* Clusters Fargate */

/*IAM Roles and Policies for ECS Fargate*/
resource "time_sleep" "wait_30_seconds" {
  depends_on = [aws_iam_role.ecs_task_role, aws_iam_role.ecs_task_execution_role]
  create_duration = "15s"
}

resource "aws_iam_role" "ecs_task_role" {
  provider = aws.virginia
  name     = "ecsTaskRole"

  assume_role_policy = jsonencode({
    Version : "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Principal : {
          Service : "ecs-tasks.amazonaws.com"
        },
        Action : "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "ecs_task_policy" {
  provider = aws.virginia
  name     = "ecsTaskPolicy"
  role     = aws_iam_role.ecs_task_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Action : [
          "ecs:DescribeClusters",
          "ecs:DescribeTasks",
          "ecs:ListTasks",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource : "*"
      }
    ]
  })
  depends_on = [aws_iam_role.ecs_task_role]
}

resource "aws_iam_role" "ecs_task_execution_role" {
  provider = aws.virginia
  name     = "ecsTaskExecutionRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement : [
      {
        Effect : "Allow",
        Principal : {
          Service : "ecs-tasks.amazonaws.com"
        },
        Action : "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  provider   = aws.virginia
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

/*IAM Roles and Policies for ECS Fargate*/

/* ECS Fargate */
resource "aws_ecs_cluster" "ecs_cluster_virginia" {
  provider = aws.virginia
  name     = "${var.environment_dev}-Prod-Cluster-Puntoxpress"
}

resource "aws_wafv2_web_acl" "web_acl_ecs_virginia" {
  provider    = aws.virginia
  name        = "alb-web-acl-ecs-virginia"
  scope       = "REGIONAL"
  description = "Web ACL to allow specific IPs"

  default_action {
    block {}
  }

  rule {
    name     = "allow-specific-ips-ecs-virginia"
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
      metric_name                = "allow-specific-ips-ecs-virginia"
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "web-acl-metrics-ecs-virginia"
    sampled_requests_enabled   = true
  }
  depends_on = [aws_wafv2_ip_set.allowed_ips_virginia]
}

resource "aws_lb" "app_lb_virginia" {
  provider           = aws.virginia
  name               = "${var.environment_dev}-ALB-Puntoxpress"
  internal           = false
  load_balancer_type = "application"
  security_groups = [aws_security_group.lb_sg_virginia.id]
  subnets            = module.vpc_virginia.public_subnets

}

resource "aws_lb_listener" "https_listener_virginia" {
  provider          = aws.virginia
  load_balancer_arn = aws_lb.app_lb_virginia.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = var.certificate_arn_virginia
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Please use a specific service URL"
      status_code  = "200"
    }
  }
  depends_on = [aws_lb.app_lb_virginia, aws_lb_target_group.app_tg_virginia]
}

resource "aws_wafv2_web_acl_association" "web_acl_association_ecs_virginia" {
  provider     = aws.virginia
  resource_arn = aws_lb.app_lb_virginia.arn
  web_acl_arn  = aws_wafv2_web_acl.web_acl_ecs_virginia.arn
  depends_on = [aws_lb.app_lb_virginia, aws_wafv2_web_acl.web_acl_ecs_virginia]
}



resource "aws_lb_target_group" "app_tg_virginia" {
  provider    = aws.virginia
  count       = 8
  name        = "${var.environment_dev}-TGroup-Puntoxpress-${count.index + 1}"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = module.vpc_virginia.vpc_id
  target_type = "ip"
  health_check {
    healthy_threshold   = "3"
    interval            = "30"
    protocol            = "HTTP"
    matcher             = "200"
    timeout             = "3"
    path                = "/"
    unhealthy_threshold = "2"
  }
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [aws_lb.app_lb_virginia]
}

resource "aws_security_group" "lb_sg_virginia" {
  provider = aws.virginia
  name     = "${var.environment_dev}-lb-sg-puntoxpress"
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
}

resource "aws_ecs_task_definition" "task_def_virginia" {
  provider           = aws.virginia
  count              = 8
  family             = "${var.environment_dev}-task-def-${count.index + 1}"
  network_mode       = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                = "256"
  memory             = "512"
  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn      = aws_iam_role.ecs_task_role.arn
  container_definitions = jsonencode([
    {
      name  = "app"
      image = "nginx"
      portMappings = [
        {
          containerPort = 80
          hostPort      = 80
          protocol      = "tcp"
        }
      ]
    }
  ])
  depends_on = [time_sleep.wait_30_seconds]
}

resource "aws_lb_listener_rule" "ecs_rule_virginia" {
  provider     = aws.virginia
  count = 8
  // tags         = { Name = "ecs_rule_virginia_${count.index + 1}" }
  listener_arn = aws_lb_listener.https_listener_virginia.arn
  priority     = 100 + count.index

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg_virginia[count.index].arn
  }

  condition {
    host_header {
      values = ["srv${count.index + 1}.isolated-virginia.kubixcorp.com"]
    }
  }

#   lifecycle {
#     create_before_destroy = true
#   }

  depends_on = [aws_lb_listener.https_listener_virginia, aws_lb_target_group.app_tg_virginia]
}

resource "aws_ecs_service" "ecs_service_virginia" {
  provider        = aws.virginia
  count           = 8
  name            = "${var.environment_dev}-ecs-service-${count.index + 1}"
  cluster         = aws_ecs_cluster.ecs_cluster_virginia.id
  task_definition = aws_ecs_task_definition.task_def_virginia[count.index].arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = module.vpc_virginia.public_subnets
    security_groups = [aws_security_group.lb_sg_virginia.id]
    assign_public_ip = true
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.app_tg_virginia[count.index].arn
    container_name   = "app"
    container_port   = 80
  }
  depends_on = [
    aws_lb_listener.https_listener_virginia,
    aws_iam_role.ecs_task_role,
    aws_iam_role.ecs_task_execution_role,
    aws_iam_role_policy.ecs_task_policy,
    aws_iam_role_policy_attachment.ecs_task_execution_role_policy
  ]
}

resource "aws_route53_record" "tasks_dns_ecs_virginia" {
  provider = aws.route53
  count    = 8
  zone_id  = "Z07774303G2AYPCGKGZSX"
  name     = "srv${count.index + 1}.isolated-virginia.kubixcorp.com"
  type     = "A"

  alias {
    name                   = aws_lb.app_lb_virginia.dns_name
    zone_id                = aws_lb.app_lb_virginia.zone_id
    evaluate_target_health = true
  }
}

/* ECS Fargate */

/* Clusters Fargate */
