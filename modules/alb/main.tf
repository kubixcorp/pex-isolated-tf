terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }
}

resource "aws_lb" "this" {
  provider                   = aws
  name                       = var.name
  internal                   = var.internal
  load_balancer_type         = "application"
  security_groups            = var.security_groups
  subnets                    = var.subnets
  enable_deletion_protection = var.enable_deletion_protection

  access_logs {
    bucket  = var.access_logs_bucket
    enabled = var.enable_access_logs
  }

  tags = var.tags
}

resource "aws_lb_target_group" "this" {
  provider    = aws
  name        = var.target_group_name
  port        = var.target_group_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    path                = var.health_check_path
    interval            = var.health_check_interval
    timeout             = var.health_check_timeout
    healthy_threshold   = var.health_check_healthy_threshold
    unhealthy_threshold = var.health_check_unhealthy_threshold
    matcher             = var.health_check_matcher
  }

  tags = var.tags
}

resource "aws_lb_listener" "https" {
  provider          = aws
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = var.certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Not Found"
      status_code  = "404"
    }
  }

}


