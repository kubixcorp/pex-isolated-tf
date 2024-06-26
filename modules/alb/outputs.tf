output "alb_arn" {
  value = aws_lb.this.arn
}

output "alb_listener_https_arn" {
  value = aws_lb_listener.https.arn
}

output "alb_dns_name" {
  value = aws_lb.this.dns_name
}

output "alb_zone_id" {
  value = aws_lb.this.zone_id
}

output "target_group_arn" {
  value = aws_lb_target_group.this.arn
}
