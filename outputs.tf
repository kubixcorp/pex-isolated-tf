output "alb_virginia_dns_name" {
  value = module.alb_virginia.alb_dns_name
}

output "alb_oregon_dns_name" {
  value = module.alb_oregon.alb_dns_name
}

output "instance_info_bastion_virginia" {
  description = "The name and ID of the bastion instance Virginia"
  value       = format("%s - %s", aws_instance.bastion_virginia.tags["Name"], aws_instance.bastion_virginia.id)
}
output "instance_info_bastion_oregon" {
  description = "The name and ID of the bastion instance Oregon : aws ssm start-session --target aws_instance.bastion_oregon.id --profile"
  value       = format("%s - %s", aws_instance.bastion_oregon.tags["Name"], aws_instance.bastion_oregon.id)
}

output "gitlab_dns_virginia_ip_name" {
  value = aws_instance.gitlab_virginia.private_ip
}
