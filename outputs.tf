output "virginia_vpc_id" {
  value = module.vpc_virginia.vpc_id
}

output "oregon_vpc_id" {
  value = module.vpc_oregon.vpc_id
}
output "alb_dns_name" {
  value = module.alb.alb_dns_name
}