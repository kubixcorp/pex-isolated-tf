variable "name" {
  description = "The name of the load balancer"
  type        = string
}

variable "internal" {
  description = "Whether the load balancer is internal or external"
  type        = bool
}

variable "security_groups" {
  description = "The security groups to attach to the load balancer"
  type = list(string)
}

variable "subnets" {
  description = "The subnets to attach to the load balancer"
  type = list(string)
}

variable "enable_deletion_protection" {
  description = "Whether to enable deletion protection on the load balancer"
  type        = bool
  default     = false
}

variable "tags" {
  description = "A map of tags to assign to the resource"
  type = map(string)
  default = {}
}

variable "target_group_name" {
  description = "The name of the target group"
  type        = string
}

variable "target_group_port" {
  description = "The port for the target group"
  type        = number
}

variable "vpc_id" {
  description = "The VPC ID where the load balancer and target group will be deployed"
  type        = string
}

variable "certificate_arn" {
  description = "The ARN of the certificate for the ALB HTTPS listener"
  type        = string
}

variable "health_check_path" {
  description = "The path for the health check"
  type        = string
  default     = "/"
}

variable "health_check_interval" {
  description = "The interval for the health check"
  type        = number
  default     = 30
}

variable "health_check_timeout" {
  description = "The timeout for the health check"
  type        = number
  default     = 5
}

variable "health_check_healthy_threshold" {
  description = "The number of healthy thresholds for the health check"
  type        = number
  default     = 2
}

variable "health_check_unhealthy_threshold" {
  description = "The number of unhealthy thresholds for the health check"
  type        = number
  default     = 2
}

variable "health_check_matcher" {
  description = "The matcher for the health check"
  type        = string
  default     = "200-399"
}

variable "access_logs_bucket" {
  description = "The S3 bucket for ALB access logs"
  type        = string
}

variable "enable_access_logs" {
  description = "Enable access logs on the load balancer"
  type        = bool
  default     = false
}

variable "routes" {
  description = "A map of routes for the ALB to handle"
  default = {}
  type = map(object({
    target_group_arn = string
    host_headers = list(string)
  }))
}
