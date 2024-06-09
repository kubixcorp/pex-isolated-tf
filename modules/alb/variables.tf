variable "name" {
  description = "The name of the ALB"
  type        = string
}

variable "internal" {
  description = "Whether the load balancer is internal"
  type        = bool
  default     = false
}

variable "security_groups" {
  description = "The security groups to associate with the ALB"
  type        = list(string)
}

variable "subnets" {
  description = "The subnets to associate with the ALB"
  type        = list(string)
}

variable "enable_deletion_protection" {
  description = "Whether to enable deletion protection"
  type        = bool
  default     = false
}

variable "tags" {
  description = "A map of tags to assign to the resource"
  type        = map(string)
  default     = {}
}

variable "target_group_name" {
  description = "The name of the target group"
  type        = string
}

variable "target_group_port" {
  description = "The port of the target group"
  type        = number
}

variable "vpc_id" {
  description = "The VPC ID"
  type        = string
}

variable "certificate_arn" {
  description = "The ARN of the certificate for the ALB HTTPS listener"
  type        = string
}