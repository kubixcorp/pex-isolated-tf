variable "region" {
  description = "AWS region for the Transit Gateway"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC to attach to the Transit Gateway"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs to attach to the Transit Gateway"
  type        = list(string)
}
