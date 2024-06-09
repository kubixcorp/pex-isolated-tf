variable "aws_profile" {
  description = "AWS CLI profile to use"
  type        = string
  default     = "fmoralesIsolated"
}

variable "vpc_virginia_cidr" {
  description = "The CIDR block for the Virginia VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "vpc_virginia_public_subnets" {
  description = "A list of public subnet CIDRs for the Virginia VPC"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "vpc_virginia_private_subnets" {
  description = "A list of private subnet CIDRs for the Virginia VPC"
  type        = list(string)
  default     = ["10.0.3.0/24", "10.0.4.0/24"]
}

variable "vpc_virginia_azs" {
  description = "A list of availability zones for the Virginia VPC"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "vpc_oregon_cidr" {
  description = "The CIDR block for the Oregon VPC"
  type        = string
  default     = "10.1.0.0/16"
}

variable "vpc_oregon_public_subnets" {
  description = "A list of public subnet CIDRs for the Oregon VPC"
  type        = list(string)
  default     = ["10.1.1.0/24", "10.1.2.0/24"]
}

variable "vpc_oregon_private_subnets" {
  description = "A list of private subnet CIDRs for the Oregon VPC"
  type        = list(string)
  default     = ["10.1.3.0/24", "10.1.4.0/24"]
}

variable "vpc_oregon_azs" {
  description = "A list of availability zones for the Oregon VPC"
  type        = list(string)
  default     = ["us-west-2a", "us-west-2b"]
}

variable "vpc_virginia_region" {
  description = "The region for the Virginia VPC"
  type        = string
  default     = "us-east-1"
}

variable "vpc_oregon_region" {
  description = "The region for the Oregon VPC"
  type        = string
  default     = "us-west-2"
}

variable "certificate_arn" {
  description = "The ARN of the certificate for the ALB HTTPS listener"
  type        = string
}

variable "environment" {
  description = "The environment for the project (e.g., dev, prod)"
  type        = string
}

variable "project_name" {
  description = "The name of the project"
  type        = string
}