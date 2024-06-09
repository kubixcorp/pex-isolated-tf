variable "aws_profile" {
  description = "The AWS profile to use"
  type        = string
  default = "fmoralesIsolated"
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

variable "vpc_virginia_cidr" {
  description = "The CIDR block for the Virginia VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "vpc_oregon_cidr" {
  description = "The CIDR block for the Oregon VPC"
  type        = string
  default     = "10.1.0.0/16"
}

variable "vpc_virginia_public_subnets" {
  description = "Public subnets for the Virginia VPC"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "vpc_oregon_public_subnets" {
  description = "Public subnets for the Oregon VPC"
  type        = list(string)
  default     = ["10.1.1.0/24", "10.1.2.0/24"]
}

variable "vpc_virginia_private_subnets" {
  description = "Private subnets for the Virginia VPC"
  type        = list(string)
  default     = ["10.0.3.0/24", "10.0.4.0/24"]
}

variable "vpc_oregon_private_subnets" {
  description = "Private subnets for the Oregon VPC"
  type        = list(string)
  default     = ["10.1.3.0/24", "10.1.4.0/24"]
}

variable "vpc_virginia_azs" {
  description = "Availability Zones for the Virginia VPC"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "vpc_oregon_azs" {
  description = "Availability Zones for the Oregon VPC"
  type        = list(string)
  default     = ["us-west-2a", "us-west-2b"]
}

variable "certificate_arn_virginia" {
  description = "The ARN of the certificate for the ALB HTTPS listener in Virginia"
  type        = string
}

variable "certificate_arn_oregon" {
  description = "The ARN of the certificate for the ALB HTTPS listener in Oregon"
  type        = string
}