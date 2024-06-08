variable "vpc_cidr" {
  description = "The CIDR block for the VPC"
  type        = string
}

variable "public_subnet_cidrs" {
  description = "A list of public subnet CIDRs"
  type        = list(string)
}

variable "private_subnet_cidrs" {
  description = "A list of private subnet CIDRs"
  type        = list(string)
}

variable "availability_zones" {
  description = "A list of availability zones"
  type        = list(string)
}