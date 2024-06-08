variable "vpc_id" {
  description = "ID of the VPC to create the VPN in"
  type        = string
}
variable "tgw_id" {
  description = "The ID of the Transit Gateway"
  type        = string
}

variable "tgw_attachment_id" {
  description = "The ID of the Transit Gateway attachment"
  type        = string
}