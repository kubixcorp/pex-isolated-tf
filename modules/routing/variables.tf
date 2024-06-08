variable "region" {
  description = "AWS region"
  type        = string
}
variable "transit_gateway_id" {
  description = "The ID of the Transit Gateway"
  type        = string
}

variable "peer_transit_gateway_id" {
  description = "The ID of the peer Transit Gateway"
  type        = string
}

variable "transit_gateway_attachment_id" {
  description = "The ID of the Transit Gateway attachment"
  type        = string
}

variable "peer_attachment_id" {
  description = "The ID of the peer Transit Gateway attachment"
  type        = string
}