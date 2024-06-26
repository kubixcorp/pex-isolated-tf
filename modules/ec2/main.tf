terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }
}


resource "aws_instance" "this" {
  ami           = var.ami
  instance_type = var.instance_type
  subnet_id     = var.subnet_id
  key_name      = var.key_name
  vpc_security_group_ids = var.security_group_ids
  user_data = var.user_data
  tags = var.tags
  iam_instance_profile = var.iam_instance_profile
  root_block_device {
    volume_type = "gp3"
    volume_size = var.instance_volume
  }
}
