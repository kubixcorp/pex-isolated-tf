variable "bucket_name" {
  type        = string
  description = "The name of the S3 bucket"
}

variable "allowed_account_arn" {
  type        = string
  description = "The ARN of the AWS account allowed to put objects in the bucket"
}
