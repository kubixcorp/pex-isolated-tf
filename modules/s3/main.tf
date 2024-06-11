resource "aws_s3_bucket" "alb_logs" {
  bucket = "my-alb-logs-bucket" # Cambia este nombre por el nombre que prefieras para tu bucket

  tags = {
    Name = "ALB Logs Bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls  = true
  restrict_public_buckets = true
}
