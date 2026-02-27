resource "aws_s3_bucket" "customer_data" {
  bucket = "prod-customer-database-backup"
  acl    = "public-read"
  
  tags = {
    Environment = "production"
  }
}