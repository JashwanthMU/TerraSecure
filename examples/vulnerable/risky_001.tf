resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-database-backup"
  acl    = "public-read"
}