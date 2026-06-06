terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  # Backend for state management
  backend "s3" {
    bucket         = "college-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "College-Result-System"
      Environment = var.environment
      ManagedBy   = "Terraform"
      CostCenter  = "Education-IT"
      Compliance  = "FERPA"
    }
  }
}
#networking
module "networking" {
  source = "./modules/networking"
  
  project_name        = var.project_name
  environment         = var.environment
  vpc_cidr            = var.vpc_cidr
  availability_zones  = var.availability_zones
  public_subnet_cidrs = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
  database_subnet_cidrs = var.database_subnet_cidrs
}
#load balancer
module "alb" {
  source = "./modules/compute/alb"
  
  project_name    = var.project_name
  environment     = var.environment
  vpc_id          = module.networking.vpc_id
  public_subnets  = module.networking.public_subnet_ids
  certificate_arn = var.ssl_certificate_arn
}
#ecs cluster
module "ecs_backend" {
  source = "./modules/compute/ecs"
  
  project_name      = var.project_name
  environment       = var.environment
  vpc_id            = module.networking.vpc_id
  private_subnets   = module.networking.private_subnet_ids
  alb_target_group  = module.alb.target_group_arn
  alb_security_group = module.alb.security_group_id
  

  desired_count = 5
  min_capacity  = 3
  max_capacity  = 20
  
  cpu_threshold    = 70
  memory_threshold = 80
  

  container_image = var.backend_image
  container_port  = 3000

  environment_vars = {
    NODE_ENV     = var.environment
    DB_HOST      = module.database.db_endpoint
    REDIS_HOST   = module.cache.redis_endpoint
    S3_BUCKET    = module.storage.results_bucket
  }
  
  secrets = {
    DB_PASSWORD   = module.database.db_password_secret_arn
    JWT_SECRET    = aws_secretsmanager_secret.jwt_secret.arn
    API_KEY       = aws_secretsmanager_secret.api_key.arn
  }
}

#Rds database
module "database" {
  source = "./modules/database"
  
  project_name       = var.project_name
  environment        = var.environment
  vpc_id             = module.networking.vpc_id
  database_subnets   = module.networking.database_subnet_ids
  app_security_group = module.ecs_backend.security_group_id
  

  multi_az               = true
  instance_class         = "db.r6g.xlarge"  
  allocated_storage      = 100
  max_allocated_storage  = 500  
  

  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  

  create_read_replica = true
  read_replica_count  = 2
  

  storage_encrypted = true
  kms_key_id       = aws_kms_key.database.arn
  

  enabled_cloudwatch_logs_exports = ["error", "general", "slowquery"]
  performance_insights_enabled    = true
}

#elasticache redis
module "cache" {
  source = "./modules/cache"
  
  project_name       = var.project_name
  environment        = var.environment
  vpc_id             = module.networking.vpc_id
  private_subnets    = module.networking.private_subnet_ids
  app_security_group = module.ecs_backend.security_group_id
  

  node_type            = "cache.r6g.large"  # 13.07 GiB memory
  num_cache_nodes      = 3
  engine_version       = "7.0"
  

  automatic_failover_enabled = true
  multi_az_enabled          = true

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
}

#S3 storage
module "storage" {
  source = "./modules/storage"
  
  project_name = var.project_name
  environment  = var.environment

  create_results_bucket    = true
  create_documents_bucket  = true
  create_backups_bucket    = true

  enable_versioning = true
  enable_encryption = true
  kms_key_id       = aws_kms_key.s3.arn

  enable_lifecycle_rules = true
  transition_to_glacier_days = 90

  enable_access_logging = true
}

# CloudFront CDN 
module "cdn" {
  source = "./modules/cdn"
  
  project_name    = var.project_name
  environment     = var.environment
  s3_bucket_id    = module.storage.frontend_bucket_id
  certificate_arn = var.ssl_certificate_arn
  domain_name     = var.domain_name
  
  # Performance optimization
  price_class = "PriceClass_200"  # US, Europe, Asia
  
  # Security
  enable_waf = true
}

# CloudWatch 
module "monitoring" {
  source = "./modules/monitoring"
  
  project_name = var.project_name
  environment  = var.environment
  
  
  alb_arn          = module.alb.arn
  ecs_cluster_name = module.ecs_backend.cluster_name
  ecs_service_name = module.ecs_backend.service_name
  db_instance_id   = module.database.instance_id
  redis_cluster_id = module.cache.cluster_id
  
 
  cpu_alarm_threshold    = 80
  memory_alarm_threshold = 85
  error_rate_threshold   = 5  # 5% error rate
  

  alert_email = var.alert_email
}

resource "aws_secretsmanager_secret" "jwt_secret" {
  name = "${var.project_name}-${var.environment}-jwt-secret"
  
  kms_key_id = aws_kms_key.secrets.arn
  
  tags = {
    Name = "JWT Secret"
  }
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  secret_id     = aws_secretsmanager_secret.jwt_secret.id
  secret_string = random_password.jwt_secret.result
}

resource "random_password" "jwt_secret" {
  length  = 64
  special = true
}

resource "aws_secretsmanager_secret" "api_key" {
  name = "${var.project_name}-${var.environment}-api-key"
  
  kms_key_id = aws_kms_key.secrets.arn
}

resource "aws_secretsmanager_secret_version" "api_key" {
  secret_id     = aws_secretsmanager_secret.api_key.id
  secret_string = random_password.api_key.result
}

resource "random_password" "api_key" {
  length  = 48
  special = false
}

# KMS 
resource "aws_kms_key" "database" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name = "${var.project_name}-database-key"
  }
}

resource "aws_kms_key" "s3" {
  description             = "KMS key for S3 encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name = "${var.project_name}-s3-key"
  }
}

resource "aws_kms_key" "secrets" {
  description             = "KMS key for Secrets Manager"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name = "${var.project_name}-secrets-key"
  }
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = module.alb.dns_name
}

output "cloudfront_domain" {
  description = "CloudFront distribution domain"
  value       = module.cdn.domain_name
}

output "database_endpoint" {
  description = "RDS database endpoint"
  value       = module.database.db_endpoint
  sensitive   = true
}

output "redis_endpoint" {
  description = "Redis cluster endpoint"
  value       = module.cache.redis_endpoint
  sensitive   = true
}