# AWS Resources - Security Patterns Guide

**Common Resources + Security Patterns + Use Cases**

---

## 1. Amazon S3 (Simple Storage Service)

### Definition
Object storage service for storing and retrieving any amount of data.

### Common Use Cases
- Static website hosting
- Data lakes and analytics
- Backup and disaster recovery
- Application data storage

### Security Patterns (6 patterns)

####  SECURE Configuration
```hcl
resource "aws_s3_bucket" "secure" {
  bucket = "my-secure-bucket"
  acl    = "private"  # ← CRITICAL
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  
  versioning {
    enabled = true
  }
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

####  VULNERABLE Patterns TerraSecure Detects

**Pattern 1: `s3_public_acl`**
```hcl
acl = "public-read"  # CRITICAL
```
- **Risk:** Anyone on internet can read bucket
- **Breach:** Capital One (2019) - $190M loss
- **Fix:** `acl = "private"`

**Pattern 2: `s3_encryption_disabled`**
```hcl
# No encryption block  # HIGH
```
- **Risk:** Data stored in plaintext
- **Compliance:** Violates PCI-DSS, HIPAA
- **Fix:** Add `server_side_encryption_configuration`

**Pattern 3: `s3_versioning_disabled`**
```hcl
# No versioning  # MEDIUM
```
- **Risk:** Ransomware can permanently delete data
- **Breach:** Code Spaces (2014) - business closure
- **Fix:** Enable versioning

**Pattern 4: `s3_block_public_access_disabled`**
- **Risk:** Bucket can be made public accidentally
- **Fix:** Set all 4 block public access settings to `true`

**Pattern 5: `s3_lifecycle_policy_missing`**
- **Risk:** Unnecessary storage costs
- **Fix:** Add lifecycle rules to transition to cheaper storage

**Pattern 6: `s3_mfa_delete_disabled`**
- **Risk:** Accidental deletion without MFA
- **Fix:** Enable MFA delete for critical buckets

---

## 2. AWS EC2 (Elastic Compute Cloud)

### Definition
Virtual servers (instances) in the cloud.

### Common Use Cases
- Web application hosting
- Microservices deployment
- Batch processing
- Development/test environments

### Security Patterns (4 patterns)

####  SECURE Configuration
```hcl
resource "aws_instance" "secure" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  
  vpc_security_group_ids = [aws_security_group.app.id]
  
  metadata_options {
    http_tokens   = "required"  # IMDSv2
    http_endpoint = "enabled"
  }
  
  monitoring    = true
  ebs_optimized = true
  
  root_block_device {
    encrypted = true
  }
}
```

####  VULNERABLE Patterns

**Pattern 1: IMDSv1 Enabled**
```hcl
metadata_options {
  http_tokens = "optional"  # Allows IMDSv1
}
```
- **Risk:** SSRF attacks can steal credentials
- **Breach:** Capital One used IMDSv1 exploit
- **Fix:** Require IMDSv2 (`http_tokens = "required"`)

**Pattern 2: Unencrypted EBS Volumes**
```hcl
root_block_device {
  encrypted = false  # Data at rest unencrypted
}
```
- **Risk:** Data readable if volume compromised
- **Fix:** `encrypted = true`

**Pattern 3: No Monitoring**
```hcl
monitoring = false  # No CloudWatch metrics
```
- **Risk:** Can't detect compromises
- **Fix:** `monitoring = true`

**Pattern 4: Public IP with Open Security Group**
- **Risk:** Direct internet exposure
- **Fix:** Use private subnets + NAT gateway

---

## 3. AWS Security Groups

### Definition
Virtual firewalls controlling inbound/outbound traffic.

### Common Use Cases
- Control access to EC2 instances
- Database access restrictions
- Application tier isolation

### Security Patterns (7 patterns)

####  SECURE Configuration
```hcl
resource "aws_security_group" "app" {
  name = "app-tier-sg"
  
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]  # ← Specific source
    description     = "HTTPS from load balancer only"
  }
  
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS outbound for API calls"
  }
}
```

####  VULNERABLE Patterns

**Pattern 1: `open_cidr_0_0_0_0`**
```hcl
cidr_blocks = ["0.0.0.0/0"]  # CRITICAL
```
- **Risk:** Entire internet can access
- **Fix:** Specific IP ranges only

**Pattern 2: `open_ssh_port_22`**
```hcl
ingress {
  from_port   = 22
  cidr_blocks = ["0.0.0.0/0"]  # CRITICAL
}
```
- **Risk:** Brute force attacks (millions daily)
- **Breach:** Shodan catalogs these in hours
- **Fix:** Restrict to office IP or use Systems Manager

**Pattern 3: `open_rdp_port_3389`**
```hcl
ingress {
  from_port   = 3389
  cidr_blocks = ["0.0.0.0/0"]  # CRITICAL
}
```
- **Risk:** Ransomware deployment
- **Breach:** 90% of Windows ransomware via RDP
- **Fix:** VPN or bastion only

**Pattern 4: `sg_all_ports_open`**
```hcl
from_port = 0
to_port   = 65535  # All ports
```
- **Risk:** Massive attack surface
- **Fix:** Specific ports only

**Pattern 5: `sg_egress_unrestricted`**
- **Risk:** Data exfiltration
- **Fix:** Allow only necessary outbound ports

**Pattern 6: `default_sg_in_use`**
- **Risk:** Shared across resources (overly permissive)
- **Fix:** Create resource-specific security groups

**Pattern 7: `security_group_allows_all_ingress`**
- **Risk:** Complete exposure
- **Fix:** Least privilege principle

---

## 4. AWS RDS (Relational Database Service)

### Definition
Managed relational databases (MySQL, PostgreSQL, etc.)

### Common Use Cases
- Application databases
- Data warehousing
- SaaS application backends

### Security Patterns (5 patterns)

####  SECURE Configuration
```hcl
resource "aws_db_instance" "secure" {
  identifier = "mydb"
  engine     = "mysql"
  
  publicly_accessible    = false  #  CRITICAL
  storage_encrypted      = true
  kms_key_id            = aws_kms_key.db.arn
  
  db_subnet_group_name   = aws_db_subnet_group.private.name
  vpc_security_group_ids = [aws_security_group.db.id]
  
  backup_retention_period = 7
  
  iam_database_authentication_enabled = true
  enabled_cloudwatch_logs_exports     = ["error", "slowquery"]
}
```

####  VULNERABLE Patterns

**Pattern 1: `rds_publicly_accessible`**
```hcl
publicly_accessible = true  #  CRITICAL
```
- **Risk:** Database exposed to internet
- **Breach:** MongoDB ransomware (27K databases)
- **Fix:** `publicly_accessible = false`

**Pattern 2: `rds_storage_unencrypted`**
```hcl
storage_encrypted = false  #  HIGH
```
- **Risk:** Data readable if storage compromised
- **Compliance:** PCI-DSS violation
- **Fix:** `storage_encrypted = true`

**Pattern 3: `rds_backup_retention_short`**
```hcl
backup_retention_period = 1  #  MEDIUM
```
- **Risk:** Insufficient recovery window
- **Fix:** Minimum 7 days

**Pattern 4: No IAM Authentication**
- **Risk:** Password-based auth only
- **Fix:** Enable IAM database authentication

**Pattern 5: No CloudWatch Logs**
- **Risk:** Can't detect SQL injection or anomalies
- **Fix:** Enable error and slow query logs

---

## 5. AWS IAM (Identity and Access Management)

### Definition
Service for managing users, groups, roles, and permissions.

### Common Use Cases
- User access control
- Service-to-service permissions
- Cross-account access
- Federation with corporate directory

### Security Patterns (8 patterns)

####  SECURE Configuration
```hcl
resource "aws_iam_policy" "secure" {
  name = "s3-read-specific-bucket"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:ListBucket"
      ]  # ← Specific actions
      Resource = [
        "arn:aws:s3:::my-specific-bucket",
        "arn:aws:s3:::my-specific-bucket/*"
      ]  # ← Specific resources
    }]
  })
}
```

####  VULNERABLE Patterns

**Pattern 1: `iam_wildcard_action`**
```hcl
Action = "*"  #  CRITICAL
```
- **Risk:** Administrative access
- **Breach:** Uber (2016) - Wildcard permissions enabled 57M record theft
- **Fix:** List specific actions needed

**Pattern 2: `iam_wildcard_resource`**
```hcl
Resource = "*"  #  CRITICAL
```
- **Risk:** Access to all resources
- **Breach:** Capital One - IAM wildcards enabled breach
- **Fix:** Specific ARNs only

**Pattern 3: `iam_inline_user_policy`**
- **Risk:** Hard to audit and manage
- **Fix:** Use managed policies

**Pattern 4: `mfa_not_enabled`**
- **Risk:** Credential theft = full access
- **Fix:** Require MFA for all users

**Pattern 5: `password_policy_weak`**
- **Risk:** Brute force attacks
- **Fix:** Strong password policy (14+ chars, complexity)

**Pattern 6: `cross_account_access_unrestricted`**
- **Risk:** Any AWS account can assume role
- **Fix:** Specific account IDs in trust policy

**Pattern 7: `root_account_in_use`**
- **Risk:** No MFA, full access, can't revoke
- **Fix:** Create IAM users, lock root account

**Pattern 8: `iam_assume_role_unrestricted`**
- **Risk:** Role assumption without conditions
- **Fix:** Add MFA or IP conditions

---

## 6. AWS Lambda

### Definition
Serverless compute - run code without managing servers.

### Common Use Cases
- API backends
- Event processing
- Data transformation
- Scheduled tasks

### Security Patterns (3 patterns)

####  SECURE Configuration
```hcl
resource "aws_lambda_function" "secure" {
  function_name = "my-function"
  
  vpc_config {
    subnet_ids         = [aws_subnet.private.id]
    security_group_ids = [aws_security_group.lambda.id]
  }
  
  environment {
    variables = {
      DB_HOST = aws_db_instance.main.endpoint
      # No secrets here - use Secrets Manager
    }
  }
  
  kms_key_arn = aws_kms_key.lambda.arn  # Encrypt env vars
  
  reserved_concurrent_executions = 100  # Prevent runaway costs
}
```

####  VULNERABLE Patterns

**Pattern 1: `lambda_env_vars_unencrypted`**
```hcl
# No kms_key_arn  # Env vars in plaintext
```
- **Risk:** Secrets visible in console
- **Fix:** Use KMS encryption

**Pattern 2: `secrets_in_environment_vars`**
```hcl
environment {
  variables = {
    DB_PASSWORD = "hardcoded"  # CRITICAL
  }
}
```
- **Risk:** Secrets in plaintext
- **Fix:** Use AWS Secrets Manager

**Pattern 3: No VPC Configuration**
- **Risk:** Can't access private resources securely
- **Fix:** Add VPC config with private subnets

---

## 7. AWS VPC (Virtual Private Cloud)

### Definition
Isolated network within AWS cloud.

### Common Use Cases
- Multi-tier application hosting
- Hybrid cloud connectivity
- Network segmentation

### Security Patterns (3 patterns)

#### VULNERABLE Patterns

**Pattern 1: `vpc_flow_logs_disabled`**
```hcl
# No flow logs  # MEDIUM
```
- **Risk:** Can't detect network anomalies
- **Fix:** Enable VPC Flow Logs to CloudWatch

**Pattern 2: `nacl_unrestricted`**
```hcl
egress {
  rule_no    = 100
  action     = "allow"
  cidr_block = "0.0.0.0/0"
  from_port  = 0
  to_port    = 65535
}
```
- **Risk:** No network-level restrictions
- **Fix:** Specific ports and CIDRs

**Pattern 3: Default VPC in Use**
- **Risk:** Predictable IP ranges, shared across accounts
- **Fix:** Create custom VPC

---

## 8. AWS CloudTrail

### Definition
Logs all AWS API calls for auditing.

### Common Use Cases
- Security auditing
- Compliance logging
- Incident investigation
- Change tracking

### Security Pattern

#### VULNERABLE Pattern

**Pattern 1: `cloudtrail_not_enabled`**
```hcl
# No CloudTrail  # CRITICAL
```
- **Risk:** No audit trail of actions
- **Compliance:** Required by PCI-DSS, HIPAA, SOC2
- **Breach:** Capital One - No CloudTrail delayed detection
- **Fix:** Enable CloudTrail in all regions

---

## Summary Table

| Resource | Critical Patterns | Most Common Breach |
|----------|-------------------|-------------------|
| **S3** | Public ACL, No encryption | Capital One ($190M) |
| **Security Groups** | 0.0.0.0/0, Open SSH/RDP | MongoDB ransomware |
| **RDS** | Publicly accessible | MongoDB (27K DBs) |
| **IAM** | Wildcard *, No MFA | Uber (57M records) |
| **Lambda** | Hardcoded secrets | Various |
| **VPC** | No flow logs | Detection delays |
| **CloudTrail** | Not enabled | All major breaches |

---

## Interview Talking Points

**"How did you identify these 50+ patterns?"**

> "I studied real-world breaches:
> - Capital One: S3 public + IAM wildcards + No CloudTrail
> - Uber: Hardcoded credentials + Excessive permissions
> - Tesla: Public S3 buckets
> - MongoDB: Public databases + Default credentials
> 
> Then I mapped each breach to specific Terraform misconfigurations.
> Each pattern in TerraSecure corresponds to a real attack vector."

**"Why these resources specifically?"**

> "These 8 resources are involved in 95% of cloud security incidents:
> - S3: Storage (data breaches)
> - Security Groups: Network (unauthorized access)
> - RDS: Databases (data theft)
> - IAM: Permissions (privilege escalation)
> - Lambda: Compute (code execution)
> - VPC: Network (lateral movement)
> - CloudTrail: Auditing (detection)
> 
> Focus on highest-risk resources first - that's where attacks happen."