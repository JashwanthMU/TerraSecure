"""
Security Rules for TerraSecure
-------------------------------
Collection of security rules for detecting misconfigurations
"""

from typing import Dict, Any, Optional


class SecurityRules:
    """
    Security rules for Terraform resource analysis
    
    Each rule is a function that:
    - Takes a resource dict as input
    - Returns a finding dict if violation found
    - Returns None if no violation
    """
    
    def __init__(self):
        """Initialize all security rules"""
        pass
    
    def items(self):
        """
        Return all rules as (name, function) tuples
        
        This allows iteration: for rule_name, rule_func in rules.items()
        """
        return [
            ('public_s3_with_sensitive_data', self.check_public_s3_sensitive),
            ('public_s3_general', self.check_public_s3),
            ('unencrypted_s3', self.check_unencrypted_s3),
            ('no_versioning', self.check_no_versioning),
            ('ssh_open_to_world', self.check_ssh_open),
            ('rdp_open_to_world', self.check_rdp_open),
            ('public_rds', self.check_public_rds),
            ('unencrypted_rds', self.check_unencrypted_rds),
            ('no_backup', self.check_no_backup),
            ('wildcard_iam', self.check_wildcard_iam),
            ('security_group_all_open', self.check_sg_all_open),
        ]
    
    def get_all_rules(self):
        """Return rules as dict for compatibility"""
        return dict(self.items())
    
    # S3 Security Rules
    
    def check_public_s3_sensitive(self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for public S3 buckets with sensitive naming"""
        if resource.get('type') != 'aws_s3_bucket':
            return None
        
        props = resource.get('properties', {})
        bucket_name = resource.get('name', '').lower()
        
        # Check if bucket has sensitive naming
        sensitive_keywords = ['customer', 'user', 'data', 'private', 'secret', 'personal']
        is_sensitive = any(keyword in bucket_name for keyword in sensitive_keywords)
        
        # Check if bucket is public
        acl = props.get('acl', '').lower()
        is_public = acl in ['public-read', 'public-read-write']
        
        if is_sensitive and is_public:
            return {
                'severity': 'CRITICAL',
                'message': f'S3 bucket with sensitive naming is publicly accessible',
                'file': resource.get('file', 'unknown'),
                'line': resource.get('line', 0),
                'remediation': 'Set acl = "private" and enable block_public_access'
            }
        
        return None
    
    def check_public_s3(self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for public S3 buckets"""
        if resource.get('type') != 'aws_s3_bucket':
            return None
        
        props = resource.get('properties', {})
        acl = props.get('acl', '').lower()
        
        if acl in ['public-read', 'public-read-write']:
            return {
                'severity': 'HIGH',
                'message': 'S3 bucket has public access enabled',
                'file': resource.get('file', 'unknown'),
                'line': resource.get('line', 0),
                'remediation': 'Set acl = "private" and enable block_public_access'
            }
        
        return None
    
    def check_unencrypted_s3(self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for S3 buckets without encryption"""
        if resource.get('type') != 'aws_s3_bucket':
            return None
        
        props = resource.get('properties', {})
        encryption = props.get('server_side_encryption_configuration')
        
        if not encryption:
            return {
                'severity': 'HIGH',
                'message': 'S3 bucket does not have encryption enabled',
                'file': resource.get('file', 'unknown'),
                'line': resource.get('line', 0),
                'remediation': 'Enable server_side_encryption_configuration with AES256 or aws:kms'
            }
        
        return None
    
    def check_no_versioning(self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for S3 buckets without versioning"""
        if resource.get('type') != 'aws_s3_bucket':
            return None
        
        props = resource.get('properties', {})
        versioning = props.get('versioning', {})
        
        if not versioning or not versioning.get('enabled'):
            return {
                'severity': 'MEDIUM',
                'message': 'S3 bucket does not have versioning enabled',
                'file': resource.get('file', 'unknown'),
                'line': resource.get('line', 0),
                'remediation': 'Enable versioning to protect against accidental deletion'
            }
        
        return None
    
    # Security Group Rules
    
    def check_ssh_open(self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for SSH open to the world"""
        if resource.get('type') != 'aws_security_group':
            return None
        
        props = resource.get('properties', {})
        ingress_rules = props.get('ingress', [])
        
        if not isinstance(ingress_rules, list):
            ingress_rules = [ingress_rules] if ingress_rules else []
        
        for rule in ingress_rules:
            if not isinstance(rule, dict):
                continue
            
            from_port = rule.get('from_port')
            to_port = rule.get('to_port')
            cidr_blocks = rule.get('cidr_blocks', [])
            
            # Check if SSH (port 22) is open to 0.0.0.0/0
            if (from_port == 22 or to_port == 22) and '0.0.0.0/0' in cidr_blocks:
                return {
                    'severity': 'CRITICAL',
                    'message': 'SSH (port 22) is open to the world (0.0.0.0/0)',
                    'file': resource.get('file', 'unknown'),
                    'line': resource.get('line', 0),
                    'remediation': 'Restrict SSH access to specific IP addresses or use a VPN'
                }
        
        return None
    
    def check_rdp_open(self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for RDP open to the world"""
        if resource.get('type') != 'aws_security_group':
            return None
        
        props = resource.get('properties', {})
        ingress_rules = props.get('ingress', [])
        
        if not isinstance(ingress_rules, list):
            ingress_rules = [ingress_rules] if ingress_rules else []
        
        for rule in ingress_rules:
            if not isinstance(rule, dict):
                continue
            
            from_port = rule.get('from_port')
            to_port = rule.get('to_port')
            cidr_blocks = rule.get('cidr_blocks', [])
            
            # Check if RDP (port 3389) is open to 0.0.0.0/0
            if (from_port == 3389 or to_port == 3389) and '0.0.0.0/0' in cidr_blocks:
                return {
                    'severity': 'CRITICAL',
                    'message': 'RDP (port 3389) is open to the world (0.0.0.0/0)',
                    'file': resource.get('file', 'unknown'),
                    'line': resource.get('line', 0),
                    'remediation': 'Restrict RDP access to specific IP addresses or use a VPN'
                }
        
        return None
    
    def check_sg_all_open(self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for security groups with all ports open"""
        if resource.get('type') != 'aws_security_group':
            return None
        
        props = resource.get('properties', {})
        ingress_rules = props.get('ingress', [])
        
        if not isinstance(ingress_rules, list):
            ingress_rules = [ingress_rules] if ingress_rules else []
        
        for rule in ingress_rules:
            if not isinstance(rule, dict):
                continue
            
            from_port = rule.get('from_port', 0)
            to_port = rule.get('to_port', 0)
            cidr_blocks = rule.get('cidr_blocks', [])
            
            # Check if all ports (0-65535) are open to 0.0.0.0/0
            if from_port == 0 and to_port == 65535 and '0.0.0.0/0' in cidr_blocks:
                return {
                    'severity': 'CRITICAL',
                    'message': 'Security group allows all traffic from the world',
                    'file': resource.get('file', 'unknown'),
                    'line': resource.get('line', 0),
                    'remediation': 'Restrict security group to specific ports and IP ranges'
                }
        
        return None
    
    # RDS Security Rules
    
    def check_public_rds(self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for publicly accessible RDS instances"""
        if resource.get('type') != 'aws_db_instance':
            return None
        
        props = resource.get('properties', {})
        publicly_accessible = props.get('publicly_accessible', False)
        
        if publicly_accessible:
            return {
                'severity': 'CRITICAL',
                'message': 'RDS database instance is publicly accessible',
                'file': resource.get('file', 'unknown'),
                'line': resource.get('line', 0),
                'remediation': 'Set publicly_accessible = false and use VPC/security groups'
            }
        
        return None
    
    def check_unencrypted_rds(self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for unencrypted RDS instances"""
        if resource.get('type') != 'aws_db_instance':
            return None
        
        props = resource.get('properties', {})
        storage_encrypted = props.get('storage_encrypted', False)
        
        if not storage_encrypted:
            return {
                'severity': 'HIGH',
                'message': 'RDS database instance does not have encryption enabled',
                'file': resource.get('file', 'unknown'),
                'line': resource.get('line', 0),
                'remediation': 'Set storage_encrypted = true and specify a KMS key'
            }
        
        return None
    
    def check_no_backup(self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for RDS instances without automated backups"""
        if resource.get('type') != 'aws_db_instance':
            return None
        
        props = resource.get('properties', {})
        backup_retention = props.get('backup_retention_period', 0)
        
        if backup_retention == 0:
            return {
                'severity': 'MEDIUM',
                'message': 'RDS instance does not have automated backups enabled',
                'file': resource.get('file', 'unknown'),
                'line': resource.get('line', 0),
                'remediation': 'Set backup_retention_period to at least 7 days'
            }
        
        return None
    
    # IAM Security Rules
    
    def check_wildcard_iam(self, resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for overly permissive IAM policies"""
        if 'iam_policy' not in resource.get('type', ''):
            return None
        
        props = resource.get('properties', {})
        policy = props.get('policy', '')
        
        # Check for wildcards in policy
        if '*' in str(policy):
            return {
                'severity': 'HIGH',
                'message': 'IAM policy contains wildcard (*) permissions',
                'file': resource.get('file', 'unknown'),
                'line': resource.get('line', 0),
                'remediation': 'Use specific actions and resources instead of wildcards'
            }
        
        return None