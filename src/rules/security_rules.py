class SecurityRules:
    """Defines security rules for Terraform resources"""
    
    CRITICAL_RULES = {
        'public_s3_with_sensitive_data': {
            'severity': 'CRITICAL',
            'pattern': {
                'resource_type': 'aws_s3_bucket',
                'conditions': [
                    {'property': 'acl', 'contains': 'public'},
                    {'property': 'bucket', 'contains': ['customer', 'user', 'data', 'backup', 'prod']}
                ]
            },
            'message': 'S3 bucket with sensitive naming is publicly accessible',
            'fix': 'Change acl to "private" and enable encryption'
        },
        'ssh_open_to_world': {
            'severity': 'CRITICAL',
            'pattern': {
                'resource_type': 'aws_security_group',
                'conditions': [
                    {'property': 'from_port', 'equals': 22},
                    {'property': 'cidr_blocks', 'contains': '0.0.0.0/0'}
                ]
            },
            'message': 'SSH port (22) open to entire internet',
            'fix': 'Restrict cidr_blocks to specific IP ranges'
        },
        'rdp_open_to_world': {
            'severity': 'CRITICAL',
            'pattern': {
                'resource_type': 'aws_security_group',
                'conditions': [
                    {'property': 'from_port', 'equals': 3389},
                    {'property': 'cidr_blocks', 'contains': '0.0.0.0/0'}
                ]
            },
            'message': 'RDP port (3389) open to entire internet',
            'fix': 'Restrict cidr_blocks to specific IP ranges'
        },
        'public_rds': {
            'severity': 'CRITICAL',
            'pattern': {
                'resource_type': 'aws_db_instance',
                'conditions': [
                    {'property': 'publicly_accessible', 'equals': True}
                ]
            },
            'message': 'RDS database is publicly accessible',
            'fix': 'Set publicly_accessible = false'
        }
    }
    
    HIGH_RULES = {
        'unencrypted_s3': {
            'severity': 'HIGH',
            'pattern': {
                'resource_type': 'aws_s3_bucket',
                'conditions': [
                    {'property': 'server_side_encryption_configuration', 'absent': True}
                ]
            },
            'message': 'S3 bucket does not have encryption enabled',
            'fix': 'Add server_side_encryption_configuration block'
        },
        'unencrypted_rds': {
            'severity': 'HIGH',
            'pattern': {
                'resource_type': 'aws_db_instance',
                'conditions': [
                    {'property': 'storage_encrypted', 'equals': False}
                ]
            },
            'message': 'RDS instance does not have encryption enabled',
            'fix': 'Set storage_encrypted = true'
        },
        'public_s3_general': {
            'severity': 'HIGH',
            'pattern': {
                'resource_type': 'aws_s3_bucket',
                'conditions': [
                    {'property': 'acl', 'contains': 'public'}
                ]
            },
            'message': 'S3 bucket has public access enabled',
            'fix': 'Review if public access is intentional, consider CloudFront with private bucket'
        }
    }
    
    MEDIUM_RULES = {
        'no_versioning': {
            'severity': 'MEDIUM',
            'pattern': {
                'resource_type': 'aws_s3_bucket',
                'conditions': [
                    {'property': 'versioning', 'absent': True}
                ]
            },
            'message': 'S3 bucket does not have versioning enabled',
            'fix': 'Add versioning { enabled = true }'
        },
        'no_backup': {
            'severity': 'MEDIUM',
            'pattern': {
                'resource_type': 'aws_db_instance',
                'conditions': [
                    {'property': 'backup_retention_period', 'less_than': 7}
                ]
            },
            'message': 'RDS backup retention is less than 7 days',
            'fix': 'Set backup_retention_period = 7 or higher'
        }
    }
    
    @classmethod
    def get_all_rules(cls):
        """Get all rules combined"""
        return {
            **cls.CRITICAL_RULES,
            **cls.HIGH_RULES,
            **cls.MEDIUM_RULES
        }
    
    @classmethod
    def get_severity_color(cls, severity):
        """Get color code for severity"""
        colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow
            'MEDIUM': '\033[94m',    # Blue
            'LOW': '\033[92m',       # Green
            'PASS': '\033[92m'       # Green
        }
        return colors.get(severity, '\033[0m')