class SecurityFeatureExtractor:
    """Extract ML features from Terraform resources"""
    
    def extract_features(self, resource):
        """
        Extract 20 security features
        
        Returns:
            dict with 20 binary features (0 or 1)
        """
        
        features = {}
        resource_type = resource.get('type', '')
        props = resource.get('properties', {})
        
        # Feature 1: open_cidr_0_0_0_0
        features['open_cidr_0_0_0_0'] = self._check_open_cidr(props)
        
        # Feature 2: open_ssh_port_22
        features['open_ssh_port_22'] = self._check_ssh_open(props)
        
        # Feature 3: open_rdp_port_3389
        features['open_rdp_port_3389'] = self._check_rdp_open(props)
        
        # Feature 4: iam_wildcard_action
        features['iam_wildcard_action'] = self._check_iam_wildcard_action(props)
        
        # Feature 5: iam_wildcard_resource
        features['iam_wildcard_resource'] = self._check_iam_wildcard_resource(props)
        
        # Feature 6: iam_inline_user_policy
        features['iam_inline_user_policy'] = 1 if resource_type == 'aws_iam_user_policy' else 0
        
        # Feature 7: s3_public_acl
        features['s3_public_acl'] = self._check_s3_public_acl(props)
        
        # Feature 8: s3_block_public_access_disabled
        features['s3_block_public_access_disabled'] = self._check_s3_block_public_access(props)
        
        # Feature 9: s3_versioning_disabled
        features['s3_versioning_disabled'] = self._check_s3_versioning(props)
        
        # Feature 10: s3_encryption_disabled
        features['s3_encryption_disabled'] = self._check_s3_encryption(props)
        
        # Feature 11: rds_publicly_accessible
        features['rds_publicly_accessible'] = self._check_rds_public(props)
        
        # Feature 12: rds_storage_unencrypted
        features['rds_storage_unencrypted'] = self._check_rds_encryption(props)
        
        # Feature 13: ec2_public_ip_associated
        features['ec2_public_ip_associated'] = self._check_ec2_public_ip(props)
        
        # Feature 14: ebs_unencrypted_volume
        features['ebs_unencrypted_volume'] = self._check_ebs_encryption(resource_type, props)
        
        # Feature 15: kms_key_rotation_disabled
        features['kms_key_rotation_disabled'] = self._check_kms_rotation(props)
        
        # Feature 16: cloudtrail_not_enabled
        features['cloudtrail_not_enabled'] = 1 if resource_type != 'aws_cloudtrail' else 0
        
        # Feature 17: cloudwatch_log_retention_missing
        features['cloudwatch_log_retention_missing'] = self._check_log_retention(props)
        
        # Feature 18: elb_http_listener_only
        features['elb_http_listener_only'] = self._check_http_listener(props)
        
        # Feature 19: lambda_no_vpc_config
        features['lambda_no_vpc_config'] = self._check_lambda_vpc(resource_type, props)
        
        # Feature 20: hardcoded_aws_credentials
        features['hardcoded_aws_credentials'] = self._check_hardcoded_creds(props)
        
        return features
    
    def _check_open_cidr(self, props):
        """Check for 0.0.0.0/0"""
        cidr_blocks = self._get_nested(props, ['ingress', 'cidr_blocks'], [])
        if isinstance(cidr_blocks, list):
            return 1 if '0.0.0.0/0' in str(cidr_blocks) else 0
        return 0
    
    def _check_ssh_open(self, props):
        """Check if SSH port 22 is open to public"""
        ingress = self._get_nested(props, ['ingress'], {})
        if isinstance(ingress, list):
            for rule in ingress:
                from_port = rule.get('from_port', 0)
                to_port = rule.get('to_port', 0)
                cidr = str(rule.get('cidr_blocks', ''))
                if (from_port == 22 or to_port == 22) and '0.0.0.0/0' in cidr:
                    return 1
        return 0
    
    def _check_rdp_open(self, props):
        """Check if RDP port 3389 is open to public"""
        ingress = self._get_nested(props, ['ingress'], {})
        if isinstance(ingress, list):
            for rule in ingress:
                from_port = rule.get('from_port', 0)
                to_port = rule.get('to_port', 0)
                cidr = str(rule.get('cidr_blocks', ''))
                if (from_port == 3389 or to_port == 3389) and '0.0.0.0/0' in cidr:
                    return 1
        return 0
    
    def _check_iam_wildcard_action(self, props):
        """Check for IAM Action = '*'"""
        policy_str = str(props.get('policy', ''))
        return 1 if '"Action":"*"' in policy_str or '"Action": "*"' in policy_str else 0
    
    def _check_iam_wildcard_resource(self, props):
        """Check for IAM Resource = '*'"""
        policy_str = str(props.get('policy', ''))
        return 1 if '"Resource":"*"' in policy_str or '"Resource": "*"' in policy_str else 0
    
    def _check_s3_public_acl(self, props):
        """Check for public S3 ACL"""
        acl = props.get('acl', '')
        return 1 if 'public' in str(acl).lower() else 0
    
    def _check_s3_block_public_access(self, props):
        """Check if S3 block public access is disabled"""
        block_config = self._get_nested(props, ['block_public_access'], None)
        if block_config is None:
            return 1  # Not configured = risky
        return 0
    
    def _check_s3_versioning(self, props):
        """Check if S3 versioning is disabled"""
        versioning = self._get_nested(props, ['versioning', 'enabled'], False)
        return 0 if versioning else 1
    
    def _check_s3_encryption(self, props):
        """Check if S3 encryption is disabled"""
        encryption = self._get_nested(props, ['server_side_encryption_configuration'], None)
        return 0 if encryption else 1
    
    def _check_rds_public(self, props):
        """Check if RDS is publicly accessible"""
        return 1 if props.get('publicly_accessible', False) else 0
    
    def _check_rds_encryption(self, props):
        """Check if RDS storage is unencrypted"""
        encrypted = props.get('storage_encrypted', False)
        return 0 if encrypted else 1
    
    def _check_ec2_public_ip(self, props):
        """Check if EC2 has public IP"""
        return 1 if props.get('associate_public_ip_address', False) else 0
    
    def _check_ebs_encryption(self, resource_type, props):
        """Check if EBS volume is unencrypted"""
        if resource_type == 'aws_ebs_volume':
            return 0 if props.get('encrypted', False) else 1
        return 0
    
    def _check_kms_rotation(self, props):
        """Check if KMS key rotation is disabled"""
        return 0 if props.get('enable_key_rotation', False) else 1
    
    def _check_log_retention(self, props):
        """Check if CloudWatch log retention is missing"""
        retention = props.get('retention_in_days', 0)
        return 1 if retention == 0 else 0
    
    def _check_http_listener(self, props):
        """Check if ELB uses HTTP instead of HTTPS"""
        listener = self._get_nested(props, ['listener'], {})
        if isinstance(listener, list):
            for l in listener:
                if l.get('protocol', '').upper() == 'HTTP':
                    return 1
        return 0
    
    def _check_lambda_vpc(self, resource_type, props):
        """Check if Lambda has no VPC config"""
        if resource_type == 'aws_lambda_function':
            vpc_config = props.get('vpc_config', None)
            return 1 if vpc_config is None else 0
        return 0
    
    def _check_hardcoded_creds(self, props):
        """Check for hardcoded AWS credentials"""
        props_str = str(props).lower()
        keywords = ['aws_access_key_id', 'aws_secret_access_key', 'akia', 'password']
        return 1 if any(kw in props_str for kw in keywords) else 0
    
    def _get_nested(self, d, keys, default=None):
        """Safely get nested dictionary value"""
        for key in keys:
            if isinstance(d, dict):
                d = d.get(key, default)
            elif isinstance(d, list) and d:
                d = d[0].get(key, default) if isinstance(d[0], dict) else default
            else:
                return default
        return d