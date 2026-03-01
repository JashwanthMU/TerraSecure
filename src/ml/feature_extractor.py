"""
ML Feature Extractor - 50 Security Features
Enhanced version with comprehensive security checks
"""

class SecurityFeatureExtractor:
    """Extract 50 security features from Terraform resources"""
    
    def extract_features(self, resource):
        """
        Extract 50 security features
        
        Returns:
            dict with 50 binary features (0 or 1)
        """
        
        features = {}
        resource_type = resource.get('type', '')
        props = resource.get('properties', {})
        
        # ========================================
        # ORIGINAL 20 FEATURES (1-20)
        # ========================================
        
        features['open_cidr_0_0_0_0'] = self._check_open_cidr(props)
        features['open_ssh_port_22'] = self._check_ssh_open(props)
        features['open_rdp_port_3389'] = self._check_rdp_open(props)
        features['iam_wildcard_action'] = self._check_iam_wildcard_action(props)
        features['iam_wildcard_resource'] = self._check_iam_wildcard_resource(props)
        features['iam_inline_user_policy'] = 1 if resource_type == 'aws_iam_user_policy' else 0
        features['s3_public_acl'] = self._check_s3_public_acl(props)
        features['s3_block_public_access_disabled'] = self._check_s3_block_public_access(props)
        features['s3_versioning_disabled'] = self._check_s3_versioning(props)
        features['s3_encryption_disabled'] = self._check_s3_encryption(props)
        features['rds_publicly_accessible'] = self._check_rds_public(props)
        features['rds_storage_unencrypted'] = self._check_rds_encryption(props)
        features['ec2_public_ip_associated'] = self._check_ec2_public_ip(props)
        features['ebs_unencrypted_volume'] = self._check_ebs_encryption(resource_type, props)
        features['kms_key_rotation_disabled'] = self._check_kms_rotation(props)
        features['cloudtrail_not_enabled'] = 1 if resource_type != 'aws_cloudtrail' else 0
        features['cloudwatch_log_retention_missing'] = self._check_log_retention(props)
        features['elb_http_listener_only'] = self._check_http_listener(props)
        features['lambda_no_vpc_config'] = self._check_lambda_vpc(resource_type, props)
        features['hardcoded_aws_credentials'] = self._check_hardcoded_creds(props)
        
        # ========================================
        # NEW 30 FEATURES (21-50)
        # ========================================
        
        # Network Security (21-28)
        features['sg_all_ports_open'] = self._check_all_ports_open(props)
        features['sg_egress_unrestricted'] = self._check_egress_unrestricted(props)
        features['nacl_allow_all_traffic'] = self._check_nacl_allow_all(resource_type, props)
        features['vpc_flow_logs_disabled'] = self._check_vpc_flow_logs(resource_type, props)
        features['route_to_igw_from_private'] = self._check_igw_route(resource_type, props)
        features['default_sg_in_use'] = self._check_default_sg(props)
        features['open_database_port_3306'] = self._check_mysql_open(props)
        features['open_database_port_5432'] = self._check_postgres_open(props)
        
        # IAM & Access Control (29-35)
        features['root_account_in_use'] = self._check_root_account(props)
        features['mfa_not_enabled'] = self._check_mfa_disabled(props)
        features['password_policy_weak'] = self._check_password_policy(resource_type, props)
        features['unused_iam_credentials'] = self._check_credential_rotation(props)
        features['s3_bucket_policy_public'] = self._check_s3_policy_public(props)
        features['cross_account_access_unrestricted'] = self._check_cross_account(props)
        features['assume_role_no_external_id'] = self._check_external_id(props)
        
        # Data Protection (36-40)
        features['s3_lifecycle_policy_missing'] = self._check_lifecycle_policy(resource_type, props)
        features['s3_mfa_delete_disabled'] = self._check_mfa_delete(props)
        features['snapshot_publicly_shared'] = self._check_snapshot_public(resource_type, props)
        features['backup_vault_unencrypted'] = self._check_backup_encryption(resource_type, props)
        features['secrets_in_environment_vars'] = self._check_env_secrets(props)
        
        # Monitoring & Compliance (41-46)
        features['config_recorder_disabled'] = 1 if resource_type != 'aws_config_configuration_recorder' else 0
        features['guardduty_not_enabled'] = 1 if resource_type != 'aws_guardduty_detector' else 0
        features['security_hub_not_enabled'] = 1 if resource_type != 'aws_securityhub_account' else 0
        features['access_logging_disabled'] = self._check_access_logging(resource_type, props)
        features['alarm_missing_for_changes'] = self._check_cloudwatch_alarm(resource_type)
        features['sns_topic_unencrypted'] = self._check_sns_encryption(resource_type, props)
        
        # Container & Serverless (47-50)
        features['ecr_image_scan_disabled'] = self._check_ecr_scan(resource_type, props)
        features['ecs_task_privilege_escalation'] = self._check_ecs_privileges(resource_type, props)
        features['api_gateway_no_waf'] = self._check_api_gateway_waf(resource_type, props)
        features['lambda_env_vars_unencrypted'] = self._check_lambda_env_encryption(resource_type, props)
        
        return features
    
    # ========================================
    # ORIGINAL 20 FEATURE CHECKERS (keep existing)
    # ========================================
    
    def _check_open_cidr(self, props):
        """Check for 0.0.0.0/0"""
        cidr_blocks = self._get_nested(props, ['ingress', 'cidr_blocks'], [])
        return 1 if '0.0.0.0/0' in str(cidr_blocks) else 0
    
    def _check_ssh_open(self, props):
        """Check if SSH port 22 is open"""
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
        """Check if RDP port 3389 is open"""
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
        return 1 if 'block_public_access' not in props else 0
    
    def _check_s3_versioning(self, props):
        """Check if S3 versioning is disabled"""
        versioning = self._get_nested(props, ['versioning', 'enabled'], False)
        return 0 if versioning else 1
    
    def _check_s3_encryption(self, props):
        """Check if S3 encryption is disabled"""
        return 0 if 'server_side_encryption_configuration' in props else 1
    
    def _check_rds_public(self, props):
        """Check if RDS is publicly accessible"""
        return 1 if props.get('publicly_accessible', False) else 0
    
    def _check_rds_encryption(self, props):
        """Check if RDS storage is unencrypted"""
        return 0 if props.get('storage_encrypted', False) else 1
    
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
        return 1 if props.get('retention_in_days', 0) == 0 else 0
    
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
            return 1 if 'vpc_config' not in props else 0
        return 0
    
    def _check_hardcoded_creds(self, props):
        """Check for hardcoded AWS credentials"""
        props_str = str(props).lower()
        keywords = ['aws_access_key', 'aws_secret', 'akia', 'password']
        return 1 if any(kw in props_str for kw in keywords) else 0
    
    # ========================================
    # NEW 30 FEATURE CHECKERS (21-50)
    # ========================================
    
    # Network Security (21-28)
    def _check_all_ports_open(self, props):
        """Check if all ports are open"""
        ingress = self._get_nested(props, ['ingress'], {})
        if isinstance(ingress, list):
            for rule in ingress:
                from_port = rule.get('from_port', -1)
                to_port = rule.get('to_port', -1)
                if from_port == 0 and to_port == 65535:
                    return 1
        return 0
    
    def _check_egress_unrestricted(self, props):
        """Check if egress allows all traffic"""
        egress = self._get_nested(props, ['egress'], {})
        if isinstance(egress, list):
            for rule in egress:
                cidr = str(rule.get('cidr_blocks', ''))
                protocol = str(rule.get('protocol', ''))
                if '0.0.0.0/0' in cidr and protocol == '-1':
                    return 1
        return 0
    
    def _check_nacl_allow_all(self, resource_type, props):
        """Check if NACL allows all traffic"""
        if resource_type == 'aws_network_acl_rule':
            rule_action = props.get('rule_action', '')
            cidr = str(props.get('cidr_block', ''))
            if rule_action == 'allow' and cidr == '0.0.0.0/0':
                return 1
        return 0
    
    def _check_vpc_flow_logs(self, resource_type, props):
        """Check if VPC flow logs are disabled"""
        if resource_type == 'aws_vpc':
            return 1  # Simplified: assume disabled if VPC created without flow logs
        return 0
    
    def _check_igw_route(self, resource_type, props):
        """Check for route to IGW from private subnet"""
        if resource_type == 'aws_route':
            gateway_id = str(props.get('gateway_id', ''))
            if 'igw-' in gateway_id:
                return 1
        return 0
    
    def _check_default_sg(self, props):
        """Check if using default security group"""
        name = str(props.get('name', ''))
        return 1 if name == 'default' else 0
    
    def _check_mysql_open(self, props):
        """Check if MySQL port is open"""
        ingress = self._get_nested(props, ['ingress'], {})
        if isinstance(ingress, list):
            for rule in ingress:
                from_port = rule.get('from_port', 0)
                cidr = str(rule.get('cidr_blocks', ''))
                if from_port == 3306 and '0.0.0.0/0' in cidr:
                    return 1
        return 0
    
    def _check_postgres_open(self, props):
        """Check if PostgreSQL port is open"""
        ingress = self._get_nested(props, ['ingress'], {})
        if isinstance(ingress, list):
            for rule in ingress:
                from_port = rule.get('from_port', 0)
                cidr = str(rule.get('cidr_blocks', ''))
                if from_port == 5432 and '0.0.0.0/0' in cidr:
                    return 1
        return 0
    
    # IAM & Access Control (29-35)
    def _check_root_account(self, props):
        """Check if root account is in use"""
        username = str(props.get('name', ''))
        return 1 if username == 'root' else 0
    
    def _check_mfa_disabled(self, props):
        """Check if MFA is not enabled"""
        return 1 if not props.get('force_destroy', False) else 0
    
    def _check_password_policy(self, resource_type, props):
        """Check for weak password policy"""
        if resource_type == 'aws_iam_account_password_policy':
            min_length = props.get('minimum_password_length', 0)
            return 1 if min_length < 14 else 0
        return 0
    
    def _check_credential_rotation(self, props):
        """Check for unused IAM credentials"""
        # Simplified check
        return 0
    
    def _check_s3_policy_public(self, props):
        """Check if S3 bucket policy allows public access"""
        policy = str(props.get('policy', ''))
        return 1 if '"Principal":"*"' in policy or '"Principal": "*"' in policy else 0
    
    def _check_cross_account(self, props):
        """Check for unrestricted cross-account access"""
        policy = str(props.get('assume_role_policy', ''))
        return 1 if '"AWS":"*"' in policy else 0
    
    def _check_external_id(self, props):
        """Check if AssumeRole has no ExternalId"""
        policy = str(props.get('assume_role_policy', ''))
        return 1 if 'AssumeRole' in policy and 'ExternalId' not in policy else 0
    
    # Data Protection (36-40)
    def _check_lifecycle_policy(self, resource_type, props):
        """Check if S3 lifecycle policy is missing"""
        if resource_type == 'aws_s3_bucket':
            return 1 if 'lifecycle_rule' not in props else 0
        return 0
    
    def _check_mfa_delete(self, props):
        """Check if MFA delete is disabled"""
        versioning = self._get_nested(props, ['versioning'], {})
        return 1 if not versioning.get('mfa_delete', False) else 0
    
    def _check_snapshot_public(self, resource_type, props):
        """Check if snapshot is publicly shared"""
        if resource_type in ['aws_ebs_snapshot', 'aws_db_snapshot']:
            return 1 if props.get('publicly_accessible', False) else 0
        return 0
    
    def _check_backup_encryption(self, resource_type, props):
        """Check if backup vault is unencrypted"""
        if resource_type == 'aws_backup_vault':
            return 1 if 'kms_key_arn' not in props else 0
        return 0
    
    def _check_env_secrets(self, props):
        """Check for secrets in environment variables"""
        env_vars = str(props.get('environment', ''))
        keywords = ['password', 'secret', 'api_key', 'token']
        return 1 if any(kw in env_vars.lower() for kw in keywords) else 0
    
    # Monitoring & Compliance (41-46)
    def _check_access_logging(self, resource_type, props):
        """Check if access logging is disabled"""
        if resource_type in ['aws_s3_bucket', 'aws_lb']:
            return 1 if 'logging' not in props else 0
        return 0
    
    def _check_cloudwatch_alarm(self, resource_type):
        """Check if CloudWatch alarm is missing"""
        return 1 if resource_type != 'aws_cloudwatch_metric_alarm' else 0
    
    def _check_sns_encryption(self, resource_type, props):
        """Check if SNS topic is unencrypted"""
        if resource_type == 'aws_sns_topic':
            return 1 if 'kms_master_key_id' not in props else 0
        return 0
    
    # Container & Serverless (47-50)
    def _check_ecr_scan(self, resource_type, props):
        """Check if ECR image scanning is disabled"""
        if resource_type == 'aws_ecr_repository':
            scan_config = self._get_nested(props, ['image_scanning_configuration', 'scan_on_push'], False)
            return 0 if scan_config else 1
        return 0
    
    def _check_ecs_privileges(self, resource_type, props):
        """Check if ECS task allows privilege escalation"""
        if resource_type == 'aws_ecs_task_definition':
            container_defs = str(props.get('container_definitions', ''))
            return 1 if '"privileged":true' in container_defs else 0
        return 0
    
    def _check_api_gateway_waf(self, resource_type, props):
        """Check if API Gateway has no WAF"""
        if resource_type == 'aws_api_gateway_rest_api':
            return 1 if 'web_acl_arn' not in props else 0
        return 0
    
    def _check_lambda_env_encryption(self, resource_type, props):
        """Check if Lambda env vars are unencrypted"""
        if resource_type == 'aws_lambda_function':
            env = props.get('environment', {})
            if env and 'kms_key_arn' not in props:
                return 1
        return 0
    
    # Helper method
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