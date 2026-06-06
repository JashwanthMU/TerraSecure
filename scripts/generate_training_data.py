import pandas as pd
import random

FEATURE_NAMES = [

    'open_cidr_0_0_0_0', 'open_ssh_port_22', 'open_rdp_port_3389',
    'iam_wildcard_action', 'iam_wildcard_resource', 'iam_inline_user_policy',
    's3_public_acl', 's3_block_public_access_disabled', 's3_versioning_disabled',
    's3_encryption_disabled', 'rds_publicly_accessible', 'rds_storage_unencrypted',
    'ec2_public_ip_associated', 'ebs_unencrypted_volume', 'kms_key_rotation_disabled',
    'cloudtrail_not_enabled', 'cloudwatch_log_retention_missing', 'elb_http_listener_only',
    'lambda_no_vpc_config', 'hardcoded_aws_credentials',
    'sg_all_ports_open', 'sg_egress_unrestricted', 'nacl_allow_all_traffic',
    'vpc_flow_logs_disabled', 'route_to_igw_from_private', 'default_sg_in_use',
    'open_database_port_3306', 'open_database_port_5432', 'root_account_in_use',
    'mfa_not_enabled', 'password_policy_weak', 'unused_iam_credentials',
    's3_bucket_policy_public', 'cross_account_access_unrestricted', 'assume_role_no_external_id',
    's3_lifecycle_policy_missing', 's3_mfa_delete_disabled', 'snapshot_publicly_shared',
    'backup_vault_unencrypted', 'secrets_in_environment_vars', 'config_recorder_disabled',
    'guardduty_not_enabled', 'security_hub_not_enabled', 'access_logging_disabled',
    'alarm_missing_for_changes', 'sns_topic_unencrypted', 'ecr_image_scan_disabled',
    'ecs_task_privilege_escalation', 'api_gateway_no_waf', 'lambda_env_vars_unencrypted'
]

CRITICAL_FEATURES = [
    'open_cidr_0_0_0_0', 'open_ssh_port_22', 'open_rdp_port_3389',
    'iam_wildcard_action', 'iam_wildcard_resource', 's3_public_acl',
    'rds_publicly_accessible', 'hardcoded_aws_credentials', 'sg_all_ports_open',
    'root_account_in_use', 's3_bucket_policy_public', 'snapshot_publicly_shared',
    'secrets_in_environment_vars'
]

HIGH_RISK_FEATURES = [
    's3_encryption_disabled', 'rds_storage_unencrypted', 'ebs_unencrypted_volume',
    'sg_egress_unrestricted', 'open_database_port_3306', 'open_database_port_5432',
    'mfa_not_enabled', 'cross_account_access_unrestricted', 'ecs_task_privilege_escalation'
]

MEDIUM_RISK_FEATURES = [
    's3_versioning_disabled', 'kms_key_rotation_disabled', 'cloudwatch_log_retention_missing',
    'lambda_no_vpc_config', 'vpc_flow_logs_disabled', 'password_policy_weak',
    's3_lifecycle_policy_missing', 'access_logging_disabled'
]

def generate_risky_examples(n=200):
    """Generate risky configurations"""
    examples = []
    
    for _ in range(n):
        features = [0] * 50
        
        if random.random() < 0.7:
            num_critical = random.randint(1, 2)
            critical_indices = [FEATURE_NAMES.index(f) for f in random.sample(CRITICAL_FEATURES, num_critical)]
            for idx in critical_indices:
                features[idx] = 1
        
        if random.random() < 0.5:
            num_high = random.randint(1, 3)
            high_indices = [FEATURE_NAMES.index(f) for f in random.sample(HIGH_RISK_FEATURES, num_high)]
            for idx in high_indices:
                features[idx] = 1
    
        if random.random() < 0.3:
            num_medium = random.randint(1, 2)
            medium_indices = [FEATURE_NAMES.index(f) for f in random.sample(MEDIUM_RISK_FEATURES, num_medium)]
            for idx in medium_indices:
                features[idx] = 1
        
        features.append(1)
        examples.append(features)
    
    return examples

def generate_safe_examples(n=200):
    """Generate safe configurations"""
    examples = []
    
    for _ in range(n):
        features = [0] * 50
        
        if random.random() < 0.2:
            num_issues = random.randint(1, 2)
            issue_indices = [FEATURE_NAMES.index(f) for f in random.sample(MEDIUM_RISK_FEATURES, num_issues)]
            for idx in issue_indices:
                features[idx] = 1

        features.append(0)
        examples.append(features)
    
    return examples

def main():
    """Generate and save 50-feature training data"""
    
    print("=" * 60)
    print("Generating 50-Feature Training Dataset")
    print("=" * 60)

    print("\n Generating data...")
    risky = generate_risky_examples(250)
    safe = generate_safe_examples(250)

    all_data = risky + safe
    random.shuffle(all_data)

    columns = FEATURE_NAMES + ['label']
    df = pd.DataFrame(all_data, columns=columns)

    df.to_csv('data/training_data_50features.csv', index=False)
    
    print(f"\n Dataset Created!")
    print(f"   Total examples: {len(df)}")
    print(f"   Risky: {df['label'].sum()} ({df['label'].sum()/len(df)*100:.1f}%)")
    print(f"   Safe: {len(df) - df['label'].sum()} ({(len(df)-df['label'].sum())/len(df)*100:.1f}%)")
    print(f"   Features: {len(FEATURE_NAMES)}")
    print(f"\n Saved to: data/training_data_50features.csv")
    print("=" * 60)

if __name__ == '__main__':
    main()
