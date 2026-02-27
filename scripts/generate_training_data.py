import pandas as pd
import random

def generate_risky_examples(n=100):
    """Generate risky configurations"""
    examples = []
    
    for _ in range(n):
        # Start with all safe
        features = [0] * 20
        
        # Randomly enable 1-5 risky features
        num_risks = random.randint(1, 5)
        risk_indices = random.sample(range(20), num_risks)
        
        for idx in risk_indices:
            features[idx] = 1
        
        # Add label (1 = risky)
        features.append(1)
        examples.append(features)
    
    return examples

def generate_safe_examples(n=100):
    """Generate safe configurations"""
    examples = []
    
    for _ in range(n):
        # Most features are 0 (safe)
        features = [0] * 20
        
        # Occasionally have 1-2 minor issues
        if random.random() < 0.3:
            minor_issues = random.sample([8, 9, 14, 16, 17], random.randint(1, 2))
            for idx in minor_issues:
                features[idx] = 1
        
        # Add label (0 = safe)
        features.append(0)
        examples.append(features)
    
    return examples

def main():
    """Generate and save training data"""
    
    # Column names
    columns = [
        'open_cidr_0_0_0_0', 'open_ssh_port_22', 'open_rdp_port_3389',
        'iam_wildcard_action', 'iam_wildcard_resource', 'iam_inline_user_policy',
        's3_public_acl', 's3_block_public_access_disabled', 's3_versioning_disabled',
        's3_encryption_disabled', 'rds_publicly_accessible', 'rds_storage_unencrypted',
        'ec2_public_ip_associated', 'ebs_unencrypted_volume', 'kms_key_rotation_disabled',
        'cloudtrail_not_enabled', 'cloudwatch_log_retention_missing', 'elb_http_listener_only',
        'lambda_no_vpc_config', 'hardcoded_aws_credentials', 'label'
    ]
    
    # Generate data
    print("Generating training data...")
    risky = generate_risky_examples(150)
    safe = generate_safe_examples(150)
    
    # Combine
    all_data = risky + safe
    
    # Shuffle
    random.shuffle(all_data)
    
    # Create DataFrame
    df = pd.DataFrame(all_data, columns=columns)
    
    # Save
    df.to_csv('data/training_data.csv', index=False)
    
    print(f"✅ Generated {len(df)} examples")
    print(f"   Risky: {len(risky)}")
    print(f"   Safe: {len(safe)}")
    print(f"   Saved to: data/training_data.csv")

if __name__ == '__main__':
    main()