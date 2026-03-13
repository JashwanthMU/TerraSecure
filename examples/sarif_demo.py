"""
SARIF Demo - Test SARIF Output Generation
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from formatters.sarif_formatter import format_sarif

# Sample findings
findings = [
    {
        'rule_id': 'AWS-S3-PUBLIC',
        'title': 'S3 bucket with public access',
        'description': 'S3 bucket is configured with public ACL allowing anyone to read/write data',
        'severity': 'critical',
        'file': 'examples/vulnerable/public_s3.tf',
        'line': 2,
        'resource': 'aws_s3_bucket.customer_data',
        'ml_risk_score': 0.95,
        'ml_confidence': 0.92,
        'remediation': '''
Change ACL to private and enable block public access:
```hcl
resource "aws_s3_bucket" "customer_data" {
  bucket = "customer-data-bucket"
  acl    = "private"  # Changed from "public-read"
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```
        ''',
        'references': [
            'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html',
            'https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration'
        ],
        'cwe': ['CWE-732']
    },
    {
        'rule_id': 'AWS-S3-ENCRYPTION',
        'title': 'S3 bucket without encryption',
        'description': 'S3 bucket does not have server-side encryption enabled',
        'severity': 'high',
        'file': 'examples/vulnerable/public_s3.tf',
        'line': 2,
        'resource': 'aws_s3_bucket.customer_data',
        'ml_risk_score': 0.82,
        'ml_confidence': 0.88,
        'remediation': 'Enable server-side encryption with AES256 or KMS',
        'references': [
            'https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html'
        ]
    },
    {
        'rule_id': 'AWS-SG-OPEN',
        'title': 'Security group allows traffic from 0.0.0.0/0',
        'description': 'Security group allows inbound traffic from any IP address',
        'severity': 'high',
        'file': 'examples/vulnerable/open_sg.tf',
        'line': 5,
        'resource': 'aws_security_group.web',
        'ml_risk_score': 0.78,
        'ml_confidence': 0.85
    }
]

# Generate SARIF
print(" Generating SARIF output...")
sarif = format_sarif(findings, scan_path="examples", output_path="terrasecure-demo.sarif")

print("\n SARIF generated successfully!")
print(f"\n Summary:")
print(f"   Version: {sarif['version']}")
print(f"   Rules: {len(sarif['runs'][0]['tool']['driver']['rules'])}")
print(f"   Results: {len(sarif['runs'][0]['results'])}")
print(f"\n Saved to: terrasecure-demo.sarif")

# Display sample
import json
print(f"\n Sample (first result):")
print(json.dumps(sarif['runs'][0]['results'][0], indent=2))