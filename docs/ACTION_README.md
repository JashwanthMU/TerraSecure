# TerraSecure GitHub Action

AI-Powered Terraform Security Scanner with ML risk scoring and GitHub Security integration.

## Features

-  **ML-Powered**: 92% accuracy with pre-trained model
-  **AI Explanations**: Business impact and attack scenarios  
-  **SARIF Output**: Integrates with GitHub Security tab
-  **Fast**: <100ms per resource
-  **Offline**: No external API dependencies
-  **Easy**: One-line integration

## Usage

### Basic Usage
```yaml
name: Security Scan
on: [push, pull_request]

permissions:
  security-events: write  # Required for SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run TerraSecure
        uses: JashwanthMU/TerraSecure@v1
```

### Advanced Usage
```yaml
- name: Run TerraSecure
  uses: JashwanthMU/TerraSecure@v1
  with:
    path: 'infrastructure'           # Path to scan (default: '.')
    format: 'sarif'                  # Output format (default: 'sarif')
    output: 'results.sarif'          # Output file (default: 'terrasecure.sarif')
    fail-on: 'high'                  # Fail on severity (default: 'critical')
    upload-sarif: 'true'             # Upload to Security tab (default: 'true')
```

### Multiple Paths
```yaml
- name: Scan Infrastructure
  uses: JashwanthMU/TerraSecure@v1
  with:
    path: 'infrastructure'
    output: 'infra-results.sarif'

- name: Scan Modules
  uses: JashwanthMU/TerraSecure@v1
  with:
    path: 'modules'
    output: 'modules-results.sarif'
```

### With PR Comments
```yaml
- name: Run TerraSecure
  id: terrasecure
  uses: JashwanthMU/TerraSecure@v1

- name: Comment on PR
  if: github.event_name == 'pull_request'
  uses: actions/github-script@v7
  with:
    script: |
      const issues = '${{ steps.terrasecure.outputs.issues-found }}';
      const critical = '${{ steps.terrasecure.outputs.critical-count }}';
      
      const comment = `##  TerraSecure Scan Results\n\n` +
        `**Issues Found:** ${issues}\n` +
        `**Critical:** ${critical}\n\n` +
        `View details in the [Security tab](https://github.com/${{ github.repository }}/security/code-scanning).`;
      
      github.rest.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        body: comment
      });
```

## Inputs

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `path` | Path to Terraform files | `.` | No |
| `format` | Output format (text, json, sarif) | `sarif` | No |
| `output` | Output file path | `terrasecure.sarif` | No |
| `fail-on` | Fail on severity (critical, high, medium, any) | `critical` | No |
| `upload-sarif` | Upload to GitHub Security | `true` | No |
| `github-token` | GitHub token for upload | `${{ github.token }}` | No |

## Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to generated SARIF file |
| `issues-found` | Total number of issues |
| `critical-count` | Number of critical issues |

## Permissions Required
```yaml
permissions:
  contents: read
  security-events: write  # For SARIF upload
  pull-requests: write    # For PR comments (optional)
```

## Examples

### Fail on High Severity
```yaml
- uses: JashwanthMU/TerraSecure@v1
  with:
    fail-on: 'high'  # Will fail if high or critical issues found
```

### Scan Specific Directory
```yaml
- uses: JashwanthMU/TerraSecure@v1
  with:
    path: 'terraform/production'
```

### JSON Output
```yaml
- uses: JashwanthMU/TerraSecure@v1
  with:
    format: 'json'
    output: 'report.json'
    upload-sarif: 'false'
```

## What Gets Scanned

TerraSecure checks for:

-  **Critical**: Public S3 buckets, open security groups, IAM wildcards
-  **High**: Unencrypted storage, public databases, hardcoded secrets
-  **Medium**: Missing logging, disabled monitoring, weak policies

## Security Features

-  ML risk scoring (50 security features)
-  Real-world breach pattern detection (Capital One, Uber, Tesla)
-  Business impact analysis
-  Attack scenario descriptions
-  Step-by-step remediation
