<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://img.shields.io/badge/🛡️_TERRASECURE-AI_Powered_Security_Scanner-4A90E2?style=for-the-badge&labelColor=1a1a1a&logoColor=white">
  <img alt="TerraSecure" src="https://img.shields.io/badge/🛡️_TERRASECURE-AI_Powered_Security_Scanner-4A90E2?style=for-the-badge&labelColor=f0f0f0">
</picture>

### ML-Powered Terraform & IaC Security Scanner

<p align="center">
  <b>92% Accuracy</b> • <b>10.7% False Positives</b> • <b>Offline Ready</b>
</p>

<p align="center">
  <a href="https://github.com/JashwanthMU/TerraSecure/releases">
    <img src="https://img.shields.io/github/v/release/JashwanthMU/TerraSecure?style=flat-square&logo=github&color=blue" alt="Release"/>
  </a>
  <a href="https://github.com/JashwanthMU/TerraSecure/pkgs/container/terrasecure">
    <img src="https://img.shields.io/badge/docker-ghcr.io-2496ED?style=flat-square&logo=docker" alt="Docker"/>
  </a>
  <a href="https://github.com/marketplace/actions/terrasecure-security-scanner">
    <img src="https://img.shields.io/badge/marketplace-action-2088FF?style=flat-square&logo=github-actions" alt="Action"/>
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"/>
  </a>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-documentation">Documentation</a>
</p>

</div>

---

##  What is TerraSecure?

TerraSecure is an **AI-powered security scanner** for Terraform/IaC that uses **machine learning (92% accuracy)** to detect misconfigurations before they become breaches. Unlike traditional rule-based tools, TerraSecure understands **context** and provides **business impact analysis** with every finding.

### Why TerraSecure?

-  **ML-Powered**: 92% accuracy with <11% false positives
-  **AI Explanations**: Business impact + attack scenarios + step-by-step fixes
-  **GitHub Integration**: Native SARIF output for Security tab
-  **Fast**: <100ms per resource, scans 1000+ resources in seconds
-  **Offline**: No external API dependencies, runs in air-gapped environments
-  **Real-World Trained**: Detects patterns from actual breaches (Capital One, Uber, Tesla)

---

##  Quick Start

### GitHub Action (Recommended)
```yaml
name: Security Scan
on: [push, pull_request]

permissions:
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: JashwanthMU/TerraSecure@v1
```

### Docker
```bash
# Scan current directory
docker run --rm -v $(pwd):/scan ghcr.io/jashwanthmu/terrasecure:latest /scan

# Generate SARIF for GitHub Security
docker run --rm -v $(pwd):/scan -v $(pwd):/output \
  ghcr.io/jashwanthmu/terrasecure:latest \
  /scan --format sarif --output /output/results.sarif
```

### Local Install
```bash
git clone https://github.com/JashwanthMU/TerraSecure.git
cd TerraSecure
pip install -r requirements.txt
python src/cli.py examples/vulnerable
```

---

##  Features

<table>
<tr>
<td width="50%">

###  ML-Powered Analysis
- Pre-trained XGBoost model (92% accuracy)
- 50 security features
- Real-world breach pattern detection
- <11% false positive rate

</td>
<td width="50%">

###  AI Explanations
- Business impact analysis
- Attack scenario descriptions
- Step-by-step remediation
- Compliance context (NIST, CIS)

</td>
</tr>
<tr>
<td>

###  Multi-Format Output
- Human-readable text (colored)
- JSON (machine-readable)
- SARIF 2.1.0 (GitHub Security)

</td>
<td>

###  Enterprise-Ready
- Docker containerized
- GitHub Marketplace action
- Offline operation
- Comprehensive tests (54% coverage)

</td>
</tr>
</table>

---

##  What Gets Detected

TerraSecure scans for **50+ security patterns** across all major AWS services:

| Category | Examples | Severity |
|----------|----------|----------|
| **Network** | Open 0.0.0.0/0, SSH/RDP exposed, unrestricted egress |  Critical |
| **Storage** | Public S3 buckets, unencrypted EBS/RDS, no versioning |  Critical |
| **IAM** | Wildcard policies, root account usage, no MFA |  High |
| **Secrets** | Hardcoded credentials, plaintext environment variables |  High |
| **Monitoring** | CloudTrail disabled, no VPC Flow Logs, missing alarms |  Medium |

**Trained on real breaches:**
- Capital One (2019) - S3 misconfiguration
- Uber (2016) - Hardcoded credentials
- Tesla (2018) - Public S3 bucket
- MongoDB (2017) - Exposed database

---

##  Installation

### Via Docker (Recommended)
```bash
docker pull ghcr.io/jashwanthmu/terrasecure:latest
```

### Via GitHub Action
```yaml
- uses: JashwanthMU/TerraSecure@v1
```

### From Source
```bash
git clone https://github.com/JashwanthMU/TerraSecure.git
cd TerraSecure
pip install -r requirements.txt
```

**Requirements:**
- Python 3.11+
- 512MB RAM
- No external API dependencies

---

##  Usage

### CLI
```bash
# Basic scan
python src/cli.py /path/to/terraform

# JSON output
python src/cli.py /path/to/terraform --format json --output report.json

# SARIF output (GitHub Security)
python src/cli.py /path/to/terraform --format sarif --output results.sarif

# Fail on high severity
python src/cli.py /path/to/terraform --fail-on high
```

### Docker
```bash
# Scan with text output
docker run --rm -v $(pwd):/scan ghcr.io/jashwanthmu/terrasecure:latest /scan

# Generate SARIF
docker run --rm -v $(pwd):/scan -v $(pwd):/output \
  ghcr.io/jashwanthmu/terrasecure:latest \
  /scan --format sarif --output /output/results.sarif

# Custom fail threshold
docker run --rm -v $(pwd):/scan \
  ghcr.io/jashwanthmu/terrasecure:latest \
  /scan --fail-on critical
```

### GitHub Action
```yaml
- name: Run TerraSecure
  uses: JashwanthMU/TerraSecure@v1
  with:
    path: 'infrastructure'      # Directory to scan
    format: 'sarif'             # Output format
    fail-on: 'high'             # Fail threshold
    upload-sarif: 'true'        # Upload to Security tab
```

---

##  Example Output

### Text Format (Human-Readable)
```
╔════════════════════════════════════════════════════════════╗
║                     TerraSecure                            ║
║          AI-Powered Terraform Security Scanner             ║
╚════════════════════════════════════════════════════════════╝

Scan Summary
============================================================
Total Resources Scanned: 3
Resources Passed: 0
Issues Found: 8

Severity Breakdown:
  Critical: 2
  High:     4
  Medium:   2

Detailed Findings
============================================================

[CRITICAL] S3 bucket with sensitive naming is publicly accessible
   Resource: aws_s3_bucket.customer_data
   File: infrastructure/storage.tf
   ML Risk: 90% | Confidence: 90%
   Triggered: s3_public_acl, s3_encryption_disabled (+13 more)

  ━━━  AI-Enhanced Analysis ━━━

  Explanation:
     This S3 bucket "customer_data" is configured with public access, 
     allowing anyone on the internet to discover and potentially access 
     its contents.

  Business Impact:
     Public S3 buckets are the leading cause of cloud data breaches.
     Exposure could lead to: (1) Data theft affecting customer privacy,
     (2) Regulatory fines (GDPR: up to €20M or 4% of revenue)...

  Attack Scenario:
     Attackers use automated scanners that continuously probe for public
     S3 buckets. Real-world example: Capital One breach (2019) exposed
     100M records through misconfigured S3, costing $190M in settlements.

  Detailed Fix:
     Step 1: Change ACL to private
         acl = "private"
     Step 2: Enable block public access
         block_public_acls = true
     ...
```

### SARIF Format (GitHub Security)

Integrates directly with GitHub's Security tab:

![GitHub Security Tab](https://docs.github.com/assets/cb-77251/mw-1440/images/help/security/security-tab-code-scanning-alerts.webp)

---

##  Performance

| Metric | Value | Target |
|--------|-------|--------|
| **Accuracy** | 92.45% | >85%  |
| **False Positive Rate** | 10.71% | <15%  |
| **False Negative Rate** | 4.00% | <5%  |
| **Scan Speed** | <100ms/resource | <200ms  |
| **Model Size** | 177 KB | <1MB  |

Tested on:
- 1000+ Terraform resources
- Real-world production configurations
- 5 major breach patterns

---

##  Comparison

| Feature | Checkov | Trivy | **TerraSecure** |
|---------|---------|-------|-----------------|
| ML-Powered | NO | NO |  92% accuracy |
| AI Explanations | NO | NO |  Business impact |
| False Positives | ~15% | ~12% | **10.7%** |
| Attack Scenarios | NO | NO |  Real breaches |
| Offline Mode | YES | YES | YES |
| SARIF Output | YES | YES | YES |
| GitHub Action | YES | YES | YES |
| Speed | Fast | Fast | Fast |

---

##  CI/CD Integration

### GitHub Actions
```yaml
- uses: JashwanthMU/TerraSecure@v1
```

### GitLab CI
```yaml
terrasecure:
  image: ghcr.io/jashwanthmu/terrasecure:latest
  script:
    - terrasecure . --format json
```

### Jenkins
```groovy
docker.image('ghcr.io/jashwanthmu/terrasecure:latest').inside {
    sh 'terrasecure . --format json'
}
```

### Azure DevOps
```yaml
- task: Docker@2
  inputs:
    command: run
    arguments: '-v $(Build.SourcesDirectory):/scan ghcr.io/jashwanthmu/terrasecure:latest /scan'
```

---

##  Documentation

- [ Full Documentation](https://github.com/JashwanthMU/TerraSecure/wiki)
- [ GitHub Action Guide](ACTION_README.md)
- [ Docker Guide](DOCKER.md)


---

##  Contributing

Contributions welcomed! 
```bash
# Setup development environment
git clone https://github.com/JashwanthMU/TerraSecure.git
cd TerraSecure
pip install -r requirements.txt

# Run tests
pytest

# Build model
python scripts/build_production_model.py
```

---

##  License

MIT License - see [LICENSE](LICENSE)

---

##  Inspired By

- Trained on breach data from [CVE Database](https://cve.mitre.org/)
- SARIF format: [OASIS SARIF TC](https://www.oasis-open.org/committees/sarif/)
- Inspired by: [Checkov](https://www.checkov.io/), [Trivy](https://trivy.dev/)

---

##  Links

- [GitHub Repository](https://github.com/JashwanthMU/TerraSecure)
- [GitHub Marketplace](https://github.com/marketplace/actions/terrasecure-security-scanner)
- [Docker Hub](https://github.com/JashwanthMU/TerraSecure/pkgs/container/terrasecure)
- [Issue Tracker](https://github.com/JashwanthMU/TerraSecure/issues)
- [Discussions](https://github.com/JashwanthMU/TerraSecure/discussions)

---

<div align="center">

**Star this repo if TerraSecure helped secure your infrastructure!**

For a proactive shift left progress,by [JashwanthMU](https://github.com/JashwanthMU)

</div>
