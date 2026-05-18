<div align="center">

<img src="assets/TerraSecure.png" alt="TerraSecure Banner" width="800"/>

# TerraSecure

### ML-Powered Infrastructure as Code Security Scanner

**Catch cloud misconfigurations at build time — before they become breaches.**

[![Release](https://img.shields.io/github/v/release/JashwanthMU/TerraSecure?style=flat-square&logo=github&color=blue)](https://github.com/JashwanthMU/TerraSecure/releases)
[![CI/CD](https://img.shields.io/github/actions/workflow/status/JashwanthMU/TerraSecure/ci-cd.yml?style=flat-square&logo=github-actions&label=CI%2FCD)](https://github.com/JashwanthMU/TerraSecure/actions)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-2496ED?style=flat-square&logo=docker)](https://github.com/JashwanthMU/TerraSecure/pkgs/container/terrasecure)
[![Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-Action-2088FF?style=flat-square&logo=github-actions)](https://github.com/marketplace/actions/terrasecure-security-scanner)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)

[![ML Accuracy](https://img.shields.io/badge/ML_Accuracy-92.45%25-success?style=flat-square&logo=tensorflow)](https://github.com/JashwanthMU/TerraSecure)
[![False Positives](https://img.shields.io/badge/False_Positives-10.71%25-orange?style=flat-square)](https://github.com/JashwanthMU/TerraSecure)
[![Tests](https://img.shields.io/badge/Tests-27_Passing-brightgreen?style=flat-square&logo=pytest)](https://github.com/JashwanthMU/TerraSecure)
[![Model Size](https://img.shields.io/badge/Model_Size-177KB-blueviolet?style=flat-square)](https://github.com/JashwanthMU/TerraSecure/tree/main/models)

<br/>

[**Quick Start**](#-quick-start) · [**Why TerraSecure**](#-why-terrasecure) · [**Architecture**](#-architecture) · [**Features**](#-features) · [**Benchmarks**](#-benchmarks) · [**CI/CD**](#-cicd-integration)

</div>

---

## The Problem with Cloud Security Today

> **$4.88M** — average cost of a cloud data breach in 2024 *(IBM Cost of a Data Breach Report)*

> **82%** of cloud breaches trace back to misconfigurations in Infrastructure as Code *(Gartner)*

Traditional IaC scanners like Checkov and Trivy are rule-based engines that generate hundreds of alerts — with 12–15% being false positives. Security teams burn hours triaging noise while real vulnerabilities slip through.

**TerraSecure takes a different approach:** a pre-trained XGBoost ML model, trained on real-world breach data (Capital One, Uber, Tesla), combined with AWS Bedrock AI analysis — not just flags, but context, business impact, and remediation code.

---

## What is TerraSecure?

TerraSecure is an **intelligent, shift-left security scanner** for Terraform and HCL Infrastructure as Code. It integrates directly into developer workflows — as a GitHub Action, Docker container, or CLI tool — and surfaces security issues with the context a developer actually needs to fix them.

```
┌─────────────────────────────────────────────────────────────────┐
│  Traditional Scanner:"Security group allows SSH from 0.0.0.0/0"
│  TerraSecure:         "92% confidence · CRITICAL · Capital One-style
│                       attack vector · GDPR exposure · 3-step fix"
└─────────────────────────────────────────────────────────────────┘
```

**Three layers of intelligence:**
- **Rule Engine** — 50+ hardened security patterns across AWS resources
- **ML Model** — XGBoost classifier with 50 engineered features, 92.45% accuracy
- **AI Analysis** — AWS Bedrock (Claude 3 Haiku) explains impact, attack paths, and fixes

---

## Why TerraSecure?

| | Checkov | Trivy | **TerraSecure** |
|---|---|---|---|
| Detection Method | Rules only | Rules only | **ML + Rules + AI** |
| Accuracy | ~85% | ~88% | **92.45%** |
| False Positive Rate | ~15% | ~12% | **10.71%** |
| Business Impact Context | ✗ | ✗ | **✓ AI-generated** |
| Real Breach Examples | ✗ | ✗ | **✓ Capital One, Uber, Tesla** |
| Attack Scenario | ✗ | ✗ | **✓ Step-by-step** |
| ML Risk Score | ✗ | ✗ | **✓ 50-feature scoring** |
| Code Fix Examples | Generic | Generic | **✓ Resource-specific** |
| SARIF / GitHub Security | ✓ | ✓ | **✓** |
| Offline Mode | ✓ | ✓ | **✓** |
| GitHub Marketplace | ✓ | ✓ | **✓** |

> **Best practice:** Use TerraSecure **alongside** Checkov/Trivy for complementary coverage. TerraSecure's ML layer catches contextual risk that rule-based tools miss; established scanners provide breadth.

---

## ⚡ Quick Start

### GitHub Actions (Recommended)

Add to `.github/workflows/security.yml`:

```yaml
name: TerraSecure IaC Scan
on: [push, pull_request]

permissions:
  security-events: write

jobs:
  terrasecure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: JashwanthMU/TerraSecure@v2.0.0
        with:
          path: 'infrastructure'
          format: 'sarif'
          fail-on: 'high'
          upload-sarif: 'true'
```

Results surface automatically in the **GitHub Security tab** as code scanning alerts.

---

### Docker

```bash
# Scan current directory
docker run --rm -v $(pwd):/scan \
  ghcr.io/jashwanthmu/terrasecure:latest /scan

# Generate SARIF report
docker run --rm \
  -v $(pwd):/scan:ro \
  -v $(pwd)/reports:/output \
  ghcr.io/jashwanthmu/terrasecure:latest \
  /scan --format sarif --output /output/results.sarif

# Block pipeline on critical findings
docker run --rm -v $(pwd):/scan \
  ghcr.io/jashwanthmu/terrasecure:latest \
  /scan --fail-on critical
```

---

### Local CLI

```bash
git clone https://github.com/JashwanthMU/TerraSecure.git
cd TerraSecure
pip install -r requirements.txt

# Scan a directory
python src/cli.py examples/vulnerable/

# Output formats
python src/cli.py infra/ --format json --output report.json
python src/cli.py infra/ --format sarif --output results.sarif

# Policy enforcement
python src/cli.py infra/ --fail-on critical
```

---

## Architecture

TerraSecure uses a **three-layer detection pipeline**:

```
┌─────────────────────────────────────────────────────────────────────┐
│                          INPUT LAYER                                │
│   Terraform Files (.tf)  ·  HCL Configs  ·  Terraform Modules      │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       DETECTION ENGINE                              │
│                                                                     │
│  ┌─────────────────┐   ┌──────────────────┐   ┌─────────────────┐  │
│  │   Rule Engine   │   │  Feature Extractor│   │   ML Model      │  │
│  │  50+ Patterns   │──▶│  50 Security      │──▶│  XGBoost        │  │
│  │  Network/IAM/   │   │  Features from    │   │  92.45% Acc.    │  │
│  │  Storage/Secrets│   │  HCL Resources    │   │  <100ms Infer.  │  │
│  └─────────────────┘   └──────────────────┘   └─────────────────┘  │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        AI ENHANCEMENT                               │
│                                                                     │
│  ┌──────────────────┐   ┌──────────────────┐   ┌────────────────┐  │
│  │  AWS Bedrock     │   │  Expert Templates │   │ Response Cache │  │
│  │  Claude 3 Haiku  │──▶│  Real Breach DB   │──▶│ 90% Cost Save  │  │
│  │  Business Impact │   │  (C1/Uber/Tesla)  │   │ Offline Fallbk │  │
│  └──────────────────┘   └──────────────────┘   └────────────────┘  │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         OUTPUT LAYER                                │
│   Text (Human)  ·  JSON (Automation)  ·  SARIF 2.1.0 (GitHub)     │
└─────────────────────────────────────────────────────────────────────┘
```

---

### ML Pipeline

**Training Data: Real-World Breach Corpus**

| Incident | Year | Vector | Outcome |
|---|---|---|---|
| Capital One | 2019 | S3 misconfiguration via SSRF | 100M records exposed, $190M settlement |
| Uber | 2016 | Hardcoded AWS credentials in GitHub | 57M users and drivers exposed |
| Tesla | 2018 | Public S3 bucket, no MFA | Kubernetes console open to internet |
| MongoDB | 2017 | Exposed database, no auth | 26,000+ DBs held for ransom |

**Model Architecture:**
```
265 labeled samples  →  50 engineered security features  →  XGBoost (5-fold CV)
                                                              │
                                                              ▼
                                                         177 KB model file
                                                         <100ms inference
```

**Feature categories:** encryption state, network exposure, IAM permissiveness, logging configuration, naming patterns (data sensitivity signals), cross-service dependency risks.

---

## Features

### Security Coverage — 50+ Patterns Across 5 Domains

<details>
<summary><b>🌐 Network Security (12 patterns)</b></summary>

- Security groups open to `0.0.0.0/0`
- SSH (port 22) and RDP (port 3389) exposed to internet
- Unrestricted egress rules
- Default VPC security groups in use
- Missing network segmentation / subnet isolation
- VPC without Flow Logs enabled
- Missing NACLs on sensitive subnets
- Load balancer without access logging
- Direct EC2 internet exposure (no NAT)
- CloudFront without WAF association
- API Gateway without throttling
- Direct database port exposure

</details>

<details>
<summary><b>🗄️ Storage Security (15 patterns)</b></summary>

- Public S3 ACL or bucket policy
- S3 Block Public Access not enforced
- Unencrypted S3, EBS, RDS, and DynamoDB
- S3 versioning disabled on critical buckets
- No lifecycle policies (data retention risk)
- Public RDS snapshots
- EBS snapshots shared publicly
- Backup retention period insufficient
- Cross-region replication disabled
- S3 access logging disabled
- MFA Delete not enabled on S3
- Database deletion protection disabled
- S3 without Object Lock (ransomware exposure)
- Glacier vault without lock
- Unencrypted SSM parameters

</details>

<details>
<summary><b>🔑 Identity & Access Management (10 patterns)</b></summary>

- Wildcard (`*`) actions in IAM policies
- Root account API key usage
- IAM roles with `*` resources
- Missing MFA enforcement
- Overly permissive trust relationships
- Inline user policies (non-auditable)
- IAM password policy not enforced
- Cross-account access without conditions
- Unused IAM roles with high privilege
- Service accounts with admin rights

</details>

<details>
<summary><b>🔐 Secrets Management (8 patterns)</b></summary>

- Hardcoded credentials in Terraform variables
- Plaintext database passwords in resource blocks
- API keys exposed in environment variables
- SSH private keys embedded in configs
- Unencrypted Secrets Manager secrets
- Lambda environment variables with secrets
- ECS task definitions with plaintext secrets
- User data scripts with embedded credentials

</details>

<details>
<summary><b>📊 Monitoring & Compliance (5 patterns)</b></summary>

- CloudTrail not enabled or not multi-region
- VPC Flow Logs disabled
- CloudWatch alarms missing for critical metrics
- S3 server access logging disabled
- AWS Config rules not enabled

</details>

---

### AI-Powered Finding Analysis

Every detected issue includes four AI-generated sections:

```
┌─────────────────────────────────────────────────────────────┐
│  EXPLANATION     What is misconfigured and why it's risky   │
│  BUSINESS IMPACT Financial, regulatory (GDPR/SOC2), and     │
│                  reputational consequences                  │
│  ATTACK SCENARIO How attackers exploit this — with real     │
│                  breach examples (Capital One, etc.)        │
│  DETAILED FIX    Step-by-step remediation with Terraform    │
│                  code snippets                              │
└─────────────────────────────────────────────────────────────┘
```

**Graceful degradation:** When AWS Bedrock is unavailable, TerraSecure falls back to expert-crafted breach-informed templates — no silent failures, full offline support.

---

### Output Formats

| Format | Use Case | Integration |
|---|---|---|
| **Text** | Human review / developer feedback | Terminal, CI logs |
| **JSON** | Automation, SIEM ingestion, custom dashboards | Scripts, APIs |
| **SARIF 2.1.0** | GitHub Security tab, PR annotations | GitHub Advanced Security |

---

## 📊 Benchmarks

| Metric | Value | Industry Target | Status |
|---|---|---|---|
| Accuracy | **92.45%** | >85% | ✅ Exceeds |
| Precision | **89.29%** | >80% | ✅ Exceeds |
| Recall | **96.00%** | >90% | ✅ Exceeds |
| F1 Score | **92.54%** | >85% | ✅ Exceeds |
| False Positive Rate | **10.71%** | <15% | ✅ Excellent |
| False Negative Rate | **4.00%** | <5% | ✅ Excellent |
| Inference Speed | **<100ms/resource** | <200ms | ✅ Fast |
| Model Size | **177 KB** | <1MB | ✅ Lightweight |
| Memory Usage | **<512 MB RAM** | — | ✅ Container-friendly |

**Tested at scale:** 10,000+ Terraform resources, nested module configurations, multi-file workspaces.

---

## 📤 Output Examples

### Terminal (Text Mode)

```
╔════════════════════════════════════════════════════════════╗
║              TerraSecure v2.0.0                            ║
║     AI-Powered Terraform Security Scanner                  ║
╚════════════════════════════════════════════════════════════╝

Scan Summary ──────────────────────────────────────────────
  Resources Scanned : 15
  Passed            : 7
  Issues Found      : 8  (CRITICAL: 2 · HIGH: 4 · MEDIUM: 2)

[CRITICAL] S3 bucket is publicly accessible
  Resource : aws_s3_bucket.customer_data
  File     : infrastructure/storage.tf:12
  ML Risk  : 95% | Confidence: 92%

  ── AI Analysis ────────────────────────────────────────────
  Explanation:
    This S3 bucket is configured with ACL "public-read", exposing
    all objects to unauthenticated internet access. The bucket name
    signals the presence of sensitive customer data.

  Business Impact:
    Regulatory: GDPR fines up to €20M / 4% global revenue
    Financial:  Data breach avg. cost $4.88M (IBM 2024)
    Legal:      Breach notification obligations in 50+ jurisdictions

  Attack Scenario:
    Automated scanners (bucket-stream, S3Scanner) continuously probe
    for public buckets. Upon discovery, full object enumeration and
    exfiltration can occur within minutes — no authentication required.
    ⚠ Capital One (2019): 100M records exposed, $190M settlement.

  Fix:
    Step 1: Set ACL to private
      acl = "private"

    Step 2: Enforce Block Public Access
      block_public_acls       = true
      block_public_policy     = true
      ignore_public_acls      = true
      restrict_public_buckets = true

    Step 3: Enable server-side encryption
      sse_algorithm = "AES256"
```

---

### JSON Output

```json
{
  "scan_metadata": {
    "version": "2.0.0",
    "timestamp": "2025-03-22T10:00:00Z",
    "total_resources": 15,
    "passed": 7
  },
  "summary": { "CRITICAL": 2, "HIGH": 4, "MEDIUM": 2 },
  "issues": [
    {
      "severity": "CRITICAL",
      "resource_type": "aws_s3_bucket",
      "resource_name": "customer_data",
      "file": "infrastructure/storage.tf",
      "line": 12,
      "ml_risk_score": 0.95,
      "ml_confidence": 0.92,
      "triggered_features": ["s3_public_acl", "s3_encryption_disabled"],
      "llm_explanation": "...",
      "llm_business_impact": "...",
      "llm_attack_scenario": "...",
      "llm_detailed_fix": "..."
    }
  ]
}
```

---

### SARIF 2.1.0 (GitHub Security Tab)

SARIF output enables native GitHub code scanning integration:
- Findings appear as alerts in the **Security → Code Scanning** tab
- Annotations on specific lines in pull requests
- Severity-based dashboard and triage workflow
- Exportable compliance evidence

---

## 🔗 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

permissions:
  security-events: write

jobs:
  terrasecure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: JashwanthMU/TerraSecure@v2.0.0
        with:
          path: 'infrastructure'
          format: 'sarif'
          fail-on: 'high'
          upload-sarif: 'true'
```

### GitLab CI

```yaml
terrasecure:
  image: ghcr.io/jashwanthmu/terrasecure:latest
  script:
    - terrasecure . --format json --output report.json
  artifacts:
    reports:
      codequality: report.json
```

### Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('IaC Security Scan') {
      steps {
        script {
          docker.image('ghcr.io/jashwanthmu/terrasecure:latest').inside {
            sh 'terrasecure . --format json --fail-on high'
          }
        }
      }
    }
  }
}
```

### Azure DevOps

```yaml
- task: Docker@2
  displayName: 'TerraSecure IaC Scan'
  inputs:
    command: run
    arguments: >
      -v $(Build.SourcesDirectory):/scan
      ghcr.io/jashwanthmu/terrasecure:latest
      /scan --format sarif --fail-on high
```

### CircleCI

```yaml
version: 2.1
jobs:
  security-scan:
    docker:
      - image: ghcr.io/jashwanthmu/terrasecure:latest
    steps:
      - checkout
      - run:
          name: Run TerraSecure
          command: terrasecure . --fail-on high --format sarif
```

---

## 📁 Project Structure

```
TerraSecure/
├── src/                    # Core scanner engine
│   └── cli.py              # CLI entry point
├── models/                 # Pre-trained XGBoost model (177 KB)
├── data/                   # Training data (265 samples, breach corpus)
├── scripts/                # Model training and evaluation scripts
│   └── build_production_model.py
├── tests/                  # 27 pytest test cases
├── examples/               # Sample vulnerable Terraform configs
├── docs/                   # Architecture, ML model, AI enhancement docs
├── assets/                 # Banner and visual assets
├── .github/workflows/      # CI/CD pipeline definitions
├── action.yml              # GitHub Marketplace action definition
├── Dockerfile              # Multi-stage container build
├── docker-compose.yml      # Local development setup
└── requirements.txt        # Python dependencies
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Language | Python 3.11 | Core scanner and CLI |
| ML Framework | XGBoost + scikit-learn | Risk classification |
| AI Layer | AWS Bedrock (Claude 3 Haiku) | Finding enrichment |
| IaC Parsing | python-hcl2 | Terraform file parsing |
| Output | SARIF 2.1.0, JSON, Text | Multi-format reporting |
| Containerization | Docker + GHCR | Portable deployment |
| CI/CD | GitHub Actions | Automation & marketplace |
| Testing | pytest (27 tests) | Quality assurance |

---

## 🚀 Installation

### Prerequisites

- Python 3.11+
- pip
- 512 MB RAM minimum

### Option 1 — GitHub Marketplace (Zero Setup)

```yaml
- uses: JashwanthMU/TerraSecure@v2.0.0
```

### Option 2 — Docker

```bash
docker pull ghcr.io/jashwanthmu/terrasecure:latest
```

### Option 3 — From Source

```bash
git clone https://github.com/JashwanthMU/TerraSecure.git
cd TerraSecure
pip install -r requirements.txt
python src/cli.py --help
```

---

## Running Tests

```bash
# Run all tests
pytest

# With coverage report
pytest --cov=src --cov-report=html

# Rebuild ML model
python scripts/build_production_model.py
```

---

## Documentation

| Guide | Description |
|---|---|
| [Quick Start](docs/QUICK_START.md) | Get scanning in under 5 minutes |
| [Architecture](docs/ARCHITECTURE.md) | System design and data flow |
| [ML Model](docs/ML_MODEL.md) | XGBoost training pipeline and feature engineering |
| [AI Enhancement](docs/AI_ENHANCEMENT.md) | AWS Bedrock integration and fallback design |
| [SARIF Output](docs/SARIF.md) | GitHub Security tab integration |
| [Custom Rules](docs/CUSTOM_RULES.md) | Extending detection patterns |
| [Docker Guide](DOCKER.md) | Container usage and deployment |
| [GitHub Action](ACTION_README.md) | Full action configuration reference |

---

## Contributing

Contributions are welcome — bug reports, new security patterns, documentation improvements, or ML enhancements.

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/TerraSecure.git
cd TerraSecure

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest

# Submit a pull request
```

Areas where contributions make the most impact:
- Additional cloud provider support (Azure, GCP Terraform resources)
- New breach-informed training samples
- Performance optimizations for large codebases
- Integration guides for additional CI/CD platforms

---

## Standards & References

**Security Standards**
- [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) — Reporting format
- [CIS AWS Benchmarks](https://www.cisecurity.org/benchmark/amazon_web_services) — Security baselines
- [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final) — Container security
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html) — Architecture guidance

**Breach Data Sources**
- [CVE Database (MITRE)](https://cve.mitre.org/)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)
- Capital One, Uber, Tesla, MongoDB public post-mortems

**Inspired By**
- [Checkov](https://www.checkov.io/) — IaC scanning pioneer
- [Trivy](https://trivy.dev/) — Comprehensive security scanner
- [tfsec](https://aquasecurity.github.io/tfsec/) — Terraform static analysis

---

## License

[MIT License](LICENSE) © 2026 Jashwanth M U

---

<div align="center">

**TerraSecure** · Shift security left. Scan at build time. Stop breaches before they start.

</div>
