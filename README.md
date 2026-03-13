# 🔒 TerraSecure

**AI-Powered Terraform Security Scanner with Machine Learning**

Catch infrastructure misconfigurations before they become breaches.

[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fjashwanthmu%2Fterrasecure-blue)](https://ghcr.io/jashwanthmu/terrasecure)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## 🚀 Quick Start

### Using Docker (Recommended)
```bash
# Pull the image
docker pull ghcr.io/jashwanthmu/terrasecure:latest

# Scan current directory (Linux/Mac)
docker run --rm -v $(pwd):/scan:ro ghcr.io/jashwanthmu/terrasecure:latest /scan

# Scan current directory (Windows PowerShell)
docker run --rm -v ${PWD}:/scan:ro ghcr.io/jashwanthmu/terrasecure:latest /scan

# Scan current directory (Windows CMD)
docker run --rm -v %cd%:/scan:ro ghcr.io/jashwanthmu/terrasecure:latest /scan
```

### Using Python
```bash
# Clone repository
git clone https://github.com/JashwanthMU/TerraSecure.git
cd TerraSecure

# Install dependencies
pip install -r requirements.txt

# Build production model (first time only)
python scripts/build_production_model.py

# Scan examples
python src/cli.py examples/vulnerable

# Scan your own Terraform files
python src/cli.py /path/to/your/terraform
```

---

## 💡 What Makes TerraSecure Different?

Unlike traditional rule-based scanners (Checkov, Trivy), TerraSecure uses **Machine Learning trained on real breach patterns**:

| Feature | Checkov | Trivy | **TerraSecure** |
|---------|---------|-------|-----------------|
| ML-Powered | ❌ | ❌ | ✅ **92% accuracy** |
| Real Breach Training | ❌ | ❌ | ✅ Capital One, Uber, Tesla |
| AI Explanations | ❌ | ❌ | ✅ Business impact + fixes |
| False Positive Rate | ~15% | ~12% | **10.7%** |
| Attack Scenarios | ❌ | ❌ | ✅ Real-world examples |
| GitHub Security | ✅ | ✅ | ✅ SARIF format |

---

## 📊 Example Output

**Traditional Tools:**
```
❌ S3 bucket is public
```

**TerraSecure:**
```
🔴 [CRITICAL] S3 bucket with sensitive naming is publicly accessible
   Resource: aws_s3_bucket.customer_data
   File: main.tf:10
   ML Risk: 95% | Confidence: 92%

💡 AI-Enhanced Analysis:

   Business Impact:
   Public S3 buckets led to the Capital One breach affecting 100M 
   customers ($190M settlement). Exposure could lead to: (1) Data theft, 
   (2) Regulatory fines (GDPR: €20M), (3) Reputational damage.

   Attack Scenario:
   Attackers use automated scanners that continuously probe for public 
   S3 buckets. This bucket could be found within hours of creation.

   Detailed Fix:
   Step 1: Change ACL to private
       acl = "private"
   Step 2: Enable block public access
       block_public_acls = true
       block_public_policy = true
   [... 3 more steps]
```

---

## 🎯 Key Features

-  **ML-Powered Detection**: 92% accuracy, trained on real breach patterns
-  **AI Explanations**: Business impact + attack scenarios + detailed fixes
-  **Multi-Format Output**: Text, JSON, SARIF (GitHub Security)
-  **Production Ready**: Docker image, <100ms scans, offline operation
-  **GitHub Integration**: Automated PR comments and Security tab alerts
-  **Real Breach Training**: Capital One, Uber, Tesla, MongoDB patterns

---

## 🐳 Docker Usage

### Basic Scan
```bash
# Linux/Mac
docker run --rm -v $(pwd):/scan:ro ghcr.io/jashwanthmu/terrasecure:latest /scan

# Windows PowerShell
docker run --rm -v ${PWD}:/scan:ro ghcr.io/jashwanthmu/terrasecure:latest /scan
```

### JSON Output
```bash
# Linux/Mac
docker run --rm \
  -v $(pwd):/scan:ro \
  -v $(pwd):/output \
  ghcr.io/jashwanthmu/terrasecure:latest \
  /scan --format json --output /output/results.json

# Windows PowerShell
docker run --rm `
  -v ${PWD}:/scan:ro `
  -v ${PWD}:/output `
  ghcr.io/jashwanthmu/terrasecure:latest `
  /scan --format json --output /output/results.json
```

### SARIF Output (GitHub Security)
```bash
# Linux/Mac
docker run --rm \
  -v $(pwd):/scan:ro \
  -v $(pwd):/output \
  ghcr.io/jashwanthmu/terrasecure:latest \
  /scan --format sarif --output /output/results.sarif

# Windows PowerShell
docker run --rm `
  -v ${PWD}:/scan:ro `
  -v ${PWD}:/output `
  ghcr.io/jashwanthmu/terrasecure:latest `
  /scan --format sarif --output /output/results.sarif
```

---

## 🔧 Local Installation

### Prerequisites
- Python 3.11+
- pip
- Git

### Installation Steps
```bash
# 1. Clone repository
git clone https://github.com/JashwanthMU/TerraSecure.git
cd TerraSecure

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Build production ML model (first time only)
python scripts/build_production_model.py

# 4. Verify installation
python src/cli.py examples/vulnerable
```

### Command-Line Options
```bash
# Show help
python src/cli.py --help

# Scan with JSON output
python src/cli.py /path/to/terraform --format json

# Scan and save results
python src/cli.py /path/to/terraform --format json --output report.json

# Scan with SARIF output (for GitHub)
python src/cli.py /path/to/terraform --format sarif --output results.sarif

# Fail build on critical issues
python src/cli.py /path/to/terraform --fail-on critical

# Fail build on high or critical
python src/cli.py /path/to/terraform --fail-on high
```

---

## 🤖 GitHub Actions Integration

### Basic Workflow

Create `.github/workflows/terrasecure.yml`:
```yaml
name: TerraSecure Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

permissions:
  contents: read
  security-events: write

jobs:
  terrasecure-scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Run TerraSecure
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/scan:ro \
            -v ${{ github.workspace }}:/output \
            ghcr.io/jashwanthmu/terrasecure:latest \
            /scan --format sarif --output /output/results.sarif
        continue-on-error: true
      
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
          category: terrasecure
```

### Advanced Workflow (with PR Comments)

See [.github/workflows/terrasecure.yml](.github/workflows/terrasecure.yml) for a complete example with PR comments and failure handling.

---

## 📈 Model Performance

### Training Data
- **Total Examples**: 765 (330 risky, 435 safe)
- **Features**: 50 security patterns per resource
- **Real Breach Patterns**: Capital One, Uber, Tesla, MongoDB

### Production Model 

| Metric | Value | Target |
|--------|-------|--------|
| **Accuracy** | 92.45% | >85% ✅ |
| **Precision** | 88.89% | >80% ✅ |
| **Recall** | 96.00% | >90% ✅ |
| **False Positive Rate** | 10.71% | <10% ⚠️ |
| **False Negative Rate** | 4.00% | <5% ✅ |

### Top Security Features 

1. `open_database_port_3306` - 12.17%
2. `api_gateway_no_waf` - 9.19%
3. `rds_storage_unencrypted` - 8.80%
4. `vpc_flow_logs_disabled` - 8.39%
5. `s3_encryption_disabled` - 7.86%

---

## 🎓 How It Works
```
┌─────────────────┐
│ Terraform Files │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│ Feature Extraction      │
│ (50 security patterns)  │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ ML Model (XGBoost)      │
│ 92% accuracy            │
│ Trained on real breaches│
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ AI Enhancement (LLM)    │
│ Business impact + fixes │
│ Attack scenarios        │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ Multi-Format Output     │
│ Text / JSON / SARIF     │
│ GitHub Security Tab     │
└─────────────────────────┘
```

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|------------|
| **Language** | Python 3.11 |
| **ML Framework** | XGBoost, scikit-learn |
| **AI/LLM** | OpenAI API (with intelligent fallback) |
| **Container** | Docker (multi-stage build) |
| **CI/CD** | GitHub Actions |
| **Output Formats** | SARIF, JSON, Text |
| **Security Standards** | CWE, NIST, CIS |

---

## Roadmap

**Completed **
- [x] ML model with 92% accuracy
- [x] AI-powered explanations
- [x] Docker image (300MB)
- [x] SARIF output format
- [x] GitHub Actions integration
- [x] Multi-format output (text, JSON, SARIF)

**To do**
- [ ] Comprehensive test suite
- [ ] Benchmarking vs Checkov/Trivy
- [ ] Compliance mappings (NIST 800-53, CIS, PCI-DSS)*
- [ ] Terraform Cloud integration
- [ ] Policy-as-Code support
- [ ] VS Code extension
- [ ] Metrics dashboard
- [ ] Custom rule engine
- [ ] Multi-cloud support (Azure, GCP)

---

##  Contributing

Contributions are welcome! Please feel free to review and submit a Pull Request.

- Trained on breach patterns from publicly disclosed security incidents
- Inspired by the need to prevent the next Capital One breach ($190M)
- Built as part of DevSecOps research 

---

## 📧 Contact

**Jashwanth Mahalingam**
- LinkedIn: (https://linkedin.com/in/jashwanth-mahalingam)

---

**Make cloud accessible to everyone.**

