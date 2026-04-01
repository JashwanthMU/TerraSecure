# TerraSecure Docker Image

Official Docker image for TerraSecure - AI-Powered Terraform Security Scanner

##  Quick Start
```bash
# Pull the image
docker pull ghcr.io/jashwanthmu/terrasecure:latest

# Scan current directory
docker run --rm -v $(pwd):/scan:ro ghcr.io/jashwanthmu/terrasecure:latest /scan

# Scan with JSON output
docker run --rm -v $(pwd):/scan:ro ghcr.io/jashwanthmu/terrasecure:latest /scan --format json

# Scan with SARIF output (for GitHub Security)
docker run --rm -v $(pwd):/scan:ro -v $(pwd):/output ghcr.io/jashwanthmu/terrasecure:latest /scan --format sarif --output /output/results.sarif
```

##  Available Tags

- `latest` - Latest stable release
- `1.0.0` - Specific version
- `develop` - Development branch (unstable)

##  Features

-  **ML-Powered**: 92% accuracy with pre-trained model
-  **AI Explanations**: Business impact and attack scenarios
-  **Multi-Format**: Text, JSON, SARIF output
-  **Offline**: No external API dependencies
-  **Fast**: <100ms per resource prediction
-  **Secure**: Non-root user, minimal attack surface

##  Image Details

- **Size**: ~300MB
- **Base**: Python 3.11-slim
- **Architecture**: linux/amd64
- **User**: Non-root (uid 1000)

##  Usage Examples

### CI/CD Integration

**GitHub Actions:**
```yaml
- name: Run TerraSecure
  run: |
    docker run --rm -v ${{ github.workspace }}:/scan:ro \
      ghcr.io/jashwanthmu/terrasecure:latest \
      /scan --format sarif --output results.sarif
```

**GitLab CI:**
```yaml
terrasecure:
  image: ghcr.io/jashwanthmu/terrasecure:latest
  script:
    - terrasecure /builds/$CI_PROJECT_PATH --format json
```

**Jenkins:**
```groovy
docker.image('ghcr.io/jashwanthmu/terrasecure:latest').inside {
    sh 'terrasecure . --format json --output report.json'
}
```
