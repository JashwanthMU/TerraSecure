param(
    [Parameter(Mandatory=$false)]
    [string]$Version = "1.0.0",
    
    [Parameter(Mandatory=$false)]
    [string]$Registry = "ghcr.io/jashwanthmu",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipTests = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Push = $false
)

$ErrorActionPreference = "Stop"


function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-ColorOutput "╔══════════════════════════════════════════════════════════════╗" Cyan
    Write-ColorOutput "║  $($Title.PadRight(60))║" Cyan
    Write-ColorOutput "╚══════════════════════════════════════════════════════════════╝" Cyan
    Write-Host ""
}


Clear-Host
Write-Header "TerraSecure Docker Image Builder"

Write-ColorOutput "Build Configuration:" Yellow
Write-Host "  Version:      $Version"
Write-Host "  Registry:     $Registry"
Write-Host "  Skip Tests:   $SkipTests"
Write-Host "  Auto Push:    $Push"
Write-Host ""

Write-ColorOutput " Checking prerequisites..." Cyan
try {
    $dockerVersion = docker --version
    Write-ColorOutput " Docker installed: $dockerVersion" Green
} catch {
    Write-ColorOutput " Docker is not installed or not in PATH!" Red
    Write-Host "   Install Docker Desktop from: https://www.docker.com/products/docker-desktop"
    exit 1
}

if (-not (Test-Path "src/cli.py")) {
    Write-ColorOutput " Error: Must run from TerraSecure root directory" Red
    Write-Host "   Current directory: $PWD"
    Write-Host "   Expected files: src/cli.py, requirements.txt, Dockerfile"
    exit 1
}

Write-ColorOutput " In correct directory" Green

Write-Host ""
Write-ColorOutput " Checking production model..." Cyan

if (Test-Path "models/terrasecure_production_v1.0.pkl") {
    Write-ColorOutput " Production model already exists" Green
    $rebuild = Read-Host "Rebuild model? (y/n)"
    if ($rebuild -eq "y" -or $rebuild -eq "Y") {
        Write-ColorOutput " Rebuilding production model..." Yellow
        python scripts\build_production_model.py
        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput " Model build failed!" Red
            exit 1
        }
    }
} else {
    Write-ColorOutput "  Production model not found - building..." Yellow
    python scripts\build_production_model.py
    if ($LASTEXITCODE -ne 0) {
        Write-ColorOutput "  Model build failed - Docker will build in fallback mode" Yellow
        Write-Host "   Press Enter to continue or Ctrl+C to abort..."
        Read-Host
    }
}

Write-Host ""
Write-ColorOutput " Building Docker image..." Cyan
Write-Host ""

$imageTags = @(
    "terrasecure:latest",
    "terrasecure:$Version",
    "$Registry/terrasecure:latest",
    "$Registry/terrasecure:$Version"
)

$tagArgs = $imageTags | ForEach-Object { "--tag", $_ }

try {
    & docker build `
        --build-arg VERSION=$Version `
        --build-arg BUILD_DATE=$(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ") `
        $tagArgs `
        --progress=plain `
        .
    
    if ($LASTEXITCODE -ne 0) {
        throw "Docker build failed with exit code $LASTEXITCODE"
    }
    
    Write-Host ""
    Write-ColorOutput " Docker image built successfully" Green
    
} catch {
    Write-Host ""
    Write-ColorOutput " Docker build failed!" Red
    Write-Host $_.Exception.Message
    exit 1
}


if (-not $SkipTests) {
    Write-Host ""
    Write-ColorOutput " Testing Docker image..." Cyan
    Write-Host ""

    Write-Host "Test 1: Version check"
    docker run --rm terrasecure:latest --version
    if ($LASTEXITCODE -ne 0) {
        Write-ColorOutput " Version test failed!" Red
        exit 1
    }
    Write-ColorOutput " Version test passed" Green
    

    Write-Host ""
    Write-Host "Test 2: Help command"
    docker run --rm terrasecure:latest --help | Select-Object -First 5
    if ($LASTEXITCODE -ne 0) {
        Write-ColorOutput " Help test failed!" Red
        exit 1
    }
    Write-ColorOutput " Help test passed" Green

    if (Test-Path "examples/vulnerable") {
        Write-Host ""
        Write-Host "Test 3: Scan vulnerable examples"
        docker run --rm -v "${PWD}/examples:/scan:ro" terrasecure:latest /scan/vulnerable --format json | Out-Null
        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 2) {
            Write-ColorOutput " Scan test passed" Green
        } else {
            Write-ColorOutput "  Scan test returned unexpected exit code: $LASTEXITCODE" Yellow
        }
    }
}


Write-Host ""
Write-ColorOutput " Image Information:" Cyan
docker images terrasecure:latest --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"

$imageSize = docker images terrasecure:latest --format "{{.Size}}"
Write-Host ""
Write-Host "  Image Size: $imageSize"

Write-Host ""
$secScan = Read-Host "Run security scan with Trivy? (y/n)"
if ($secScan -eq "y" -or $secScan -eq "Y") {
    Write-ColorOutput " Running security scan..." Cyan

    try {
        trivy --version | Out-Null
        trivy image terrasecure:latest
    } catch {
        Write-ColorOutput "  Trivy not installed. Install from: https://aquasecurity.github.io/trivy/" Yellow
    }
}

Write-Host ""
if ($Push) {
    $pushConfirm = "y"
} else {
    $pushConfirm = Read-Host "Push to registry $Registry ? (y/n)"
}

if ($pushConfirm -eq "y" -or $pushConfirm -eq "Y") {
    Write-ColorOutput " Pushing to registry..." Cyan
    Write-Host ""
    
    foreach ($tag in $imageTags | Where-Object { $_ -like "$Registry/*" }) {
        Write-Host "Pushing: $tag"
        docker push $tag
        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput " Push failed for $tag" Red
            Write-Host "   Make sure you're logged in: docker login $Registry"
            exit 1
        }
    }
    
    Write-Host ""
    Write-ColorOutput " All images pushed successfully!" Green
}

# Summary
Write-Header "BUILD COMPLETE"

Write-ColorOutput " SUCCESS!" Green
Write-Host ""
Write-Host "Built Images:"
foreach ($tag in $imageTags) {
    Write-Host "  - $tag"
}

Write-Host ""
Write-ColorOutput "Usage Examples:" Yellow
Write-Host ""
Write-Host "  # Show help"
Write-Host "  docker run --rm terrasecure:latest --help"
Write-Host ""
Write-Host "  # Scan current directory"
Write-Host "  docker run --rm -v `"`${PWD}:/scan:ro`" terrasecure:latest /scan"
Write-Host ""
Write-Host "  # Scan with JSON output"
Write-Host "  docker run --rm -v `"`${PWD}:/scan:ro`" terrasecure:latest /scan --format json"
Write-Host ""
Write-Host "  # Scan and fail on critical issues"
Write-Host "  docker run --rm -v `"`${PWD}:/scan:ro`" terrasecure:latest /scan --fail-on critical"
Write-Host ""
Write-Host "  # Scan specific directory"
Write-Host "  docker run --rm -v `"`${PWD}/infrastructure:/scan:ro`" terrasecure:latest /scan"
Write-Host ""

Write-Host ""
Write-ColorOutput "Documentation:" Cyan
Write-Host "  GitHub: https://github.com/JashwanthMU/TerraSecure"
Write-Host "  Issues: https://github.com/JashwanthMU/TerraSecure/issues"
Write-Host ""

Write-ColorOutput "Next Steps:" Yellow
Write-Host "  1. Test the image: docker run --rm terrasecure:latest examples/vulnerable"
Write-Host "  2. Integrate into CI/CD"
Write-Host "  3. Create GitHub Action"
Write-Host ""