set -e

VERSION=${1:-"1.0.0"}
REGISTRY=${2:-"ghcr.io/jashwanthmu"}

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         TerraSecure Docker Image Builder                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Version:  $VERSION"
echo "Registry: $REGISTRY"
echo ""

echo " Building production model..."
python scripts/build_production_model.py

echo ""
echo " Building Docker image..."
docker build \
    --build-arg VERSION=$VERSION \
    --tag terrasecure:latest \
    --tag terrasecure:$VERSION \
    --tag $REGISTRY/terrasecure:latest \
    --tag $REGISTRY/terrasecure:$VERSION \
    .

echo ""
echo " Testing Docker image..."
docker run --rm terrasecure:latest --version

echo ""
echo " Image Info:"

read -p "Push to registry? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo " Pushing to registry..."
    docker push $REGISTRY/terrasecure:latest
    docker push $REGISTRY/terrasecure:$VERSION
    echo " Pushed successfully!"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  BUILD COMPLETE                               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Usage Examples:"
echo ""
echo "  # Scan directory"
echo "  docker run -v \$(pwd):/scan terrasecure:latest /scan"
echo ""
echo "  # Scan with JSON output"
echo "  docker run -v \$(pwd):/scan terrasecure:latest /scan --format json"
echo ""
echo "  # Scan and fail on critical"
echo "  docker run -v \$(pwd):/scan terrasecure:latest /scan --fail-on critical"
echo ""