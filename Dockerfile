FROM python:3.11-slim AS builder

LABEL maintainer="TerraSecure Team"
LABEL version="1.0.0"
LABEL description="AI-Powered Terraform Security Scanner"

WORKDIR /build

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 -s /bin/bash terrasecure && \
    mkdir -p /app /scan /models /data && \
    chown -R terrasecure:terrasecure /app /scan /models /data

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

WORKDIR /app

COPY --chown=terrasecure:terrasecure src/ ./src/
COPY --chown=terrasecure:terrasecure scripts/ ./scripts/
COPY --chown=terrasecure:terrasecure examples/ ./examples/
COPY --chown=terrasecure:terrasecure requirements.txt .
COPY --chown=terrasecure:terrasecure setup.py .
COPY --chown=terrasecure:terrasecure README.md .

COPY --chown=terrasecure:terrasecure models/ ./models/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/terrasecure/.local/bin:$PATH"

USER terrasecure

RUN if [ ! -f models/terrasecure_production_v1.0.pkl ]; then \
        echo "  Production model not found - building..."; \
        python scripts/build_production_model.py || \
        echo "  Model build failed - will use fallback mode"; \
    else \
        echo " Production model found"; \
    fi

VOLUME ["/scan"]

ENTRYPOINT ["python", "src/cli.py"]
CMD ["--help"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import sys; sys.path.insert(0, 'src'); from ml.ml_analyzer import MLAnalyzer; MLAnalyzer()" || exit 1

LABEL org.opencontainers.image.source="https://github.com/JashwanthMU/TerraSecure"
LABEL org.opencontainers.image.documentation="https://github.com/JashwanthMU/TerraSecure"
LABEL org.opencontainers.image.licenses="MIT"