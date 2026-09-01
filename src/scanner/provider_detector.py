PREFIX_MAP = {
    "aws_": "aws",
    "azurerm_": "azure",
    "google_": "gcp",
}

def detect_provider(resource_type: str) -> str:
    for prefix, provider in PREFIX_MAP.items():
        if resource_type.startswith(prefix):
            return provider
    return "unknown"