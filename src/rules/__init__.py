"""
Multi-cloud rule engine registry for TerraSecure.

Each engine exposes an `items()` method returning
[(rule_name, rule_func), ...] and a `get_all_rules()` dict form,
so the analyzer can normalize either interface.
"""

from rules.aws_security_rules import SecurityRules as AWSSecurityRules
from rules.azure_security_rules import AzureSecurityRules
from rules.gcp_security_rules import GCPSecurityRules

RULE_ENGINES = {
    "aws": AWSSecurityRules(),
    "azure": AzureSecurityRules(),
    "gcp": GCPSecurityRules(),
}

__all__ = ["RULE_ENGINES"]