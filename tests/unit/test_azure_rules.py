"""
Unit tests for Azure Security Rules
"""

import unittest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from rules.azure_security_rules import AzureSecurityRules


class TestAzureSecurityRules(unittest.TestCase):
    """Test Azure Security Rules functionality"""

    @classmethod
    def setUpClass(cls):
        cls.rules = AzureSecurityRules()

    # ── Coverage / schema ────────────────────────────────────────────

    def test_rule_count(self):
        """Rule registry should expose exactly 50 patterns"""
        self.assertEqual(len(self.rules.items()), 50)

    def test_get_all_rules_matches_items(self):
        items_dict = dict(self.rules.items())
        all_rules = self.rules.get_all_rules()
        self.assertEqual(set(items_dict.keys()), set(all_rules.keys()))

    def test_finding_schema(self):
        """Every finding must carry the fields the analyzer/formatters rely on"""
        resource = {
            'type': 'azurerm_network_security_rule',
            'name': 'ssh_open',
            'file': 'main.tf',
            'line': 12,
            'properties': {
                'direction': 'Inbound',
                'access': 'Allow',
                'destination_port_range': '22',
                'source_address_prefix': '*',
            }
        }
        finding = self.rules.check_nsg_ssh_open(resource)
        self.assertIsNotNone(finding)
        for key in ('severity', 'message', 'file', 'line', 'remediation', 'cloud'):
            self.assertIn(key, finding)
        self.assertEqual(finding['cloud'], 'azure')
        self.assertEqual(finding['file'], 'main.tf')
        self.assertEqual(finding['line'], 12)

    def test_wrong_resource_type_returns_none(self):
        """Rules must not fire on resource types they don't own"""
        resource = {'type': 'aws_s3_bucket', 'properties': {}}
        self.assertIsNone(self.rules.check_nsg_ssh_open(resource))
        self.assertIsNone(self.rules.check_storage_public_access(resource))
        self.assertIsNone(self.rules.check_role_owner(resource))

    # ── Network Security ─────────────────────────────────────────────

    def test_nsg_rdp_open_detects_violation(self):
        resource = {
            'type': 'azurerm_network_security_rule',
            'properties': {
                'direction': 'Inbound', 'access': 'Allow',
                'destination_port_range': '3389', 'source_address_prefix': '0.0.0.0/0',
            }
        }
        finding = self.rules.check_nsg_rdp_open(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_nsg_rdp_restricted_source_is_safe(self):
        resource = {
            'type': 'azurerm_network_security_rule',
            'properties': {
                'direction': 'Inbound', 'access': 'Allow',
                'destination_port_range': '3389', 'source_address_prefix': '10.0.0.0/24',
            }
        }
        self.assertIsNone(self.rules.check_nsg_rdp_open(resource))

    def test_nsg_ssh_open_detects_violation(self):
        resource = {
            'type': 'azurerm_network_security_rule',
            'properties': {
                'direction': 'Inbound', 'access': 'Allow',
                'destination_port_range': '22', 'source_address_prefix': '*',
            }
        }
        finding = self.rules.check_nsg_ssh_open(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_nsg_all_inbound_open(self):
        resource = {
            'type': 'azurerm_network_security_rule',
            'properties': {
                'direction': 'Inbound', 'access': 'Allow',
                'protocol': '*', 'destination_port_range': '*',
                'source_address_prefix': '*',
            }
        }
        finding = self.rules.check_nsg_all_inbound(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_vm_public_ip_detected(self):
        resource = {
            'type': 'azurerm_linux_virtual_machine',
            'properties': {'public_ip_address_id': '/subscriptions/x/publicip'}
        }
        finding = self.rules.check_vm_public_ip(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')

    def test_vm_without_public_ip_is_safe(self):
        resource = {'type': 'azurerm_linux_virtual_machine', 'properties': {}}
        self.assertIsNone(self.rules.check_vm_public_ip(resource))

    def test_app_gateway_waf_missing(self):
        resource = {
            'type': 'azurerm_application_gateway',
            'properties': {
                'sku': {'tier': 'Standard_v2'},
                'waf_configuration': [{'enabled': False}],
            }
        }
        finding = self.rules.check_app_gateway_waf(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')

    def test_app_gateway_waf_enabled_is_safe(self):
        resource = {
            'type': 'azurerm_application_gateway',
            'properties': {
                'sku': {'tier': 'WAF_v2'},
                'waf_configuration': [{'enabled': True}],
            }
        }
        self.assertIsNone(self.rules.check_app_gateway_waf(resource))

    def test_sql_firewall_public_detected(self):
        resource = {
            'type': 'azurerm_sql_firewall_rule',
            'properties': {'start_ip_address': '0.0.0.0', 'end_ip_address': '255.255.255.255'}
        }
        finding = self.rules.check_sql_firewall_public(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_function_https_off_detected(self):
        resource = {'type': 'azurerm_linux_function_app', 'properties': {'https_only': False}}
        finding = self.rules.check_function_https(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')

    def test_function_https_on_is_safe(self):
        resource = {'type': 'azurerm_linux_function_app', 'properties': {'https_only': True}}
        self.assertIsNone(self.rules.check_function_https(resource))

    # ── Storage Security ──────────────────────────────────────────────

    def test_storage_public_access_detected(self):
        resource = {
            'type': 'azurerm_storage_account',
            'properties': {'allow_nested_items_to_be_public': True, 'allow_blob_public_access': True}
        }
        finding = self.rules.check_storage_public_access(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_storage_public_access_disabled_is_safe(self):
        resource = {
            'type': 'azurerm_storage_account',
            'properties': {'allow_nested_items_to_be_public': False, 'allow_blob_public_access': False}
        }
        self.assertIsNone(self.rules.check_storage_public_access(resource))

    def test_storage_blob_container_public(self):
        resource = {'type': 'azurerm_storage_container', 'properties': {'container_access_type': 'blob'}}
        finding = self.rules.check_storage_blob_public(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_storage_container_private_is_safe(self):
        resource = {'type': 'azurerm_storage_container', 'properties': {'container_access_type': 'private'}}
        self.assertIsNone(self.rules.check_storage_blob_public(resource))

    def test_storage_weak_tls_detected(self):
        resource = {'type': 'azurerm_storage_account', 'properties': {'min_tls_version': 'TLS1_0'}}
        finding = self.rules.check_storage_encryption(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')

    def test_storage_tls12_is_safe(self):
        resource = {'type': 'azurerm_storage_account', 'properties': {'min_tls_version': 'TLS1_2'}}
        self.assertIsNone(self.rules.check_storage_encryption(resource))

    def test_keyvault_soft_delete_off_detected(self):
        resource = {'type': 'azurerm_key_vault', 'properties': {'soft_delete_enabled': False}}
        finding = self.rules.check_keyvault_soft_delete(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')

    def test_keyvault_purge_protection_off_by_default(self):
        resource = {'type': 'azurerm_key_vault', 'properties': {}}
        finding = self.rules.check_keyvault_purge_protection(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')

    def test_keyvault_purge_protection_enabled_is_safe(self):
        resource = {'type': 'azurerm_key_vault', 'properties': {'purge_protection_enabled': True}}
        self.assertIsNone(self.rules.check_keyvault_purge_protection(resource))

    def test_sql_tde_disabled_detected(self):
        resource = {
            'type': 'azurerm_mssql_database',
            'properties': {'transparent_data_encryption_enabled': False}
        }
        finding = self.rules.check_sql_tde(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    # ── IAM Security ──────────────────────────────────────────────────

    def test_role_owner_subscription_scope_detected(self):
        resource = {
            'type': 'azurerm_role_assignment',
            'properties': {
                'role_definition_name': 'Owner',
                'scope': '/subscriptions/00000000-0000-0000-0000-000000000000',
            }
        }
        finding = self.rules.check_role_owner(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_role_owner_resource_group_scope_is_safe(self):
        resource = {
            'type': 'azurerm_role_assignment',
            'properties': {
                'role_definition_name': 'Owner',
                'scope': '/subscriptions/xxx/resourceGroups/example-rg',
            }
        }
        self.assertIsNone(self.rules.check_role_owner(resource))

    def test_aks_rbac_disabled_detected(self):
        resource = {
            'type': 'azurerm_kubernetes_cluster',
            'properties': {'role_based_access_control_enabled': False}
        }
        finding = self.rules.check_aks_rbac(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_vm_password_auth_enabled_detected(self):
        resource = {
            'type': 'azurerm_linux_virtual_machine',
            'properties': {'disable_password_authentication': False}
        }
        finding = self.rules.check_vm_password_auth(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')

    # ── Secrets Management ────────────────────────────────────────────

    def test_sql_admin_password_hardcoded_detected(self):
        resource = {
            'type': 'azurerm_mssql_server',
            'properties': {'administrator_login_password': 'SuperSecret123!'}
        }
        finding = self.rules.check_sql_admin_password(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_sql_admin_password_variable_is_safe(self):
        resource = {
            'type': 'azurerm_mssql_server',
            'properties': {'administrator_login_password': 'var.sql_admin_password'}
        }
        self.assertIsNone(self.rules.check_sql_admin_password(resource))

    def test_vm_admin_password_hardcoded_detected(self):
        resource = {
            'type': 'azurerm_linux_virtual_machine',
            'properties': {'admin_password': 'hardcoded123!'}
        }
        finding = self.rules.check_vm_admin_password(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_app_settings_plaintext_secret_detected(self):
        resource = {
            'type': 'azurerm_linux_web_app',
            'properties': {'app_settings': {'DB_PASSWORD': 'hunter2'}}
        }
        finding = self.rules.check_app_settings_secrets(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_app_settings_keyvault_reference_is_safe(self):
        resource = {
            'type': 'azurerm_linux_web_app',
            'properties': {'app_settings': {'DB_PASSWORD': '@Microsoft.KeyVault(SecretUri=https://x)'}}
        }
        self.assertIsNone(self.rules.check_app_settings_secrets(resource))

    # ── Monitoring & Compliance ────────────────────────────────────────

    def test_defender_free_tier_detected(self):
        resource = {
            'type': 'azurerm_security_center_subscription_pricing',
            'properties': {'tier': 'Free'}
        }
        finding = self.rules.check_defender(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')

    def test_defender_standard_tier_is_safe(self):
        resource = {
            'type': 'azurerm_security_center_subscription_pricing',
            'properties': {'tier': 'Standard'}
        }
        self.assertIsNone(self.rules.check_defender(resource))

    def test_sql_threat_detection_missing(self):
        resource = {'type': 'azurerm_mssql_server', 'properties': {}}
        finding = self.rules.check_sql_threat_detection(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')


if __name__ == '__main__':
    unittest.main()