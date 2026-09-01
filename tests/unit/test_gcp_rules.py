"""
Unit tests for GCP Security Rules
"""

import unittest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from rules.gcp_security_rules import GCPSecurityRules


class TestGCPSecurityRules(unittest.TestCase):
    """Test GCP Security Rules functionality"""

    @classmethod
    def setUpClass(cls):
        cls.rules = GCPSecurityRules()

    # ── Coverage / schema ────────────────────────────────────────────

    def test_rule_count(self):
        """Rule registry should expose exactly 22 patterns (v1 — see file docstring)"""
        self.assertEqual(len(self.rules.items()), 22)

    def test_get_all_rules_matches_items(self):
        items_dict = dict(self.rules.items())
        all_rules = self.rules.get_all_rules()
        self.assertEqual(set(items_dict.keys()), set(all_rules.keys()))

    def test_finding_schema(self):
        """Every finding must carry the fields the analyzer/formatters rely on"""
        resource = {
            'type': 'google_compute_firewall',
            'name': 'ssh_open',
            'file': 'main.tf',
            'line': 5,
            'properties': {
                'direction': 'INGRESS',
                'source_ranges': ['0.0.0.0/0'],
                'allow': [{'protocol': 'tcp', 'ports': ['22']}],
            }
        }
        finding = self.rules.check_firewall_ssh_open(resource)
        self.assertIsNotNone(finding)
        for key in ('severity', 'message', 'file', 'line', 'remediation', 'cloud'):
            self.assertIn(key, finding)
        self.assertEqual(finding['cloud'], 'gcp')
        self.assertEqual(finding['file'], 'main.tf')
        self.assertEqual(finding['line'], 5)

    def test_wrong_resource_type_returns_none(self):
        """Rules must not fire on resource types they don't own"""
        resource = {'type': 'azurerm_storage_account', 'properties': {}}
        self.assertIsNone(self.rules.check_firewall_ssh_open(resource))
        self.assertIsNone(self.rules.check_storage_bucket_public(resource))
        self.assertIsNone(self.rules.check_iam_primitive_role(resource))

    # ── Network Security ─────────────────────────────────────────────

    def test_firewall_ssh_open_detected(self):
        resource = {
            'type': 'google_compute_firewall',
            'properties': {
                'direction': 'INGRESS',
                'source_ranges': ['0.0.0.0/0'],
                'allow': [{'protocol': 'tcp', 'ports': ['22']}],
            }
        }
        finding = self.rules.check_firewall_ssh_open(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_firewall_ssh_restricted_source_is_safe(self):
        resource = {
            'type': 'google_compute_firewall',
            'properties': {
                'direction': 'INGRESS',
                'source_ranges': ['10.0.0.0/24'],
                'allow': [{'protocol': 'tcp', 'ports': ['22']}],
            }
        }
        self.assertIsNone(self.rules.check_firewall_ssh_open(resource))

    def test_firewall_rdp_open_detected(self):
        resource = {
            'type': 'google_compute_firewall',
            'properties': {
                'direction': 'INGRESS',
                'source_ranges': ['0.0.0.0/0'],
                'allow': [{'protocol': 'tcp', 'ports': ['3389']}],
            }
        }
        finding = self.rules.check_firewall_rdp_open(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_firewall_all_ports_open_detected(self):
        resource = {
            'type': 'google_compute_firewall',
            'properties': {
                'direction': 'INGRESS',
                'source_ranges': ['0.0.0.0/0'],
                'allow': [{'protocol': 'tcp'}],  # no 'ports' key = all ports
            }
        }
        finding = self.rules.check_firewall_all_open(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_instance_public_ip_detected(self):
        resource = {
            'type': 'google_compute_instance',
            'properties': {'network_interface': [{'access_config': {}}]}
        }
        finding = self.rules.check_instance_public_ip(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'MEDIUM')

    def test_instance_without_access_config_is_safe(self):
        resource = {
            'type': 'google_compute_instance',
            'properties': {'network_interface': [{}]}
        }
        self.assertIsNone(self.rules.check_instance_public_ip(resource))

    def test_sql_public_ip_detected(self):
        resource = {
            'type': 'google_sql_database_instance',
            'properties': {'settings': [{'ip_configuration': [{'ipv4_enabled': True}]}]}
        }
        finding = self.rules.check_sql_public_ip(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')

    def test_sql_no_public_ip_is_safe(self):
        resource = {
            'type': 'google_sql_database_instance',
            'properties': {'settings': [{'ip_configuration': [{'ipv4_enabled': False}]}]}
        }
        self.assertIsNone(self.rules.check_sql_public_ip(resource))

    # ── Storage Security ──────────────────────────────────────────────

    def test_bucket_iam_allusers_detected(self):
        resource = {
            'type': 'google_storage_bucket_iam_member',
            'properties': {'member': 'allUsers'}
        }
        finding = self.rules.check_storage_bucket_public(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_bucket_iam_specific_member_is_safe(self):
        resource = {
            'type': 'google_storage_bucket_iam_member',
            'properties': {'member': 'serviceAccount:app@example-project.iam.gserviceaccount.com'}
        }
        self.assertIsNone(self.rules.check_storage_bucket_public(resource))

    def test_uniform_bucket_access_off_by_default(self):
        resource = {'type': 'google_storage_bucket', 'properties': {}}
        finding = self.rules.check_uniform_bucket_access(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'MEDIUM')

    def test_uniform_bucket_access_enabled_is_safe(self):
        resource = {
            'type': 'google_storage_bucket',
            'properties': {'uniform_bucket_level_access': True}
        }
        self.assertIsNone(self.rules.check_uniform_bucket_access(resource))

    def test_bucket_versioning_disabled_detected(self):
        resource = {
            'type': 'google_storage_bucket',
            'properties': {'versioning': [{'enabled': False}]}
        }
        finding = self.rules.check_storage_versioning(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'MEDIUM')

    def test_bucket_versioning_enabled_is_safe(self):
        resource = {
            'type': 'google_storage_bucket',
            'properties': {'versioning': [{'enabled': True}]}
        }
        self.assertIsNone(self.rules.check_storage_versioning(resource))

    def test_sql_backup_disabled_detected(self):
        resource = {
            'type': 'google_sql_database_instance',
            'properties': {'settings': [{'backup_configuration': [{'enabled': False}]}]}
        }
        finding = self.rules.check_sql_backup_disabled(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')

    def test_sql_no_ssl_required_detected(self):
        resource = {
            'type': 'google_sql_database_instance',
            'properties': {'settings': [{'ip_configuration': [{'require_ssl': False}]}]}
        }
        finding = self.rules.check_sql_require_ssl(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')

    def test_sql_ssl_required_is_safe(self):
        resource = {
            'type': 'google_sql_database_instance',
            'properties': {'settings': [{'ip_configuration': [{'require_ssl': True}]}]}
        }
        self.assertIsNone(self.rules.check_sql_require_ssl(resource))

    def test_disk_no_cmek_detected(self):
        resource = {'type': 'google_compute_disk', 'properties': {}}
        finding = self.rules.check_disk_cmek(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'LOW')

    # ── IAM Security ──────────────────────────────────────────────────

    def test_primitive_owner_role_detected(self):
        resource = {
            'type': 'google_project_iam_member',
            'properties': {'role': 'roles/owner'}
        }
        finding = self.rules.check_iam_primitive_role(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_granular_role_is_safe(self):
        resource = {
            'type': 'google_project_iam_member',
            'properties': {'role': 'roles/storage.objectViewer'}
        }
        self.assertIsNone(self.rules.check_iam_primitive_role(resource))

    def test_service_account_key_flagged(self):
        resource = {'type': 'google_service_account_key', 'properties': {}}
        finding = self.rules.check_service_account_key(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'MEDIUM')

    def test_project_iam_allusers_binding_detected(self):
        resource = {
            'type': 'google_project_iam_binding',
            'properties': {'members': ['allUsers']}
        }
        finding = self.rules.check_iam_allusers_binding(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_default_service_account_detected(self):
        resource = {
            'type': 'google_compute_instance',
            'properties': {
                'service_account': [{'email': '123456-compute@developer.gserviceaccount.com'}]
            }
        }
        finding = self.rules.check_default_service_account(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'MEDIUM')

    def test_dedicated_service_account_is_safe(self):
        resource = {
            'type': 'google_compute_instance',
            'properties': {
                'service_account': [{'email': 'app-sa@example-project.iam.gserviceaccount.com'}]
            }
        }
        self.assertIsNone(self.rules.check_default_service_account(resource))

    # ── Secrets Management ────────────────────────────────────────────

    def test_secret_no_rotation_detected(self):
        resource = {'type': 'google_secret_manager_secret', 'properties': {}}
        finding = self.rules.check_secret_no_rotation(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'LOW')

    def test_hardcoded_credential_env_var_detected(self):
        # Uses rtype.startswith('google_') generically — any GCP resource
        # with an environment_variables block is in scope.
        resource = {
            'type': 'google_cloudfunctions_function',
            'properties': {'environment_variables': {'DB_PASSWORD': 'hunter2'}}
        }
        finding = self.rules.check_hardcoded_credentials(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'CRITICAL')

    def test_env_var_using_variable_reference_is_safe(self):
        resource = {
            'type': 'google_cloudfunctions_function',
            'properties': {'environment_variables': {'DB_PASSWORD': 'var.db_password'}}
        }
        self.assertIsNone(self.rules.check_hardcoded_credentials(resource))

    def test_gke_basic_auth_detected(self):
        resource = {
            'type': 'google_container_cluster',
            'properties': {'master_auth': [{'username': 'admin', 'password': 'hunter2'}]}
        }
        finding = self.rules.check_gke_basic_auth(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')

    # ── Monitoring & Compliance ────────────────────────────────────────

    def test_audit_logging_no_configs_detected(self):
        resource = {
            'type': 'google_project_iam_audit_config',
            'properties': {'audit_log_config': []}
        }
        finding = self.rules.check_audit_logging_disabled(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'MEDIUM')

    def test_gke_legacy_metadata_not_disabled(self):
        resource = {
            'type': 'google_container_cluster',
            'properties': {'node_config': [{'metadata': {}}]}
        }
        finding = self.rules.check_gke_legacy_metadata(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'MEDIUM')

    def test_gke_network_policy_disabled_detected(self):
        resource = {
            'type': 'google_container_cluster',
            'properties': {'network_policy': [{'enabled': False}]}
        }
        finding = self.rules.check_gke_network_policy(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')

    def test_gke_network_policy_enabled_is_safe(self):
        resource = {
            'type': 'google_container_cluster',
            'properties': {'network_policy': [{'enabled': True}]}
        }
        self.assertIsNone(self.rules.check_gke_network_policy(resource))

    def test_gke_public_nodes_detected(self):
        resource = {
            'type': 'google_container_cluster',
            'properties': {'private_cluster_config': [{'enable_private_nodes': False}]}
        }
        finding = self.rules.check_gke_private_nodes(resource)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['severity'], 'HIGH')

    def test_gke_private_nodes_enabled_is_safe(self):
        resource = {
            'type': 'google_container_cluster',
            'properties': {'private_cluster_config': [{'enable_private_nodes': True}]}
        }
        self.assertIsNone(self.rules.check_gke_private_nodes(resource))


if __name__ == '__main__':
    unittest.main()