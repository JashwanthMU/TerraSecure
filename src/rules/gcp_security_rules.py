"""
GCP Security Rules for TerraSecure
------------------------------------
Initial pattern set for Google Cloud Terraform resources.

NOTE: This is a v1 pass (22 patterns), not full parity with the AWS (50)
or Azure (50) rule sets yet. It covers the highest-signal misconfigurations
per domain so GCP scanning is genuinely useful on day one. Remaining
patterns from the README's planned GCP list are tracked as follow-up work
— ship this honestly rather than padding it with rules that just return
None on every real-world resource.
"""

from typing import Dict, Any, Optional, List


class GCPSecurityRules:
    """Security rules for Google Cloud Terraform resources."""

    PROVIDER_PREFIX = "google_"

    def items(self) -> List[tuple]:
        return [
            # Network Security
            ("gcp_firewall_ssh_open",         self.check_firewall_ssh_open),
            ("gcp_firewall_rdp_open",         self.check_firewall_rdp_open),
            ("gcp_firewall_all_open",         self.check_firewall_all_open),
            ("gcp_instance_public_ip",        self.check_instance_public_ip),
            ("gcp_sql_public_ip",             self.check_sql_public_ip),
            # Storage Security
            ("gcp_storage_bucket_public",     self.check_storage_bucket_public),
            ("gcp_storage_uniform_access_off",self.check_uniform_bucket_access),
            ("gcp_storage_versioning_off",    self.check_storage_versioning),
            ("gcp_sql_backup_disabled",       self.check_sql_backup_disabled),
            ("gcp_sql_no_ssl",                self.check_sql_require_ssl),
            ("gcp_disk_unencrypted_cmek",     self.check_disk_cmek),
            # IAM Security
            ("gcp_iam_primitive_role",        self.check_iam_primitive_role),
            ("gcp_sa_key_created",            self.check_service_account_key),
            ("gcp_iam_allusers_binding",      self.check_iam_allusers_binding),
            ("gcp_default_sa_used",           self.check_default_service_account),
            # Secrets Management
            ("gcp_secret_no_rotation",        self.check_secret_no_rotation),
            ("gcp_hardcoded_credentials",     self.check_hardcoded_credentials),
            ("gcp_gke_hardcoded_password",    self.check_gke_basic_auth),
            # Monitoring & Compliance
            ("gcp_audit_logging_disabled",    self.check_audit_logging_disabled),
            ("gcp_gke_legacy_metadata",       self.check_gke_legacy_metadata),
            ("gcp_gke_no_network_policy",     self.check_gke_network_policy),
            ("gcp_gke_no_private_nodes",      self.check_gke_private_nodes),
        ]

    def get_all_rules(self) -> Dict[str, Any]:
        return dict(self.items())

    # ── Helpers ────────────────────────────────────────────────────────────

    def _is_type(self, resource: Dict, *types: str) -> bool:
        return resource.get("type", "") in types

    def _props(self, resource: Dict) -> Dict:
        return resource.get("properties", {})

    def _finding(self, resource: Dict, severity: str, message: str, remediation: str) -> Dict:
        return {
            "severity": severity,
            "message": message,
            "file": resource.get("file", "unknown"),
            "line": resource.get("line", 0),
            "remediation": remediation,
            "cloud": "gcp",
        }

    def _has_open_cidr(self, ranges) -> bool:
        if isinstance(ranges, str):
            ranges = [ranges]
        return isinstance(ranges, list) and "0.0.0.0/0" in ranges

    # ── Network Security ───────────────────────────────────────────────────

    def _firewall_port_open(self, resource: Dict, port: str) -> bool:
        if not self._is_type(resource, "google_compute_firewall"):
            return False
        p = self._props(resource)
        if p.get("direction", "INGRESS").upper() != "INGRESS":
            return False
        if not self._has_open_cidr(p.get("source_ranges", [])):
            return False
        allow = p.get("allow", [])
        if isinstance(allow, dict):
            allow = [allow]
        for rule in allow:
            if not isinstance(rule, dict):
                continue
            ports = rule.get("ports", [])
            if isinstance(ports, str):
                ports = [ports]
            if port in ports or not ports:  # no ports = all ports for that protocol
                return True
        return False

    def check_firewall_ssh_open(self, resource: Dict) -> Optional[Dict]:
        if self._firewall_port_open(resource, "22"):
            return self._finding(resource, "CRITICAL",
                "GCP firewall rule allows SSH (22) from 0.0.0.0/0",
                "Restrict source_ranges to known IPs or use Identity-Aware Proxy (IAP) for SSH.")
        return None

    def check_firewall_rdp_open(self, resource: Dict) -> Optional[Dict]:
        if self._firewall_port_open(resource, "3389"):
            return self._finding(resource, "CRITICAL",
                "GCP firewall rule allows RDP (3389) from 0.0.0.0/0",
                "Restrict source_ranges to known IPs or use IAP TCP forwarding.")
        return None

    def check_firewall_all_open(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_compute_firewall"):
            return None
        p = self._props(resource)
        if p.get("direction", "INGRESS").upper() != "INGRESS":
            return None
        if not self._has_open_cidr(p.get("source_ranges", [])):
            return None
        allow = p.get("allow", [])
        if isinstance(allow, dict):
            allow = [allow]
        for rule in allow:
            if isinstance(rule, dict) and not rule.get("ports"):
                return self._finding(resource, "CRITICAL",
                    "GCP firewall rule allows ALL ports from 0.0.0.0/0",
                    "Specify explicit ports in the allow block and narrow source_ranges.")
        return None

    def check_instance_public_ip(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_compute_instance"):
            return None
        p = self._props(resource)
        for iface in (p.get("network_interface", []) if isinstance(p.get("network_interface"), list)
                      else [p.get("network_interface", {})]):
            if isinstance(iface, dict) and iface.get("access_config") is not None:
                return self._finding(resource, "MEDIUM",
                    "GCP Compute Instance has a public IP via access_config — increases attack surface",
                    "Remove access_config block and use Cloud NAT / IAP for outbound and admin access.")
        return None

    def check_sql_public_ip(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_sql_database_instance"):
            return None
        p = self._props(resource)
        settings = p.get("settings", {})
        if isinstance(settings, list) and settings:
            settings = settings[0]
        ip_config = settings.get("ip_configuration", {}) if isinstance(settings, dict) else {}
        if isinstance(ip_config, list) and ip_config:
            ip_config = ip_config[0]
        if isinstance(ip_config, dict) and ip_config.get("ipv4_enabled", True):
            return self._finding(resource, "HIGH",
                "Cloud SQL instance has a public IPv4 address enabled",
                "Set ipv4_enabled = false and use private_network with VPC peering instead.")
        return None

    # ── Storage Security ───────────────────────────────────────────────────

    def check_storage_bucket_public(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_storage_bucket_iam_binding",
                             "google_storage_bucket_iam_member"):
            return None
        p = self._props(resource)
        members = p.get("members", p.get("member", []))
        if isinstance(members, str):
            members = [members]
        if isinstance(members, list) and any(m in ("allUsers", "allAuthenticatedUsers") for m in members):
            return self._finding(resource, "CRITICAL",
                "GCS bucket IAM binding grants access to allUsers/allAuthenticatedUsers",
                "Remove public members. Grant access to specific service accounts or groups instead.")
        return None

    def check_uniform_bucket_access(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_storage_bucket"):
            return None
        p = self._props(resource)
        ubla = p.get("uniform_bucket_level_access", False)
        if not ubla:
            return self._finding(resource, "MEDIUM",
                "GCS bucket does not enforce uniform bucket-level access",
                "Set uniform_bucket_level_access = true to disable legacy per-object ACLs.")
        return None

    def check_storage_versioning(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_storage_bucket"):
            return None
        p = self._props(resource)
        versioning = p.get("versioning", {})
        if isinstance(versioning, list) and versioning:
            versioning = versioning[0]
        if not isinstance(versioning, dict) or not versioning.get("enabled", False):
            return self._finding(resource, "MEDIUM",
                "GCS bucket does not have object versioning enabled",
                "Set versioning { enabled = true } to protect against accidental overwrite/delete.")
        return None

    def check_sql_backup_disabled(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_sql_database_instance"):
            return None
        p = self._props(resource)
        settings = p.get("settings", {})
        if isinstance(settings, list) and settings:
            settings = settings[0]
        backup_config = settings.get("backup_configuration", {}) if isinstance(settings, dict) else {}
        if isinstance(backup_config, list) and backup_config:
            backup_config = backup_config[0]
        if not isinstance(backup_config, dict) or not backup_config.get("enabled", False):
            return self._finding(resource, "HIGH",
                "Cloud SQL instance has automated backups disabled",
                "Set backup_configuration { enabled = true, point_in_time_recovery_enabled = true }.")
        return None

    def check_sql_require_ssl(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_sql_database_instance"):
            return None
        p = self._props(resource)
        settings = p.get("settings", {})
        if isinstance(settings, list) and settings:
            settings = settings[0]
        ip_config = settings.get("ip_configuration", {}) if isinstance(settings, dict) else {}
        if isinstance(ip_config, list) and ip_config:
            ip_config = ip_config[0]
        if isinstance(ip_config, dict) and not ip_config.get("require_ssl", False):
            return self._finding(resource, "HIGH",
                "Cloud SQL instance does not require SSL for connections",
                "Set ip_configuration { require_ssl = true } or enforce via Cloud SQL Auth Proxy.")
        return None

    def check_disk_cmek(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_compute_disk"):
            return None
        p = self._props(resource)
        if not p.get("disk_encryption_key"):
            return self._finding(resource, "LOW",
                "GCP Compute Disk uses Google-managed encryption key — no CMEK",
                "Set disk_encryption_key { kms_key_self_link = ... } for customer-managed key compliance.")
        return None

    # ── IAM Security ──────────────────────────────────────────────────────

    _PRIMITIVE_ROLES = ("roles/owner", "roles/editor")

    def check_iam_primitive_role(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_project_iam_binding", "google_project_iam_member"):
            return None
        p = self._props(resource)
        role = str(p.get("role", ""))
        if role in self._PRIMITIVE_ROLES:
            return self._finding(resource, "CRITICAL",
                f"GCP IAM binding grants primitive role '{role}' at project scope",
                "Replace Owner/Editor with granular predefined or custom roles (least privilege).")
        return None

    def check_service_account_key(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_service_account_key"):
            return None
        return self._finding(resource, "MEDIUM",
            "GCP service account key (long-lived credential) is being created via Terraform",
            "Prefer Workload Identity Federation over static SA keys; if required, rotate frequently.")

    def check_iam_allusers_binding(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_project_iam_binding", "google_project_iam_member"):
            return None
        p = self._props(resource)
        members = p.get("members", p.get("member", []))
        if isinstance(members, str):
            members = [members]
        if isinstance(members, list) and any(m in ("allUsers", "allAuthenticatedUsers") for m in members):
            return self._finding(resource, "CRITICAL",
                "GCP project IAM binding grants a role to allUsers/allAuthenticatedUsers",
                "Remove public principals from project-level IAM bindings.")
        return None

    def check_default_service_account(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_compute_instance", "google_container_cluster"):
            return None
        p = self._props(resource)
        sa_block = p.get("service_account", {})
        if isinstance(sa_block, list) and sa_block:
            sa_block = sa_block[0]
        email = sa_block.get("email", "") if isinstance(sa_block, dict) else ""
        if not email or "compute@developer.gserviceaccount.com" in email:
            return self._finding(resource, "MEDIUM",
                "Resource uses the default Compute Engine service account (broad project access)",
                "Create a dedicated, least-privilege service account for this workload.")
        return None

    # ── Secrets Management ────────────────────────────────────────────────

    _SECRET_KEYWORDS = ("password", "secret", "api_key", "token", "credential", "private_key")

    def _has_secret_in_value(self, val: Any) -> bool:
        return any(kw in str(val).lower() for kw in self._SECRET_KEYWORDS)

    def check_secret_no_rotation(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_secret_manager_secret"):
            return None
        p = self._props(resource)
        if not p.get("rotation"):
            return self._finding(resource, "LOW",
                "Secret Manager secret has no rotation policy configured",
                "Add a rotation { rotation_period = ... } block or document manual rotation SLAs.")
        return None

    def check_hardcoded_credentials(self, resource: Dict) -> Optional[Dict]:
        rtype = resource.get("type", "")
        if not rtype.startswith("google_"):
            return None
        p = self._props(resource)
        env_vars = p.get("environment_variables", {})
        if isinstance(env_vars, dict):
            for key, value in env_vars.items():
                if self._has_secret_in_value(key) and not str(value).startswith(("var.", "${")):
                    return self._finding(resource, "CRITICAL",
                        f"Potential secret '{key}' hardcoded in plaintext environment variable",
                        "Use Secret Manager references instead of plaintext environment variables.")
        return None

    def check_gke_basic_auth(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_container_cluster"):
            return None
        p = self._props(resource)
        master_auth = p.get("master_auth", {})
        if isinstance(master_auth, list) and master_auth:
            master_auth = master_auth[0]
        if isinstance(master_auth, dict) and (master_auth.get("username") or master_auth.get("password")):
            return self._finding(resource, "HIGH",
                "GKE cluster has static basic auth username/password configured",
                "Remove master_auth username/password; rely on IAM/RBAC authentication instead.")
        return None

    # ── Monitoring & Compliance ────────────────────────────────────────────

    def check_audit_logging_disabled(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_project_iam_audit_config"):
            return None
        p = self._props(resource)
        audit_log_configs = p.get("audit_log_config", [])
        if isinstance(audit_log_configs, dict):
            audit_log_configs = [audit_log_configs]
        if not audit_log_configs:
            return self._finding(resource, "MEDIUM",
                "GCP audit config resource has no audit_log_config blocks defined",
                "Add audit_log_config blocks for ADMIN_READ, DATA_READ, and DATA_WRITE log types.")
        return None

    def check_gke_legacy_metadata(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_container_cluster"):
            return None
        p = self._props(resource)
        node_config = p.get("node_config", {})
        if isinstance(node_config, list) and node_config:
            node_config = node_config[0]
        metadata = node_config.get("metadata", {}) if isinstance(node_config, dict) else {}
        if isinstance(metadata, dict) and metadata.get("disable-legacy-endpoints") != "true":
            return self._finding(resource, "MEDIUM",
                "GKE node pool does not explicitly disable legacy metadata endpoints",
                "Set node_config { metadata = { disable-legacy-endpoints = \"true\" } }.")
        return None

    def check_gke_network_policy(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_container_cluster"):
            return None
        p = self._props(resource)
        network_policy = p.get("network_policy", {})
        if isinstance(network_policy, list) and network_policy:
            network_policy = network_policy[0]
        if not isinstance(network_policy, dict) or not network_policy.get("enabled", False):
            return self._finding(resource, "HIGH",
                "GKE cluster has no network policy enabled — pods can communicate freely",
                "Set network_policy { enabled = true, provider = \"CALICO\" }.")
        return None

    def check_gke_private_nodes(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "google_container_cluster"):
            return None
        p = self._props(resource)
        private_cluster_config = p.get("private_cluster_config", {})
        if isinstance(private_cluster_config, list) and private_cluster_config:
            private_cluster_config = private_cluster_config[0]
        if not isinstance(private_cluster_config, dict) or not private_cluster_config.get("enable_private_nodes", False):
            return self._finding(resource, "HIGH",
                "GKE cluster nodes have public IP addresses (private nodes not enabled)",
                "Set private_cluster_config { enable_private_nodes = true }.")
        return None