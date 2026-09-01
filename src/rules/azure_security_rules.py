"""
Azure Security Rules for TerraSecure
-------------------------------------
50 security patterns across 5 domains for Azure Terraform resources.
"""

from typing import Dict, Any, Optional, List


class AzureSecurityRules:
    """Security rules for Azure Terraform resources."""

    PROVIDER_PREFIX = "azurerm_"

    def items(self) -> List[tuple]:
        return [
            # Network Security (12)
            ("az_nsg_rdp_open",                self.check_nsg_rdp_open),
            ("az_nsg_ssh_open",                self.check_nsg_ssh_open),
            ("az_nsg_all_inbound_open",        self.check_nsg_all_inbound),
            ("az_nsg_all_outbound_open",       self.check_nsg_all_outbound),
            ("az_vm_public_ip_direct",         self.check_vm_public_ip),
            ("az_app_gateway_no_waf",          self.check_app_gateway_waf),
            ("az_lb_no_diagnostics",           self.check_lb_diagnostics),
            ("az_aks_network_policy_missing",  self.check_aks_network_policy),
            ("az_sql_firewall_all_azure",      self.check_sql_firewall_all_azure),
            ("az_sql_firewall_public",         self.check_sql_firewall_public),
            ("az_function_https_only_off",     self.check_function_https),
            ("az_app_service_https_only_off",  self.check_app_service_https),
            # Storage Security (15)
            ("az_storage_public_access",       self.check_storage_public_access),
            ("az_storage_blob_public",         self.check_storage_blob_public),
            ("az_storage_no_https",            self.check_storage_https),
            ("az_storage_no_encryption",       self.check_storage_encryption),
            ("az_storage_soft_delete_off",     self.check_storage_soft_delete),
            ("az_storage_versioning_off",      self.check_storage_versioning),
            ("az_storage_no_logging",          self.check_storage_logging),
            ("az_keyvault_soft_delete_off",    self.check_keyvault_soft_delete),
            ("az_keyvault_purge_protect_off",  self.check_keyvault_purge_protection),
            ("az_keyvault_no_firewall",        self.check_keyvault_firewall),
            ("az_sql_no_tde",                  self.check_sql_tde),
            ("az_sql_auditing_off",            self.check_sql_auditing),
            ("az_sql_retention_short",         self.check_sql_retention),
            ("az_managed_disk_unencrypted",    self.check_managed_disk_encryption),
            ("az_backup_retention_short",      self.check_backup_retention),
            # IAM Security (10)
            ("az_role_owner_broad",            self.check_role_owner),
            ("az_role_contributor_broad",      self.check_role_contributor),
            ("az_custom_role_wildcard",        self.check_custom_role_wildcard),
            ("az_role_subscription_scope",     self.check_role_subscription_scope),
            ("az_aks_rbac_disabled",           self.check_aks_rbac),
            ("az_aks_aad_disabled",            self.check_aks_aad),
            ("az_app_service_no_managed_id",   self.check_app_managed_identity),
            ("az_function_no_managed_id",      self.check_function_managed_identity),
            ("az_sql_aad_admin_missing",       self.check_sql_aad_admin),
            ("az_vm_password_auth",            self.check_vm_password_auth),
            # Secrets Management (8)
            ("az_keyvault_access_all",         self.check_keyvault_all_access),
            ("az_app_settings_secrets",        self.check_app_settings_secrets),
            ("az_function_settings_secrets",   self.check_function_settings_secrets),
            ("az_sql_admin_hardcoded",         self.check_sql_admin_password),
            ("az_vm_admin_hardcoded",          self.check_vm_admin_password),
            ("az_sp_secret_no_expiry",         self.check_sp_secret_expiry),
            ("az_keyvault_key_no_expiry",      self.check_keyvault_key_expiry),
            ("az_storage_account_key_exposed", self.check_storage_key_exposed),
            # Monitoring & Compliance (5)
            ("az_defender_disabled",           self.check_defender),
            ("az_monitor_diag_missing",        self.check_monitor_diagnostics),
            ("az_activity_log_retention",      self.check_activity_log_retention),
            ("az_sql_threat_detection_off",    self.check_sql_threat_detection),
            ("az_aks_monitoring_off",          self.check_aks_monitoring),
        ]

    def get_all_rules(self) -> Dict[str, Any]:
        """Return rules as dict for compatibility with the analyzer."""
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
            "cloud": "azure",
        }

    def _check_cidr_open(self, props: Dict, field: str = "source_address_prefix") -> bool:
        val = str(props.get(field, "")).strip()
        return val in ("*", "0.0.0.0/0", "Internet", "Any")

    # ── Network Security ───────────────────────────────────────────────────

    def check_nsg_rdp_open(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_network_security_rule"):
            return None
        p = self._props(resource)
        dest_port = str(p.get("destination_port_range", ""))
        if (p.get("direction", "").lower() == "inbound"
                and p.get("access", "").lower() == "allow"
                and ("3389" in dest_port or dest_port == "*")
                and self._check_cidr_open(p)):
            return self._finding(resource, "CRITICAL",
                "Azure NSG allows RDP (3389) from the internet (0.0.0.0/0 or *)",
                "Restrict source_address_prefix to a corporate IP range or use Azure Bastion")
        return None

    def check_nsg_ssh_open(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_network_security_rule"):
            return None
        p = self._props(resource)
        dest_port = str(p.get("destination_port_range", ""))
        if (p.get("direction", "").lower() == "inbound"
                and p.get("access", "").lower() == "allow"
                and ("22" in dest_port or dest_port == "*")
                and self._check_cidr_open(p)):
            return self._finding(resource, "CRITICAL",
                "Azure NSG allows SSH (22) from the internet (0.0.0.0/0 or *)",
                "Restrict SSH to VPN/Bastion only. Set source_address_prefix to a specific CIDR.")
        return None

    def check_nsg_all_inbound(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_network_security_rule"):
            return None
        p = self._props(resource)
        if (p.get("direction", "").lower() == "inbound"
                and p.get("access", "").lower() == "allow"
                and p.get("protocol", "") == "*"
                and p.get("destination_port_range", "") == "*"
                and self._check_cidr_open(p)):
            return self._finding(resource, "CRITICAL",
                "Azure NSG allows ALL inbound traffic from the internet",
                "Remove wildcard allow rules. Explicitly allow only required ports and sources.")
        return None

    def check_nsg_all_outbound(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_network_security_rule"):
            return None
        p = self._props(resource)
        if (p.get("direction", "").lower() == "outbound"
                and p.get("access", "").lower() == "allow"
                and p.get("destination_port_range", "") == "*"
                and self._check_cidr_open(p, "destination_address_prefix")):
            return self._finding(resource, "MEDIUM",
                "Azure NSG allows unrestricted outbound traffic — enables data exfiltration",
                "Restrict egress to known destinations. Block unexpected outbound internet traffic.")
        return None

    def check_vm_public_ip(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_linux_virtual_machine",
                             "azurerm_windows_virtual_machine", "azurerm_virtual_machine"):
            return None
        p = self._props(resource)
        if p.get("public_ip_address_id") or p.get("public_ip_allocation_method"):
            return self._finding(resource, "HIGH",
                "Azure VM appears to have a public IP assigned directly — increases attack surface",
                "Place VMs behind a load balancer or Application Gateway. Use Azure Bastion for admin access.")
        return None

    def check_app_gateway_waf(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_application_gateway"):
            return None
        p = self._props(resource)
        waf_config = p.get("waf_configuration", {})
        sku = p.get("sku", {})
        tier = sku.get("tier", "") if isinstance(sku, dict) else ""
        waf_enabled = False
        if isinstance(waf_config, list) and waf_config:
            waf_enabled = waf_config[0].get("enabled", False)
        elif isinstance(waf_config, dict):
            waf_enabled = waf_config.get("enabled", False)
        if "WAF" not in tier or not waf_enabled:
            return self._finding(resource, "HIGH",
                "Azure Application Gateway does not have WAF enabled",
                "Set sku.tier = 'WAF_v2' and enable waf_configuration { enabled = true, firewall_mode = 'Prevention' }")
        return None

    def check_lb_diagnostics(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_lb"):
            return None
        return self._finding(resource, "LOW",
            "Azure Load Balancer found — ensure diagnostic settings are configured separately",
            "Create an azurerm_monitor_diagnostic_setting resource targeting this LB's resource ID.")

    def check_aks_network_policy(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_kubernetes_cluster"):
            return None
        p = self._props(resource)
        net_profile = p.get("network_profile", {})
        if isinstance(net_profile, list) and net_profile:
            net_profile = net_profile[0]
        network_policy = net_profile.get("network_policy", "") if isinstance(net_profile, dict) else ""
        if not network_policy:
            return self._finding(resource, "HIGH",
                "AKS cluster has no network policy — pods can communicate freely across namespaces",
                "Set network_profile { network_policy = 'azure' } or 'calico' to enforce pod-level segmentation.")
        return None

    def check_sql_firewall_all_azure(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_sql_firewall_rule"):
            return None
        p = self._props(resource)
        if p.get("start_ip_address", "") == "0.0.0.0" and p.get("end_ip_address", "") == "0.0.0.0":
            return self._finding(resource, "MEDIUM",
                "Azure SQL firewall rule 'Allow all Azure services' enabled — allows all Azure IPs",
                "Replace with explicit IP ranges. This rule allows any Azure-hosted attacker service.")
        return None

    def check_sql_firewall_public(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_sql_firewall_rule"):
            return None
        p = self._props(resource)
        if p.get("start_ip_address", "") == "0.0.0.0" and p.get("end_ip_address", "") == "255.255.255.255":
            return self._finding(resource, "CRITICAL",
                "Azure SQL firewall rule allows ALL public IPs (0.0.0.0 – 255.255.255.255)",
                "Restrict SQL firewall to known office/VPN IP ranges only.")
        return None

    def check_function_https(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_function_app", "azurerm_linux_function_app",
                             "azurerm_windows_function_app"):
            return None
        p = self._props(resource)
        if not p.get("https_only", False):
            return self._finding(resource, "HIGH",
                "Azure Function App does not enforce HTTPS — HTTP traffic allowed",
                "Set https_only = true on the azurerm_function_app resource.")
        return None

    def check_app_service_https(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_app_service", "azurerm_linux_web_app",
                             "azurerm_windows_web_app"):
            return None
        p = self._props(resource)
        if not p.get("https_only", False):
            return self._finding(resource, "HIGH",
                "Azure App Service does not enforce HTTPS — allows plaintext HTTP traffic",
                "Set https_only = true. Also configure minimum_tls_version = '1.2' in site_config.")
        return None

    # ── Storage Security ───────────────────────────────────────────────────

    def check_storage_public_access(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_storage_account"):
            return None
        p = self._props(resource)
        if p.get("allow_nested_items_to_be_public", True) or p.get("allow_blob_public_access", True):
            return self._finding(resource, "CRITICAL",
                "Azure Storage Account allows public blob access — data is internet-readable",
                "Set allow_nested_items_to_be_public = false and allow_blob_public_access = false.")
        return None

    def check_storage_blob_public(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_storage_container"):
            return None
        p = self._props(resource)
        access = p.get("container_access_type", "private")
        if access in ("blob", "container"):
            return self._finding(resource, "CRITICAL",
                f"Azure Storage Container container_access_type = '{access}' — publicly readable",
                "Set container_access_type = 'private'. Serve public assets via SAS tokens or CDN.")
        return None

    def check_storage_https(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_storage_account"):
            return None
        p = self._props(resource)
        if not p.get("enable_https_traffic_only", True):
            return self._finding(resource, "HIGH",
                "Azure Storage Account allows HTTP traffic — data in transit unencrypted",
                "Set enable_https_traffic_only = true (default). Never disable this.")
        return None

    def check_storage_encryption(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_storage_account"):
            return None
        p = self._props(resource)
        min_tls = p.get("min_tls_version", "TLS1_0")
        if min_tls in ("TLS1_0", "TLS1_1"):
            return self._finding(resource, "HIGH",
                f"Azure Storage Account uses weak TLS version: {min_tls}",
                "Set min_tls_version = 'TLS1_2' to enforce modern encryption in transit.")
        return None

    def check_storage_soft_delete(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_storage_account"):
            return None
        p = self._props(resource)
        blob_props = p.get("blob_properties", {})
        if isinstance(blob_props, list) and blob_props:
            blob_props = blob_props[0]
        if isinstance(blob_props, dict):
            delete_policy = blob_props.get("delete_retention_policy", {})
            if isinstance(delete_policy, list) and delete_policy:
                delete_policy = delete_policy[0]
            days = delete_policy.get("days", 0) if isinstance(delete_policy, dict) else 0
            if days < 7:
                return self._finding(resource, "MEDIUM",
                    "Azure Storage blob soft delete retention is less than 7 days (or disabled)",
                    "Set blob_properties { delete_retention_policy { days = 30 } } to enable soft delete.")
        return None

    def check_storage_versioning(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_storage_account"):
            return None
        p = self._props(resource)
        blob_props = p.get("blob_properties", {})
        if isinstance(blob_props, list) and blob_props:
            blob_props = blob_props[0]
        if isinstance(blob_props, dict) and not blob_props.get("versioning_enabled", False):
            return self._finding(resource, "MEDIUM",
                "Azure Storage Account blob versioning is disabled — no protection from overwrites",
                "Set blob_properties { versioning_enabled = true }.")
        return None

    def check_storage_logging(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_storage_account"):
            return None
        p = self._props(resource)
        queue_props = p.get("queue_properties", {})
        if isinstance(queue_props, list) and queue_props:
            queue_props = queue_props[0]
        if not queue_props or not isinstance(queue_props, dict):
            return self._finding(resource, "LOW",
                "Azure Storage Account has no queue_properties/logging configured",
                "Add queue_properties { logging { read=true, write=true, delete=true, version='1.0' } }.")
        return None

    def check_keyvault_soft_delete(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_key_vault"):
            return None
        p = self._props(resource)
        if not p.get("soft_delete_enabled", True):
            return self._finding(resource, "HIGH",
                "Azure Key Vault soft delete is disabled — secrets permanently deleted immediately",
                "Set soft_delete_enabled = true and soft_delete_retention_days = 90.")
        return None

    def check_keyvault_purge_protection(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_key_vault"):
            return None
        p = self._props(resource)
        if not p.get("purge_protection_enabled", False):
            return self._finding(resource, "HIGH",
                "Azure Key Vault purge protection is disabled — vault can be permanently destroyed",
                "Set purge_protection_enabled = true. Required for GDPR/compliance workloads.")
        return None

    def check_keyvault_firewall(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_key_vault"):
            return None
        p = self._props(resource)
        net_acls = p.get("network_acls", {})
        if isinstance(net_acls, list) and net_acls:
            net_acls = net_acls[0]
        default_action = net_acls.get("default_action", "Allow") if isinstance(net_acls, dict) else "Allow"
        if default_action == "Allow" or not net_acls:
            return self._finding(resource, "HIGH",
                "Azure Key Vault network ACL default action is 'Allow' — accessible from all networks",
                "Set network_acls { default_action = 'Deny', bypass = ['AzureServices'], ip_rules = [...] }.")
        return None

    def check_sql_tde(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_mssql_database", "azurerm_sql_database"):
            return None
        p = self._props(resource)
        if p.get("transparent_data_encryption_enabled", True) is False:
            return self._finding(resource, "CRITICAL",
                "Azure SQL Database has Transparent Data Encryption (TDE) explicitly disabled",
                "Remove transparent_data_encryption_enabled = false or set it to true.")
        return None

    def check_sql_auditing(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_mssql_server", "azurerm_sql_server"):
            return None
        p = self._props(resource)
        if "extended_auditing_policy" not in p:
            return self._finding(resource, "HIGH",
                "Azure SQL Server has no auditing policy configured",
                "Add extended_auditing_policy { storage_endpoint = ... retention_in_days = 90 }.")
        return None

    def check_sql_retention(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_mssql_server", "azurerm_sql_server"):
            return None
        p = self._props(resource)
        policy = p.get("extended_auditing_policy", {})
        if isinstance(policy, list) and policy:
            policy = policy[0]
        days = policy.get("retention_in_days", 0) if isinstance(policy, dict) else 0
        if 0 < days < 90:
            return self._finding(resource, "MEDIUM",
                f"Azure SQL Server audit log retention is {days} days — PCI-DSS requires 90+",
                "Set extended_auditing_policy { retention_in_days = 90 }.")
        return None

    def check_managed_disk_encryption(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_managed_disk"):
            return None
        p = self._props(resource)
        if not p.get("disk_encryption_set_id"):
            return self._finding(resource, "MEDIUM",
                "Azure Managed Disk uses platform-managed key — no customer-managed key (CMK)",
                "Set disk_encryption_set_id to an azurerm_disk_encryption_set for CMK compliance.")
        return None

    def check_backup_retention(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_backup_policy_vm"):
            return None
        p = self._props(resource)
        retention = p.get("retention_daily", {})
        if isinstance(retention, list) and retention:
            retention = retention[0]
        days = retention.get("count", 0) if isinstance(retention, dict) else 0
        if days < 7:
            return self._finding(resource, "MEDIUM",
                f"Azure VM backup retention is only {days} days — insufficient for most workloads",
                "Set retention_daily { count = 30 } minimum. Consider weekly/monthly tiers too.")
        return None

    # ── IAM Security ──────────────────────────────────────────────────────

    def check_role_owner(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_role_assignment"):
            return None
        p = self._props(resource)
        role_def = str(p.get("role_definition_name", "")).lower()
        scope = str(p.get("scope", ""))
        if role_def == "owner" and "/subscriptions/" in scope and "/resourceGroups/" not in scope:
            return self._finding(resource, "CRITICAL",
                "Azure Owner role assigned at subscription scope — full control over all resources",
                "Grant Owner only at resource group scope and only to specific service principals.")
        return None

    def check_role_contributor(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_role_assignment"):
            return None
        p = self._props(resource)
        role_def = str(p.get("role_definition_name", "")).lower()
        scope = str(p.get("scope", ""))
        if role_def == "contributor" and "/subscriptions/" in scope and "/resourceGroups/" not in scope:
            return self._finding(resource, "HIGH",
                "Azure Contributor role assigned at subscription scope — write access to all resources",
                "Scope Contributor assignments to specific resource groups.")
        return None

    def check_custom_role_wildcard(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_role_definition"):
            return None
        p = self._props(resource)
        permissions = p.get("permissions", [])
        if isinstance(permissions, dict):
            permissions = [permissions]
        for perm in permissions:
            if isinstance(perm, dict) and "*" in perm.get("actions", []):
                return self._finding(resource, "HIGH",
                    "Azure custom role definition contains wildcard (*) action",
                    "Replace '*' with explicit action list following least-privilege principle.")
        return None

    def check_role_subscription_scope(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_role_assignment"):
            return None
        p = self._props(resource)
        scope = str(p.get("scope", ""))
        role = str(p.get("role_definition_name", ""))
        if "/subscriptions/" in scope and scope.count("/") == 2:
            return self._finding(resource, "MEDIUM",
                f"Azure role '{role}' assigned at subscription scope — broad blast radius",
                "Scope role assignments to resource groups or individual resources where possible.")
        return None

    def check_aks_rbac(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_kubernetes_cluster"):
            return None
        p = self._props(resource)
        if not p.get("role_based_access_control_enabled", True):
            return self._finding(resource, "CRITICAL",
                "AKS cluster has Kubernetes RBAC disabled — no access control on cluster API",
                "Set role_based_access_control_enabled = true and configure Azure AD integration.")
        return None

    def check_aks_aad(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_kubernetes_cluster"):
            return None
        p = self._props(resource)
        aad = p.get("azure_active_directory_role_based_access_control", {})
        if isinstance(aad, list) and aad:
            aad = aad[0]
        if not aad or (isinstance(aad, dict) and not aad.get("managed", False)):
            return self._finding(resource, "HIGH",
                "AKS cluster is not integrated with Azure Active Directory for RBAC",
                "Configure azure_active_directory_role_based_access_control { managed = true }.")
        return None

    def check_app_managed_identity(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_app_service", "azurerm_linux_web_app",
                             "azurerm_windows_web_app"):
            return None
        p = self._props(resource)
        if not p.get("identity"):
            return self._finding(resource, "MEDIUM",
                "Azure App Service has no managed identity — may be using hardcoded credentials",
                "Add identity { type = 'SystemAssigned' } and use managed identity for Key Vault access.")
        return None

    def check_function_managed_identity(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_function_app", "azurerm_linux_function_app",
                             "azurerm_windows_function_app"):
            return None
        p = self._props(resource)
        if not p.get("identity"):
            return self._finding(resource, "MEDIUM",
                "Azure Function App has no managed identity configured",
                "Add identity { type = 'SystemAssigned' } to use managed identity for downstream auth.")
        return None

    def check_sql_aad_admin(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_mssql_server", "azurerm_sql_server"):
            return None
        p = self._props(resource)
        if "azuread_administrator" not in p:
            return self._finding(resource, "HIGH",
                "Azure SQL Server has no Azure AD administrator configured",
                "Add azuread_administrator { login_username = '...', object_id = '...' } block.")
        return None

    def check_vm_password_auth(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_linux_virtual_machine"):
            return None
        p = self._props(resource)
        if p.get("disable_password_authentication", True) is False:
            return self._finding(resource, "HIGH",
                "Azure Linux VM allows password authentication — brute-force vulnerable",
                "Set disable_password_authentication = true. Use SSH public keys via admin_ssh_key block.")
        return None

    # ── Secrets Management ────────────────────────────────────────────────

    _SECRET_KEYWORDS = ("password", "secret", "api_key", "token", "credential", "private_key")

    def _has_secret_in_value(self, val: Any) -> bool:
        return any(kw in str(val).lower() for kw in self._SECRET_KEYWORDS)

    def check_keyvault_all_access(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_key_vault_access_policy"):
            return None
        p = self._props(resource)
        secret_perms = p.get("secret_permissions", [])
        if "Get" in secret_perms and "List" in secret_perms and len(secret_perms) > 5:
            return self._finding(resource, "HIGH",
                "Azure Key Vault access policy grants broad secret permissions",
                "Apply least-privilege: only grant Get/List permissions needed by each identity.")
        return None

    def check_app_settings_secrets(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_app_service", "azurerm_linux_web_app",
                             "azurerm_windows_web_app"):
            return None
        p = self._props(resource)
        app_settings = p.get("app_settings", {})
        if isinstance(app_settings, dict):
            for key, value in app_settings.items():
                if self._has_secret_in_value(key) and not str(value).startswith("@Microsoft.KeyVault"):
                    return self._finding(resource, "CRITICAL",
                        f"Azure App Service app_settings contains potential secret key '{key}' in plaintext",
                        "Use Key Vault references: @Microsoft.KeyVault(SecretUri=...) instead of plaintext.")
        return None

    def check_function_settings_secrets(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_function_app", "azurerm_linux_function_app",
                             "azurerm_windows_function_app"):
            return None
        p = self._props(resource)
        app_settings = p.get("app_settings", {})
        if isinstance(app_settings, dict):
            for key, value in app_settings.items():
                if self._has_secret_in_value(key) and not str(value).startswith("@Microsoft.KeyVault"):
                    return self._finding(resource, "CRITICAL",
                        f"Azure Function App app_settings has potential secret '{key}' in plaintext",
                        "Reference secrets from Key Vault using Key Vault references in app_settings.")
        return None

    def check_sql_admin_password(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_mssql_server", "azurerm_sql_server"):
            return None
        p = self._props(resource)
        password = str(p.get("administrator_login_password", ""))
        if password and not password.startswith("var.") and not password.startswith("${"):
            return self._finding(resource, "CRITICAL",
                "Azure SQL Server administrator_login_password appears hardcoded in Terraform",
                "Use var.sql_admin_password with a sensitive variable or reference from Key Vault.")
        return None

    def check_vm_admin_password(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_linux_virtual_machine",
                             "azurerm_windows_virtual_machine", "azurerm_virtual_machine"):
            return None
        p = self._props(resource)
        password = str(p.get("admin_password", ""))
        if password and not password.startswith("var.") and not password.startswith("${"):
            return self._finding(resource, "CRITICAL",
                "Azure VM admin_password appears hardcoded — credential exposure risk",
                "Use a sensitive Terraform variable: var.vm_admin_password = sensitive(...).")
        return None

    def check_sp_secret_expiry(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_application_password"):
            return None
        p = self._props(resource)
        if not p.get("end_date") and not p.get("end_date_relative"):
            return self._finding(resource, "HIGH",
                "Azure Service Principal secret has no expiry date — credential never rotates",
                "Set end_date = '<ISO8601 date>' or end_date_relative = '8760h' (1 year).")
        return None

    def check_keyvault_key_expiry(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_key_vault_key"):
            return None
        p = self._props(resource)
        if not p.get("expiration_date"):
            return self._finding(resource, "MEDIUM",
                "Azure Key Vault key has no expiration date set",
                "Set expiration_date = '<ISO8601>' to enforce key rotation policy.")
        return None

    def check_storage_key_exposed(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_storage_account"):
            return None
        p = self._props(resource)
        if p.get("shared_access_key_enabled", True):
            return self._finding(resource, "LOW",
                "Azure Storage Account has shared access key (SAS) enabled — prefer AAD auth",
                "Set shared_access_key_enabled = false and use Azure AD for blob/queue access.")
        return None

    # ── Monitoring & Compliance ────────────────────────────────────────────

    def check_defender(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_security_center_subscription_pricing"):
            return None
        p = self._props(resource)
        if p.get("tier", "Free") == "Free":
            return self._finding(resource, "HIGH",
                "Azure Defender (Security Center) is on Free tier — no threat detection",
                "Set tier = 'Standard' for the resource type to enable Microsoft Defender.")
        return None

    def check_monitor_diagnostics(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_monitor_diagnostic_setting"):
            return None
        p = self._props(resource)
        if not p.get("log_analytics_workspace_id") and not p.get("storage_account_id"):
            return self._finding(resource, "MEDIUM",
                "Azure Monitor diagnostic setting has no destination configured",
                "Set log_analytics_workspace_id or storage_account_id for log retention.")
        return None

    def check_activity_log_retention(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_monitor_activity_log_alert"):
            return None
        p = self._props(resource)
        if not p.get("enabled", True):
            return self._finding(resource, "HIGH",
                "Azure Monitor Activity Log Alert is disabled",
                "Set enabled = true to receive alerts on security-relevant control plane events.")
        return None

    def check_sql_threat_detection(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_mssql_server", "azurerm_sql_server"):
            return None
        p = self._props(resource)
        threat_policy = p.get("threat_detection_policy", {})
        if isinstance(threat_policy, list) and threat_policy:
            threat_policy = threat_policy[0]
        state = threat_policy.get("state", "Disabled") if isinstance(threat_policy, dict) else "Disabled"
        if not threat_policy or state != "Enabled":
            return self._finding(resource, "HIGH",
                "Azure SQL Server has Threat Detection Policy disabled",
                "Add threat_detection_policy { state = 'Enabled', email_addresses = [...] }.")
        return None

    def check_aks_monitoring(self, resource: Dict) -> Optional[Dict]:
        if not self._is_type(resource, "azurerm_kubernetes_cluster"):
            return None
        p = self._props(resource)
        if not p.get("oms_agent"):
            return self._finding(resource, "MEDIUM",
                "AKS cluster has no OMS agent (Azure Monitor for containers) configured",
                "Add oms_agent { log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id }.")
        return None