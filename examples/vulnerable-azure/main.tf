# Intentionally vulnerable Azure resources — used by CI to verify the
# Azure rule engine actually fires. Do not deploy this.

resource "azurerm_network_security_rule" "ssh_open" {
  name                        = "allow-ssh-anywhere"
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "example-rg"
  network_security_group_name = "example-nsg"
}

resource "azurerm_storage_account" "public_storage" {
  name                             = "examplestorageacct"
  resource_group_name              = "example-rg"
  location                         = "eastus"
  account_tier                     = "Standard"
  account_replication_type         = "LRS"
  allow_nested_items_to_be_public  = true
  min_tls_version                  = "TLS1_0"
}

resource "azurerm_key_vault" "no_purge_protection" {
  name                       = "example-kv"
  location                   = "eastus"
  resource_group_name        = "example-rg"
  sku_name                   = "standard"
  soft_delete_enabled        = false
  purge_protection_enabled   = false
}
