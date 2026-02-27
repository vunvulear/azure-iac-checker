provider "azurerm" {
  features {}
}

# VIOLATION: Resource group with wrong naming prefix and no tags
resource "azurerm_resource_group" "bad" {
  name     = "my-resource-group"
  location = "eastus2"
}

# VIOLATION: Storage with LRS (no geo-redundancy), no TLS, no network rules, no tags
resource "azurerm_storage_account" "bad" {
  name                     = "mybadstorage"
  resource_group_name      = azurerm_resource_group.bad.name
  location                 = azurerm_resource_group.bad.location
  account_tier             = "Premium"
  account_replication_type = "LRS"
}

# VIOLATION: SQL Server with hardcoded password and invalid env tag value
resource "azurerm_mssql_server" "bad" {
  name                         = "sql-myapp-prod-eastus2-001"
  resource_group_name          = azurerm_resource_group.bad.name
  location                     = azurerm_resource_group.bad.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd123!"

  tags = {
    env = "production"
  }
}

# VIOLATION: Key Vault without RBAC or purge protection
resource "azurerm_key_vault" "bad" {
  name                      = "kv-myapp-prod-eus2-002"
  location                  = azurerm_resource_group.bad.location
  resource_group_name       = azurerm_resource_group.bad.name
  tenant_id                 = "00000000-0000-0000-0000-000000000000"
  sku_name                  = "standard"
  enable_rbac_authorization = false
  purge_protection_enabled  = false

  tags = {
    app        = "myapp"
    env        = "prod"
    costCenter = "CC-1234"
    owner      = "team-platform"
  }
}

# VIOLATION: AKS without zones, private cluster, or managed identity
resource "azurerm_kubernetes_cluster" "bad" {
  name                = "aks-myapp-prod-eastus2-001"
  location            = azurerm_resource_group.bad.location
  resource_group_name = azurerm_resource_group.bad.name
  dns_prefix          = "myaks"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  tags = {
    app        = "myapp"
    env        = "prod"
    costCenter = "CC-1234"
    owner      = "team-platform"
  }
}

# VIOLATION: VM without availability zone
resource "azurerm_linux_virtual_machine" "bad" {
  name                = "vm-myapp-prod-eastus2-001"
  resource_group_name = azurerm_resource_group.bad.name
  location            = azurerm_resource_group.bad.location
  size                = "Standard_D2s_v3"
  admin_username      = "azureuser"

  admin_ssh_key {
    username   = "azureuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  tags = {
    app        = "myapp"
    env        = "prod"
    costCenter = "CC-1234"
    owner      = "team-platform"
  }
}

# VIOLATION: NSG rule with wildcard source/destination
resource "azurerm_network_security_rule" "allow_all" {
  name                        = "allow-all-inbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.bad.name
  network_security_group_name = "nsg-myapp-prod"
}

# VIOLATION: RBAC Owner at subscription scope
resource "azurerm_role_assignment" "bad_rbac" {
  scope                = "/subscriptions/00000000-0000-0000-0000-000000000000"
  role_definition_name = "Owner"
  principal_id         = "11111111-1111-1111-1111-111111111111"
}

# Example of inline suppression
# waf-ignore: WAF-SEC-019
resource "azurerm_mssql_server" "legacy" {
  name                         = "sql-legacy-prod-eastus2-001"
  resource_group_name          = azurerm_resource_group.bad.name
  location                     = azurerm_resource_group.bad.location
  version                      = "12.0"
  administrator_login          = "legacyadmin"
  administrator_login_password = "LegacyP@ss!"

  tags = {
    app        = "legacy"
    env        = "prod"
    costCenter = "CC-0000"
    owner      = "team-legacy"
  }
}
