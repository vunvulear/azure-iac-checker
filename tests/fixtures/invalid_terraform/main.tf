provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "bad" {
  name     = "my-resource-group"
  location = "eastus2"
  # No tags at all!
}

resource "azurerm_storage_account" "bad" {
  name                     = "mybadstorage"
  resource_group_name      = azurerm_resource_group.bad.name
  location                 = azurerm_resource_group.bad.location
  account_tier             = "Premium"
  account_replication_type = "LRS"
  # Missing: min_tls_version, network_rules, tags
  # allow_nested_items_to_be_public defaults to true (bad)
}

resource "azurerm_mssql_server" "bad" {
  name                         = "sqlserver-bad"
  resource_group_name          = azurerm_resource_group.bad.name
  location                     = azurerm_resource_group.bad.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd123!"  # HARDCODED SECRET!

  tags = {
    env = "production"  # Invalid env value (should be 'prod')
  }
}

resource "azurerm_kubernetes_cluster" "bad" {
  name                = "my-aks"
  location            = azurerm_resource_group.bad.location
  resource_group_name = azurerm_resource_group.bad.name
  dns_prefix          = "myaks"
  # Missing: private_cluster_enabled, zones, identity

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
    # Missing: zones / availability_zones
  }
}

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
  network_security_group_name = "some-nsg"
}
