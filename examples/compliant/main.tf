terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
  }

  backend "azurerm" {
    resource_group_name  = "rg-terraform-state-prod-eastus2-001"
    storage_account_name = "stterraformstateprod001"
    container_name       = "tfstate"
    key                  = "prod.terraform.tfstate"
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "main" {
  name     = "rg-myapp-prod-eastus2-001"
  location = "eastus2"

  tags = {
    app        = "myapp"
    env        = "prod"
    costCenter = "CC-1234"
    owner      = "team-platform"
    createdBy  = "Terraform"
  }
}

resource "azurerm_storage_account" "main" {
  name                            = "stmyappprodeastus2001"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  min_tls_version                 = "TLS1_2"
  enable_https_traffic_only       = true
  allow_nested_items_to_be_public = false

  network_rules {
    default_action = "Deny"
  }

  tags = {
    app        = "myapp"
    env        = "prod"
    costCenter = "CC-1234"
    owner      = "team-platform"
    createdBy  = "Terraform"
  }
}

resource "azurerm_key_vault" "main" {
  name                       = "kv-myapp-prod-eus2-001"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = true
  purge_protection_enabled   = true
  soft_delete_retention_days = 90

  tags = {
    app        = "myapp"
    env        = "prod"
    costCenter = "CC-1234"
    owner      = "team-platform"
    createdBy  = "Terraform"
  }
}
