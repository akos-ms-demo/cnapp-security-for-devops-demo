############################################################
# Intentionally misconfigured Terraform for the DevSecOps demo.
# Checkov / Terrascan / Template Analyzer (via Microsoft
# Security DevOps action) and Defender for Cloud CSPM will
# flag every resource below. DO NOT deploy to prod.
############################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "prefix" {
  type    = string
  default = "cnappdemo"
}

resource "azurerm_resource_group" "rg" {
  name     = "${var.prefix}-rg"
  location = var.location
}

############################################################
# VULN: NSG allows unrestricted inbound SSH + RDP + HTTP
# Checkov CKV_AZURE_10 / CKV_AZURE_77 / Terrascan AC_AZURE_0128
############################################################
resource "azurerm_network_security_group" "nsg" {
  name                = "${var.prefix}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "allow-ssh-from-internet"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-rdp-from-internet"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-http-any"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

############################################################
# VULN: Public storage account, public blob access, HTTP allowed,
# no encryption-at-rest customer key, no min TLS version enforced.
# Checkov CKV_AZURE_33 / CKV_AZURE_35 / CKV_AZURE_44
############################################################
resource "azurerm_storage_account" "sa" {
  name                     = "${var.prefix}sa"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public = true
  public_network_access_enabled   = true
  enable_https_traffic_only       = false
  min_tls_version                 = "TLS1_0"
}

resource "azurerm_storage_container" "public" {
  name                  = "public-data"
  storage_account_name  = azurerm_storage_account.sa.name
  container_access_type = "container" # anonymous blob + container list
}

############################################################
# VULN: Azure SQL Server with weak admin creds hardcoded,
# public network access, firewall open to the entire internet,
# auditing/TDE/AAD-admin not configured.
# Checkov CKV_AZURE_23 / CKV_AZURE_24 / CKV_AZURE_27
############################################################
resource "azurerm_mssql_server" "sql" {
  name                         = "${var.prefix}-sql"
  resource_group_name          = azurerm_resource_group.rg.name
  location                     = azurerm_resource_group.rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd1234!" # pragma: allowlist secret
  public_network_access_enabled = true
  minimum_tls_version           = "1.0"
}

resource "azurerm_mssql_firewall_rule" "allow_all" {
  name             = "allow-all-internet"
  server_id        = azurerm_mssql_server.sql.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_mssql_database" "db" {
  name      = "${var.prefix}-db"
  server_id = azurerm_mssql_server.sql.id
  sku_name  = "Basic"
}

############################################################
# VULN: Public container instance exposing the vulnerable app
# directly to the internet, no managed identity, no log config.
############################################################
resource "azurerm_container_group" "app" {
  name                = "${var.prefix}-aci"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  os_type             = "Linux"
  ip_address_type     = "Public"
  dns_name_label      = "${var.prefix}-app"

  container {
    name   = "web"
    image  = "ghcr.io/OWNER/cnapp-security-for-devops-demo:latest"
    cpu    = "0.5"
    memory = "1.0"

    ports {
      port     = 8080
      protocol = "TCP"
    }

    environment_variables = {
      DB_PATH = "/tmp/demo.db"
      # VULN: secret in plain env var
      AWS_ACCESS_KEY_ID     = "AKIAZ7XDEMO4CNAPPDEV2"
      AWS_SECRET_ACCESS_KEY = "Xy9pQ2vR7sT4uVwZ1aB3cD5eF6gH8iJ0kLmNoPqR"
    }
  }
}

output "app_fqdn" {
  value = azurerm_container_group.app.fqdn
}

output "sql_server_fqdn" {
  value = azurerm_mssql_server.sql.fully_qualified_domain_name
}
