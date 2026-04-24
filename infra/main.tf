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
  # MCAPS policy forbids shared-key auth on storage accounts; force AAD for data plane.
  storage_use_azuread = true
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

  # Demo: new rule added in a PR to show MSDO inline annotation.
  security_rule {
    name                       = "allow-mongo-from-internet"
    priority                   = 130
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "27017"
    source_address_prefix      = "*"
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
  https_traffic_only_enabled      = false
  min_tls_version                 = "TLS1_0"
}

############################################################
# NOTE: Azure SQL Server creation is blocked by MCAPS deny
# policy in this tenant. The open NSG + public storage + public
# ACI are enough to drive the Phase 3-5 Defender for Cloud
# recommendations and attack-path narrative.
############################################################

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
    image  = "ghcr.io/akos-ms-demo/cnapp-security-for-devops-demo:latest"
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
