data "azurerm_resource_group" "lab" {
  name = "takehome-rg"
}

data "azurerm_client_config" "current" {}

resource "random_id" "instance" {
  byte_length = 5
}

locals {
  rg       = data.azurerm_resource_group.lab
  location = "eastus2"
  tags = {
    owner   = "takehome"
    expires = "2026-12-08"
  }
  subnet_ranges = {
    nodes     = "10.84.0.0/24"
    agc       = "10.84.1.0/24"
    api       = "10.84.2.0/27"
    mongo     = "10.84.2.32/27"
    endpoints = "10.84.2.64/27"
  }
  mongo_ip   = "10.84.2.36"
  identities = data.azurerm_user_assigned_identity.lab
}

data "azurerm_user_assigned_identity" "lab" {
  for_each = toset([
    "takehome-id", "id-aks-control-plane", "id-aks-kubelet", "id-mongo",
    "id-backup-reader", "id-release", "id-image-publisher", "id-lab-scheduler", "id-backup-cmk", "id-disk-cmk"
  ])
  name                = each.key
  resource_group_name = local.rg.name
}
