locals {
  private_endpoints = {
    vault = { id = azurerm_key_vault.lab.id, zone = "privatelink.vaultcore.azure.net" }
    blob  = { id = azurerm_storage_account.backup.id, zone = "privatelink.blob.core.windows.net" }
  }
}

resource "azurerm_private_dns_zone" "endpoint" {
  for_each            = local.private_endpoints
  name                = each.value.zone
  resource_group_name = local.rg.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "endpoint" {
  for_each              = local.private_endpoints
  name                  = "outpost"
  resource_group_name   = local.rg.name
  private_dns_zone_name = azurerm_private_dns_zone.endpoint[each.key].name
  virtual_network_id    = azurerm_virtual_network.lab.id
  registration_enabled  = false
  tags                  = local.tags
}

resource "azurerm_private_endpoint" "lab" {
  for_each            = local.private_endpoints
  name                = "pe-outpost-${each.key}"
  location            = local.location
  resource_group_name = local.rg.name
  subnet_id           = azurerm_subnet.lab["endpoints"].id
  private_service_connection {
    name                           = "outpost-${each.key}"
    private_connection_resource_id = each.value.id
    subresource_names              = [each.key]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = each.key
    private_dns_zone_ids = [azurerm_private_dns_zone.endpoint[each.key].id]
  }
  tags = local.tags
}
