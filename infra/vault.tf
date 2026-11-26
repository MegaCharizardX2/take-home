resource "azurerm_key_vault" "lab" {
  name                          = "kv-outpost-${random_id.instance.hex}"
  location                      = local.location
  resource_group_name           = local.rg.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "premium"
  rbac_authorization_enabled    = true
  public_network_access_enabled = false
  purge_protection_enabled      = true
  soft_delete_retention_days    = 7
  tags                          = local.tags
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = []
  }
  lifecycle {
    prevent_destroy = true
    # Pipeline 1 opens only its /32 for data-plane calls and closes both in cleanup.
    ignore_changes = [public_network_access_enabled, network_acls[0].ip_rules]
  }
}

resource "azurerm_key_vault_key" "backup" {
  name            = "backup-cmk"
  key_vault_id    = azurerm_key_vault.lab.id
  key_type        = "RSA-HSM"
  key_size        = 2048
  key_opts        = ["wrapKey", "unwrapKey"]
  expiration_date = "2027-03-01T00:00:00Z"
  rotation_policy {
    expire_after         = "P90D"
    notify_before_expiry = "P15D"
    automatic { time_before_expiry = "P30D" }
  }
  depends_on = [azurerm_role_assignment.crypto_officer]
  tags       = local.tags
  lifecycle { prevent_destroy = true }
}

resource "azurerm_key_vault_key" "mongo_disk" {
  name            = "mongo-disk-cmk"
  key_vault_id    = azurerm_key_vault.lab.id
  key_type        = "RSA-HSM"
  key_size        = 2048
  key_opts        = ["wrapKey", "unwrapKey"]
  expiration_date = "2027-03-01T00:00:00Z"
  rotation_policy {
    expire_after         = "P90D"
    notify_before_expiry = "P15D"
    automatic { time_before_expiry = "P30D" }
  }
  depends_on = [azurerm_role_assignment.crypto_officer]
  tags       = local.tags
  lifecycle { prevent_destroy = true }
}
