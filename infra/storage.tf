# Outpost state: no anonymous access, no public network path, Entra-only data
# access and a Key Vault customer-managed key. Clients reach Blob only through
# pe-outpost-blob (private-endpoints.tf) and the privatelink DNS zone.
resource "azurerm_storage_account" "backup" {
  name                              = "stoutpost${random_id.instance.hex}"
  resource_group_name               = local.rg.name
  location                          = local.location
  account_kind                      = "StorageV2"
  account_tier                      = "Standard"
  account_replication_type          = "GRS"
  https_traffic_only_enabled        = true
  min_tls_version                   = "TLS1_2"
  public_network_access_enabled     = false
  allow_nested_items_to_be_public   = false
  default_to_oauth_authentication   = true
  shared_access_key_enabled         = false
  local_user_enabled                = false
  sftp_enabled                      = false
  cross_tenant_replication_enabled  = false
  infrastructure_encryption_enabled = true
  allowed_copy_scope                = "AAD"
  # Defense in depth: even if public network access were re-enabled, no public
  # source is allowed. Private endpoint traffic is not subject to these rules.
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
  identity {
    type         = "UserAssigned"
    identity_ids = [local.identities["id-backup-cmk"].id]
  }
  # A versionless key ID follows the key's automatic rotation.
  customer_managed_key {
    key_vault_key_id          = azurerm_key_vault_key.backup.versionless_id
    user_assigned_identity_id = local.identities["id-backup-cmk"].id
  }
  blob_properties {
    versioning_enabled = true
    delete_retention_policy { days = 7 }
    container_delete_retention_policy { days = 7 }
  }
  # Classic queue logging is a data-plane setting that hosted runners cannot
  # reach once public network access is off (versions.tf: data_plane_available).
  # The setting already applied stays on, and queueServices diagnostics send
  # read, write and delete logs to Log Analytics (monitoring.tf).
  tags = local.tags
  lifecycle {
    prevent_destroy = true
  }
  depends_on = [azurerm_role_assignment.backup_cmk]
}

resource "azurerm_storage_container" "backups" {
  name                  = "backups"
  storage_account_id    = azurerm_storage_account.backup.id
  container_access_type = "private"
  lifecycle { prevent_destroy = true }
}
