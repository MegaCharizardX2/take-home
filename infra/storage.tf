#trivy:ignore:AZU-0012:exp:2026-12-08
resource "azurerm_storage_account" "backup" {
  name                              = "stoutpost${random_id.instance.hex}"
  resource_group_name               = local.rg.name
  location                          = local.location
  account_kind                      = "StorageV2"
  account_tier                      = "Standard"
  account_replication_type          = "GRS"
  https_traffic_only_enabled        = true
  min_tls_version                   = "TLS1_2"
  public_network_access_enabled     = true
  allow_nested_items_to_be_public   = var.backup_stage == "public"
  default_to_oauth_authentication   = true
  shared_access_key_enabled         = false
  cross_tenant_replication_enabled  = false
  infrastructure_encryption_enabled = true
  allowed_copy_scope                = "AAD"
  blob_properties {
    versioning_enabled = true
    delete_retention_policy { days = 7 }
    container_delete_retention_policy { days = 7 }
  }
  queue_properties {
    logging {
      version               = "1.0"
      read                  = true
      write                 = true
      delete                = true
      retention_policy_days = 7
    }
  }
  tags = local.tags
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.backup_stage != "public" || timecmp(plantimestamp(), "2026-12-08T00:00:00Z") < 0
      error_message = "The public backup stage is available only during the approved baseline window."
    }
  }
}

#trivy:ignore:AZU-0007:exp:2026-12-08
resource "azurerm_storage_container" "backups" {
  name                  = "backups"
  storage_account_id    = azurerm_storage_account.backup.id
  container_access_type = var.backup_stage == "public" ? "container" : "private"
  lifecycle { prevent_destroy = true }
}

# This is a separate apply while the account is still closed. An exemption
# scoped to the account cannot precede creation of that same account.
resource "azurerm_resource_policy_exemption" "backup" {
  count                           = var.backup_stage == "closed" ? 0 : 1
  name                            = "wiz-public-backup-baseline"
  resource_id                     = azurerm_storage_account.backup.id
  policy_assignment_id            = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn"
  policy_definition_reference_ids = ["StorageDisallowPublicAccess"]
  exemption_category              = "Waiver"
  expires_on                      = "2026-12-08T00:00:00Z"
  description                     = "Approved exercise waiver for anonymous read and listing of synthetic daily backups."
}
