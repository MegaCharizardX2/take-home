resource "azurerm_log_analytics_workspace" "lab" {
  name                         = "law-outpost-${random_id.instance.hex}"
  resource_group_name          = local.rg.name
  location                     = local.location
  sku                          = "PerGB2018"
  retention_in_days            = 30
  daily_quota_gb               = var.daily_quota_gb
  local_authentication_enabled = false
  tags                         = local.tags
}

resource "azurerm_monitor_diagnostic_setting" "aks" {
  name                           = "aks-audit"
  target_resource_id             = azapi_resource.aks.id
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.lab.id
  log_analytics_destination_type = "Dedicated"
  enabled_log { category = "kube-audit-admin" }
}

resource "azurerm_monitor_diagnostic_setting" "automation" {
  name                       = "automation-jobs"
  target_resource_id         = azurerm_automation_account.lab.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id
  enabled_log { category = "JobLogs" }
}

resource "azurerm_monitor_diagnostic_setting" "registry" {
  name                           = "registry-audit"
  target_resource_id             = azurerm_container_registry.images.id
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.lab.id
  log_analytics_destination_type = "Dedicated"
  enabled_log { category = "ContainerRegistryLoginEvents" }
  enabled_log { category = "ContainerRegistryRepositoryEvents" }
}

resource "azurerm_monitor_diagnostic_setting" "vault" {
  name                       = "key-audit"
  target_resource_id         = azurerm_key_vault.lab.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id
  enabled_log { category = "AuditEvent" }
}

resource "azurerm_monitor_diagnostic_setting" "backup_services" {
  for_each                       = toset(["blobServices", "queueServices"])
  name                           = "backup-data"
  target_resource_id             = "${azurerm_storage_account.backup.id}/${each.key}/default"
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.lab.id
  log_analytics_destination_type = "Dedicated"
  enabled_log { category = "StorageRead" }
  enabled_log { category = "StorageWrite" }
  enabled_log { category = "StorageDelete" }
}

resource "azurerm_monitor_action_group" "lab" {
  name                = "outpost-alerts"
  resource_group_name = local.rg.name
  short_name          = "outpost"
  email_receiver {
    name                    = "operator"
    email_address           = var.alert_email
    use_common_alert_schema = true
  }
  tags = local.tags
}

resource "azurerm_monitor_activity_log_alert" "lab" {
  for_each = {
    exemption = { scope = local.rg.id, op = "Microsoft.Authorization/policyExemptions/write" }
    backup    = { scope = azurerm_storage_account.backup.id, op = "Microsoft.Storage/storageAccounts/write" }
    nsg       = { scope = local.rg.id, op = "Microsoft.Network/networkSecurityGroups/securityRules/write" }
    role      = { scope = local.rg.id, op = "Microsoft.Authorization/roleAssignments/write" }
  }
  name                = "outpost-${each.key}-write"
  resource_group_name = local.rg.name
  location            = "global"
  scopes              = [each.value.scope]
  criteria {
    category       = "Administrative"
    operation_name = each.value.op
  }
  action { action_group_id = azurerm_monitor_action_group.lab.id }
  tags = local.tags
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "lab" {
  for_each = {
    binding  = <<-KQL
      AKSAuditAdmin
      | where _ResourceId =~ "${azapi_resource.aks.id}" and Stage == "ResponseComplete"
      | where tostring(ObjectRef.apiGroup) == "rbac.authorization.k8s.io" and tostring(ObjectRef.resource) == "clusterrolebindings"
      | where Verb in ("create", "update", "patch", "delete", "deletecollection")
      | where toint(ResponseStatus.code) between (200 .. 299) and RequestUri !contains "dryRun=All"
      | project TimeGenerated, Actor=tostring(User.username), Verb, Binding=tostring(ObjectRef.name), AuditId
    KQL
    power    = <<-KQL
      AzureDiagnostics
      | where _ResourceId =~ "${azurerm_automation_account.lab.id}" and Category == "JobLogs"
      | where ResultType in~ ("Failed", "Suspended")
      | project TimeGenerated, ResultType, RunbookName_s
    KQL
    registry = <<-KQL
      ContainerRegistryRepositoryEvents
      | where _ResourceId =~ "${azurerm_container_registry.images.id}"
      | where OperationName contains "Push" or OperationName contains "Delete"
          or OperationName contains "Untag" or OperationName contains "Purge"
      | where isempty(Identity) or Identity !in~ ("${local.identities["id-image-publisher"].principal_id}", "${local.identities["id-image-publisher"].client_id}")
      | project TimeGenerated, OperationName, Identity, Repository, Tag, Digest, CallerIpAddress, ResultType
    KQL
  }
  name                 = "outpost-${each.key}"
  resource_group_name  = local.rg.name
  location             = local.location
  scopes               = [azurerm_log_analytics_workspace.lab.id]
  evaluation_frequency = "PT5M"
  window_duration      = "PT15M"
  severity             = 2
  # A fresh workspace creates the tables only after the first matching event.
  skip_query_validation = true
  criteria {
    query                   = each.value
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
  }
  action { action_groups = [azurerm_monitor_action_group.lab.id] }
  depends_on = [azurerm_monitor_diagnostic_setting.aks, azurerm_monitor_diagnostic_setting.automation, azurerm_monitor_diagnostic_setting.registry]
  tags       = local.tags
}

resource "azurerm_consumption_budget_resource_group" "lab" {
  name              = "outpost-budget"
  resource_group_id = local.rg.id
  amount            = 200
  # One budget period spans both calendar months of the lab.
  time_grain = "Quarterly"
  time_period {
    start_date = "2026-11-01T00:00:00Z"
    end_date   = "2027-02-01T00:00:00Z"
  }
  dynamic "notification" {
    for_each = [50, 75, 90]
    content {
      enabled        = true
      threshold      = notification.value
      operator       = "GreaterThanOrEqualTo"
      contact_emails = [var.alert_email]
    }
  }
}
