resource "azurerm_automation_account" "lab" {
  name                          = "aa-outpost-${random_id.instance.hex}"
  resource_group_name           = local.rg.name
  location                      = local.location
  sku_name                      = "Basic"
  local_authentication_enabled  = false
  public_network_access_enabled = false
  identity {
    type         = "UserAssigned"
    identity_ids = [local.identities["id-lab-scheduler"].id]
  }
  tags = local.tags
}

resource "azurerm_automation_runtime_environment" "power" {
  name                     = "outpost-pwsh74"
  automation_account_id    = azurerm_automation_account.lab.id
  location                 = local.location
  runtime_language         = "PowerShell"
  runtime_version          = "7.4"
  runtime_default_packages = { Az = "12.3.0" }
  tags                     = local.tags
}

locals {
  # The November/December exercise is on Israel Standard Time (UTC+2).
  # Azure needs at least five minutes' lead. Calculate at apply, including
  # reviewed saved plans, then let the named timezone drive daily recurrence.
  schedule_after = timeadd(timestamp(), "15m")
  schedule_date  = formatdate("YYYY-MM-DD", timeadd(local.schedule_after, "2h"))
  first_run = {
    start = "${local.schedule_date}T09:00:00+02:00"
    stop  = "${local.schedule_date}T00:00:00+02:00"
  }
}

resource "azurerm_automation_runbook" "power" {
  for_each                 = toset(["stop", "start"])
  name                     = "lab-${each.key}"
  location                 = local.location
  resource_group_name      = local.rg.name
  automation_account_name  = azurerm_automation_account.lab.name
  runbook_type             = "PowerShell"
  runtime_environment_name = azurerm_automation_runtime_environment.power.name
  log_progress             = false
  log_verbose              = false
  content                  = replace(file("${path.module}/automation/power.ps1"), "__LAB_DIRECTION__", each.key)
  tags                     = local.tags
}

resource "azurerm_automation_schedule" "power" {
  for_each                = local.first_run
  name                    = "daily-${each.key}"
  resource_group_name     = local.rg.name
  automation_account_name = azurerm_automation_account.lab.name
  frequency               = "Day"
  interval                = 1
  timezone                = "Asia/Jerusalem"
  start_time              = timecmp(each.value, local.schedule_after) > 0 ? each.value : timeadd(each.value, "24h")
  expiry_time             = "2026-12-08T00:05:00+02:00"
  lifecycle { ignore_changes = [start_time] }
}

resource "azurerm_automation_job_schedule" "power" {
  for_each                = azurerm_automation_runbook.power
  resource_group_name     = local.rg.name
  automation_account_name = azurerm_automation_account.lab.name
  schedule_name           = azurerm_automation_schedule.power[each.key].name
  runbook_name            = each.value.name
  parameters = {
    subscriptionid    = data.azurerm_client_config.current.subscription_id
    schedulerclientid = local.identities["id-lab-scheduler"].client_id
    clusterid         = azapi_resource.aks.id
    vmid              = azurerm_linux_virtual_machine.mongo.id
  }
  depends_on = [azurerm_role_assignment.lab]
}
