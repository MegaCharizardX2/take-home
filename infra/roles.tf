resource "azurerm_role_assignment" "aks_network" {
  for_each = {
    nodes   = azurerm_subnet.lab["nodes"].id
    api     = azurerm_subnet.lab["api"].id
    ingress = azurerm_public_ip.ingress.id
  }
  scope                = each.value
  role_definition_name = "Network Contributor"
  principal_id         = local.identities["id-aks-control-plane"].principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "kubelet_operator" {
  scope                = local.identities["id-aks-kubelet"].id
  role_definition_name = "Managed Identity Operator"
  principal_id         = local.identities["id-aks-control-plane"].principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "lab" {
  for_each = {
    vm_compute    = ["id-mongo", "Virtual Machine Contributor", local.rg.id]
    vm_backup     = ["id-mongo", "Storage Blob Data Contributor", azurerm_storage_container.backups.id]
    reader        = ["id-backup-reader", "Storage Blob Data Reader", azurerm_storage_container.backups.id]
    cmk           = ["id-backup-cmk", "Key Vault Crypto Service Encryption User", azurerm_key_vault_key.backup.resource_versionless_id]
    infra_admin   = ["takehome-id", "Azure Kubernetes Service RBAC Cluster Admin", azapi_resource.aks.id]
    release_write = ["id-release", "Azure Kubernetes Service RBAC Writer", "${azapi_resource.aks.id}/namespaces/wiz-web"]
    release_run   = ["id-release", "Lab AKS Run Command", azapi_resource.aks.id]
    release_nodes = ["id-release", "Lab AKS Node Reader", azapi_resource.aks.id]
    schedule_aks  = ["id-lab-scheduler", "Lab Power Operator", azapi_resource.aks.id]
    schedule_vm   = ["id-lab-scheduler", "Lab Power Operator", azurerm_linux_virtual_machine.mongo.id]
  }
  principal_id         = local.identities[each.value[0]].principal_id
  principal_type       = "ServicePrincipal"
  role_definition_name = each.value[1]
  scope                = each.value[2]
}

locals {
  registry_repositories = <<-CONDITION
    (@Request[Microsoft.ContainerRegistry/registries/repositories:name] StringEquals 'tasky'
     OR @Request[Microsoft.ContainerRegistry/registries/repositories:name] StringEquals 'busybox')
  CONDITION
}

resource "azurerm_role_assignment" "registry_pull" {
  scope                = azurerm_container_registry.images.id
  role_definition_name = "Container Registry Repository Reader"
  principal_id         = local.identities["id-aks-kubelet"].principal_id
  principal_type       = "ServicePrincipal"
  condition_version    = "2.0"
  condition            = trimspace(local.registry_repositories)
}

resource "azurerm_role_assignment" "registry_push" {
  scope                = azurerm_container_registry.images.id
  role_definition_name = "Container Registry Repository Writer"
  principal_id         = local.identities["id-image-publisher"].principal_id
  principal_type       = "ServicePrincipal"
  condition_version    = "2.0"
  # Docker pushes need content/read as well as content/write. The publisher
  # can read metadata but cannot change repository protections or delete images.
  condition = "(!(ActionMatches{'Microsoft.ContainerRegistry/registries/repositories/metadata/write'})) AND ${trimspace(local.registry_repositories)}"
}

resource "azurerm_role_assignment" "crypto_officer" {
  scope                = azurerm_key_vault.lab.id
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = local.identities["takehome-id"].principal_id
  principal_type       = "ServicePrincipal"
}

# The Owner adds this generated principal to the delegation condition after
# the one-time DES bootstrap. Both disk creates wait for the key-scoped grant.
resource "azurerm_role_assignment" "mongo_disk_key" {
  scope                = azurerm_key_vault_key.mongo_disk.resource_versionless_id
  role_definition_name = "Key Vault Crypto Service Encryption User"
  principal_id         = azurerm_disk_encryption_set.mongo.identity[0].principal_id
  principal_type       = "ServicePrincipal"
}
