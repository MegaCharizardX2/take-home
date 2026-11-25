output "cluster_name" {
  description = "AKS target for the protected command-invoke steps."
  value       = azapi_resource.aks.name
}

output "registry_login_server" {
  description = "Registry used by the image publishing job."
  value       = azurerm_container_registry.images.login_server
}

output "backup_account" {
  description = "Backup account for the policy-denial evidence and later public-read verification."
  value       = azurerm_storage_account.backup.name
}

output "ingress_ip" {
  description = "Static address for the Traefik load balancer."
  value       = azurerm_public_ip.ingress.ip_address
}

output "workspace_name" {
  description = "Workspace for the Owner's subscription Activity Log export."
  value       = azurerm_log_analytics_workspace.lab.name
}

output "vault_name" {
  description = "Key Vault for the protected job's temporary firewall rule."
  value       = azurerm_key_vault.lab.name
}

output "disk_encryption_principal_id" {
  description = "System-assigned DES principal for the Owner's role-delegation condition."
  value       = azurerm_disk_encryption_set.mongo.identity[0].principal_id
}
