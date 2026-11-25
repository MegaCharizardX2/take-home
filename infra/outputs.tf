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
