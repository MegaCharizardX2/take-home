output "cluster_name" {
  description = "AKS target for the protected command-invoke steps."
  value       = azapi_resource.aks.name
}

output "registry_login_server" {
  description = "Registry used by the image publishing job."
  value       = azurerm_container_registry.images.login_server
}

output "backup_account" {
  description = "Private backup account read back by the Outpost evidence job."
  value       = azurerm_storage_account.backup.name
}

output "backup_stage" {
  description = "Pipeline 1 stage applied to this state (Outpost is one-way)."
  value       = var.backup_stage
}

output "ingress_ip" {
  description = "Static address for the Traefik load balancer."
  value       = azurerm_public_ip.ingress.ip_address
}

output "ingress_fqdn" {
  description = "Azure DNS name for the Traefik host and Let's Encrypt certificate."
  value       = azurerm_public_ip.ingress.fqdn
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
  description = "Pre-created id-disk-cmk principal in the Owner's delegation condition."
  value       = local.identities["id-disk-cmk"].principal_id
}

output "backup_writer_role_id" {
  description = "Owner-defined write-only role that id-mongo holds on the backup container."
  value       = basename(data.azurerm_role_definition.backup_writer.id)
}
