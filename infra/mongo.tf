resource "azurerm_public_ip" "mongo" {
  name                = "pip-mongo"
  location            = local.location
  resource_group_name = local.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1"]
  tags                = local.tags
}

#trivy:ignore:AZU-0076:exp:2026-12-08
resource "azurerm_network_interface" "mongo" {
  name                = "nic-mongo"
  location            = local.location
  resource_group_name = local.rg.name
  ip_configuration {
    name                          = "mongo"
    subnet_id                     = azurerm_subnet.lab["mongo"].id
    private_ip_address_allocation = "Static"
    private_ip_address            = local.mongo_ip
    public_ip_address_id          = azurerm_public_ip.mongo.id
  }
  tags = local.tags
}

# Keep the same database boundary on the NIC if its subnet attachment changes.
resource "azurerm_network_interface_security_group_association" "mongo" {
  network_interface_id      = azurerm_network_interface.mongo.id
  network_security_group_id = azurerm_network_security_group.lab["mongo"].id
}

resource "azurerm_linux_virtual_machine" "mongo" {
  name                            = "vm-mongo"
  resource_group_name             = local.rg.name
  location                        = local.location
  zone                            = "1"
  size                            = "Standard_D2as_v5"
  network_interface_ids           = [azurerm_network_interface.mongo.id]
  admin_username                  = "labadmin"
  disable_password_authentication = true
  provision_vm_agent              = true
  secure_boot_enabled             = true
  vtpm_enabled                    = true
  encryption_at_host_enabled      = true
  admin_ssh_key {
    username   = "labadmin"
    public_key = trimspace(var.ssh_public_key)
  }
  identity {
    type         = "UserAssigned"
    identity_ids = [local.identities["id-mongo"].id]
  }
  os_disk {
    name                   = "disk-mongo-os"
    caching                = "ReadWrite"
    storage_account_type   = "StandardSSD_LRS"
    disk_size_gb           = 32
    disk_encryption_set_id = azurerm_disk_encryption_set.mongo.id
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-focal"
    sku       = "20_04-lts-gen2"
    version   = "20.04.202505200"
  }
  boot_diagnostics {}
  tags = local.tags
  lifecycle { ignore_changes = [tags["lab-keep-running"]] }
  depends_on = [
    azurerm_network_interface_security_group_association.mongo,
    azurerm_subnet_network_security_group_association.lab,
    azurerm_network_security_rule.mongo,
    azurerm_subnet_nat_gateway_association.lab, azurerm_nat_gateway_public_ip_association.lab
  ]
}

resource "azurerm_disk_encryption_set" "mongo" {
  name                      = "des-mongo"
  location                  = local.location
  resource_group_name       = local.rg.name
  key_vault_key_id          = azurerm_key_vault_key.mongo_disk.versionless_id
  auto_key_rotation_enabled = true
  identity {
    type         = "UserAssigned"
    identity_ids = [local.identities["id-disk-cmk"].id]
  }
  depends_on = [azurerm_role_assignment.mongo_disk_key]
  tags       = local.tags
}

resource "azurerm_managed_disk" "data" {
  name                          = "disk-mongo-data"
  location                      = local.location
  resource_group_name           = local.rg.name
  zone                          = "1"
  storage_account_type          = "StandardSSD_LRS"
  create_option                 = "Empty"
  disk_size_gb                  = 32
  network_access_policy         = "DenyAll"
  public_network_access_enabled = false
  disk_encryption_set_id        = azurerm_disk_encryption_set.mongo.id
  tags                          = local.tags
}

resource "azurerm_virtual_machine_data_disk_attachment" "data" {
  managed_disk_id    = azurerm_managed_disk.data.id
  virtual_machine_id = azurerm_linux_virtual_machine.mongo.id
  lun                = 0
  caching            = "None"
}

# VM extensions run after the disk is attached. Sending only nonsecret guest
# files also allows fixes to be applied without replacing the database VM.
resource "azurerm_virtual_machine_extension" "mongo" {
  name                       = "configure-mongo"
  virtual_machine_id         = azurerm_linux_virtual_machine.mongo.id
  publisher                  = "Microsoft.Azure.Extensions"
  type                       = "CustomScript"
  type_handler_version       = "2.1"
  auto_upgrade_minor_version = true
  settings = jsonencode({
    script = base64gzip(join("\n", concat(
      ["#!/bin/bash", "set -euo pipefail", "umask 077", "install -d -m 0700 /etc/outpost"],
      [for name in ["install.sh", "backup.sh", "bootstrap-users.js", "commission.sh"] :
        "base64 -d > /etc/outpost/${name} <<'GUEST_FILE'\n${filebase64("${path.module}/mongo/${name}")}\nGUEST_FILE"
      ],
      [
        "chmod 0700 /etc/outpost/install.sh /etc/outpost/backup.sh /etc/outpost/commission.sh",
        "printf '%s\\n' '${local.identities["id-mongo"].client_id}' > /etc/outpost/client-id",
        "printf '%s\\n' '${azurerm_storage_account.backup.primary_blob_endpoint}${azurerm_storage_container.backups.name}' > /etc/outpost/container",
        "exec /etc/outpost/install.sh '${local.mongo_ip}'"
      ]
    )))
  })
  depends_on = [azurerm_virtual_machine_data_disk_attachment.data]
  tags       = local.tags
}
