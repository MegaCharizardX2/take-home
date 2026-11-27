# The lab scan attaches the dated AZU-0047 exception to this ingress rule.
resource "azurerm_network_security_rule" "ingress" {
  name                        = "Internet-to-ingress"
  resource_group_name         = local.rg.name
  network_security_group_name = azurerm_network_security_group.lab["nodes"].name
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_address_prefix       = "Internet"
  source_port_range           = "*"
  destination_address_prefix  = azurerm_public_ip.ingress.ip_address
  destination_port_ranges     = ["80", "443"]
}
