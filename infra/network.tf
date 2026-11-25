resource "azurerm_virtual_network" "lab" {
  name                = "vnet-outpost"
  address_space       = ["10.84.0.0/20"]
  location            = local.location
  resource_group_name = local.rg.name
  tags                = local.tags
}

resource "azurerm_subnet" "lab" {
  for_each                        = local.subnet_ranges
  name                            = "snet-${each.key}"
  resource_group_name             = local.rg.name
  virtual_network_name            = azurerm_virtual_network.lab.name
  address_prefixes                = [each.value]
  default_outbound_access_enabled = false

  dynamic "delegation" {
    for_each = each.key == "api" ? [true] : []
    content {
      name = "aks-api"
      service_delegation {
        name    = "Microsoft.ContainerService/managedClusters"
        actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
      }
    }
  }
}

resource "azurerm_network_security_group" "lab" {
  for_each            = local.subnet_ranges
  name                = "nsg-${each.key}"
  location            = local.location
  resource_group_name = local.rg.name
  tags                = local.tags
}

resource "azurerm_subnet_network_security_group_association" "lab" {
  for_each                  = local.subnet_ranges
  subnet_id                 = azurerm_subnet.lab[each.key].id
  network_security_group_id = azurerm_network_security_group.lab[each.key].id
}

resource "azurerm_public_ip" "ingress" {
  name                = "pip-ingress"
  location            = local.location
  resource_group_name = local.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1", "2", "3"]
  tags                = local.tags
}

resource "azurerm_network_security_rule" "mongo" {
  for_each = {
    aks    = { priority = 100, access = "Allow", source = local.subnet_ranges.nodes, port = "27017" }
    others = { priority = 110, access = "Deny", source = "*", port = "27017" }
  }
  name                        = "mongo-${each.key}"
  resource_group_name         = local.rg.name
  network_security_group_name = azurerm_network_security_group.lab["mongo"].name
  priority                    = each.value.priority
  direction                   = "Inbound"
  access                      = each.value.access
  protocol                    = "Tcp"
  source_address_prefix       = each.value.source
  source_port_range           = "*"
  destination_address_prefix  = local.mongo_ip
  destination_port_range      = each.value.port
}

resource "azurerm_public_ip" "nat" {
  name                = "pip-nat"
  location            = local.location
  resource_group_name = local.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1"]
  tags                = local.tags
}

resource "azurerm_nat_gateway" "lab" {
  name                = "nat-outpost"
  location            = local.location
  resource_group_name = local.rg.name
  sku_name            = "Standard"
  zones               = ["1"]
  tags                = local.tags
}

resource "azurerm_nat_gateway_public_ip_association" "lab" {
  nat_gateway_id       = azurerm_nat_gateway.lab.id
  public_ip_address_id = azurerm_public_ip.nat.id
}

resource "azurerm_subnet_nat_gateway_association" "lab" {
  for_each       = toset(["nodes", "mongo"])
  subnet_id      = azurerm_subnet.lab[each.key].id
  nat_gateway_id = azurerm_nat_gateway.lab.id
}

resource "azurerm_private_dns_zone" "mongo" {
  name                = "wiz.internal"
  resource_group_name = local.rg.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "mongo" {
  name                 = "outpost"
  private_dns_zone_id  = azurerm_private_dns_zone.mongo.id
  virtual_network_id   = azurerm_virtual_network.lab.id
  registration_enabled = false
  tags                 = local.tags
}

resource "azurerm_private_dns_a_record" "mongo" {
  name                = "mongo"
  private_dns_zone_id = azurerm_private_dns_zone.mongo.id
  ttl                 = 60
  records             = [azurerm_network_interface.mongo.private_ip_address]
  tags                = local.tags
}
