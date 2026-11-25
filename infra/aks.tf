# AzureRM omits the API server subnet on cluster creation. AzAPI submits the
# integrated API server, identities and both pools in the initial ARM request.
resource "azapi_resource" "aks" {
  type      = "Microsoft.ContainerService/managedClusters@2025-10-01"
  name      = "aks-outpost"
  parent_id = local.rg.id
  location  = local.location
  tags      = local.tags
  identity {
    type         = "UserAssigned"
    identity_ids = [local.identities["id-aks-control-plane"].id]
  }

  body = {
    sku = { name = "Base", tier = "Free" }
    properties = {
      kubernetesVersion    = var.kubernetes_version
      dnsPrefix            = "aks-outpost-${random_id.instance.hex}"
      enableRBAC           = true
      disableLocalAccounts = true
      aadProfile = {
        managed         = true
        enableAzureRBAC = true
        tenantID        = data.azurerm_client_config.current.tenant_id
      }
      apiServerAccessProfile = {
        enableVnetIntegration = true
        subnetId              = azurerm_subnet.lab["api"].id
        enablePrivateCluster  = false
      }
      agentPoolProfiles = [for pool in [
        { name = "system", mode = "System", size = "Standard_D4as_v5", count = 2, zones = ["1", "2"] },
        { name = "web", mode = "User", size = "Standard_D2as_v5", count = 1, zones = ["1"] }
        ] : {
        name               = pool.name
        mode               = pool.mode
        type               = "VirtualMachineScaleSets"
        vmSize             = pool.size
        count              = pool.count
        availabilityZones  = pool.zones
        vnetSubnetID       = azurerm_subnet.lab["nodes"].id
        enableNodePublicIP = false
        enableAutoScaling  = false
        osType             = "Linux"
        osSKU              = "AzureLinux3"
        osDiskType         = "Managed"
        osDiskSizeGB       = 64
        nodeLabels         = pool.name == "web" ? { workload = "web" } : {}
        nodeTaints         = pool.name == "web" ? ["workload=web:NoSchedule"] : []
        upgradeSettings    = { maxSurge = "1" }
        securityProfile    = { sshAccess = "Disabled" }
      }]
      networkProfile = {
        networkPlugin     = "azure"
        networkPluginMode = "overlay"
        networkDataplane  = "cilium"
        networkPolicy     = "cilium"
        outboundType      = "userAssignedNATGateway"
        loadBalancerSku   = "standard"
        podCidr           = "10.85.0.0/20"
        serviceCidr       = "10.86.0.0/24"
        dnsServiceIP      = "10.86.0.10"
      }
      identityProfile = {
        kubeletidentity = {
          resourceId = local.identities["id-aks-kubelet"].id
          clientId   = local.identities["id-aks-kubelet"].client_id
          objectId   = local.identities["id-aks-kubelet"].principal_id
        }
      }
      autoUpgradeProfile = { upgradeChannel = "none", nodeOSUpgradeChannel = "None" }
      addonProfiles      = { azurepolicy = { enabled = true } }
      oidcIssuerProfile  = { enabled = true }
      securityProfile    = { workloadIdentity = { enabled = true } }
    }
  }

  response_export_values = ["properties.oidcIssuerProfile.issuerURL"]
  depends_on = [
    azurerm_role_assignment.aks_network, azurerm_role_assignment.kubelet_operator,
    azurerm_subnet_network_security_group_association.lab,
    azurerm_subnet_nat_gateway_association.lab, azurerm_nat_gateway_public_ip_association.lab
  ]
  lifecycle { ignore_changes = [tags["lab-keep-running"]] }
}

resource "azurerm_container_registry" "images" {
  name                          = "acroutpost${random_id.instance.hex}"
  resource_group_name           = local.rg.name
  location                      = local.location
  sku                           = "Basic"
  admin_enabled                 = false
  anonymous_pull_enabled        = false
  public_network_access_enabled = true
  role_assignment_mode          = "LegacyRegistryPermissions"
  tags                          = local.tags
}

resource "azurerm_federated_identity_credential" "reader" {
  name                      = "backup-reader"
  user_assigned_identity_id = local.identities["id-backup-reader"].id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = azapi_resource.aks.output.properties.oidcIssuerProfile.issuerURL
  subject                   = "system:serviceaccount:wiz-evidence:backup-reader"
}
