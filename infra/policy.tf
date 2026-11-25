locals {
  k8s_policies = {
    deny-privileged = { id = "95edb821-ddaf-4404-9732-666045e056b4", effect = "Deny" }
    audit-admin     = { id = "a3dc4946-dba6-43e6-950d-f96532848c9f", effect = "Audit" }
    audit-token     = { id = "423dd1ba-798e-40e4-9c4d-b6902674b423", effect = "Audit" }
    audit-writable  = { id = "df49d893-a74c-421d-bc95-c663042e5b80", effect = "Audit" }
  }
}

resource "azurerm_resource_policy_assignment" "kubernetes" {
  for_each             = local.k8s_policies
  name                 = each.key
  resource_id          = azapi_resource.aks.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/${each.value.id}"
  # ClusterRoleBindings are cluster-scoped. Only the pod policies select wiz-web.
  parameters = jsonencode(merge(
    { effect = { value = each.value.effect } },
    each.key == "audit-admin" ? {} : { namespaces = { value = ["wiz-web"] } }
  ))
}
