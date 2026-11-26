terraform {
  required_version = ">= 1.11, < 2.0"

  backend "azurerm" {
    resource_group_name  = "takehome-rg"
    storage_account_name = "sttakehometf20581"
    container_name       = "tfstate"
    key                  = "outpost.tfstate"
    use_azuread_auth     = true
    use_oidc             = true
    use_cli              = false
  }

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= 4.81.0"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "= 2.14.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "= 3.7.2"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy       = false
      purge_soft_deleted_keys_on_destroy = false
    }
    # The backup account has no public network path, so hosted runners can't
    # reach its data plane. Manage it, and its container, through ARM only.
    storage {
      data_plane_available = false
    }
  }
  resource_provider_registrations = "none"
  storage_use_azuread             = true
  use_oidc                        = true
  use_cli                         = false
}

provider "azapi" {
  skip_provider_registration = true
  use_oidc                   = true
  use_cli                    = false
}
