variable "ssh_public_key" {
  type        = string
  sensitive   = true
  description = "Operator's RSA SSH public key (at least 2048 bits) for the MongoDB VM."
  validation {
    condition     = can(regex("^ssh-rsa [A-Za-z0-9+/]+={0,2}( [^\r\n]*)?$", trimspace(var.ssh_public_key)))
    error_message = "Supply a single OpenSSH RSA public key."
  }
}

variable "alert_email" {
  type        = string
  sensitive   = true
  description = "Email destination for the action group and budget, supplied by the protected job."
  validation {
    condition     = can(regex("^[^ @]+@[^ @]+[.][^ @]+$", var.alert_email))
    error_message = "Supply the monitored lab email address."
  }
}

variable "daily_quota_gb" {
  type        = number
  default     = 0.5
  description = "Daily Log Analytics ingestion cap in GB. Use 2 for evidence days."
  validation {
    condition     = var.daily_quota_gb >= 0.5
    error_message = "The daily workspace cap must be at least 0.5 GB."
  }
}

variable "kubernetes_version" {
  type        = string
  default     = "1.36.5"
  description = "Exact AKS patch verified by the deployer in East US 2 before creation."
}

variable "backup_stage" {
  type        = string
  default     = "outpost"
  description = "Pipeline 1 stage. Outpost is one-way: the Phase-1 closed, waiver and public stages are retired and refused."
  validation {
    condition     = var.backup_stage == "outpost"
    error_message = "The Phase-1 backup stages are retired after Outpost. Only the outpost stage can be planned."
  }
}

variable "aks_api_home_cidr" {
  type        = string
  sensitive   = true
  description = "Operator's home public IPv4 as a /32, the only customer range on the public AKS API. In-VNet clients use the integrated private API path."
  validation {
    condition = (
      can(regex("^([0-9]{1,3}[.]){3}[0-9]{1,3}/32$", var.aks_api_home_cidr)) &&
      can(cidrhost(var.aks_api_home_cidr, 0)) &&
      try(cidrhost(var.aks_api_home_cidr, 0) == split("/", var.aks_api_home_cidr)[0], false) &&
      !can(regex("^(0|10|127)[.]|^169[.]254[.]|^172[.](1[6-9]|2[0-9]|3[01])[.]|^192[.]168[.]|^100[.](6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])[.]|^(22[4-9]|2[3-5][0-9])[.]|^192[.]0[.][02][.]|^198[.]51[.]100[.]|^203[.]0[.]113[.]|^198[.]1[89][.]", var.aks_api_home_cidr))
    )
    error_message = "Supply exactly one public IPv4 address as a /32."
  }
}
