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
  default     = "closed"
  description = "Apply closed first, record the expected policy denial, apply waiver, then public after propagation."
  validation {
    condition     = contains(["closed", "waiver", "public"], var.backup_stage)
    error_message = "Choose closed, waiver, or public."
  }
}
