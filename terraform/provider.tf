// Teleport Terraform provider — manages roles, login rules, and access lists as
// code in the Teleport cluster. This is the SOURCE OF TRUTH; the Go engine's
// policy package mirrors the same department->role mapping so runtime decisions
// and enforced cluster state never drift.
//
// Auth: a Machine ID (tbot) identity file scoped to a `terraform-provider` role,
// so this pipeline itself authenticates with short-lived certs — no static
// admin token. (Dogfooding Teleport Machine & Workload Identity.)
//
// Docs: https://goteleport.com/docs/admin-guides/infrastructure-as-code/terraform-provider/

terraform {
  required_version = ">= 1.6"
  required_providers {
    teleport = {
      source  = "terraform.releases.teleport.dev/gravitational/teleport"
      version = "~> 16.0"
    }
  }
}

provider "teleport" {
  addr               = var.teleport_addr
  identity_file_path = var.identity_file_path
}

variable "teleport_addr" {
  type        = string
  description = "Teleport proxy/auth address, e.g. teleport.goteleport.com:443"
  default     = "teleport.goteleport.com:443"
}

variable "identity_file_path" {
  type        = string
  description = "Path to the tbot-issued identity file used to authenticate Terraform."
  default     = "terraform-identity"
}
