
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    hcp = {
      source = "hashicorp/hcp"
    }
  }
}

provider "hcp" {
  client_id     = var.hcp_client_id
  client_secret = var.hcp_client_secret
}
provider "aws" {
  profile = ""
  region  = "us-east-1"
}

provider "vault" {
  address   = hcp_vault_cluster.vault.vault_public_endpoint_url
  token     = hcp_vault_cluster_admin_token.cluster.token
  namespace = var.vault_namespace
}
