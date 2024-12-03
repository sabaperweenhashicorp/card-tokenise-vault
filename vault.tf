resource "hcp_hvn" "vault_hvn" {
  hvn_id         = "hvn-vault-${var.environment}"
  cloud_provider = "aws"
  region         = var.aws_region
  cidr_block     = var.hvn_cidr_block
}

resource "hcp_vault_cluster" "vault" {
  cluster_id      = "vault-cluster-${var.environment}"
  hvn_id          = hcp_hvn.vault_hvn.hvn_id
  tier            = "dev"
  public_endpoint = true
}

data "aws_caller_identity" "current_aws" {}

resource "hcp_aws_network_peering" "peer" {
  hvn_id          = hcp_hvn.vault_hvn.hvn_id
  peering_id      = "peer-${var.environment}"
  peer_vpc_id     = aws_vpc.main.id
  peer_account_id = data.aws_caller_identity.current_aws.account_id
  peer_vpc_region = var.aws_region
}

resource "aws_vpc_peering_connection_accepter" "peer" {
  vpc_peering_connection_id = hcp_aws_network_peering.peer.provider_peering_id
  auto_accept               = true
}

resource "aws_route" "peer_route" {
  count                     = length(aws_route_table.private)
  route_table_id            = aws_route_table.private[count.index].id
  destination_cidr_block    = hcp_hvn.vault_hvn.cidr_block
  vpc_peering_connection_id = hcp_aws_network_peering.peer.provider_peering_id
}

resource "hcp_vault_secrets_app" "card_tokens" {
  app_name    = "card-tokens-${var.environment}"
  description = "Card tokenization secrets"
  depends_on  = [hcp_vault_cluster.vault, vault_kv_secret_v2.card_tokens]
}

resource "hcp_vault_cluster_admin_token" "cluster" {
  cluster_id = hcp_vault_cluster.vault.cluster_id
}

resource "vault_mount" "kv" {
  path       = "secret"
  type       = "kv"
  options    = { version = "2" }
  depends_on = [hcp_vault_cluster_admin_token.cluster]
}

resource "vault_kv_secret_v2" "card_tokens" {
  mount = vault_mount.kv.path
  name  = "card-tokens"
  data_json = jsonencode({
    initialized = "true"
  })
  depends_on = [vault_mount.kv]
}
