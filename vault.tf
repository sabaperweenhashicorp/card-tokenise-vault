resource "hcp_hvn" "vault_hvn" {
  hvn_id         = "hvn-vault-${var.environment}"
  cloud_provider = "aws"
  region         = var.aws_region
  cidr_block     = var.hvn_cidr_block
}

resource "hcp_vault_cluster" "vault" {
  cluster_id      = "vault-cluster-${var.environment}"
  hvn_id          = hcp_hvn.vault_hvn.hvn_id
  tier            = "plus_small"
  public_endpoint = true
}

resource "hcp_vault_cluster_admin_token" "cluster" {
  cluster_id = hcp_vault_cluster.vault.cluster_id
}

resource "hcp_aws_network_peering" "peer" {
  hvn_id          = hcp_hvn.vault_hvn.hvn_id
  peering_id      = "peer-${var.environment}"
  peer_vpc_id     = aws_vpc.main.id
  peer_account_id = data.aws_caller_identity.current.account_id
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

resource "vault_mount" "transform" {
  depends_on = [null_resource.verify_cluster]

  path        = "transform"
  type        = "transform"
  description = "Transform engine for patient data formatting"

  lifecycle {
    ignore_changes = [
      type,
      description
    ]
  }
}

resource "vault_transform_alphabet" "alphanumeric" {
  depends_on = [vault_mount.transform]

  path     = vault_mount.transform.path
  name     = "alphanumeric"
  alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
}

resource "vault_transform_template" "patient_mrn" {
  path     = vault_mount.transform.path
  name     = "patient-mrn"
  type     = "regex"
  pattern  = "(P|p)([0-9]{8})"
  alphabet = vault_transform_alphabet.alphanumeric.name

  lifecycle {
    ignore_changes = [
      type,
      pattern,
      alphabet
    ]
    prevent_destroy = false
  }
}

resource "vault_transform_transformation" "patient_mrn_encode" {
  path          = vault_mount.transform.path
  name          = "patient-mrn"
  type          = "fpe"
  template      = vault_transform_template.patient_mrn.name
  tweak_source  = "internal"
  allowed_roles = ["patient-processor"]
  deletion_allowed = true
}

resource "vault_transform_role" "patient_processor" {
  path            = vault_mount.transform.path
  name            = "patient-processor"
  transformations = [vault_transform_transformation.patient_mrn_encode.name]
}

resource "vault_policy" "patient_encryption_policy" {
  name = "patient-encryption-policy"

  policy = <<EOT
# Transit engine permissions
path "transit/encrypt/patient-encryption-key" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/patient-encryption-key" {
  capabilities = ["create", "update"]
}

# Transform engine permissions for patient records
path "transform/encode/patient-processor" {
  capabilities = ["create", "update"]
}

path "transform/decode/patient-processor" {
  capabilities = ["create", "update"]
}
EOT
}

resource "null_resource" "verify_cluster" {
  depends_on = [hcp_vault_cluster_admin_token.cluster]

  triggers = {
    cluster_id = hcp_vault_cluster.vault.cluster_id
  }

  provisioner "local-exec" {
    command = <<EOF
      # Wait for cluster to be fully ready
      sleep 60
      
      export VAULT_ADDR="${hcp_vault_cluster.vault.vault_public_endpoint_url}"
      export VAULT_TOKEN="${hcp_vault_cluster_admin_token.cluster.token}"
      export VAULT_NAMESPACE="admin"
      
      # Check if we can connect and verify version
      echo "Checking Vault status..."
      vault status || {
        echo "Failed to connect to Vault"
        exit 1
      }
      
      # List enabled secret engines to verify access
      echo "Verifying secret engines..."
      vault secrets list || {
        echo "Failed to list secret engines"
        exit 1
      }
EOF
  }
}