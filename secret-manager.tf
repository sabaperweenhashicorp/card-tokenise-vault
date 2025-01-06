resource "null_resource" "delete_secret" {
  provisioner "local-exec" {
    command = <<EOF
      aws secretsmanager delete-secret \
        --secret-id "hcp-vault-credentials-${var.environment}" \
        --force-delete-without-recovery \
        --region ${var.aws_region} \
        --profile ${var.aws_profile}
    EOF
  }
}

resource "aws_secretsmanager_secret" "vault_credentials" {
  name = "hcp-vault-credentials-${var.environment}"
  
  tags = {
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "vault_credentials" {
  secret_id = aws_secretsmanager_secret.vault_credentials.id
  
  secret_string = jsonencode({
    VAULT_ADDR       = hcp_vault_cluster.vault.vault_public_endpoint_url
    VAULT_TOKEN      = hcp_vault_cluster_admin_token.cluster.token
    VAULT_NAMESPACE  = "admin"
    VAULT_PATIENT_ROLE = "patient-processor"
  })

  depends_on = [
    hcp_vault_cluster.vault,
    hcp_vault_cluster_admin_token.cluster
  ]
}