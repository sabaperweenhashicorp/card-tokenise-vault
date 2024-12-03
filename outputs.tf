output "api_url" {
  value = "${aws_api_gateway_stage.card_api_stage.invoke_url}/${aws_api_gateway_resource.card_resource.path_part}"
}

output "user_credentials" {
  value = {
    for key, user in var.api_users : user.username => {
      api_key = aws_api_gateway_api_key.user_api_keys[key].value
      email   = user.email
      role    = user.role
    }
  }
  sensitive = true
}

output "cognito_pool_id" {
  value = aws_cognito_user_pool.card_processor_pool.id
}

output "cognito_client_id" {
  value = aws_cognito_user_pool_client.card_processor_client.id
}

output "cognito_arn" {
  value = aws_cognito_user_pool.card_processor_pool.arn
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "private_route_table_ids" {
  description = "IDs of private route tables"
  value       = aws_route_table.private[*].id
}

output "vault_public_endpoint_url" {
  description = "HCP Vault public endpoint URL"
  value       = hcp_vault_cluster.vault.vault_public_endpoint_url
}

output "vault_secrets_path" {
  description = "Path for card token secrets in Vault"
  value       = "secret/card-tokens"
}
