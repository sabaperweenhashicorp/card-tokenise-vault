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
  description = "Path for patient record secrets in Vault"
  value       = "secret/patient-records"
}

output "patient_dynamodb_table" {
  description = "Name of the DynamoDB table for patient records"
  value       = aws_dynamodb_table.patient_records.name
}

output "private_subnets" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "public_subnets" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "api_url" {
  value = "${aws_api_gateway_stage.patient_api_stage.invoke_url}/${aws_api_gateway_resource.patient_resource.path_part}"
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
  value = aws_cognito_user_pool.patient_processor_pool.id
}

output "cognito_client_id" {
  value = aws_cognito_user_pool_client.patient_processor_client.id
}

output "cognito_arn" {
  value = aws_cognito_user_pool.patient_processor_pool.arn
}

