resource "aws_cognito_user_pool" "patient_processor_pool" {
  name = "patient-processor-pool-${var.environment}"
  deletion_protection = "INACTIVE"
  
  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }

  schema {
    name                = "role"
    attribute_data_type = "String"
    mutable             = true
    required            = false

    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }
}

resource "aws_cognito_user_pool_client" "patient_processor_client" {
  name         = "patient-processor-client-${var.environment}"
  user_pool_id = aws_cognito_user_pool.patient_processor_pool.id

  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH"
  ]
}

resource "aws_cognito_user" "pool_users" {
  for_each = var.api_users

  user_pool_id = aws_cognito_user_pool.patient_processor_pool.id
  username     = each.value.username

  attributes = {
    email = each.value.email
    role  = each.value.role
  }

  password = each.value.password
}