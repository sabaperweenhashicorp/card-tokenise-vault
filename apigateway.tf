resource "aws_api_gateway_rest_api" "patient_api" {
  name        = "patient-processor-api"
  description = "API Gateway for patient record processing"
}

resource "aws_api_gateway_resource" "patient_resource" {
  rest_api_id = aws_api_gateway_rest_api.patient_api.id
  parent_id   = aws_api_gateway_rest_api.patient_api.root_resource_id
  path_part   = "process-patient"
}

resource "aws_api_gateway_integration" "lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.patient_api.id
  resource_id             = aws_api_gateway_resource.patient_resource.id
  http_method             = aws_api_gateway_method.patient_method.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.patient_processor.invoke_arn
}

resource "aws_api_gateway_authorizer" "cognito" {
  name            = "cognito-authorizer"
  rest_api_id     = aws_api_gateway_rest_api.patient_api.id
  type            = "COGNITO_USER_POOLS"
  identity_source = "method.request.header.Authorization"
  provider_arns   = [aws_cognito_user_pool.patient_processor_pool.arn]
}

resource "aws_api_gateway_method" "options" {
  rest_api_id   = aws_api_gateway_rest_api.patient_api.id
  resource_id   = aws_api_gateway_resource.patient_resource.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_method_response" "options" {
  rest_api_id = aws_api_gateway_rest_api.patient_api.id
  resource_id = aws_api_gateway_resource.patient_resource.id
  http_method = aws_api_gateway_method.options.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration" "options" {
  rest_api_id = aws_api_gateway_rest_api.patient_api.id
  resource_id = aws_api_gateway_resource.patient_resource.id
  http_method = aws_api_gateway_method.options.http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

resource "aws_api_gateway_integration_response" "options" {
  rest_api_id = aws_api_gateway_rest_api.patient_api.id
  resource_id = aws_api_gateway_resource.patient_resource.id
  http_method = aws_api_gateway_method.options.http_method
  status_code = aws_api_gateway_method_response.options.status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'"
    "method.response.header.Access-Control-Allow-Methods" = "'POST,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }
}

resource "aws_api_gateway_method" "patient_method" {
  rest_api_id      = aws_api_gateway_rest_api.patient_api.id
  resource_id      = aws_api_gateway_resource.patient_resource.id
  http_method      = "POST"
  authorization    = "COGNITO_USER_POOLS"
  authorizer_id    = aws_api_gateway_authorizer.cognito.id
  api_key_required = true

  request_parameters = {
    "method.request.header.Authorization" = true
    "method.request.header.x-api-key"     = true
  }
}

resource "aws_api_gateway_stage" "patient_api_stage" {
  deployment_id = aws_api_gateway_deployment.patient_api_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.patient_api.id
  stage_name    = "prod"
}

resource "aws_api_gateway_method" "get_patient" {
  rest_api_id      = aws_api_gateway_rest_api.patient_api.id
  resource_id      = aws_api_gateway_resource.patient_resource.id
  http_method      = "GET"
  authorization    = "COGNITO_USER_POOLS"
  authorizer_id    = aws_api_gateway_authorizer.cognito.id
  api_key_required = true

  request_parameters = {
    "method.request.querystring.patient_id" = true
  }
}

resource "aws_api_gateway_integration" "get_patient_integration" {
  rest_api_id             = aws_api_gateway_rest_api.patient_api.id
  resource_id             = aws_api_gateway_resource.patient_resource.id
  http_method             = aws_api_gateway_method.get_patient.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.patient_processor.invoke_arn
}

resource "aws_api_gateway_deployment" "patient_api_deployment" {
  depends_on = [
    aws_api_gateway_integration.lambda_integration,
    aws_api_gateway_integration.get_patient_integration,
    aws_api_gateway_method.patient_method,
    aws_api_gateway_method.get_patient,
    aws_api_gateway_method.options,
    aws_api_gateway_integration.options
  ]

  rest_api_id = aws_api_gateway_rest_api.patient_api.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.patient_resource,
      aws_api_gateway_method.patient_method,
      aws_api_gateway_method.get_patient,
      aws_api_gateway_integration.lambda_integration,
      aws_api_gateway_integration.get_patient_integration,
      aws_api_gateway_authorizer.cognito,
      aws_api_gateway_method.options,
      aws_api_gateway_integration.options
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "random_string" "api_key_suffix" {
  for_each = var.api_users

  length  = 16
  special = false
}

resource "aws_api_gateway_api_key" "user_api_keys" {
  for_each = var.api_users

  name  = "api-key-${each.value.username}-${var.environment}"
  value = "${each.value.username}-${random_string.api_key_suffix[each.key].result}"
}

resource "aws_api_gateway_usage_plan" "patient_processor_usage_plan" {
  name = "patient-processor-usage-plan"

  api_stages {
    api_id = aws_api_gateway_rest_api.patient_api.id
    stage  = aws_api_gateway_stage.patient_api_stage.stage_name
  }

  quota_settings {
    limit  = 1000
    period = "DAY"
  }

  throttle_settings {
    burst_limit = 10
    rate_limit  = 5
  }
}

resource "aws_api_gateway_usage_plan_key" "user_keys" {
  for_each = var.api_users

  key_id        = aws_api_gateway_api_key.user_api_keys[each.key].id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.patient_processor_usage_plan.id
}

resource "aws_api_gateway_method_settings" "patient_api_settings" {
  depends_on = [aws_api_gateway_account.main]
  
  rest_api_id = aws_api_gateway_rest_api.patient_api.id
  stage_name  = aws_api_gateway_stage.patient_api_stage.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled        = true
    logging_level         = "INFO"
    data_trace_enabled    = true
    throttling_burst_limit = 5000
    throttling_rate_limit  = 10000
  }
}


resource "aws_api_gateway_account" "main" {
  cloudwatch_role_arn = aws_iam_role.api_gateway_cloudwatch.arn
}