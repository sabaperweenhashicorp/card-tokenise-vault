

resource "aws_lambda_layer_version" "dependencies" {
  filename            = "lambda_layer.zip"
  layer_name          = "card-processor-dependencies"
  compatible_runtimes = ["python3.9"]
  description         = "Layer containing hvac package"
}

resource "aws_lambda_function" "card_processor" {
  filename         = "lambda_function.zip"
  source_code_hash = filebase64sha256("lambda_function.zip")
  function_name    = "card_processor"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.9"
  timeout          = 30
  layers           = [aws_lambda_layer_version.dependencies.arn] # Add the layer
  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }
  environment {
    variables = {
      DYNAMODB_TABLE           = aws_dynamodb_table.card_tokens.name
      VAULT_SECRETS_PATH       = "secret/card-tokens"
      VAULT_CREDENTIALS_SECRET = aws_secretsmanager_secret.vault_credentials.name
    }
  }
}

resource "aws_lambda_permission" "apigw_lambda" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.card_processor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.card_api.execution_arn}/*/${aws_api_gateway_method.card_method.http_method}${aws_api_gateway_resource.card_resource.path}"
}

resource "aws_lambda_permission" "apigw_lambda_get" {
  statement_id  = "AllowAPIGatewayInvokeGet"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.card_processor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.card_api.execution_arn}/*/GET${aws_api_gateway_resource.card_resource.path}"
}


