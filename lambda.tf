resource "aws_lambda_layer_version" "dependencies" {
  filename            = "lambda_layer.zip"
  layer_name          = "patient-processor-dependencies"
  compatible_runtimes = ["python3.9"]
  description         = "Layer containing hvac package"
}

resource "aws_lambda_function" "patient_processor" {
  filename         = "lambda_function.zip"
  source_code_hash = filebase64sha256("lambda_function.zip")
  function_name    = "patient_processor"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.9"
  timeout          = 60
  memory_size      = 512
  layers          = [aws_lambda_layer_version.dependencies.arn]

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }
  
  environment {
    variables = {
      PATIENT_DYNAMODB_TABLE     = aws_dynamodb_table.patient_records.name
      VAULT_SECRETS_PATH         = "secret/patient-records"
      VAULT_CREDENTIALS_SECRET   = aws_secretsmanager_secret.vault_credentials.name
      LOG_LEVEL                 = "DEBUG"
    }
  }
}

resource "aws_lambda_permission" "apigw_lambda" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.patient_processor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.patient_api.execution_arn}/*/${aws_api_gateway_method.patient_method.http_method}${aws_api_gateway_resource.patient_resource.path}"
}

resource "aws_lambda_permission" "apigw_lambda_get" {
  statement_id  = "AllowAPIGatewayInvokeGet"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.patient_processor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.patient_api.execution_arn}/*/${aws_api_gateway_method.get_patient.http_method}${aws_api_gateway_resource.patient_resource.path}"
}

resource "aws_security_group" "lambda" {
  name        = "lambda-sg-${var.environment}"
  description = "Security group for Lambda function"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "lambda-sg-${var.environment}"
    Environment = var.environment
  }
}