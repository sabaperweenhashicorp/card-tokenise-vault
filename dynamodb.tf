
resource "aws_dynamodb_table" "card_tokens" {
  name           = "card-tokens"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "cardToken"
  stream_enabled = false

  attribute {
    name = "cardToken"
    type = "S"
  }

  tags = {
    Environment = "production"
  }
}
