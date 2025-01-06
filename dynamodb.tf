resource "aws_dynamodb_table" "patient_records" {
  name           = "patient-records"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "patient_id"
  stream_enabled = false

  attribute {
    name = "patient_id"
    type = "S"
  }

  tags = {
    Environment = "production"
  }
}