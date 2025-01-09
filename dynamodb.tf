resource "aws_dynamodb_table" "patient_records" {
  name           = "patient-records"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "patient_id"
  stream_enabled = false

  attribute {
    name = "patient_id"
    type = "S"
  }

  attribute {
    name = "encoded_mrn"
    type = "S"
  }

  global_secondary_index {
    name               = "encoded_mrn-index"
    hash_key           = "encoded_mrn"
    projection_type    = "ALL"
  }

  tags = {
    Environment = "production"
  }
}