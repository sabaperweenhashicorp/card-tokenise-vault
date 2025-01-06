# Patient Processing API

This API provides secure endpoints for processing and retrieving patient records with encryption and access control. The infrastructure is deployed using Terraform and integrates with HCP Vault for secure data transformation.

## Quick Start Guide

### 1. Deploy Infrastructure

Build the Lambda package and deploy the infrastructure:

```bash
# Build Lambda package and deploy infrastructure
chmod +x build_lambda.sh && ./build_lambda.sh && \
terraform init && terraform validate && \
terraform plan && terraform apply -auto-approve
```

### 2. Get Authentication Token

Obtain a Cognito authentication token using the AWS CLI:

```bash
aws cognito-idp initiate-auth \
  --client-id $(terraform output -raw cognito_client_id) \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME=<your-username>,PASSWORD=<your-password> \
  --profile <your-aws-profile>
```

### 3. API Usage Examples

#### Create/Update Patient Record

```bash
curl -X POST \
  'https://<api-gateway-url>/prod/process-patient' \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: <your-api-key>' \
  -H 'Authorization: Bearer <your-jwt-token>' \
  -d '{
    "patient_id": "P1234567811",
    "name": "Sachin Tendulkar",
    "email": "sachin.tendulkar@example.com",
    "mrn": "P1234567811"
  }' | jq '.'
```

Example Response:
```json
{
  "patient_id": "P1234567811",
  "encoded_mrn": "DcaCGgUda11",
  "metadata": {
    "created_at": "2025-01-06T13:39:23.253271",
    "created_by": "saba_perween",
    "email": "saba.perween@abc.com"
  }
}
```

#### Retrieve Patient Record

```bash
curl -X GET \
  'https://<api-gateway-url>/prod/process-patient?patient_id=P1234567811' \
  -H 'x-api-key: <your-api-key>' \
  -H 'Authorization: Bearer <your-jwt-token>' | jq '.'
```

Example Response:
```json
{
  "created_by": "saba_perween",
  "timestamp": "2025-01-06T13:39:23.253271",
  "user_role": "admin",
  "email": "sachin.tendulkar@example.com",
  "encoded_mrn": "DcaCGgUda11",
  "name": "Sachin Tendulkar",
  "patient_id": "P1234567811"
}
```

## Infrastructure Components

- **API Gateway**: Secure REST API with Cognito authentication and API key validation
- **Lambda**: Patient processing function in Python 3.9
- **DynamoDB**: Patient records storage
- **HCP Vault**: Data encryption and transformation
- **VPC**: Private networking with NAT gateways
- **Cognito**: User authentication and authorization

## Authentication Details

The API requires two forms of authentication:

1. **Cognito JWT Token**: Obtained through the authentication process shown above
2. **API Key**: Generated during infrastructure deployment and available in Terraform outputs

### Required Headers

| Header          | Description                         | Example                                |
|-----------------|-------------------------------------|----------------------------------------|
| Authorization   | Bearer token from Cognito           | Bearer eyJraWQ...                     |
| x-api-key       | API key for your application        | username-xxxxxxxxxxxxx                 |
| Content-Type    | Required for POST requests          | application/json                       |

## API Endpoints

### 1. Process Patient Record (POST)

Creates or updates a patient record with encrypted data.

#### Request Body Parameters

| Parameter   | Type   | Description                                |
|------------|--------|--------------------------------------------|
| patient_id | string | Unique patient identifier (e.g., P12345678)|
| name       | string | Patient's full name                        |
| email      | string | Patient's email address                    |
| mrn        | string | Medical Record Number (format: P12345678)  |

### 2. Retrieve Patient Record (GET)

Retrieves a patient's record by their ID.

#### Query Parameters

| Parameter  | Type   | Description               |
|-----------|--------|---------------------------|
| patient_id | string | Unique patient identifier |

## Data Transformation

The API automatically handles:
- MRN encryption using HCP Vault's transform engine
- Metadata addition (timestamp, creator information)
- Role-based access control

## Security Features

1. **Authentication & Authorization**:
   - Cognito user pools for identity management
   - API keys for client application authentication
   - Role-based access through Cognito user attributes

2. **Data Protection**:
   - HCP Vault Transform engine for MRN format-preserving encryption
   - Data encryption at rest in DynamoDB
   - Secrets management through AWS Secrets Manager

## Troubleshooting

Common issues and solutions:

1. **Authentication Errors**:
   - Ensure your JWT token is not expired
   - Verify API key is correct
   - Check if user exists in Cognito user pool

2. **Request Errors**:
   - Validate JSON format in POST requests
   - Ensure all required fields are present
   - Check MRN format (should be P followed by 8 digits)

## Monitoring and Logging

- CloudWatch logs enabled for API Gateway and Lambda
- API Gateway execution logs with INFO level
- Lambda function logs with DEBUG level
- Metrics enabled for API Gateway methods

## Support

For issues or questions:
1. Check CloudWatch logs for detailed error messages
2. Review API Gateway metrics for performance issues
3. Contact system administrators for access-related problems

---

*Note: Replace placeholders (`<api-gateway-url>`, `<your-jwt-token>`, `<your-api-key>`, etc.) with actual values from your deployment.*