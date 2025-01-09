# Patient Processing API

This API provides secure endpoints for processing and retrieving patient records with encryption and access control. The infrastructure is deployed using Terraform and integrates with HCP Vault for secure data transformation.

## Quick Start Guide

### 1. Deploy Infrastructure

Build the Lambda package and deploy the infrastructure:

```bash
chmod +x build_lambda.sh && ./build_lambda.sh && \
terraform init && terraform validate && \
terraform plan && terraform apply -auto-approve
```

### 2. Get User Credentials

Retrieve the generated user credentials:

```bash
terraform output user_credentials
```

### 3. Get Authentication Token

Obtain a Cognito authentication token using the AWS CLI:

```bash
aws cognito-idp initiate-auth \
  --client-id $(terraform output -raw cognito_client_id) \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME=<your-username>,PASSWORD=<your-password> \
  --profile <your-aws-profile>
```

### 4. API Usage Examples

#### Create/Update Patient Record

```bash
curl -X POST \
  'https://<api-gateway-url>/prod/process-patient' \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: <your-api-key>' \
  -H 'Authorization: Bearer <your-jwt-token>' \
  -d '{
    "patient_id": "PATIENT123",
    "name": "John Doe",
    "email": "john.doe@example.com",
    "mrn": "9999-9999-9999"
  }' | jq '.'
```

#### Retrieve Patient Record by ID

```bash
curl -X GET \
  'https://<api-gateway-url>/prod/process-patient?patient_id=PATIENT123' \
  -H 'x-api-key: <your-api-key>' \
  -H 'Authorization: Bearer <your-jwt-token>' | jq '.'
```

#### Retrieve Patient Record by MRN

```bash
curl -X GET \
  'https://<api-gateway-url>/prod/process-patient?encoded_mrn=9999-9999-9999' \
  -H 'x-api-key: <your-api-key>' \
  -H 'Authorization: Bearer <your-jwt-token>' | jq '.'
```

## Infrastructure Components

- **API Gateway**: Secure REST API with Cognito authentication and API key validation
- **Lambda**: Patient processing function in Python 3.9
- **DynamoDB**: Patient records storage
- **HCP Vault**: Data encryption and transformation
- **VPC**: Private networking with NAT gateways
- **Cognito**: User authentication and authorization with role-based access

## Authentication Details

The API requires two forms of authentication:

1. **Cognito JWT Token**: Obtained through the authentication process
2. **API Key**: Generated during infrastructure deployment, unique per user

### Required Headers

| Header          | Description                         | Example                                |
|-----------------|-------------------------------------|----------------------------------------|
| Authorization   | Bearer token from Cognito           | Bearer eyJraWQ...                     |
| x-api-key       | User-specific API key              | username-xxxxxxxxxxxxx                 |
| Content-Type    | Required for POST requests          | application/json                       |

## API Endpoints

### 1. Process Patient Record (POST)

Creates or updates a patient record.

#### Request Body Parameters

| Parameter   | Type   | Description                                |
|------------|--------|--------------------------------------------|
| patient_id | string | Unique patient identifier (e.g., PATIENT123)|
| name       | string | Patient's full name                        |
| email      | string | Patient's email address                    |
| mrn        | string | Medical Record Number (format: XXXX-XXXX-XXXX) |

### 2. Retrieve Patient Record (GET)

Retrieves a patient's record by ID or MRN.

#### Query Parameters (use one)

| Parameter    | Type   | Description               |
|-------------|--------|---------------------------|
| patient_id  | string | Unique patient identifier |
| encoded_mrn | string | Encoded medical record number |

## Vault Integration

HCP Vault is used for secure data transformation. Environment variables required:

```bash
export VAULT_ADDR="https://your-vault-cluster-address:8200"
export VAULT_TOKEN="your-vault-token"
```

### Vault Operations

Transform MRN data:

```bash
# Encode MRN
vault write transform/encode/patient-processor value=<mrn> transformation=patient-mrn

# Decode MRN
vault write transform/decode/patient-processor value=<encoded-mrn> transformation=patient-mrn
```

## Role-Based Access

The system supports two user roles:

1. **Admin**: Full access to all endpoints and operations
2. **User**: Read-only access to patient records

Role information is included in the Cognito JWT token as a custom claim.

## Security Features

1. **Authentication & Authorization**:
   - Cognito user pools with role-based access
   - User-specific API keys
   - JWT token validation

2. **Data Protection**:
   - HCP Vault Transform engine for MRN encryption
   - Data encryption at rest
   - Secure secret management

## Troubleshooting

Common issues and solutions:

1. **Authentication Errors**:
   - Check JWT token expiration
   - Verify API key matches username
   - Ensure user exists in Cognito pool

2. **Request Errors**:
   - Validate JSON format in POST requests
   - Check required fields
   - Verify MRN format (XXXX-XXXX-XXXX)

3. **Access Denied**:
   - Verify user role permissions
   - Check API key association
   - Validate JWT token claims

## Monitoring

- CloudWatch logs for API Gateway and Lambda
- API Gateway execution logging
- Lambda function debugging
- Request/response monitoring

## Support

For technical issues:
1. Review CloudWatch logs
2. Check API Gateway metrics
3. Contact system administrators

---

*Note: Replace placeholders (`<api-gateway-url>`, `<your-jwt-token>`, `<your-api-key>`, etc.) with your actual values.*