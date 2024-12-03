# Card Processing System

A secure card processing system built with AWS Lambda, API Gateway, Cognito, and HashiCorp Vault for secure token storage.

## Overview

This system provides a secure way to process and store card information using:
- AWS Lambda for serverless processing
- Amazon Cognito for authentication
- API Gateway for REST endpoints
- HashiCorp Vault for secure token storage
- Terraform for infrastructure as code

## Prerequisites

- AWS CLI installed and configured
- Terraform >= 1.0.0
- HashiCorp Vault access
- Python 3.8 or higher
- jq (for JSON processing)

## Quick Start

1. Clone the repository:
```bash
git clone [repository-url]
cd vault-customer-tokenisation
```

2. Deploy the infrastructure:
```bash
chmod +x build_lambda.sh && ./build_lambda.sh && \
terraform init && terraform validate && \
terraform plan && terraform apply -auto-approve
```

## Detailed Setup

### 1. Package Preparation
```bash
# Clean existing packages
rm -rf lambda_package lambda_function.zip

# Build Lambda package
chmod +x build_lambda.sh
./build_lambda.sh
zip lambda_function.zip lambda_function.py
```

### 2. Infrastructure Deployment
```bash
terraform init
terraform validate
terraform plan
terraform apply -auto-approve
```

## Usage

### Authentication

1. Get authentication token:
```bash
aws cognito-idp initiate-auth \
  --client-id $(terraform output -raw cognito_client_id) \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME=<username>,PASSWORD=<password> \
  --profile <aws-profile>
```

2. Store your credentials:
```bash
terraform output user_credentials
```

### API Operations

#### Process a New Card

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <jwt-token>" \
  -H "x-api-key: <api-key>" \
  -d '{
    "cardNumber": "000011112222",
    "expMonth": "12",
    "expYear": "2025",
    "cvv": "123",
    "cardholderName": "Example Name"
  }' \
  https://<api-gateway-url>/prod/process-card | jq '.'
```

#### Retrieve Card Details

```bash
curl -X GET \
  -H "x-api-key: <api-key>" \
  -H "Authorization: Bearer <jwt-token>" \
  "https://<api-gateway-url>/prod/process-card?token=<card-token>" | jq '.'
```

## HashiCorp Vault Integration

### Accessing Vault

#### Web UI Method
1. Navigate to Vault Dedicated portal
2. Generate new admin token
3. Launch web UI
4. Login to view card tokens

#### API Method
```bash
curl \
    --header "X-Vault-Token: <vault-token>" \
    --header "X-Vault-Namespace: admin" \
    "https://<vault-url>/v1/secret/data/card-tokens/<card-token>"
```

## Security Considerations

- Never commit sensitive information (tokens, passwords, etc.) to version control
- Rotate access credentials regularly
- Monitor AWS CloudWatch logs for suspicious activities
- Follow the principle of least privilege for IAM roles
- Regularly audit Vault access logs

## Project Structure

```
.
├── README.md
├── build_lambda.sh
├── lambda_function.py
├── variables.tf
└── apigateway.tf
└── build_lambda.sh
└── cognito.tf
└── dynamodb.tf
└── iam.tf
└── lambda_function.py
└── lambda.tf
└── main.tf
└── outputs.tf
└── providers.tf
└── secret-manager.tf
└── terraform.tfvars     
└── vaulttf
└── vpc.tf

```

## Troubleshooting

Common issues and solutions:

1. **Build Script Permission Denied**
   ```bash
   chmod +x build_lambda.sh
   ```

2. **Token Expiration**
   - JWT tokens expire after 1 hour
   - Request new token using the authentication process

3. **API Gateway 403 Error**
   - Verify API key is correct
   - Check if JWT token is still valid
   - Ensure proper IAM roles are configured

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request


---