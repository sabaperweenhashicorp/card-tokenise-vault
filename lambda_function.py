import json
import logging
import boto3
import os
import traceback
import hvac
import base64
import requests
from datetime import datetime
from typing import Dict, Any, Tuple

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)  # Set to DEBUG for maximum verbosity

def redact_sensitive(data: Dict[str, Any]) -> Dict[str, Any]:
    """Redact sensitive information from dictionaries for logging."""
    sensitive_keys = ['token', 'password', 'secret', 'key', 'Authorization']
    redacted = data.copy()
    for k, v in redacted.items():
        if any(sensitive in k.lower() for sensitive in sensitive_keys):
            redacted[k] = '[REDACTED]'
    return redacted

def test_network_connectivity(vault_url: str):
    """Test network connectivity to Vault server."""
    try:
        logger.info(f"Testing connection to Vault server: {vault_url}")
        
        # Parse the vault URL
        from urllib.parse import urlparse
        parsed_url = urlparse(vault_url)
        host = parsed_url.netloc.split(':')[0]
        
        # Test DNS resolution
        logger.info(f"Testing DNS resolution for {host}")
        import socket
        ip_address = socket.gethostbyname(host)
        logger.info(f"DNS resolution successful. IP: {ip_address}")
        
        # Test TCP connection
        logger.info(f"Testing TCP connection to {host}:8200")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((ip_address, 8200))
        sock.close()
        
        if result == 0:
            logger.info("TCP connection successful")
        else:
            logger.error(f"TCP connection failed with error code: {result}")
            
        # Test HTTPS connection
        logger.info("Testing HTTPS connection")
        import requests
        response = requests.get(
            f"{vault_url}/v1/sys/health",
            timeout=5,
            verify=True
        )
        logger.info(f"HTTPS connection successful. Status code: {response.status_code}")
        
    except Exception as e:
        logger.error(f"Network test failed: {str(e)}")
        logger.error(traceback.format_exc())
        raise

def get_vault_client() -> Tuple[hvac.Client, Dict[str, str]]:
    try:
        logger.info("Starting Vault client initialization")
        
        secrets_client = boto3.client('secretsmanager')
        vault_creds = secrets_client.get_secret_value(
            SecretId=os.environ['VAULT_CREDENTIALS_SECRET']
        )
        vault_config = json.loads(vault_creds['SecretString'])
        
        # Test network connectivity before creating client
        test_network_connectivity(vault_config['VAULT_ADDR'])
        
        client = hvac.Client(
            url=vault_config['VAULT_ADDR'].rstrip('/'),
            token=vault_config['VAULT_TOKEN'],
            namespace=vault_config.get('VAULT_NAMESPACE', 'admin'),
            timeout=10
        )
        
        return client, vault_config
        
    except Exception as e:
        logger.error(f"Failed to initialize Vault client: {str(e)}")
        logger.error(traceback.format_exc())
        raise
    
def encode_patient_mrn(vault_client: hvac.Client, config: Dict[str, str], mrn: str) -> str:
    """Encode patient MRN with detailed logging."""
    try:
        logger.info(f"Starting MRN encoding process for MRN pattern: {mrn[:2]}****")
        
        # Construct URL
        base_url = vault_client.url.rstrip('/')
        url = f"{base_url}/v1/transform/encode/{config['VAULT_PATIENT_ROLE']}"
        logger.info(f"Using Vault endpoint: {url}")
        
        # Prepare request
        headers = {
            'X-Vault-Token': config['VAULT_TOKEN'],
            'X-Vault-Namespace': config['VAULT_NAMESPACE'],
            'Content-Type': 'application/json'
        }
        logger.info("Request headers (redacted): %s", redact_sensitive(headers))
        
        payload = {
            'value': mrn,
            'transformation': 'patient-mrn'
        }
        logger.info("Request payload: %s", json.dumps(payload))
        
        # Make request
        logger.info("Sending request to Vault...")
        response = requests.post(
            url=url,
            json=payload,
            headers=headers,
            verify=True,
            timeout=10
        )
        logger.info(f"Vault response status code: {response.status_code}")
        
        # Handle response
        if response.status_code == 200:
            result = response.json()
            logger.info("Successfully encoded MRN")
            return result['data']['encoded_value']
        
        logger.error(f"Failed to encode MRN. Status: {response.status_code}")
        logger.error(f"Response body: {response.text}")
        raise Exception(f"Failed to encode patient MRN: {response.text}")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"HTTP Request failed: {str(e)}")
        logger.error("Full traceback:")
        logger.error(traceback.format_exc())
        raise
    except Exception as e:
        logger.error(f"Unexpected error in encode_patient_mrn: {str(e)}")
        logger.error("Full traceback:")
        logger.error(traceback.format_exc())
        raise

def handle_patient_post_request(event: Dict[str, Any], user_info: Dict[str, Any]) -> Dict[str, Any]:
    """Handle patient record creation with detailed logging."""
    try:
        logger.info("Starting patient record creation")
        logger.info(f"Event: {json.dumps(redact_sensitive(event))}")
        logger.info(f"User info: {json.dumps(redact_sensitive(user_info))}")
        
        # Parse request body
        request_data = json.loads(event.get('body', '{}'))
        logger.info(f"Request data: {json.dumps(redact_sensitive(request_data))}")
        
        # Validate required fields
        required_fields = ['patient_id', 'name', 'email', 'mrn']
        missing_fields = [field for field in required_fields if field not in request_data]
        if missing_fields:
            logger.warning(f"Missing required fields: {missing_fields}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'message': f'Missing required fields: {", ".join(missing_fields)}',
                    'error_details': {'missing_fields': missing_fields}
                })
            }
        
        # Initialize Vault client
        logger.info("Initializing Vault client...")
        vault_client, vault_config = get_vault_client()
        
        # Encode MRN
        logger.info("Encoding patient MRN...")
        encoded_mrn = encode_patient_mrn(vault_client, vault_config, request_data['mrn'])
        logger.info("Successfully encoded MRN")
        
        # Process patient data
        patient_data = {
            'patient_id': request_data['patient_id'],
            'name': request_data['name'],
            'email': request_data['email'],
            'mrn': encoded_mrn
        }
        
        logger.info("Storing patient record in DynamoDB...")
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(os.environ['PATIENT_DYNAMODB_TABLE'])
        
        item = {
            'patient_id': patient_data['patient_id'],
            'name': patient_data['name'],
            'email': patient_data['email'],
            'encoded_mrn': patient_data['mrn'],
            'timestamp': datetime.now().isoformat(),
            'created_by': user_info['username'],
            'user_role': user_info.get('role', 'user')
        }
        
        table.put_item(Item=item)
        logger.info("Successfully stored patient record")
        
        # Prepare response
        response_data = {
            'patient_id': patient_data['patient_id'],
            'encoded_mrn': encoded_mrn
        }
        
        if user_info.get('role') == 'admin':
            response_data['metadata'] = {
                'created_at': item['timestamp'],
                'created_by': user_info['username'],
                'email': user_info.get('email')
            }
        
        logger.info("Returning successful response")
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(response_data)
        }
        
    except Exception as e:
        logger.error(f"Error in handle_patient_post_request: {str(e)}")
        logger.error("Full traceback:")
        logger.error(traceback.format_exc())
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': 'Internal server error',
                'error_details': {
                    'error': str(e),
                    'trace': traceback.format_exc()
                }
            })
        }

def handle_patient_get_request(event: Dict[str, Any], user_info: Dict[str, Any]) -> Dict[str, Any]:
    try:
        logger.info("Starting GET request handler")
        logger.info(f"Event: {json.dumps(event)}")
        logger.info(f"User info: {json.dumps(user_info)}")

        # Get patient_id from query parameters
        query_params = event.get('queryStringParameters', {})
        logger.info(f"Query parameters: {query_params}")
        
        if not query_params or 'patient_id' not in query_params:
            logger.error("Missing patient_id in query parameters")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'message': 'patient_id is required'
                })
            }

        patient_id = query_params['patient_id']
        logger.info(f"Retrieving patient with ID: {patient_id}")

        # Get the DynamoDB table
        try:
            dynamodb = boto3.resource('dynamodb')
            table = dynamodb.Table(os.environ['PATIENT_DYNAMODB_TABLE'])
            logger.info(f"Successfully connected to DynamoDB table: {os.environ['PATIENT_DYNAMODB_TABLE']}")
        except Exception as e:
            logger.error(f"Failed to connect to DynamoDB: {str(e)}")
            raise

        # Get the item from DynamoDB
        try:
            response = table.get_item(Key={'patient_id': patient_id})
            logger.info(f"DynamoDB response: {json.dumps(response)}")
        except Exception as e:
            logger.error(f"Failed to get item from DynamoDB: {str(e)}")
            raise

        if 'Item' not in response:
            logger.info(f"No patient found with ID: {patient_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'message': 'Patient not found'
                })
            }

        item = response['Item']
        logger.info("Successfully retrieved patient record")

        # If admin user and encoded_mrn exists, decode it
        if user_info.get('role') == 'admin' and 'encoded_mrn' in item:
            try:
                logger.info("Attempting to decode MRN for admin user")
                vault_client, vault_config = get_vault_client()
                decoded_mrn = decode_patient_mrn(vault_client, vault_config, item['encoded_mrn'])
                item['mrn'] = decoded_mrn
                logger.info("Successfully decoded MRN")
            except Exception as e:
                logger.error(f"Failed to decode MRN: {str(e)}")
                # Continue without decoded MRN

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(item)
        }

    except Exception as e:
        logger.error(f"Error in handle_patient_get_request: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': 'Internal server error',
                'error_details': {
                    'error': str(e),
                    'trace': traceback.format_exc()
                }
            })
        }

# Update lambda_handler to include GET method
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Main Lambda handler with detailed logging."""
    try:
        logger.info("Lambda handler started")
        logger.info(f"Event: {json.dumps(redact_sensitive(event))}")
        logger.info(f"Lambda context: {context}")
        
        http_method = event.get('httpMethod')
        resource_path = event.get('resource', '')
        logger.info(f"HTTP Method: {http_method}, Resource: {resource_path}")
        
        # Extract user info from claims
        claims = event.get('requestContext', {}).get('authorizer', {}).get('claims', {})
        user_info = {
            'username': claims.get('cognito:username'),
            'email': claims.get('email'),
            'role': claims.get('custom:role', 'user')
        }
        logger.info(f"User info from claims: {json.dumps(redact_sensitive(user_info))}")
        
        # Handle request based on path and method
        if resource_path == '/process-patient':
            if http_method == 'POST':
                logger.info("Processing POST request for patient")
                return handle_patient_post_request(event, user_info)
            elif http_method == 'GET':
                logger.info("Processing GET request for patient")
                return handle_patient_get_request(event, user_info)
            else:
                logger.warning(f"Method not allowed: {http_method}")
                return {
                    'statusCode': 405,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({
                        'message': f'Method not allowed: {http_method}',
                        'error_details': {
                            'method': http_method,
                            'allowed_methods': ['GET', 'POST']
                        }
                    })
                }
        
        logger.warning(f"Resource not found: {resource_path}")
        return {
            'statusCode': 404,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': f'Resource not found: {resource_path}',
                'error_details': {
                    'resource': resource_path,
                    'method': http_method
                }
            })
        }
            
    except Exception as e:
        logger.error(f"Unexpected error in lambda_handler: {str(e)}")
        logger.error("Full traceback:")
        logger.error(traceback.format_exc())
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': 'Internal server error',
                'error_details': {
                    'error': str(e),
                    'trace': traceback.format_exc()
                }
            })
        }
    try:
        logger.info(f"Received event: {json.dumps(event)}")
        
        http_method = event.get('httpMethod')
        resource_path = event.get('resource', '')
        
        claims = event.get('requestContext', {}).get('authorizer', {}).get('claims', {})
        user_info = {
            'username': claims.get('cognito:username'),
            'email': claims.get('email'),
            'role': claims.get('custom:role', 'user')
        }
        
        if resource_path == '/process-patient':
            if http_method == 'POST':
                return handle_patient_post_request(event, user_info)
            elif http_method == 'GET':
                return handle_patient_get_request(event, user_info)
            else:
                return {
                    'statusCode': 405,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({
                        'message': f'Method not allowed: {http_method}',
                        'error_details': {
                            'method': http_method,
                            'allowed_methods': ['GET', 'POST']
                        }
                    })
                }
        
        return {
            'statusCode': 404,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': f'Resource not found: {resource_path}',
                'error_details': {'resource': resource_path}
            })
        }
            
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': 'Internal server error',
                'error_details': {'error': str(e)}
            })
        }

    """Main Lambda handler with detailed logging."""
    try:
        logger.info("Lambda handler started")
        logger.info(f"Event: {json.dumps(redact_sensitive(event))}")
        logger.info(f"Lambda context: {context}")
        
        http_method = event.get('httpMethod')
        resource_path = event.get('resource', '')
        logger.info(f"HTTP Method: {http_method}, Resource: {resource_path}")
        
        # Extract user info from claims
        claims = event.get('requestContext', {}).get('authorizer', {}).get('claims', {})
        user_info = {
            'username': claims.get('cognito:username'),
            'email': claims.get('email'),
            'role': claims.get('custom:role', 'user')
        }
        logger.info(f"User info from claims: {json.dumps(redact_sensitive(user_info))}")
        
        # Handle request based on path and method
        if resource_path == '/process-patient':
            if http_method == 'POST':
                logger.info("Processing POST request for patient")
                return handle_patient_post_request(event, user_info)
            else:
                logger.warning(f"Method not allowed: {http_method}")
                return {
                    'statusCode': 405,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({
                        'message': f'Method not allowed: {http_method}',
                        'error_details': {
                            'method': http_method,
                            'allowed_methods': ['POST']
                        }
                    })
                }
        
        logger.warning(f"Resource not found: {resource_path}")
        return {
            'statusCode': 404,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': f'Resource not found: {resource_path}',
                'error_details': {
                    'resource': resource_path,
                    'method': http_method
                }
            })
        }
            
    except Exception as e:
        logger.error(f"Unexpected error in lambda_handler: {str(e)}")
        logger.error("Full traceback:")
        logger.error(traceback.format_exc())
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': 'Internal server error',
                'error_details': {
                    'error': str(e),
                    'trace': traceback.format_exc()
                }
            })
        }