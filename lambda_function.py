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
from urllib.parse import urlparse
import socket
import re

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def redact_sensitive(data: Dict[str, Any]) -> Dict[str, Any]:
    sensitive_keys = ['token', 'password', 'secret', 'key', 'Authorization']
    redacted = data.copy()
    for k, v in redacted.items():
        if any(sensitive in k.lower() for sensitive in sensitive_keys):
            redacted[k] = '[REDACTED]'
    return redacted

def test_network_connectivity(vault_url: str):
    try:
        logger.info(f"Testing connection to Vault server: {vault_url}")
        parsed_url = urlparse(vault_url)
        host = parsed_url.netloc.split(':')[0]
        port = int(parsed_url.port or 8200)
        
        logger.info(f"Testing DNS resolution for {host}")
        ip_address = socket.gethostbyname(host)
        logger.info(f"DNS resolution successful. IP: {ip_address}")
        
        logger.info(f"Testing TCP connection to {host}:{port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((ip_address, port))
        sock.close()
        
        if result == 0:
            logger.info("TCP connection successful")
        else:
            logger.error(f"TCP connection failed with error code: {result}")
            
        logger.info("Testing HTTPS connection")
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
        
        required_config = ['VAULT_ADDR', 'VAULT_TOKEN', 'VAULT_NAMESPACE', 'VAULT_PATIENT_ROLE']
        missing = [k for k in required_config if k not in vault_config]
        if missing:
            raise ValueError(f"Missing required vault config: {missing}")
        
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

def validate_mrn_format(mrn: str) -> str:
    """
    Validates and formats an MRN to match the Vault template pattern (####-####-####).
    Returns the formatted MRN if valid, raises ValueError if invalid.
    """
    clean_mrn = ''.join(c for c in mrn if c.isdigit())
    if len(clean_mrn) != 12:
        raise ValueError(f"MRN must contain exactly 12 digits. Got {len(clean_mrn)} digits.")
    
    if not clean_mrn.isdigit():
        raise ValueError("MRN must contain only numeric characters (0-9)")
    
    formatted_mrn = f"{clean_mrn[0:4]}-{clean_mrn[4:8]}-{clean_mrn[8:12]}"
    return formatted_mrn

def encode_patient_mrn(vault_client: hvac.Client, config: Dict[str, str], mrn: str) -> str:
    try:
        formatted_mrn = validate_mrn_format(mrn)
        logger.info(f"Starting MRN encoding process for MRN pattern: XXXX-****-****")
        
        base_url = vault_client.url.rstrip('/')
        url = f"{base_url}/v1/transform/encode/{config['VAULT_PATIENT_ROLE']}"
        logger.info(f"Using Vault endpoint: {url}")
        
        headers = {
            'X-Vault-Token': config['VAULT_TOKEN'],
            'X-Vault-Namespace': config['VAULT_NAMESPACE'],
            'Content-Type': 'application/json'
        }
        logger.info("Request headers (redacted): %s", redact_sensitive(headers))
        
        payload = {
            'value': formatted_mrn,
            'transformation': 'patient-mrn'
        }
        logger.info("Request payload: %s", json.dumps(payload))
        
        logger.info("Sending request to Vault...")
        response = requests.post(
            url=url,
            json=payload,
            headers=headers,
            verify=True,
            timeout=10
        )
        logger.info(f"Vault response status code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            logger.info("Successfully encoded MRN")
            return result['data']['encoded_value']
        
        logger.error(f"Failed to encode MRN. Status: {response.status_code}")
        logger.error(f"Response body: {response.text}")
        raise Exception(f"Failed to encode patient MRN: {response.text}")
        
    except ValueError as e:
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"HTTP Request failed: {str(e)}")
        logger.error(traceback.format_exc())
        raise
    except Exception as e:
        logger.error(f"Unexpected error in encode_patient_mrn: {str(e)}")
        logger.error(traceback.format_exc())
        raise

def decode_patient_mrn(vault_client: hvac.Client, config: Dict[str, str], encoded_mrn: str, format: str = 'default') -> str:
    try:
        logger.info(f"Starting MRN decoding process with format: {format}")
        
        transform_mount_point = 'transform'
        role_name = config['VAULT_PATIENT_ROLE']
        
        try:
            response = vault_client.secrets.transform.decode(
                role_name=role_name,
                value=encoded_mrn,
                transformation='patient-mrn',
                mount_point=transform_mount_point,
                decode_format=format
            )
            
            logger.info(f"Direct hvac response: {json.dumps(response)}")
            return response['data']['decoded_value']
            
        except Exception as e:
            logger.error(f"Direct hvac decode failed: {str(e)}")
            logger.error(traceback.format_exc())
            
            base_url = vault_client.url.rstrip('/')
            url = f"{base_url}/v1/transform/decode/{config['VAULT_PATIENT_ROLE']}"
            
            headers = {
                'X-Vault-Token': config['VAULT_TOKEN'],
                'X-Vault-Namespace': config['VAULT_NAMESPACE'],
                'Content-Type': 'application/json'
            }
            payload = {
                'value': encoded_mrn,
                'transformation': 'patient-mrn',
                'decode_format': format
            }

            logger.info("Request details:")
            logger.info(f"URL: {url}")
            logger.info(f"Headers (redacted): {redact_sensitive(headers)}")
            logger.info(f"Payload: {json.dumps(payload, indent=2)}")
            
            response = requests.post(url=url, json=payload, headers=headers, verify=True)
            
            if response.status_code == 200:
                result = response.json()
                return result['data']['decoded_value']
                
            logger.error(f"Failed to decode MRN. Status: {response.status_code}")
            logger.error(f"Response: {response.text}")
            raise Exception(f"Failed to decode MRN: {response.text}")
            
    except Exception as e:
        logger.error(f"Error in decode_patient_mrn: {str(e)}")
        logger.error(traceback.format_exc())
        raise

def handle_patient_post_request(event: Dict[str, Any], user_info: Dict[str, Any]) -> Dict[str, Any]:
    try:
        logger.info("Starting patient record creation")
        logger.info(f"Event: {json.dumps(redact_sensitive(event))}")
        logger.info(f"User info: {json.dumps(redact_sensitive(user_info))}")
        
        request_data = json.loads(event.get('body', '{}'))
        logger.info(f"Request data: {json.dumps(redact_sensitive(request_data))}")
        
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
            
        try:
            _ = validate_mrn_format(request_data['mrn'])
        except ValueError as e:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'message': 'Invalid MRN format',
                    'error_details': {
                        'expected': 'XXXX-XXXX-XXXX (12 digits)',
                        'received': request_data['mrn'],
                        'error': str(e)
                    }
                })
            }
        
        logger.info("Initializing Vault client...")
        vault_client, vault_config = get_vault_client()
        
        logger.info("Encoding patient MRN...")
        encoded_mrn = encode_patient_mrn(vault_client, vault_config, request_data['mrn'])
        logger.info("Successfully encoded MRN")
        
        logger.info("Storing patient record in DynamoDB...")
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(os.environ['PATIENT_DYNAMODB_TABLE'])
        
        item = {
            'patient_id': request_data['patient_id'],
            'name': request_data['name'],
            'email': request_data['email'],
            'encoded_mrn': encoded_mrn,
            'timestamp': datetime.now().isoformat(),
            'created_by': user_info['username'],
            'user_role': user_info.get('role', 'user')
        }
        
        table.put_item(Item=item)
        logger.info("Successfully stored patient record")
        
        response_data = {
            'patient_id': request_data['patient_id'],
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

        query_params = event.get('queryStringParameters', {})
        logger.info(f"Query parameters: {query_params}")
        
        if not query_params or ('patient_id' not in query_params and 'encoded_mrn' not in query_params):
            logger.error("Missing required query parameters")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'message': 'Either patient_id or encoded_mrn is required'
                })
            }

        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(os.environ['PATIENT_DYNAMODB_TABLE'])

        if 'patient_id' in query_params:
            response = table.get_item(Key={'patient_id': query_params['patient_id']})
        else:
            response = table.query(
                IndexName='encoded_mrn-index',
                KeyConditionExpression='encoded_mrn = :mrn',
                ExpressionAttributeValues={':mrn': query_params['encoded_mrn']}
            )
            if response.get('Items'):
                response = {'Item': response['Items'][0]}
            else:
                response = {}

        if 'Item' not in response:
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'message': 'Patient not found'})
            }

        item = response['Item']
        
        if user_info.get('role') == 'admin' and 'encoded_mrn' in item:
            try:
                logger.info("Attempting to decode MRN for admin user")
                vault_client, vault_config = get_vault_client()
                
                # Get both full MRN and last four digits for admin users
                decoded_mrn = decode_patient_mrn(vault_client, vault_config, item['encoded_mrn'])
                
                item['mrn'] = decoded_mrn
                logger.info("Successfully decoded MRN")
            except Exception as e:
                logger.error(f"Failed to decode MRN: {str(e)}")

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

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    try:
        logger.info("Lambda handler started")
        logger.info(f"Event: {json.dumps(redact_sensitive(event))}")
        logger.info(f"Lambda context: {context}")
        
        http_method = event.get('httpMethod')
        resource_path = event.get('resource', '')
        logger.info(f"HTTP Method: {http_method}, Resource: {resource_path}")
        
        claims = event.get('requestContext', {}).get('authorizer', {}).get('claims', {})
        user_info = {
            'username': claims.get('cognito:username'),
            'email': claims.get('email'),
            'role': claims.get('custom:role', 'user')
        }
        logger.info(f"User info from claims: {json.dumps(redact_sensitive(user_info))}")
        
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