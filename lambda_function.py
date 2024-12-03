import json
import logging
import boto3
import os
import traceback
import hvac
from datetime import datetime
from typing import Dict, Any, Tuple

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_vault_client() -> hvac.Client:
    try:
        secrets_client = boto3.client('secretsmanager')
        vault_creds = secrets_client.get_secret_value(
            SecretId=os.environ['VAULT_CREDENTIALS_SECRET']
        )
        vault_config = json.loads(vault_creds['SecretString'])
        
        client = hvac.Client(
            url=vault_config['VAULT_ADDR'],
            token=vault_config['VAULT_TOKEN'],
            namespace=vault_config['VAULT_NAMESPACE']
        )
        
        return client
    except Exception as e:
        logger.error(f"Failed to initialize Vault client: {str(e)}")
        raise

def store_card_in_vault(vault_client: hvac.Client, card_data: Dict[str, str]) -> str:
    try:
        timestamp = datetime.now().isoformat()
        token = f"card-{card_data['cardNumber'][-4:]}-{timestamp}"
        
        vault_client.secrets.kv.v2.create_or_update_secret(
            path=f'card-tokens/{token}',
            secret=dict(
                card_number=card_data['cardNumber'],
                cvv=card_data['cvv'],
                exp_month=card_data['expMonth'],
                exp_year=card_data['expYear'],
                cardholder_name=card_data['cardholderName']
            )
        )
        
        return token
    except Exception as e:
        logger.error(f"Failed to store card in Vault: {str(e)}")
        raise

def get_card_from_vault(vault_client: hvac.Client, token: str) -> Dict[str, Any]:
    try:
        secret = vault_client.secrets.kv.v2.read_secret_version(
            path=f'card-tokens/{token}'
        )
        return secret['data']['data']
    except Exception as e:
        logger.error(f"Failed to retrieve card from Vault: {str(e)}")
        raise

def handle_post_request(event: Dict[str, Any], user_info: Dict[str, Any]) -> Dict[str, Any]:
    try:
        request_data = json.loads(event.get('body', '{}'))
        logger.info("Parsing request body")
        
        required_fields = ['cardNumber', 'expMonth', 'expYear', 'cvv', 'cardholderName']
        missing_fields = [field for field in required_fields if field not in request_data]
        if missing_fields:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'message': f'Missing required fields: {", ".join(missing_fields)}',
                    'error_details': {'missing_fields': missing_fields}
                })
            }
        
        vault_client = get_vault_client()
        
        card_data = {
            'cardNumber': request_data['cardNumber'].replace(' ', ''),
            'expMonth': request_data['expMonth'],
            'expYear': request_data['expYear'],
            'cvv': request_data['cvv'],
            'cardholderName': request_data['cardholderName']
        }
        
        token = store_card_in_vault(vault_client, card_data)
        
        dynamodb = boto3.resource('dynamodb')
        table_name = os.environ.get('DYNAMODB_TABLE')
        if not table_name:
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'message': 'Server configuration error',
                    'error_details': {
                        'error': 'DYNAMODB_TABLE environment variable is not set'
                    }
                })
            }
        
        table = dynamodb.Table(table_name)
        
        timestamp = datetime.now().isoformat()
        item = {
            'cardToken': token,
            'lastFour': card_data['cardNumber'][-4:],
            'cardholderName': card_data['cardholderName'],
            'expiryMonth': card_data['expMonth'],
            'expiryYear': card_data['expYear'],
            'timestamp': timestamp,
            'createdBy': user_info['username'],
            'userRole': user_info['role']
        }
        
        try:
            table.put_item(Item=item)
        except Exception as e:
            logger.error(f"Failed to store in DynamoDB: {str(e)}")
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'message': 'Failed to store data',
                    'error_details': {'error': str(e)}
                })
            }
        
        response_data = {
            'token': token,
            'lastFour': card_data['cardNumber'][-4:],
            'cardholderName': card_data['cardholderName'],
            'expiryMonth': card_data['expMonth'],
            'expiryYear': card_data['expYear']
        }
        
        if user_info.get('role') == 'admin':
            response_data['metadata'] = {
                'createdAt': timestamp,
                'createdBy': user_info['username'],
                'email': user_info['email']
            }
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(response_data)
        }
        
    except Exception as e:
        logger.error(f"Error in handle_post_request: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': 'Internal server error',
                'error_details': {'error': str(e)}
            })
        }

def handle_get_request(event: Dict[str, Any], user_info: Dict[str, Any]) -> Dict[str, Any]:
    try:
        token = event.get('queryStringParameters', {}).get('token')
        if not token:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'message': 'Token is required',
                    'error_details': {'missing_parameter': 'token'}
                })
            }

        vault_client = get_vault_client()
        
        try:
            card_data = get_card_from_vault(vault_client, token)
            
            dynamodb = boto3.resource('dynamodb')
            table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])
            response = table.get_item(Key={'cardToken': token})
            
            if 'Item' not in response:
                return {
                    'statusCode': 404,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({
                        'message': 'Token not found',
                        'error_details': {'token': token}
                    })
                }
            
            item = response['Item']
            
            result = {
                'lastFour': card_data['card_number'][-4:],
                'cardholderName': card_data['cardholder_name'],
                'expiryMonth': card_data['exp_month'],
                'expiryYear': card_data['exp_year']
            }
            
            if user_info.get('role') == 'admin':
                result['metadata'] = {
                    'createdAt': item['timestamp'],
                    'createdBy': item.get('createdBy'),
                    'userRole': item.get('userRole')
                }
                result['cardDetails'] = {
                    'cardNumber': f"****-****-****-{card_data['card_number'][-4:]}",
                    'cvv': '***' 
                }
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps(result)
            }
            
        except Exception as e:
            logger.error(f"Failed to retrieve card data: {str(e)}")
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'message': 'Failed to retrieve card data',
                    'error_details': {'error': str(e)}
                })
            }
            
    except Exception as e:
        logger.error(f"Error in handle_get_request: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': 'Internal server error',
                'error_details': {'error': str(e)}
            })
        }


def lambda_handler(event, context):
    try:
        logger.info(f"Received event: {json.dumps(event, default=str)}")
        logger.info("=== Running Lambda Version 1.0 ===")
        logger.info(f"DYNAMODB_TABLE env var: {os.environ.get('DYNAMODB_TABLE')}")
        
        http_method = event.get('httpMethod')
        logger.info(f"HTTP Method: {http_method}")
        
        claims = event.get('requestContext', {}).get('authorizer', {}).get('claims', {})
        logger.info(f"Auth Claims: {json.dumps(claims)}")
        
        user_info = {
            'username': claims.get('cognito:username'),
            'email': claims.get('email'),
            'role': claims.get('custom:role', 'user')
        }
        logger.info(f"User Info: {json.dumps(user_info)}")
        
        if http_method == 'GET':
            return handle_get_request(event, user_info)
        elif http_method == 'POST':
            return handle_post_request(event, user_info)
        else:
            error_response = {
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
            return error_response
            
    except Exception as e:
        logger.error(f"Unexpected error in lambda_handler: {str(e)}")
        error_response = {
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
        return error_response