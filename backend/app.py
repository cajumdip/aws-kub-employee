from flask import Flask, request, jsonify, g
from flask_cors import CORS
import boto3
import os
import uuid
from datetime import datetime
from decimal import Decimal
import jwt
from jwt.algorithms import RSAAlgorithm
import requests
from functools import wraps
import time
import random
import string
import secrets

app = Flask(__name__)
CORS(app)

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb', region_name=os.environ.get('AWS_REGION', 'eu-central-1'))
ec2 = boto3.client('ec2', region_name=os.environ.get('AWS_REGION', 'eu-central-1'))

employees_table = dynamodb.Table(os.environ.get('DYNAMODB_TABLE_NAME', 'innovatech-employees'))
workstations_table = dynamodb.Table(os.environ.get('WORKSTATIONS_TABLE', 'innovatech-workstations'))

# Cognito Configuration
COGNITO_REGION = os.environ.get('COGNITO_REGION', os.environ.get('AWS_REGION', 'eu-central-1'))
COGNITO_USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID', '')
COGNITO_APP_CLIENT_ID = os.environ.get('COGNITO_APP_CLIENT_ID', '')
COGNITO_KEYS_URL = f'https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json'

# Development mode flag - only allow bypassing auth when explicitly enabled
DEV_MODE = os.environ.get('DEV_MODE', '').lower() == 'true'

# Initialize Cognito client for user management
cognito_client = boto3.client('cognito-idp', region_name=COGNITO_REGION)

# Cache for Cognito public keys
_cognito_keys_cache = {
    'keys': None,
    'last_fetch': 0
}
KEYS_CACHE_TTL = 3600  # 1 hour

# Helper to convert Decimal to float for JSON serialization
def decimal_to_float(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError

def get_cognito_public_keys():
    """Fetch and cache Cognito public keys for JWT validation"""
    global _cognito_keys_cache
    
    current_time = time.time()
    
    # Return cached keys if still valid
    if _cognito_keys_cache['keys'] and (current_time - _cognito_keys_cache['last_fetch']) < KEYS_CACHE_TTL:
        return _cognito_keys_cache['keys']
    
    # Skip if Cognito is not configured
    if not COGNITO_USER_POOL_ID:
        app.logger.warning("Cognito User Pool ID not configured")
        return None
    
    try:
        response = requests.get(COGNITO_KEYS_URL, timeout=10)
        response.raise_for_status()
        keys = response.json().get('keys', [])
        
        _cognito_keys_cache['keys'] = keys
        _cognito_keys_cache['last_fetch'] = current_time
        
        return keys
    except requests.RequestException as e:
        app.logger.error(f"Error fetching Cognito public keys: {str(e)}")
        return _cognito_keys_cache['keys']  # Return cached keys if fetch fails

def verify_token(token):
    """Verify JWT token from Cognito"""
    if not COGNITO_USER_POOL_ID:
        app.logger.warning("Cognito not configured, skipping token verification")
        return None
    
    try:
        # Get the key ID from token header
        headers = jwt.get_unverified_header(token)
        kid = headers.get('kid')
        
        # Get Cognito public keys
        keys = get_cognito_public_keys()
        if not keys:
            return None
        
        # Find the matching key
        key = None
        for k in keys:
            if k.get('kid') == kid:
                key = k
                break
        
        if not key:
            app.logger.error("Token key ID not found in Cognito keys")
            return None
        
        # Construct the public key
        public_key = RSAAlgorithm.from_jwk(key)
        
        # Verify and decode the token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],
            audience=COGNITO_APP_CLIENT_ID,
            issuer=f'https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}'
        )
        
        return payload
        
    except jwt.ExpiredSignatureError:
        app.logger.warning("Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        app.logger.warning(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        app.logger.error(f"Error verifying token: {str(e)}")
        return None

def require_auth(allowed_groups=None):
    """Decorator to require authentication and optionally check group membership"""
    if allowed_groups is None:
        allowed_groups = ['HR-Admins']
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip auth if Cognito is not configured AND DEV_MODE is explicitly enabled
            if not COGNITO_USER_POOL_ID:
                if DEV_MODE:
                    app.logger.warning("DEV_MODE enabled: Cognito not configured, skipping authentication")
                    g.user = {'email': 'dev@localhost', 'groups': ['HR-Admins']}
                    return f(*args, **kwargs)
                else:
                    app.logger.error("Cognito not configured and DEV_MODE is not enabled")
                    return jsonify({
                        'success': False,
                        'error': 'Authentication service not configured'
                    }), 503
            
            # Get token from Authorization header
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return jsonify({
                    'success': False,
                    'error': 'Missing or invalid Authorization header'
                }), 401
            
            token = auth_header.replace('Bearer ', '')
            
            # Verify token
            payload = verify_token(token)
            if not payload:
                return jsonify({
                    'success': False,
                    'error': 'Invalid or expired token'
                }), 401
            
            # Check group membership
            user_groups = payload.get('cognito:groups', [])
            if allowed_groups and not any(group in user_groups for group in allowed_groups):
                return jsonify({
                    'success': False,
                    'error': 'Insufficient permissions. Access denied.'
                }), 403
            
            # Attach user info to request context
            g.user = {
                'email': payload.get('email', ''),
                'username': payload.get('cognito:username', payload.get('sub', '')),
                'groups': user_groups,
                'sub': payload.get('sub', '')
            }
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'service': 'backend-api'}), 200

@app.route('/api/employees', methods=['GET'])
@require_auth()
def get_employees():
    """Get all employees with workstation info"""
    try:
        # Get all employees
        employees_response = employees_table.scan()
        employees = employees_response.get('Items', [])
        
        # Get all workstations
        workstations_response = workstations_table.scan()
        workstations = workstations_response.get('Items', [])
        
        # Create workstation lookup by employee_id
        workstation_map = {w['employee_id']: w for w in workstations}
        
        # Merge employee and workstation data
        for emp in employees:
            employee_id = emp['employee_id']
            if employee_id in workstation_map:
                ws = workstation_map[employee_id]
                emp['workstation_id'] = ws.get('instance_id')
                emp['workstation_ip'] = ws.get('private_ip')
                emp['workstation_status'] = ws.get('status')
                emp['workstation_type'] = ws.get('instance_type')
        
        # Sort by created_at descending
        employees.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return jsonify({
            'success': True,
            'employees': employees,
            'count': len(employees)
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error getting employees: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/employees', methods=['POST'])
@require_auth()
def create_employee():
    """Create a new employee"""
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['name', 'email', 'department', 'role']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400
        
        # Validate email format
        if '@' not in data['email']:
            return jsonify({
                'success': False,
                'error': 'Invalid email format'
            }), 400
        
        # Create employee record
        employee_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()
        
        employee = {
            'employee_id': employee_id,
            'name': data['name'],
            'email': data['email'],
            'department': data['department'],
            'role': data['role'],
            'status': 'active',
            'created_at': timestamp,
            'updated_at': timestamp
        }
        
        # Save to DynamoDB (this triggers Lambda via DynamoDB Stream)
        employees_table.put_item(Item=employee)
        
        app.logger.info(f"Created employee: {employee['name']} ({employee_id})")
        
        return jsonify({
            'success': True,
            'message': 'Employee created successfully. Workstation is being provisioned...',
            'employee': employee
        }), 201
        
    except Exception as e:
        app.logger.error(f"Error creating employee: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/employees/<employee_id>', methods=['GET'])
@require_auth()
def get_employee(employee_id):
    """Get a specific employee with workstation details"""
    try:
        # Get employee
        emp_response = employees_table.get_item(Key={'employee_id': employee_id})
        
        if 'Item' not in emp_response:
            return jsonify({
                'success': False,
                'error': 'Employee not found'
            }), 404
        
        employee = emp_response['Item']
        
        # Get workstation if exists
        try:
            ws_response = workstations_table.get_item(Key={'employee_id': employee_id})
            if 'Item' in ws_response:
                ws = ws_response['Item']
                employee['workstation'] = {
                    'instance_id': ws.get('instance_id'),
                    'private_ip': ws.get('private_ip'),
                    'instance_type': ws.get('instance_type'),
                    'status': ws.get('status'),
                    'created_at': ws.get('created_at')
                }
                
                # Get real-time EC2 status
                try:
                    ec2_response = ec2.describe_instances(
                        InstanceIds=[ws.get('instance_id')]
                    )
                    if ec2_response['Reservations']:
                        instance = ec2_response['Reservations'][0]['Instances'][0]
                        employee['workstation']['ec2_state'] = instance['State']['Name']
                        employee['workstation']['launch_time'] = instance['LaunchTime'].isoformat()
                except Exception as ec2_error:
                    app.logger.warning(f"Could not get EC2 status: {str(ec2_error)}")
                    
        except Exception as ws_error:
            app.logger.warning(f"No workstation found for employee: {str(ws_error)}")
        
        return jsonify({
            'success': True,
            'employee': employee
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error getting employee: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/employees/<employee_id>', methods=['PUT'])
@require_auth()
def update_employee(employee_id):
    """Update an employee"""
    try:
        data = request.json
        timestamp = datetime.utcnow().isoformat()
        
        # Build update expression
        update_expr = "SET updated_at = :updated_at"
        expr_values = {':updated_at': timestamp}
        expr_names = {}
        
        if 'name' in data:
            update_expr += ", #n = :name"
            expr_values[':name'] = data['name']
            expr_names['#n'] = 'name'
        
        if 'email' in data:
            update_expr += ", email = :email"
            expr_values[':email'] = data['email']
        
        if 'department' in data:
            update_expr += ", department = :department"
            expr_values[':department'] = data['department']
        
        if 'role' in data:
            update_expr += ", #r = :role"
            expr_values[':role'] = data['role']
            expr_names['#r'] = 'role'
        
        if 'status' in data:
            update_expr += ", #s = :status"
            expr_values[':status'] = data['status']
            expr_names['#s'] = 'status'
        
        # Update item
        update_args = {
            'Key': {'employee_id': employee_id},
            'UpdateExpression': update_expr,
            'ExpressionAttributeValues': expr_values,
            'ReturnValues': 'ALL_NEW'
        }
        
        if expr_names:
            update_args['ExpressionAttributeNames'] = expr_names
        
        response = employees_table.update_item(**update_args)
        
        app.logger.info(f"Updated employee: {employee_id}")
        
        return jsonify({
            'success': True,
            'message': 'Employee updated successfully',
            'employee': response['Attributes']
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error updating employee: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    
@app.route('/', methods=['GET'])
def root_health():
    return jsonify({'status': 'healthy', 'service': 'backend-api'}), 200

@app.route('/api/employees/<employee_id>', methods=['DELETE'])
@require_auth()
def delete_employee(employee_id):
    """
    Delete an employee (Hard Delete to trigger 'REMOVE' stream event)
    """
    try:
        # DELETE the item (triggers 'REMOVE' event for Lambda)
        employees_table.delete_item(
            Key={'employee_id': employee_id}
        )
        
        app.logger.info(f"Deleted employee: {employee_id}")
        
        return jsonify({
            'success': True,
            'message': 'Employee deleted successfully. Cleanup initiated.'
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error deleting employee: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/workstations', methods=['GET'])
@require_auth()
def get_workstations():
    """Get all workstations with real-time EC2 status"""
    try:
        # Get all workstations from DynamoDB
        response = workstations_table.scan()
        workstations = response.get('Items', [])
        
        # Get real-time EC2 statuses
        instance_ids = [ws['instance_id'] for ws in workstations if 'instance_id' in ws]
        
        if instance_ids:
            try:
                ec2_response = ec2.describe_instances(InstanceIds=instance_ids)
                ec2_status_map = {}
                
                for reservation in ec2_response['Reservations']:
                    for instance in reservation['Instances']:
                        ec2_status_map[instance['InstanceId']] = {
                            'state': instance['State']['Name'],
                            'launch_time': instance['LaunchTime'].isoformat(),
                            'instance_type': instance['InstanceType'],
                            'private_ip': instance.get('PrivateIpAddress', 'N/A')
                        }
                
                # Merge EC2 status with workstation data
                for ws in workstations:
                    instance_id = ws.get('instance_id')
                    if instance_id in ec2_status_map:
                        ws['ec2_status'] = ec2_status_map[instance_id]
                        
            except Exception as ec2_error:
                app.logger.warning(f"Error getting EC2 statuses: {str(ec2_error)}")
        
        return jsonify({
            'success': True,
            'workstations': workstations,
            'count': len(workstations)
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error getting workstations: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stats', methods=['GET'])
@require_auth()
def get_stats():
    """Get dashboard statistics"""
    try:
        # Get employee count
        employees_response = employees_table.scan(
            ProjectionExpression='employee_id, #s',
            ExpressionAttributeNames={'#s': 'status'}
        )
        employees = employees_response.get('Items', [])
        
        active_count = len([e for e in employees if e.get('status') == 'active'])
        inactive_count = len([e for e in employees if e.get('status') == 'inactive'])
        
        # Get workstation count
        workstations_response = workstations_table.scan(
            ProjectionExpression='instance_id, #s',
            ExpressionAttributeNames={'#s': 'status'}
        )
        workstations = workstations_response.get('Items', [])
        
        running_workstations = len([w for w in workstations if w.get('status') in ['running', 'pending']])
        
        return jsonify({
            'success': True,
            'stats': {
                'total_employees': len(employees),
                'active_employees': active_count,
                'inactive_employees': inactive_count,
                'total_workstations': len(workstations),
                'running_workstations': running_workstations
            }
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error getting stats: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ===== HR User Management Endpoints =====

def generate_temp_password():
    """Generate secure temporary password for new HR users"""
    # Password requirements: 8+ chars, upper, lower, number, special
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    
    # Ensure it meets all requirements
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*"),
    ]
    
    # Fill remaining characters (12 more for 16 total)
    password += [secrets.choice(chars) for _ in range(12)]
    
    # Shuffle using secrets for cryptographic security
    shuffled = list(password)
    for i in range(len(shuffled) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
    
    return ''.join(shuffled)


def send_hr_user_slack_notification(email, name, temp_password, created_by):
    """Send Slack notification with HR portal credentials"""
    
    slack_webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
    
    if not slack_webhook_url:
        app.logger.warning("SLACK_WEBHOOK_URL not set, skipping Slack notification")
        return
    
    # Get portal URL from environment or use placeholder
    portal_url = os.environ.get('PORTAL_URL', 'http://your-alb-url')
    
    message = {
        "text": f"🔐 New HR Portal Account Created for {name}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔐 New HR Portal Account Created"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Name:*\n{name}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Email:*\n{email}"
                    }
                ]
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Temporary Password:*\n`{temp_password}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Group:*\nHR-Admins"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Portal URL:*\n{portal_url}"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "⚠️ User must change password on first login"
                    }
                ]
            },
            {
                "type": "divider"
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Created by: {created_by} | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
                    }
                ]
            }
        ]
    }
    
    try:
        response = requests.post(slack_webhook_url, json=message, timeout=10)
        if response.status_code == 200:
            app.logger.info(f"Slack notification sent for HR user: {email}")
        else:
            app.logger.warning(f"Failed to send Slack notification: {response.status_code}")
    except requests.RequestException as e:
        app.logger.error(f"Error sending Slack notification: {e}")


@app.route('/api/hr-users', methods=['POST'])
@require_auth()
def create_hr_user():
    """Create new HR user in Cognito and add to HR-Admins group"""
    if not COGNITO_USER_POOL_ID:
        return jsonify({
            'success': False,
            'error': 'Cognito is not configured'
        }), 500
    
    try:
        data = request.json
        email = data.get('email', '').strip()
        name = data.get('name', email.split('@')[0] if email else '')
        
        if not email or '@' not in email:
            return jsonify({
                'success': False,
                'error': 'Valid email address is required'
            }), 400
        
        # Generate temporary password
        temp_password = generate_temp_password()
        
        # Create user in Cognito - suppress email, we'll send via Slack
        response = cognito_client.admin_create_user(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=email,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
                {'Name': 'email_verified', 'Value': 'true'}
            ],
            TemporaryPassword=temp_password,
            MessageAction='SUPPRESS',  # Don't send Cognito email
            DesiredDeliveryMediums=[],  # No email/SMS delivery
            ForceAliasCreation=False
        )
        
        # Add user to HR-Admins group
        cognito_client.admin_add_user_to_group(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=email,
            GroupName='HR-Admins'
        )
        
        # Send Slack notification with credentials
        send_hr_user_slack_notification(
            email=email,
            name=name,
            temp_password=temp_password,
            created_by=g.user.get('email', 'Unknown')
        )
        
        app.logger.info(f"Created HR user: {email} by {g.user.get('email', 'unknown')}")
        
        return jsonify({
            'success': True,
            'message': f'HR user {email} created. Credentials sent to Slack.',
            'user': {
                'email': email,
                'status': response.get('User', {}).get('UserStatus', 'FORCE_CHANGE_PASSWORD')
            }
        }), 201
        
    except cognito_client.exceptions.UsernameExistsException:
        return jsonify({
            'success': False,
            'error': 'A user with this email already exists'
        }), 409
    except Exception as e:
        app.logger.error(f"Error creating HR user: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/hr-users', methods=['GET'])
@require_auth()
def list_hr_users():
    """List all HR users in the HR-Admins group"""
    if not COGNITO_USER_POOL_ID:
        return jsonify({
            'success': False,
            'error': 'Cognito is not configured'
        }), 500
    
    try:
        # List users in HR-Admins group
        response = cognito_client.list_users_in_group(
            UserPoolId=COGNITO_USER_POOL_ID,
            GroupName='HR-Admins',
            Limit=60
        )
        
        users = []
        for user in response.get('Users', []):
            user_data = {
                'username': user.get('Username', ''),
                'status': user.get('UserStatus', ''),
                'enabled': user.get('Enabled', False),
                'created_at': user.get('UserCreateDate', '').isoformat() if user.get('UserCreateDate') else '',
                'last_modified': user.get('UserLastModifiedDate', '').isoformat() if user.get('UserLastModifiedDate') else ''
            }
            
            # Extract email from attributes
            for attr in user.get('Attributes', []):
                if attr.get('Name') == 'email':
                    user_data['email'] = attr.get('Value', '')
            
            users.append(user_data)
        
        return jsonify({
            'success': True,
            'users': users,
            'count': len(users)
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error listing HR users: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/hr-users/<username>', methods=['DELETE'])
@require_auth()
def delete_hr_user(username):
    """Delete an HR user from Cognito"""
    if not COGNITO_USER_POOL_ID:
        return jsonify({
            'success': False,
            'error': 'Cognito is not configured'
        }), 500
    
    try:
        # Prevent self-deletion
        if g.user.get('email') == username or g.user.get('username') == username:
            return jsonify({
                'success': False,
                'error': 'You cannot delete your own account'
            }), 400
        
        # Delete user from Cognito
        cognito_client.admin_delete_user(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=username
        )
        
        app.logger.info(f"Deleted HR user: {username} by {g.user.get('email', 'unknown')}")
        
        return jsonify({
            'success': True,
            'message': f'HR user {username} deleted successfully'
        }), 200
        
    except cognito_client.exceptions.UserNotFoundException:
        return jsonify({
            'success': False,
            'error': 'User not found'
        }), 404
    except Exception as e:
        app.logger.error(f"Error deleting HR user: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)