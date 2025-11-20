from flask import Flask, request, jsonify
from flask_cors import CORS
import boto3
import os
import uuid
from datetime import datetime
from decimal import Decimal

app = Flask(__name__)
CORS(app)

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb', region_name=os.environ.get('AWS_REGION', 'eu-central-1'))
ec2 = boto3.client('ec2', region_name=os.environ.get('AWS_REGION', 'eu-central-1'))

employees_table = dynamodb.Table(os.environ.get('DYNAMODB_TABLE_NAME', 'innovatech-employees'))
workstations_table = dynamodb.Table(os.environ.get('WORKSTATIONS_TABLE', 'innovatech-workstations'))

# Helper to convert Decimal to float for JSON serialization
def decimal_to_float(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'service': 'backend-api'}), 200

@app.route('/api/employees', methods=['GET'])
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
def delete_employee(employee_id):
    """
    Delete an employee (soft delete by setting status to 'inactive')
    This triggers Lambda to clean up all resources:
    - Terminate EC2 workstation
    - Delete IAM user
    - Remove access keys
    - Delete secrets
    - Clean up S3 objects
    """
    try:
        timestamp = datetime.utcnow().isoformat()
        
        # Set status to inactive (triggers Lambda via DynamoDB Stream)
        employees_table.update_item(
            Key={'employee_id': employee_id},
            UpdateExpression='SET #s = :status, updated_at = :updated_at',
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={
                ':status': 'inactive',
                ':updated_at': timestamp
            }
        )
        
        app.logger.info(f"Marked employee as inactive (triggering cleanup): {employee_id}")
        
        return jsonify({
            'success': True,
            'message': 'Employee deactivation initiated. Resources are being cleaned up automatically.'
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error deleting employee: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/workstations', methods=['GET'])
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)