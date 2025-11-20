from flask import Flask, request, jsonify
from flask_cors import CORS
import uuid
from datetime import datetime

app = Flask(__name__)
CORS(app)

# In-memory storage for local testing
employees_db = {}
workstations_db = {}

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'service': 'backend-api-local'}), 200

@app.route('/api/employees', methods=['GET'])
def get_employees():
    """Get all employees"""
    try:
        employees = list(employees_db.values())
        
        # Add workstation info
        for emp in employees:
            employee_id = emp['employee_id']
            if employee_id in workstations_db:
                ws = workstations_db[employee_id]
                emp['workstation_id'] = ws.get('instance_id')
                emp['workstation_ip'] = ws.get('private_ip')
                emp['workstation_status'] = ws.get('status')
                emp['workstation_type'] = ws.get('instance_type')
        
        # Sort by created_at
        employees.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return jsonify({
            'success': True,
            'employees': employees,
            'count': len(employees)
        }), 200
        
    except Exception as e:
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
        
        # Create employee
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
        
        employees_db[employee_id] = employee
        
        # Create mock workstation
        workstation = {
            'employee_id': employee_id,
            'instance_id': f'i-{uuid.uuid4().hex[:17]}',
            'private_ip': f'10.0.{uuid.uuid4().int % 255}.{uuid.uuid4().int % 255}',
            'instance_type': 't3.medium',
            'status': 'running',
            'created_at': timestamp
        }
        workstations_db[employee_id] = workstation
        
        app.logger.info(f"Created employee: {employee['name']} ({employee_id})")
        
        return jsonify({
            'success': True,
            'message': 'Employee created successfully!',
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
    """Get a specific employee"""
    try:
        if employee_id not in employees_db:
            return jsonify({
                'success': False,
                'error': 'Employee not found'
            }), 404
        
        employee = employees_db[employee_id].copy()
        
        # Add workstation info
        if employee_id in workstations_db:
            ws = workstations_db[employee_id]
            employee['workstation'] = {
                'instance_id': ws.get('instance_id'),
                'private_ip': ws.get('private_ip'),
                'instance_type': ws.get('instance_type'),
                'status': ws.get('status'),
                'created_at': ws.get('created_at'),
                'ec2_state': 'running'
            }
        
        return jsonify({
            'success': True,
            'employee': employee
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/employees/<employee_id>', methods=['PUT'])
def update_employee(employee_id):
    """Update an employee"""
    try:
        if employee_id not in employees_db:
            return jsonify({
                'success': False,
                'error': 'Employee not found'
            }), 404
        
        data = request.json
        employee = employees_db[employee_id]
        
        # Update fields
        if 'name' in data:
            employee['name'] = data['name']
        if 'email' in data:
            employee['email'] = data['email']
        if 'department' in data:
            employee['department'] = data['department']
        if 'role' in data:
            employee['role'] = data['role']
        if 'status' in data:
            employee['status'] = data['status']
        
        employee['updated_at'] = datetime.utcnow().isoformat()
        
        return jsonify({
            'success': True,
            'message': 'Employee updated successfully',
            'employee': employee
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/employees/<employee_id>', methods=['DELETE'])
def delete_employee(employee_id):
    """Delete an employee"""
    try:
        if employee_id not in employees_db:
            return jsonify({
                'success': False,
                'error': 'Employee not found'
            }), 404
        
        # Mark as inactive
        employees_db[employee_id]['status'] = 'inactive'
        employees_db[employee_id]['updated_at'] = datetime.utcnow().isoformat()
        
        # Remove workstation
        if employee_id in workstations_db:
            del workstations_db[employee_id]
        
        return jsonify({
            'success': True,
            'message': 'Employee removed successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/workstations', methods=['GET'])
def get_workstations():
    """Get all workstations"""
    try:
        workstations = list(workstations_db.values())
        return jsonify({
            'success': True,
            'workstations': workstations,
            'count': len(workstations)
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    try:
        employees = list(employees_db.values())
        active_count = len([e for e in employees if e.get('status') == 'active'])
        inactive_count = len([e for e in employees if e.get('status') == 'inactive'])
        
        return jsonify({
            'success': True,
            'stats': {
                'total_employees': len(employees),
                'active_employees': active_count,
                'inactive_employees': inactive_count,
                'total_workstations': len(workstations_db),
                'running_workstations': len(workstations_db)
            }
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    # Add some sample data for testing
    sample_id = str(uuid.uuid4())
    employees_db[sample_id] = {
        'employee_id': sample_id,
        'name': 'John Doe',
        'email': 'john.doe@innovatech.com',
        'department': 'Engineering',
        'role': 'Senior Developer',
        'status': 'active',
        'created_at': datetime.utcnow().isoformat(),
        'updated_at': datetime.utcnow().isoformat()
    }
    workstations_db[sample_id] = {
        'employee_id': sample_id,
        'instance_id': 'i-0123456789abcdef0',
        'private_ip': '10.0.1.100',
        'instance_type': 't3.medium',
        'status': 'running',
        'created_at': datetime.utcnow().isoformat()
    }
    
    print("Starting local backend with sample data...")
    print(f"Sample employee: {employees_db[sample_id]['name']}")
    app.run(host='0.0.0.0', port=8080)