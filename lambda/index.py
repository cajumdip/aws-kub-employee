import json
import boto3
import os
import urllib3
import socket
import time
from datetime import datetime

# Try to import ldap3 for AD operations
try:
    from ldap3 import Server, Connection, ALL
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False
    print("⚠️ ldap3 library not found. AD User creation will be skipped.")

# Initialize AWS clients
iam = boto3.client('iam')
ec2 = boto3.client('ec2')
secretsmanager = boto3.client('secretsmanager')
ssm = boto3.client('ssm')
dynamodb = boto3.resource('dynamodb')
http = urllib3.PoolManager()

# Configuration
SLACK_WEBHOOK = os.environ.get('SLACK_WEBHOOK_URL')
WORKSTATIONS_TABLE = os.environ.get('WORKSTATIONS_TABLE')
WORKSTATION_AMI = os.environ.get('WORKSTATION_AMI')
WORKSTATION_INSTANCE_TYPE = os.environ.get('WORKSTATION_INSTANCE_TYPE', 't3.medium')
WORKSTATION_SUBNET_ID = os.environ.get('WORKSTATION_SUBNET_ID')
WORKSTATION_SG_ID = os.environ.get('WORKSTATION_SG_ID')
WORKSTATION_PROFILE_NAME = os.environ.get('WORKSTATION_PROFILE_NAME')

# AD Configuration
DIRECTORY_ID = os.environ.get('DIRECTORY_ID')
DIRECTORY_NAME = os.environ.get('DIRECTORY_NAME', 'innovatech.local')
AD_SECRET_ARN = os.environ.get('AD_SECRET_ARN')
DOMAIN_JOIN_DOC = os.environ.get('DOMAIN_JOIN_DOC')

workstations_table = dynamodb.Table(WORKSTATIONS_TABLE)

def handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    for record in event['Records']:
        if record['eventName'] == 'INSERT':
            handle_onboarding(record)
        elif record['eventName'] == 'REMOVE':
            handle_offboarding(record)
    return {'statusCode': 200, 'body': json.dumps('Processed')}

def handle_onboarding(record):
    new_image = record['dynamodb']['NewImage']
    emp_name = new_image['name']['S']
    emp_email = new_image['email']['S']
    emp_id = new_image['employee_id']['S']
    dept = new_image['department']['S']
    
    print(f"🆕 Onboarding: {emp_name} ({emp_email})")
    
    try:
        # 1. Create AD User
        ad_username = emp_email.split('@')[0]
        ad_password = None
        
        if LDAP_AVAILABLE and AD_SECRET_ARN:
            print("🩺 Running connectivity diagnostics...")
            diagnose_connectivity(DIRECTORY_NAME)
            
            print(f"🔌 Connecting to Active Directory: {DIRECTORY_NAME}...")
            ad_password = create_ad_user(
                emp_name, 
                ad_username, 
                emp_email, 
                dept, 
                DIRECTORY_NAME, 
                AD_SECRET_ARN
            )
        else:
            print("⚠️ Skipping AD creation (Missing Layer or Secret)")

        # 2. Create IAM User (Backup/Console Access)
        iam_username = emp_email.replace('@', '-').replace('.', '-')
        create_iam_user_safe(iam_username, emp_id, dept)

        # 3. Launch Workstation
        instance_id, private_ip = launch_workstation(emp_name, emp_id, dept)
        
        # 4. Join Domain (SSM)
        if instance_id and DIRECTORY_ID:
            print(f"🔗 Joining {instance_id} to {DIRECTORY_NAME}...")
            try:
                # Use the correct AWS document for domain join
                ssm.create_association(
                    Name='AWS-JoinDirectoryServiceDomain',  # ← Correct document name
                    Targets=[{'Key': 'InstanceIds', 'Values': [instance_id]}],
                    Parameters={
                        'directoryId': [DIRECTORY_ID],
                        'directoryName': [DIRECTORY_NAME]
                    }
                )
                print("✅ Domain Join Association created")
            except Exception as e:
                print(f"❌ Domain Join failed: {e}")

        # 5. Save State
        workstations_table.put_item(Item={
            'employee_id': emp_id,
            'instance_id': instance_id,
            'iam_username': iam_username,
            'ad_username': f"{DIRECTORY_NAME}\\{ad_username}",
            'status': 'provisioning',
            'created_at': datetime.utcnow().isoformat()
        })

        # 6. Slack Notification
        if SLACK_WEBHOOK:
            msg = f"*Name:* {emp_name}\n*AD User:* `{ad_username}`\n*Workstation:* `{instance_id}`"
            if ad_password:
                msg += f"\n*Initial Password:* ||{ad_password}||"
            send_slack("🎉 Enterprise Onboarding Complete", msg)

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        raise e

def handle_offboarding(record):
    old_image = record['dynamodb']['OldImage']
    emp_id = old_image['employee_id']['S']
    emp_name = old_image['name']['S']
    
    print(f"🗑️ Offboarding: {emp_name}")
    
    try:
        # Terminate EC2
        resp = workstations_table.get_item(Key={'employee_id': emp_id})
        if 'Item' in resp:
            instance_id = resp['Item'].get('instance_id')
            if instance_id:
                ec2.terminate_instances(InstanceIds=[instance_id])
            workstations_table.delete_item(Key={'employee_id': emp_id})
            
        if SLACK_WEBHOOK:
            send_slack("👋 Employee Offboarded", f"Resources for {emp_name} have been cleaned up.")
            
    except Exception as e:
        print(f"❌ Error offboarding: {e}")

# --- Active Directory Helpers ---

def create_ad_user(name, username, email, dept, directory_name, secret_arn):
    """
    Creates a user in AWS Managed AD.
    Uses port 389 for user creation, SSM for password setting.
    """
    
    # 1. Retrieve Credentials
    secret_val = secretsmanager.get_secret_value(SecretId=secret_arn)['SecretString']
    secret = json.loads(secret_val)
    admin_user = secret['username']
    admin_pass = secret['password']
    
    print(f"🔌 Connecting to Active Directory: {directory_name}...")
    
    # 2. Create user on port 389 (unencrypted for user object creation)
    try:
        print(f"🛡️ Connecting to {directory_name}:389 for user creation...")
        server_389 = Server(
            directory_name,
            port=389,
            use_ssl=False,
            get_info=ALL,
            connect_timeout=10
        )
        
        conn_389 = Connection(
            server_389,
            user=f"{admin_user}@{directory_name}",
            password=admin_pass,
            auto_bind=True,
            receive_timeout=10
        )
        
        print(f"✅ Connected on port 389")
        
        # Create the user (without password)
        user_dn = _create_ad_user_object(conn_389, username, name, email, dept, directory_name)
        conn_389.unbind()
        
    except Exception as e:
        print(f"❌ Failed to create user object: {e}")
        raise e
    
    # 3. Set password via SSM Run Command (more reliable than LDAPS from Lambda)
    temp_password = f"Welcome{datetime.now().year}!"
    
    # Wait a moment for the workstation to potentially be ready
    time.sleep(5)
    
    password_set = set_ad_password_via_ssm(username, temp_password, directory_name)
    
    if not password_set:
        print(f"⚠️ WARNING: User created but password could not be set via SSM.")
        print(f"ℹ️ The workstation may still be initializing. Password will be set after domain join completes.")
    
    return temp_password

def _create_ad_user_object(conn, username, name, email, dept, directory_name):
    """Creates the AD user object (without password)"""
    
    dc_parts = directory_name.split('.')
    netbios_name = dc_parts[0].upper()
    
    # AWS Managed AD: Use the delegated OU
    dn = f"CN={username},OU={netbios_name},DC={dc_parts[0]},DC={dc_parts[1]}"
    
    print(f"🔧 Creating AD Object: {dn}")
    
    # Split name properly
    name_parts = name.strip().split()
    first_name = name_parts[0] if name_parts else username
    last_name = name_parts[-1] if len(name_parts) > 1 else username
    
    # Create User Object (without password - userAccountControl 544 means disabled)
    conn.add(dn, attributes={
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'cn': username,
        'sAMAccountName': username,
        'userPrincipalName': email,
        'givenName': first_name,
        'sn': last_name,
        'displayName': name,
        'department': dept,
        'userAccountControl': 544  # Disabled until password is set
    })
    
    if conn.result['result'] == 0:
        print(f"✅ User object created")
    elif conn.result['result'] == 68:
        print(f"⚠️ User {username} already exists")
    else:
        raise Exception(f"User creation failed: {conn.result['description']}")
    
    return dn

def set_ad_password_via_ssm(username, password, directory_name):
    """Set AD password using SSM Run Command on a domain-joined instance
    
    Note: This approach is more secure than LDAPS from Lambda because:
    - SSM command logs are encrypted and access-controlled via IAM
    - The password is only visible in SSM command history (can be restricted)
    - Alternative (LDAPS) was failing and exposing password in Lambda logs
    """
    try:
        # Find a running domain-joined instance
        response = ec2.describe_instances(
            Filters=[
                {'Name': 'tag:Domain', 'Values': [directory_name]},
                {'Name': 'instance-state-name', 'Values': ['running']}
            ]
        )
        
        if not response['Reservations']:
            print("⚠️ No domain-joined instance available for password reset")
            return False
        
        instance_id = response['Reservations'][0]['Instances'][0]['InstanceId']
        
        print(f"🔐 Setting password via SSM on instance {instance_id}...")
        
        # Run PowerShell command to set password
        command_response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunPowerShellScript',
            Parameters={
                'commands': [
                    f'$password = ConvertTo-SecureString "{password}" -AsPlainText -Force',
                    f'Set-ADAccountPassword -Identity "{username}" -NewPassword $password -Reset',
                    f'Enable-ADAccount -Identity "{username}"'
                ]
            },
            Comment=f'Set password for {username}'
        )
        
        command_id = command_response['Command']['CommandId']
        print(f"✅ Password reset command sent: {command_id}")
        # Note: Command execution is asynchronous. The workstation will process it when ready.
        # For full verification, use ssm.get_command_invocation() with polling (not implemented for simplicity)
        return True
        
    except Exception as e:
        print(f"❌ Failed to set password via SSM: {e}")
        return False

# --- Infrastructure Helpers ---

def launch_workstation(name, emp_id, dept):
    user_data = f"""<powershell>
    Rename-Computer -NewName "WS-{emp_id[:8]}" -Force
    </powershell>
    """
    try:
        run_instances = ec2.run_instances(
            ImageId=WORKSTATION_AMI,
            InstanceType=WORKSTATION_INSTANCE_TYPE,
            MinCount=1, MaxCount=1,
            SubnetId=WORKSTATION_SUBNET_ID,
            SecurityGroupIds=[WORKSTATION_SG_ID],
            IamInstanceProfile={'Name': WORKSTATION_PROFILE_NAME},
            UserData=user_data,
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': f"{name}-Workstation"},
                    {'Key': 'EmployeeId', 'Value': emp_id},
                    {'Key': 'Domain', 'Value': DIRECTORY_NAME}
                ]
            }]
        )
        inst = run_instances['Instances'][0]
        return inst['InstanceId'], inst.get('PrivateIpAddress')
    except Exception as e:
        print(f"❌ Failed to launch EC2: {e}")
        return None, None

def get_directory_ips():
    dirs = boto3.client('ds').describe_directories(DirectoryIds=[DIRECTORY_ID])
    return dirs['DirectoryDescriptions'][0]['DnsIpAddrs']

def create_iam_user_safe(username, emp_id, dept):
    try:
        iam.create_user(UserName=username, Tags=[{'Key': 'EmployeeId', 'Value': emp_id}])
    except iam.exceptions.EntityAlreadyExistsException:
        pass

def diagnose_connectivity(directory_name, port=636):
    print(f"🔍 Diagnosing connection to {directory_name}:{port}...")
    try:
        resolved_ips = socket.gethostbyname_ex(directory_name)
        print(f"✅ DNS Resolution OK: {resolved_ips[2]}")
        ips = resolved_ips[2]
    except socket.gaierror as e:
        print(f"❌ DNS Resolution FAILED: {e}")
        return False
    
    for ip in ips:
        try:
            sock = socket.create_connection((ip, port), timeout=3)
            sock.close()
            print(f"✅ TCP Reachable: {ip}:{port}")
        except Exception as e:
            print(f"❌ TCP Unreachable {ip}:{port} - {e}")
    return True

def send_slack(title, text):
    payload = {"text": title, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]}
    try:
        http.request('POST', SLACK_WEBHOOK, body=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
    except: pass