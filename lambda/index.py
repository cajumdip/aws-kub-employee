import json
import boto3
import os
import urllib3
import socket
import time
from datetime import datetime

# Try to import ldap3 for AD operations
try:
    from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False
    MODIFY_REPLACE = 3  # Fallback value if ldap3 not available
    print("⚠️ ldap3 library not found. AD User creation will be skipped.")

# Active Directory userAccountControl values
USER_ACCOUNT_CONTROL_NORMAL = '512'  # Normal account, enabled

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

# Offboarding cleanup constants
AWS_CLEANUP_DELAY_SECONDS = 3
MAX_ENI_CLEANUP_RETRIES = 5
INITIAL_RETRY_DELAY_SECONDS = 2

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
        # 1. Launch Workstation FIRST
        print("🖥️ Launching workstation...")
        instance_id, private_ip = launch_workstation(emp_name, emp_id, dept)
        
        if not instance_id:
            raise Exception("Failed to launch workstation")
        
        # 2. Wait for instance to be running
        print(f"⏳ Waiting for instance {instance_id} to be running...")
        waiter = ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 20})
        print(f"✅ Instance {instance_id} is running")
        
        # NOTE: Domain join now happens via User Data script (PowerShell Add-Computer)
        # No SSM association needed!
        
        # 3. Create AD User (via LDAP)
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
        
        # 4. Create IAM User (Backup/Console Access)
        iam_username = emp_email.replace('@', '-').replace('.', '-')
        create_iam_user_safe(iam_username, emp_id, dept)

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
    emp_email = old_image.get('email', {}).get('S', '')
    
    print(f"🗑️ Offboarding: {emp_name} (Employee ID: {emp_id})")
    
    cleanup_actions = []
    errors = []
    
    try:
        # Get workstation details from DynamoDB
        resp = workstations_table.get_item(Key={'employee_id': emp_id})
        workstation_data = resp.get('Item', {})
        
        instance_id = workstation_data.get('instance_id')
        iam_username = workstation_data.get('iam_username')
        ad_username_full = workstation_data.get('ad_username', '')
        # Extract username from domain\username format (e.g., "innovatech.local\john.doe" -> "john.doe")
        ad_username = ad_username_full.split('\\')[-1] if '\\' in ad_username_full else ad_username_full
        
        # 1. Delete IAM User and Access Keys
        if iam_username:
            try:
                print(f"🔑 Deleting IAM user: {iam_username}")
                
                # Delete access keys first
                try:
                    access_keys = iam.list_access_keys(UserName=iam_username)
                    for key in access_keys.get('AccessKeyMetadata', []):
                        iam.delete_access_key(UserName=iam_username, AccessKeyId=key['AccessKeyId'])
                        print(f"   ✓ Deleted access key: {key['AccessKeyId']}")
                except Exception as e:
                    print(f"   ⚠️ Error deleting access keys: {e}")
                
                # Detach user policies
                try:
                    attached_policies = iam.list_attached_user_policies(UserName=iam_username)
                    for policy in attached_policies.get('AttachedPolicies', []):
                        iam.detach_user_policy(UserName=iam_username, PolicyArn=policy['PolicyArn'])
                        print(f"   ✓ Detached policy: {policy['PolicyName']}")
                except Exception as e:
                    print(f"   ⚠️ Error detaching policies: {e}")
                
                # Delete inline user policies
                try:
                    inline_policies = iam.list_user_policies(UserName=iam_username)
                    for policy_name in inline_policies.get('PolicyNames', []):
                        iam.delete_user_policy(UserName=iam_username, PolicyName=policy_name)
                        print(f"   ✓ Deleted inline policy: {policy_name}")
                except Exception as e:
                    print(f"   ⚠️ Error deleting inline policies: {e}")
                
                # Remove from groups
                try:
                    groups = iam.list_groups_for_user(UserName=iam_username)
                    for group in groups.get('Groups', []):
                        iam.remove_user_from_group(UserName=iam_username, GroupName=group['GroupName'])
                        print(f"   ✓ Removed from group: {group['GroupName']}")
                except Exception as e:
                    print(f"   ⚠️ Error removing from groups: {e}")
                
                # Finally, delete the user
                iam.delete_user(UserName=iam_username)
                print(f"   ✅ IAM user deleted: {iam_username}")
                cleanup_actions.append(f"Deleted IAM user: {iam_username}")
                
            except iam.exceptions.NoSuchEntityException:
                print(f"   ⚠️ IAM user not found: {iam_username}")
            except Exception as e:
                error_msg = f"Failed to delete IAM user {iam_username}: {str(e)}"
                print(f"   ❌ {error_msg}")
                errors.append(error_msg)
        
        # 2. Delete/Disable AD User
        if ad_username and LDAP_AVAILABLE and AD_SECRET_ARN:
            try:
                print(f"👤 Deleting AD user: {ad_username}")
                delete_ad_user(ad_username, DIRECTORY_NAME, AD_SECRET_ARN)
                print(f"   ✅ AD user deleted: {ad_username}")
                cleanup_actions.append(f"Deleted AD user: {ad_username}")
            except Exception as e:
                error_msg = f"Failed to delete AD user {ad_username}: {str(e)}"
                print(f"   ❌ {error_msg}")
                errors.append(error_msg)
        
        # 3. Terminate EC2 Instance and Wait for Termination
        if instance_id:
            try:
                print(f"🖥️ Terminating EC2 instance: {instance_id}")
                ec2.terminate_instances(InstanceIds=[instance_id])
                
                # Wait for instance to fully terminate
                print(f"⏳ Waiting for instance {instance_id} to terminate...")
                waiter = ec2.get_waiter('instance_terminated')
                waiter.wait(
                    InstanceIds=[instance_id],
                    WaiterConfig={'Delay': 15, 'MaxAttempts': 40}  # Wait up to 10 minutes
                )
                print(f"   ✅ Instance terminated: {instance_id}")
                cleanup_actions.append(f"Terminated EC2 instance: {instance_id}")
                
                # Check for and delete any lingering network interfaces
                try:
                    # Small delay to allow AWS to begin cleanup
                    time.sleep(AWS_CLEANUP_DELAY_SECONDS)
                    
                    # Get instance details to find network interfaces
                    try:
                        instance_details = ec2.describe_instances(InstanceIds=[instance_id])
                    except ec2.exceptions.ClientError as e:
                        if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                            print(f"   ✓ Instance {instance_id} already fully cleaned up by AWS")
                        else:
                            raise
                        # Skip ENI cleanup if instance is already gone
                        instance_details = {'Reservations': []}
                    
                    for reservation in instance_details.get('Reservations', []):
                        for instance in reservation['Instances']:
                            for eni in instance.get('NetworkInterfaces', []):
                                eni_id = eni.get('NetworkInterfaceId')
                                if eni_id and not eni.get('Attachment', {}).get('DeleteOnTermination', True):
                                    # Wait for ENI to be available for deletion with exponential backoff
                                    retry_delay = INITIAL_RETRY_DELAY_SECONDS
                                    for attempt in range(MAX_ENI_CLEANUP_RETRIES):
                                        try:
                                            # Check ENI status
                                            eni_desc = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
                                            eni_status = eni_desc['NetworkInterfaces'][0]['Status']
                                            
                                            if eni_status == 'available':
                                                ec2.delete_network_interface(NetworkInterfaceId=eni_id)
                                                print(f"   ✓ Deleted network interface: {eni_id}")
                                                cleanup_actions.append(f"Deleted network interface: {eni_id}")
                                                break
                                            else:
                                                print(f"   ⏳ ENI {eni_id} status: {eni_status}, waiting...")
                                                time.sleep(retry_delay)
                                                retry_delay *= 2  # Exponential backoff
                                        except ec2.exceptions.ClientError as e:
                                            if e.response['Error']['Code'] == 'InvalidNetworkInterfaceID.NotFound':
                                                print(f"   ✓ Network interface {eni_id} already deleted")
                                                break
                                            elif attempt < MAX_ENI_CLEANUP_RETRIES - 1:
                                                print(f"   ⏳ ENI cleanup retry {attempt + 1}/{MAX_ENI_CLEANUP_RETRIES}")
                                                time.sleep(retry_delay)
                                                retry_delay *= 2
                                            else:
                                                raise
                except Exception as e:
                    # Non-critical error - ENI might be auto-deleted by AWS
                    print(f"   Network interface cleanup: {e}")
                    
            except Exception as e:
                error_msg = f"Failed to terminate instance {instance_id}: {str(e)}"
                print(f"   {error_msg}")
                errors.append(error_msg)
        
        # 4. Remove from workstations table (only after successful termination)
        if workstation_data:
            try:
                workstations_table.delete_item(Key={'employee_id': emp_id})
                print(f"   Removed from workstations table")
                cleanup_actions.append("Removed workstation record from database")
            except Exception as e:
                error_msg = f"Failed to remove from workstations table: {str(e)}"
                print(f"{error_msg}")
                errors.append(error_msg)
        
        # 5. Send comprehensive Slack notification
        if SLACK_WEBHOOK:
            status_emoji = "✅" if not errors else "⚠️"
            status_text = "Complete" if not errors else "Complete with Errors"
            
            message = f"*Employee:* {emp_name}\n*Employee ID:* {emp_id}"
            if emp_email:
                message += f"\n*Email:* {emp_email}"
            
            message += f"\n\n*Cleanup Actions:*"
            for action in cleanup_actions:
                message += f"\n✓ {action}"
            
            if errors:
                message += f"\n\n*Errors:*"
                for error in errors:
                    message += f"\n{error}"
            
            send_slack(f"{status_emoji} Employee Offboarding {status_text}", message)
        
        print(f"✅ Offboarding complete for {emp_name}")
        print(f"   Actions: {len(cleanup_actions)}, Errors: {len(errors)}")
        
    except Exception as e:
        error_msg = f"Critical error during offboarding: {str(e)}"
        print(f"{error_msg}")
        if SLACK_WEBHOOK:
            send_slack("Offboarding Failed", f"*Employee:* {emp_name}\n*Error:* {error_msg}")
        raise e

# --- Active Directory Helpers ---

def create_ad_user(name, username, email, dept, directory_name, secret_arn):
    """
    Creates a user in AWS Managed AD.
    Uses port 389 for user creation and password setting.
    """
    
    # 1. Retrieve Credentials
    secret_val = secretsmanager.get_secret_value(SecretId=secret_arn)['SecretString']
    secret = json.loads(secret_val)
    admin_user = secret['username']
    admin_pass = secret['password']
    
    print(f"Connecting to Active Directory: {directory_name}...")
    
    # 2. Create user on port 389 (unencrypted for user object creation)
    try:
        print(f"Connecting to {directory_name}:389 for user creation...")
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
        
        print(f"Connected on port 389")
        
        # Create the user (without password)
        user_dn = _create_ad_user_object(conn_389, username, name, email, dept, directory_name)
        
    except Exception as e:
        print(f"Failed to create user object: {e}")
        raise e
    
    # 3. Password will be set by workstation User Data script after domain join
    temp_password = f"Welcome{datetime.now().year}!"
    
    print(f"AD user created (password will be set by workstation after domain join)")
    conn_389.unbind()

    return temp_password

def _create_ad_user_object(conn, username, name, email, dept, directory_name):
    """Creates the AD user object (without password)"""
    
    dc_parts = directory_name.split('.')
    netbios_name = dc_parts[0].upper()
    
    # AWS Managed AD: Use the delegated OU
    dn = f"CN={username},OU={netbios_name},DC={dc_parts[0]},DC={dc_parts[1]}"
    
    print(f"Creating AD Object: {dn}")
    
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
        print(f"User object created")
    elif conn.result['result'] == 68:
        print(f"User {username} already exists")
    else:
        raise Exception(f"User creation failed: {conn.result['description']}")
    
    return dn

def delete_ad_user(username, directory_name, secret_arn):
    """
    Deletes a user from AWS Managed AD.
    """
    
    # 1. Retrieve Credentials
    secret_val = secretsmanager.get_secret_value(SecretId=secret_arn)['SecretString']
    secret = json.loads(secret_val)
    admin_user = secret['username']
    admin_pass = secret['password']
    
    print(f"🔌 Connecting to Active Directory: {directory_name} for user deletion...")
    
    try:
        # Connect to AD
        server = Server(
            directory_name,
            port=389,
            use_ssl=False,
            get_info=ALL,
            connect_timeout=10
        )
        
        conn = Connection(
            server,
            user=f"{admin_user}@{directory_name}",
            password=admin_pass,
            auto_bind=True,
            receive_timeout=10
        )
        
        print(f"Connected to AD on port 389")
        
        # Build user DN
        dc_parts = directory_name.split('.')
        netbios_name = dc_parts[0].upper()
        user_dn = f"CN={username},OU={netbios_name},DC={dc_parts[0]},DC={dc_parts[1]}"
        
        print(f"Deleting AD user: {user_dn}")
        
        # Delete the user
        conn.delete(user_dn)
        
        if conn.result['result'] == 0:
            print(f"AD user deleted successfully")
        elif conn.result['result'] == 32:
            print(f"AD user not found: {username}")
        else:
            raise Exception(f"User deletion failed: {conn.result['description']}")
        
        conn.unbind()
        
    except Exception as e:
        print(f"Failed to delete AD user: {e}")
        raise e


# --- Infrastructure Helpers ---

def launch_workstation(name, emp_id, dept):
    # Get AD admin credentials
    secret_val = secretsmanager.get_secret_value(SecretId=AD_SECRET_ARN)['SecretString']
    secret = json.loads(secret_val)
    admin_user = secret['username']
    admin_pass = secret['password']
    
    # Generate unique computer name (max 15 chars for Windows)
    timestamp_suffix = str(int(time.time()))[-4:]  # Last 4 digits of timestamp
    computer_name = f"WS-{emp_id.replace('-', '')[:7]}{timestamp_suffix}"[:15]
    
    # *** FIX: Get actual domain controller IPs dynamically ***
    dc_ips = get_directory_ips()
    dc_ip_1 = dc_ips[0] if len(dc_ips) > 0 else "10.0.10.78"
    dc_ip_2 = dc_ips[1] if len(dc_ips) > 1 else "10.0.11.216"
    
    # Extract username from employee name for password setting
    username = name.lower().replace(' ', '.')
    temp_password = f"Welcome{datetime.now().year}!"
    
    # User Data with PowerShell domain join
    user_data = f"""<powershell>
# Configure DNS to use domain controllers
$adapter = Get-NetAdapter | Where-Object {{$_.Status -eq "Up"}} | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses ("{dc_ip_1}", "{dc_ip_2}")

# Rename computer
Rename-Computer -NewName "{computer_name}" -Force

# Wait for DNS and network
Start-Sleep -Seconds 30

# Install AD PowerShell module
Install-WindowsFeature RSAT-AD-PowerShell -ErrorAction SilentlyContinue

# Join domain
$adminUser = "{DIRECTORY_NAME}\\{admin_user}"
$adminPass = ConvertTo-SecureString "{admin_pass}" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($adminUser, $adminPass)

$maxRetries = 5
$retryCount = 0
$success = $false

while (-not $success -and $retryCount -lt $maxRetries) {{
    try {{
        Add-Computer -DomainName "{DIRECTORY_NAME}" -Credential $credential -OUPath "OU=Computers,OU=INNOVATECH,DC=innovatech,DC=local" -Force -ErrorAction Stop
        Write-Host "Domain join successful"
        $success = $true
    }} catch {{
        $retryCount++
        Write-Host "Domain join attempt $retryCount failed: $_"
        Start-Sleep -Seconds 30
    }}
}}

# If domain join succeeded, set user password and enable RDP
if ($success) {{
    Write-Host "Setting up user account and RDP..."
    
    # Enable RDP
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    
    # Grant RDP access to Domain Users
    try {{
        Add-LocalGroupMember -Group "Remote Desktop Users" -Member "Domain Users" -ErrorAction SilentlyContinue
        Write-Host "Granted RDP access to Domain Users"
    }} catch {{
        Write-Host "RDP permission already exists"
    }}
    
    # Set user password (after domain join, we can use AD cmdlets)
    $username = "{username}"
    $userPassword = ConvertTo-SecureString "{temp_password}" -AsPlainText -Force
    
    $passwordSet = $false
    $retryCount = 0
    while (-not $passwordSet -and $retryCount -lt 10) {{
        try {{
            Set-ADAccountPassword -Identity $username -NewPassword $userPassword -Reset -Server "{DIRECTORY_NAME}" -Credential $credential -ErrorAction Stop
            Enable-ADAccount -Identity $username -Server "{DIRECTORY_NAME}" -Credential $credential -ErrorAction Stop
            Write-Host "Password set and account enabled for $username"
            $passwordSet = $true
        }} catch {{
            $retryCount++
            Write-Host "Password set attempt $retryCount failed: $_ - Retrying..."
            Start-Sleep -Seconds 15
        }}
    }}
    
    Write-Host "Rebooting to complete setup..."
    Restart-Computer -Force
}}
</powershell>
<persist>true</persist>
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
                    {'Key': 'Domain', 'Value': DIRECTORY_NAME},
                    {'Key': 'ComputerName', 'Value': computer_name}
                ]
            }]
        )
        inst = run_instances['Instances'][0]
        return inst['InstanceId'], inst.get('PrivateIpAddress')
    except Exception as e:
        print(f"Failed to launch EC2: {e}")
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
    print(f"Diagnosing connection to {directory_name}:{port}...")
    try:
        resolved_ips = socket.gethostbyname_ex(directory_name)
        print(f"DNS Resolution OK: {resolved_ips[2]}")
        ips = resolved_ips[2]
    except socket.gaierror as e:
        print(f"DNS Resolution FAILED: {e}")
        return False
    
    for ip in ips:
        try:
            sock = socket.create_connection((ip, port), timeout=3)
            sock.close()
            print(f"TCP Reachable: {ip}:{port}")
        except Exception as e:
            print(f"TCP Unreachable {ip}:{port} - {e}")
    return True

def send_slack(title, text):
    payload = {"text": title, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]}
    try:
        http.request('POST', SLACK_WEBHOOK, body=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
    except: pass