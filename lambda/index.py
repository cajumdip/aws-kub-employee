import json
import boto3
import os
import time
import urllib3
import ssl  # <--- ADD THIS
import socket
from datetime import datetime, timedelta

# Try to import ldap3 for AD operations
try:
    # ADD 'Tls' to the import list below
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, Tls 
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False
    print("⚠️ ldap3 library not found. AD User creation will be skipped.")

# Initialize AWS clients
iam = boto3.client('iam')
ec2 = boto3.client('ec2')
secretsmanager = boto3.client('secretsmanager')
s3 = boto3.client('s3')
ssm = boto3.client('ssm')
dynamodb = boto3.resource('dynamodb')
http = urllib3.PoolManager()

# Configuration
SLACK_WEBHOOK = os.environ.get('SLACK_WEBHOOK_URL')
ENROLLMENT_BUCKET = os.environ.get('ENROLLMENT_BUCKET')
AWS_REGION = os.environ.get('INNOVATECH_REGION', 'eu-central-1')
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
        # 1. Create AD User (if ldap3 is available)
        ad_username = emp_email.split('@')[0]
        ad_password = None
        
        if LDAP_AVAILABLE and AD_SECRET_ARN:
            print(f"🔌 Connecting to Active Directory: {DIRECTORY_NAME}...")
            # --- FIX BELOW: Added DIRECTORY_NAME, AD_SECRET_ARN, and secretsmanager ---
            ad_password = create_ad_user(
                emp_name, 
                ad_username, 
                emp_email, 
                dept, 
                DIRECTORY_NAME, 
                AD_SECRET_ARN, 
                secretsmanager
            )
        else:
            print("⚠️ Skipping AD creation (Missing Layer or Secret)")

        # 2. Create IAM User (Backup/Console Access)
        # We keep this for now to ensure your existing login flows don't break immediately
        iam_username = emp_email.replace('@', '-').replace('.', '-')
        create_iam_user_safe(iam_username, emp_id, dept)

        # 3. Launch & Domain Join Workstation
        instance_id, private_ip = launch_workstation(emp_name, emp_id, dept)
        
        # 4. Join Domain (SSM)
        if instance_id and DOMAIN_JOIN_DOC:
            print(f"🔗 Joining {instance_id} to {DIRECTORY_NAME}...")
            # We wait a bit for SSM agent to come up (in real prod, use lifecycle hooks)
            # Creating association forces the join command
            try:
                ssm.create_association(
                    Name=DOMAIN_JOIN_DOC,
                    Targets=[{'Key': 'InstanceIds', 'Values': [instance_id]}],
                    Parameters={
                        'directoryId': [DIRECTORY_ID],
                        'directoryName': [DIRECTORY_NAME],
                        'dnsIpAddresses': get_directory_ips()
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
            
        # TODO: Add AD User Disable logic here when ldap3 is ready
        
        if SLACK_WEBHOOK:
            send_slack("👋 Employee Offboarded", f"Resources for {emp_name} have been cleaned up.")
            
    except Exception as e:
        print(f"❌ Error offboarding: {e}")

# --- Helpers ---

def create_ad_user(name, username, email, dept, directory_name, secret_arn, secretsmanager):
    """
    Try LDAPS first (port 636), fall back to LDAP+STARTTLS (port 389)
    """
    
    print(f"🔍 Python SSL Version: {ssl.OPENSSL_VERSION}")
    
    # Get Admin Creds
    secret = json.loads(secretsmanager.get_secret_value(SecretId=secret_arn)['SecretString'])
    admin_user = secret['username']
    admin_pass = secret['password']
    
    # Attempt 1: LDAPS on port 636
    print(f"\n📍 Attempt 1: LDAPS (Port 636) to {directory_name}...")
    try:
        ad_password = _create_ad_user_ldaps(
            name, username, email, dept,
            directory_name, admin_user, admin_pass
        )
        print(f"✅ LDAPS connection successful!")
        return ad_password
    except Exception as e:
        print(f"❌ LDAPS failed: {type(e).__name__}: {str(e)[:100]}")
        print(f"   Falling back to LDAP+STARTTLS...\n")
    
    # Attempt 2: LDAP + STARTTLS on port 389
    print(f"📍 Attempt 2: LDAP+STARTTLS (Port 389) to {directory_name}...")
    try:
        ad_password = _create_ad_user_starttls(
            name, username, email, dept,
            directory_name, admin_user, admin_pass
        )
        print(f"✅ LDAP+STARTTLS connection successful!")
        return ad_password
    except Exception as e:
        print(f"❌ LDAP+STARTTLS failed: {type(e).__name__}: {str(e)[:100]}")
    
    # Attempt 3: Plain LDAP on port 389 (no TLS)
    print(f"\n📍 Attempt 3: Plain LDAP (Port 389, no TLS) to {directory_name}...")
    try:
        ad_password = _create_ad_user_plain_ldap(
            name, username, email, dept,
            directory_name, admin_user, admin_pass
        )
        print(f"✅ Plain LDAP connection successful!")
        return ad_password
    except Exception as e:
        print(f"❌ Plain LDAP failed: {type(e).__name__}: {str(e)[:100]}")
    
    raise Exception("All LDAP connection methods failed")

def _create_ad_user_ldaps(name, username, email, dept, directory_name, admin_user, admin_pass):
    """Connect via LDAPS on port 636"""
    from ldap3 import Server, Connection, NTLM, Tls
    import ssl
    
    # Configure TLS for LDAPS
    tls_config = Tls(
        validate=ssl.CERT_NONE,
        version=ssl.PROTOCOL_TLS,
        ciphers='ALL:@SECLEVEL=0'
    )
    
    server = Server(directory_name, port=636, use_ssl=True, tls=tls_config)
    conn = Connection(
        server,
        user=f"{directory_name}\\{admin_user}",
        password=admin_pass,
        authentication=NTLM,
        auto_bind=True
    )
    
    return _add_ad_user_attributes(conn, username, name, email, dept, directory_name)

def _create_ad_user_starttls(name, username, email, dept, directory_name, admin_user, admin_pass):
    """Connect via LDAP+STARTTLS on port 389"""
    from ldap3 import Server, Connection, NTLM, Tls
    import ssl
    
    # Configure TLS for STARTTLS
    tls_config = Tls(
        validate=ssl.CERT_NONE,
        version=ssl.PROTOCOL_TLS,
        ciphers='ALL:@SECLEVEL=0'
    )
    
    server = Server(directory_name, port=389, use_ssl=False, tls=tls_config)
    conn = Connection(
        server,
        user=f"{directory_name}\\{admin_user}",
        password=admin_pass,
        authentication=NTLM,
        auto_bind=False  # Don't auto-bind yet
    )
    
    # Open connection and upgrade to TLS
    conn.open()
    conn.start_tls()
    conn.bind()
    
    return _add_ad_user_attributes(conn, username, name, email, dept, directory_name)


def _create_ad_user_plain_ldap(name, username, email, dept, directory_name, admin_user, admin_pass):
    """Connect via plain LDAP on port 389 (no TLS)"""
    from ldap3 import Server, Connection, NTLM
    
    server = Server(directory_name, port=389, use_ssl=False)
    conn = Connection(
        server,
        user=f"{directory_name}\\{admin_user}",
        password=admin_pass,
        authentication=NTLM,
        auto_bind=True
    )
    
    return _add_ad_user_attributes(conn, username, name, email, dept, directory_name)


def _add_ad_user_attributes(conn, username, name, email, dept, directory_name):
    """
    Shared user creation logic after successful connection
    """
    from datetime import datetime
    
    # Build distinguished name
    dc_parts = directory_name.split('.')
    dn = f"CN={username},CN=Users,DC={dc_parts[0]},DC={dc_parts[1]}"
    temp_password = f"Welcome{datetime.now().year}!"
    
    print(f"🔧 Creating AD user: CN={username}")
    
    # Add user object
    conn.add(dn, attributes={
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'cn': username,
        'sAMAccountName': username,
        'userPrincipalName': email,
        'givenName': name.split()[0],
        'sn': name.split()[-1] if ' ' in name else name,
        'displayName': name,
        'department': dept,
        'userAccountControl': 512  # Normal Account
    })
    
    if conn.result['result'] != 0:
        raise Exception(f"User creation failed: {conn.result}")
    
    print(f"✅ User object created")
    
    # Set password
    try:
        conn.extend.microsoft.modify_password(dn, temp_password)
        print(f"✅ Password set")
    except Exception as e:
        print(f"⚠️ Password set via Microsoft extension failed: {e}")
        print(f"   Trying alternative method...")
        # Alternative: use modify with unicodePwd
        import base64
        pwd_value = f'"{temp_password}"'.encode('utf-16-le')
        conn.modify(dn, {'unicodePwd': [(('MODIFY_REPLACE', [base64.b64encode(pwd_value).decode()]))]}  )
    
    # Enable account
    conn.modify(dn, {'userAccountControl': [('MODIFY_REPLACE', [512])]})
    print(f"✅ Account enabled")
    
    # Clean up
    try:
        conn.unbind()
    except:
        pass
    
    print(f"✅ AD User created successfully: {username}")
    return temp_password

def launch_workstation(name, emp_id, dept):
    user_data = f"""<powershell>
    # Set Hostname to match AD standards
    Rename-Computer -NewName "WS-{emp_id[:8]}" -Force
    </powershell>
    """
    
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
    return run_instances['Instances'][0]['InstanceId'], run_instances['Instances'][0].get('PrivateIpAddress')

def get_directory_ips():
    # Find the directory IPs dynamically
    dirs = boto3.client('ds').describe_directories(DirectoryIds=[DIRECTORY_ID])
    return dirs['DirectoryDescriptions'][0]['DnsIpAddrs']

def create_iam_user_safe(username, emp_id, dept):
    try:
        iam.create_user(UserName=username, Tags=[{'Key': 'EmployeeId', 'Value': emp_id}])
    except iam.exceptions.EntityAlreadyExistsException:
        pass

def diagnose_connectivity(directory_name, port=636):
    """Run before attempting LDAP connection"""
    print(f"🔍 Diagnosing connection to {directory_name}:{port}...")
    
    # Test 1: DNS Resolution
    try:
        resolved_ips = socket.gethostbyname_ex(directory_name)
        print(f"✅ DNS Resolution OK: {resolved_ips[2]}")
    except socket.gaierror as e:
        print(f"❌ DNS Resolution FAILED: {e}")
        print("   → Fix: Ensure Lambda is in VPC with proper DNS config")
        return False
    
    # Test 2: TCP Connection (without SSL)
    for ip in resolved_ips[2]:
        try:
            sock = socket.create_connection((ip, port), timeout=5)
            sock.close()
            print(f"✅ TCP Connection to {ip}:{port} OK")
        except Exception as e:
            print(f"❌ TCP Connection to {ip}:{port} FAILED: {e}")
            print("   → Fix: Check security groups and network ACLs")
            return False
    
    # Test 3: SSL Handshake
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((directory_name, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=directory_name) as ssock:
                print(f"✅ SSL Handshake OK: {ssock.version}")
    except Exception as e:
        print(f"❌ SSL Handshake FAILED: {e}")
        print("   → Fix: Check LDAPS certificate/port configuration")
        return False
    
    print("✅ All connectivity checks passed!")
    return True

def handle_onboarding_updated(record, iam, ec2, secretsmanager, ssm, dynamodb, workstations_table, 
                             slack_webhook, enrollment_bucket, aws_region, workstation_ami, 
                             workstation_instance_type, workstation_subnet_id, workstation_sg_id, 
                             workstation_profile_name, directory_id, directory_name, ad_secret_arn, 
                             domain_join_doc, ldap_available):
    
    new_image = record['dynamodb']['NewImage']
    emp_name = new_image['name']['S']
    emp_email = new_image['email']['S']
    emp_id = new_image['employee_id']['S']
    dept = new_image['department']['S']
    
    print(f"🆕 Onboarding: {emp_name} ({emp_email})")
    
    try:
        # 1. Create AD User with LDAPS → STARTTLS → Plain LDAP fallback
        ad_username = emp_email.split('@')[0]
        ad_password = None
        
        if ldap_available and ad_secret_arn:
            print(f"🔌 Attempting to connect to Active Directory: {directory_name}...")
            ad_password = create_ad_user(
                emp_name, ad_username, emp_email, dept,
                directory_name, ad_secret_arn, secretsmanager
            )
        else:
            print("⚠️ Skipping AD creation (Missing Layer or Secret)")
        
        # 2. Launch Workstation
        instance_id, private_ip = launch_workstation(emp_name, emp_id, dept, ec2, workstation_ami, 
                                                     workstation_instance_type, workstation_subnet_id, 
                                                     workstation_sg_id, workstation_profile_name, directory_name)
        
        # 3. Join Domain (SSM)
        if instance_id and domain_join_doc:
            print(f"🖥️ Joining {instance_id} to {directory_name}...")
            # Domain join logic...
        
        # 4. Save State & Notify
        workstations_table.put_item(Item={
            'employee_id': emp_id,
            'instance_id': instance_id,
            'ad_username': f"{directory_name}\\{ad_username}",
            'status': 'provisioning',
            'created_at': datetime.utcnow().isoformat()
        })
        
        if slack_webhook:
            msg = f"*Name:* {emp_name}\n*AD User:* `{ad_username}`\n*Workstation:* `{instance_id}`"
            if ad_password:
                msg += f"\n*Initial Password:* ||{ad_password}||"
            send_slack("🎉 Enterprise Onboarding Complete", msg, slack_webhook)
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        raise e

def send_slack(title, text):
    payload = {"text": title, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]}
    try:
        http.request('POST', SLACK_WEBHOOK, body=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
    except: pass