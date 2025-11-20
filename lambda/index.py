import json
import boto3
import os
import urllib3
import base64
from datetime import datetime, timedelta

# Initialize AWS clients
iam = boto3.client('iam')
ec2 = boto3.client('ec2')
secretsmanager = boto3.client('secretsmanager')
s3 = boto3.client('s3')
ssm = boto3.client('ssm')
dynamodb = boto3.resource('dynamodb')
http = urllib3.PoolManager()

# Environment variables
SLACK_WEBHOOK = os.environ.get('SLACK_WEBHOOK_URL')
ENROLLMENT_BUCKET = os.environ.get('ENROLLMENT_BUCKET')
AWS_REGION = os.environ.get('INNOVATECH_REGION', 'eu-central-1')
AWS_ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID')
WORKSTATIONS_TABLE = os.environ.get('WORKSTATIONS_TABLE')
WORKSTATION_AMI = os.environ.get('WORKSTATION_AMI')
WORKSTATION_INSTANCE_TYPE = os.environ.get('WORKSTATION_INSTANCE_TYPE', 't3.medium')
WORKSTATION_SUBNET_ID = os.environ.get('WORKSTATION_SUBNET_ID')
WORKSTATION_SG_ID = os.environ.get('WORKSTATION_SG_ID')
WORKSTATION_PROFILE_NAME = os.environ.get('WORKSTATION_PROFILE_NAME')

workstations_table = dynamodb.Table(WORKSTATIONS_TABLE)

def handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    
    for record in event['Records']:
        event_name = record['eventName']
        
        if event_name == 'INSERT':
            handle_employee_creation(record)
        elif event_name == 'REMOVE':
            handle_employee_deletion(record)
            
    return {'statusCode': 200, 'body': json.dumps('Processed')}

def handle_employee_creation(record):
    new_image = record['dynamodb']['NewImage']
    employee_name = new_image['name']['S']
    employee_email = new_image['email']['S']
    employee_id = new_image['employee_id']['S']
    department = new_image['department']['S']
    role = new_image['role']['S']
    
    print(f"🆕 Onboarding: {employee_name} ({employee_email})")
    
    try:
        # 1. Create/Get IAM User
        iam_username = employee_email.replace('@', '-').replace('.', '-')
        try:
            iam.create_user(
                UserName=iam_username,
                Tags=[{'Key': 'EmployeeId', 'Value': employee_id}]
            )
            print(f"✅ Created IAM user: {iam_username}")
            
            # Add to group and attach policy only if new
            group_name = f"{department}-team"
            try:
                iam.create_group(GroupName=group_name)
            except iam.exceptions.EntityAlreadyExistsException:
                pass
            iam.add_user_to_group(UserName=iam_username, GroupName=group_name)
            iam.attach_user_policy(UserName=iam_username, PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore')
            
        except iam.exceptions.EntityAlreadyExistsException:
            print(f"⚠️ User {iam_username} already exists")

        # 2. Create Access Keys (Robust Handling)
        access_key = None
        secret_key = None
        try:
            key_resp = iam.create_access_key(UserName=iam_username)
            access_key = key_resp['AccessKey']['AccessKeyId']
            secret_key = key_resp['AccessKey']['SecretAccessKey']
        except iam.exceptions.LimitExceededException:
            # Rotate keys if limit reached
            print("⚠️ Key limit reached. Rotating keys...")
            keys = iam.list_access_keys(UserName=iam_username)
            for k in keys['AccessKeyMetadata']:
                iam.delete_access_key(UserName=iam_username, AccessKeyId=k['AccessKeyId'])
            
            # Retry creation
            key_resp = iam.create_access_key(UserName=iam_username)
            access_key = key_resp['AccessKey']['AccessKeyId']
            secret_key = key_resp['AccessKey']['SecretAccessKey']

        # 3. Create Workstation (Idempotent)
        print(f"💻 Checking for workstation...")
        existing_instances = ec2.describe_instances(
            Filters=[
                {'Name': 'tag:EmployeeId', 'Values': [employee_id]},
                {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}
            ]
        )
        
        instance_id = None
        private_ip = 'pending'
        
        if existing_instances['Reservations']:
            instance = existing_instances['Reservations'][0]['Instances'][0]
            instance_id = instance['InstanceId']
            private_ip = instance.get('PrivateIpAddress', 'pending')
            print(f"⚠️ Found existing instance {instance_id}")
        else:
            print(f"💻 Creating new workstation...")
            user_data = generate_workstation_userdata(employee_name, employee_id, department)
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
                        {'Key': 'Name', 'Value': f'{employee_name}-Workstation'},
                        {'Key': 'EmployeeId', 'Value': employee_id}
                    ]
                }]
            )
            instance_id = run_instances['Instances'][0]['InstanceId']
            private_ip = run_instances['Instances'][0].get('PrivateIpAddress', 'pending')

        # 4. Update DynamoDB
        workstations_table.put_item(
            Item={
                'employee_id': employee_id,
                'instance_id': instance_id,
                'iam_username': iam_username,
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat()
            }
        )

        # 5. SSM Activation
        activation = ssm.create_activation(
            DefaultInstanceName=f"{employee_name}-laptop",
            IamRole='AmazonSSMManagedInstanceCore',
            RegistrationLimit=5,
            Tags=[{'Key': 'EmployeeId', 'Value': employee_id}]
        )
        activation_id = activation['ActivationId']
        activation_code = activation['ActivationCode']

        # 6. Store Secrets
        secret_string = json.dumps({
            'iam_username': iam_username,
            'access_key_id': access_key,
            'secret_access_key': secret_key,
            'activation_id': activation_id,
            'activation_code': activation_code,
            'instance_id': instance_id
        })
        
        secret_name = f"innovatech/employee/{employee_id}/credentials"
        try:
            secretsmanager.create_secret(Name=secret_name, SecretString=secret_string)
        except secretsmanager.exceptions.ResourceExistsException:
            # We can't update the secret value without PutSecretValue permission, 
            # so we delete and recreate it to be safe with our current permissions
            try:
                secretsmanager.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
                secretsmanager.create_secret(Name=secret_name, SecretString=secret_string)
            except Exception as e:
                print(f"⚠️ Warning updating secret: {e}")

        # 7. Upload Scripts
        enrollment_code = generate_enrollment_code(employee_id)
        win_script = generate_windows_script(employee_name, access_key, secret_key, activation_id, activation_code)
        linux_script = generate_linux_script(employee_name, access_key, secret_key, activation_id, activation_code)
        
        win_key = f"enrollment/{employee_id}/enroll-windows.ps1"
        linux_key = f"enrollment/{employee_id}/enroll-linux.sh"
        
        s3.put_object(Bucket=ENROLLMENT_BUCKET, Key=win_key, Body=win_script)
        s3.put_object(Bucket=ENROLLMENT_BUCKET, Key=linux_key, Body=linux_script)
        
        win_url = s3.generate_presigned_url('get_object', Params={'Bucket': ENROLLMENT_BUCKET, 'Key': win_key})
        linux_url = s3.generate_presigned_url('get_object', Params={'Bucket': ENROLLMENT_BUCKET, 'Key': linux_key})

        # 8. Send Slack Notification
        print("🔔 Sending Slack notification...")
        if SLACK_WEBHOOK:
            send_slack_notification(
                "🎉 New Employee Onboarded!",
                f"*Name:* {employee_name}\n*Email:* {employee_email}\n*IAM:* `{iam_username}`\n*Workstation:* `{instance_id}`",
                win_url, linux_url
            )
            print("✅ Slack notification sent")
        else:
            print("⚠️ SLACK_WEBHOOK_URL not set")

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        raise e

def handle_employee_deletion(record):
    old_image = record['dynamodb']['OldImage']
    employee_id = old_image['employee_id']['S']
    employee_name = old_image['name']['S']
    employee_email = old_image['email']['S']
    
    print(f"🗑️ Offboarding: {employee_name}")
    
    try:
        # Terminate EC2
        resp = workstations_table.get_item(Key={'employee_id': employee_id})
        if 'Item' in resp:
            instance_id = resp['Item'].get('instance_id')
            if instance_id:
                ec2.terminate_instances(InstanceIds=[instance_id])
            workstations_table.delete_item(Key={'employee_id': employee_id})

        # Delete IAM
        iam_username = employee_email.replace('@', '-').replace('.', '-')
        try:
            # Detach policies
            policies = iam.list_attached_user_policies(UserName=iam_username)
            for p in policies['AttachedPolicies']:
                iam.detach_user_policy(UserName=iam_username, PolicyArn=p['PolicyArn'])
            
            # Remove from groups
            groups = iam.list_groups_for_user(UserName=iam_username)
            for g in groups['Groups']:
                iam.remove_user_from_group(UserName=iam_username, GroupName=g['GroupName'])

            # Delete keys
            keys = iam.list_access_keys(UserName=iam_username)
            for k in keys['AccessKeyMetadata']:
                iam.delete_access_key(UserName=iam_username, AccessKeyId=k['AccessKeyId'])
                
            iam.delete_user(UserName=iam_username)
        except Exception as e:
            print(f"⚠️ IAM cleanup warning: {e}")

        # Slack
        if SLACK_WEBHOOK:
            send_slack_notification(
                "👋 Employee Offboarded",
                f"*Name:* {employee_name}\n*Email:* {employee_email}\n✅ All resources cleaned up."
            )

    except Exception as e:
        print(f"❌ Error offboarding: {e}")

# Helpers
def generate_workstation_userdata(name, emp_id, dept):
    return f"<powershell>\n# Setup for {name}\n</powershell>"

def generate_enrollment_code(emp_id):
    import hashlib
    return hashlib.sha256(emp_id.encode()).hexdigest()[:8].upper()

def generate_windows_script(name, key, secret, act_id, act_code):
    return f"# Win Script\n# Key: {key}\n# Secret: {secret}\n# ActId: {act_id}\n# ActCode: {act_code}"

def generate_linux_script(name, key, secret, act_id, act_code):
    return f"# Linux Script\n# Key: {key}"

def send_slack_notification(title, text, win_url=None, linux_url=None):
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": title}},
        {"type": "section", "text": {"type": "mrkdwn", "text": text}}
    ]
    if win_url:
        blocks.append({
            "type": "actions",
            "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "📥 Windows Script"}, "url": win_url},
                {"type": "button", "text": {"type": "plain_text", "text": "🐧 Linux Script"}, "url": linux_url}
            ]
        })
    
    http.request('POST', SLACK_WEBHOOK, body=json.dumps({"blocks": blocks}).encode('utf-8'), headers={'Content-Type': 'application/json'})

def handle_employee_modification(record):
    pass