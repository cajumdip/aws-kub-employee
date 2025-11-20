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
    """
    Lambda function triggered by DynamoDB Stream
    - INSERT: Creates IAM user, EC2 workstation, and enrollment script
    - MODIFY: Updates workstation tags if needed
    - REMOVE: Terminates EC2, deletes IAM user, cleans up resources
    """
    print(f"Received event: {json.dumps(event)}")
    
    for record in event['Records']:
        event_name = record['eventName']
        
        if event_name == 'INSERT':
            handle_employee_creation(record)
        elif event_name == 'REMOVE':
            handle_employee_deletion(record)
        elif event_name == 'MODIFY':
            handle_employee_modification(record)
    
    return {
        'statusCode': 200,
        'body': json.dumps('Employee lifecycle automation completed')
    }

def handle_employee_creation(record):
    """Handle new employee onboarding"""
    new_image = record['dynamodb']['NewImage']
    employee_name = new_image['name']['S']
    employee_email = new_image['email']['S']
    employee_id = new_image['employee_id']['S']
    department = new_image['department']['S']
    role = new_image['role']['S']
    
    print(f"🆕 Creating resources for new employee: {employee_name} ({employee_email})")
    
    try:
        # 1. Create IAM username
        iam_username = employee_email.replace('@', '-').replace('.', '-')
        
        # Check if user already exists
        try:
            iam.get_user(UserName=iam_username)
            print(f"⚠️  User {iam_username} already exists, skipping IAM creation")
        except iam.exceptions.NoSuchEntityException:
            # Create IAM user
            iam.create_user(
                UserName=iam_username,
                Tags=[
                    {'Key': 'EmployeeId', 'Value': employee_id},
                    {'Key': 'Department', 'Value': department},
                    {'Key': 'Role', 'Value': role},
                    {'Key': 'ManagedBy', 'Value': 'OnboardingAutomation'}
                ]
            )
            print(f"✅ Created IAM user: {iam_username}")
            
            # Add user to department group
            group_name = f"{department}-team"
            try:
                iam.create_group(GroupName=group_name)
            except iam.exceptions.EntityAlreadyExistsException:
                pass
            
            iam.add_user_to_group(UserName=iam_username, GroupName=group_name)
            
            # Attach policies
            iam.attach_user_policy(
                UserName=iam_username,
                PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
            )
            
            # Create access key
            access_key_response = iam.create_access_key(UserName=iam_username)
            access_key = access_key_response['AccessKey']['AccessKeyId']
            secret_key = access_key_response['AccessKey']['SecretAccessKey']
        
        # 2. Create EC2 Workstation
        print(f"💻 Creating Windows workstation for {employee_name}...")
        
        user_data_script = generate_workstation_userdata(employee_name, employee_id, department)
        
        instance_response = ec2.run_instances(
            ImageId=WORKSTATION_AMI,
            InstanceType=WORKSTATION_INSTANCE_TYPE,
            MinCount=1,
            MaxCount=1,
            SubnetId=WORKSTATION_SUBNET_ID,
            SecurityGroupIds=[WORKSTATION_SG_ID],
            IamInstanceProfile={'Name': WORKSTATION_PROFILE_NAME},
            UserData=user_data_script,
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': f'{employee_name}-Workstation'},
                        {'Key': 'EmployeeId', 'Value': employee_id},
                        {'Key': 'EmployeeName', 'Value': employee_name},
                        {'Key': 'Department', 'Value': department},
                        {'Key': 'Role', 'Value': role},
                        {'Key': 'ManagedBy', 'Value': 'Innovatech-Automation'},
                        {'Key': 'Environment', 'Value': 'production'}
                    ]
                }
            ],
            BlockDeviceMappings=[
                {
                    'DeviceName': '/dev/sda1',
                    'Ebs': {
                        'VolumeSize': 100,
                        'VolumeType': 'gp3',
                        'Encrypted': True,
                        'DeleteOnTermination': True
                    }
                }
            ]
        )
        
        instance_id = instance_response['Instances'][0]['InstanceId']
        private_ip = instance_response['Instances'][0].get('PrivateIpAddress', 'pending')
        
        print(f"✅ Created EC2 instance: {instance_id}")
        
        # 3. Store workstation info in DynamoDB
        workstations_table.put_item(
            Item={
                'employee_id': employee_id,
                'instance_id': instance_id,
                'employee_name': employee_name,
                'employee_email': employee_email,
                'department': department,
                'role': role,
                'iam_username': iam_username,
                'private_ip': private_ip,
                'instance_type': WORKSTATION_INSTANCE_TYPE,
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }
        )
        
        print(f"✅ Stored workstation info in DynamoDB")
        
        # 4. Create SSM Activation
        expiration_date = datetime.utcnow() + timedelta(days=29)
        activation_response = ssm.create_activation(
            Description=f"Activation for {employee_name} ({employee_id})",
            DefaultInstanceName=f"{employee_name.replace(' ', '-')}-laptop",
            IamRole='AmazonSSMManagedInstanceCore',
            RegistrationLimit=5,
            ExpirationDate=expiration_date,
            Tags=[
                {'Key': 'EmployeeId', 'Value': employee_id},
                {'Key': 'EmployeeName', 'Value': employee_name},
                {'Key': 'Department', 'Value': department}
            ]
        )
        
        activation_id = activation_response['ActivationId']
        activation_code = activation_response['ActivationCode']
        
        # 5. Store credentials in Secrets Manager
        secret_name = f"innovatech/employee/{employee_id}/credentials"
        try:
            secretsmanager.create_secret(
                Name=secret_name,
                SecretString=json.dumps({
                    'iam_username': iam_username,
                    'access_key_id': access_key,
                    'secret_access_key': secret_key,
                    'activation_id': activation_id,
                    'activation_code': activation_code,
                    'workstation_instance_id': instance_id,
                    'employee_name': employee_name,
                    'employee_email': employee_email,
                    'department': department,
                    'role': role,
                    'created_at': datetime.utcnow().isoformat()
                }),
                Tags=[
                    {'Key': 'EmployeeId', 'Value': employee_id},
                    {'Key': 'EmployeeName', 'Value': employee_name}
                ]
            )
        except secretsmanager.exceptions.ResourceExistsException:
            print(f"⚠️  Secret {secret_name} already exists")
        
        # 6. Generate enrollment scripts
        enrollment_code = generate_enrollment_code(employee_id)
        windows_script = generate_windows_script(
            employee_name, employee_id, department,
            access_key, secret_key, enrollment_code,
            activation_id, activation_code
        )
        
        linux_script = generate_linux_script(
            employee_name, employee_id, department,
            access_key, secret_key, enrollment_code,
            activation_id, activation_code
        )
        
        # Upload to S3
        windows_key = f"enrollment/{employee_id}/enroll-windows.ps1"
        linux_key = f"enrollment/{employee_id}/enroll-linux.sh"
        
        s3.put_object(Bucket=ENROLLMENT_BUCKET, Key=windows_key, Body=windows_script.encode('utf-8'))
        s3.put_object(Bucket=ENROLLMENT_BUCKET, Key=linux_key, Body=linux_script.encode('utf-8'))
        
        # Generate presigned URLs
        windows_url = s3.generate_presigned_url('get_object', Params={'Bucket': ENROLLMENT_BUCKET, 'Key': windows_key}, ExpiresIn=604800)
        linux_url = s3.generate_presigned_url('get_object', Params={'Bucket': ENROLLMENT_BUCKET, 'Key': linux_key}, ExpiresIn=604800)
        
        # 7. Send Slack notification
        if SLACK_WEBHOOK:
            send_slack_notification_creation(
                employee_name, employee_email, department, role,
                iam_username, instance_id, private_ip,
                enrollment_code, activation_id, activation_code,
                windows_url, linux_url
            )
        
        print(f"✅ Successfully onboarded {employee_name}")
        
    except Exception as e:
        print(f"❌ Error processing employee {employee_name}: {str(e)}")
        import traceback
        print(traceback.format_exc())
        raise e

def handle_employee_deletion(record):
    """Handle employee offboarding - terminate EC2, delete IAM user"""
    old_image = record['dynamodb']['OldImage']
    employee_id = old_image['employee_id']['S']
    employee_name = old_image['name']['S']
    employee_email = old_image['email']['S']
    
    print(f"🗑️  Offboarding employee: {employee_name} ({employee_email})")
    
    try:
        iam_username = employee_email.replace('@', '-').replace('.', '-')
        
        # 1. Get workstation info from DynamoDB
        try:
            workstation_response = workstations_table.get_item(Key={'employee_id': employee_id})
            workstation_info = workstation_response.get('Item', {})
            instance_id = workstation_info.get('instance_id')
            
            if instance_id:
                # Terminate EC2 instance
                print(f"💻 Terminating EC2 instance: {instance_id}")
                ec2.terminate_instances(InstanceIds=[instance_id])
                print(f"✅ Terminated EC2 instance: {instance_id}")
            
            # Delete workstation record from DynamoDB
            workstations_table.delete_item(Key={'employee_id': employee_id})
            print(f"✅ Deleted workstation record from DynamoDB")
            
        except Exception as e:
            print(f"⚠️  Error handling workstation: {str(e)}")
        
        # 2. Delete IAM access keys
        try:
            access_keys = iam.list_access_keys(UserName=iam_username)
            for key in access_keys['AccessKeyMetadata']:
                iam.delete_access_key(UserName=iam_username, AccessKeyId=key['AccessKeyId'])
                print(f"✅ Deleted access key: {key['AccessKeyId']}")
        except iam.exceptions.NoSuchEntityException:
            print(f"⚠️  IAM user {iam_username} not found")
        
        # 3. Detach policies
        try:
            attached_policies = iam.list_attached_user_policies(UserName=iam_username)
            for policy in attached_policies['AttachedPolicies']:
                iam.detach_user_policy(UserName=iam_username, PolicyArn=policy['PolicyArn'])
                print(f"✅ Detached policy: {policy['PolicyName']}")
        except Exception as e:
            print(f"⚠️  Error detaching policies: {str(e)}")
        
        # 4. Remove from groups
        try:
            groups = iam.list_groups_for_user(UserName=iam_username)
            for group in groups['Groups']:
                iam.remove_user_from_group(UserName=iam_username, GroupName=group['GroupName'])
                print(f"✅ Removed from group: {group['GroupName']}")
        except Exception as e:
            print(f"⚠️  Error removing from groups: {str(e)}")
        
        # 5. Delete IAM user
        try:
            iam.delete_user(UserName=iam_username)
            print(f"✅ Deleted IAM user: {iam_username}")
        except Exception as e:
            print(f"⚠️  Error deleting IAM user: {str(e)}")
        
        # 6. Delete secrets from Secrets Manager
        try:
            secret_name = f"innovatech/employee/{employee_id}/credentials"
            secretsmanager.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
            print(f"✅ Deleted secret: {secret_name}")
        except Exception as e:
            print(f"⚠️  Error deleting secret: {str(e)}")
        
        # 7. Delete enrollment scripts from S3
        try:
            s3.delete_object(Bucket=ENROLLMENT_BUCKET, Key=f"enrollment/{employee_id}/enroll-windows.ps1")
            s3.delete_object(Bucket=ENROLLMENT_BUCKET, Key=f"enrollment/{employee_id}/enroll-linux.sh")
            print(f"✅ Deleted enrollment scripts from S3")
        except Exception as e:
            print(f"⚠️  Error deleting S3 objects: {str(e)}")
        
        # 8. Send Slack notification
        if SLACK_WEBHOOK:
            send_slack_notification_deletion(employee_name, employee_email, instance_id)
        
        print(f"✅ Successfully offboarded {employee_name}")
        
    except Exception as e:
        print(f"❌ Error offboarding employee {employee_name}: {str(e)}")
        import traceback
        print(traceback.format_exc())
        raise e

def handle_employee_modification(record):
    """Handle employee updates"""
    new_image = record['dynamodb']['NewImage']
    old_image = record['dynamodb']['OldImage']
    
    employee_id = new_image['employee_id']['S']
    status = new_image.get('status', {}).get('S', 'active')
    
    # If status changed to 'inactive', trigger deletion
    if status == 'inactive':
        old_status = old_image.get('status', {}).get('S', 'active')
        if old_status == 'active':
            print(f"⚠️  Employee {employee_id} status changed to inactive, triggering offboarding")
            handle_employee_deletion(record)

def generate_workstation_userdata(name, employee_id, department):
    """Generate Windows EC2 user data script"""
    script = f"""<powershell>
# Innovatech Workstation Setup
$employeeName = "{name}"
$employeeId = "{employee_id}"
$department = "{department}"

# Set computer description
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "srvcomment" -Value "Workstation for $employeeName ($department)"

# Enable RDP
Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Install CloudWatch Agent
Invoke-WebRequest -Uri "https://s3.amazonaws.com/amazoncloudwatch-agent/windows/amd64/latest/amazon-cloudwatch-agent.msi" -OutFile "C:\\cloudwatch-agent.msi"
Start-Process msiexec.exe -ArgumentList '/i C:\\cloudwatch-agent.msi /qn' -Wait

# Configure CloudWatch
$config = @{{
  "logs" = @{{
    "logs_collected" = @{{
      "windows_events" = @{{
        "collect_list" = @(
          @{{ "log_name" = "System"; "log_group_name" = "/aws/ec2/workstations/system"; "log_stream_name" = "$employeeId" }}
          @{{ "log_name" = "Application"; "log_group_name" = "/aws/ec2/workstations/application"; "log_stream_name" = "$employeeId" }}
        )
      }}
    }}
  }}
}}

$config | ConvertTo-Json -Depth 10 | Out-File -FilePath "C:\\Program Files\\Amazon\\AmazonCloudWatchAgent\\config.json"

& "C:\\Program Files\\Amazon\\AmazonCloudWatchAgent\\amazon-cloudwatch-agent-ctl.ps1" -a fetch-config -m ec2 -s -c file:"C:\\Program Files\\Amazon\\AmazonCloudWatchAgent\\config.json"

Write-Host "Workstation setup complete for $employeeName"
</powershell>
"""
    return script

def generate_enrollment_code(employee_id):
    """Generate unique enrollment code"""
    import hashlib
    return hashlib.sha256(employee_id.encode()).hexdigest()[:8].upper()

def generate_windows_script(name, employee_id, department, access_key, secret_key, enrollment_code, activation_id, activation_code):
    """Generate Windows PowerShell enrollment script"""
    credentials_block = f'''[default]
aws_access_key_id = {access_key}
aws_secret_access_key = {secret_key}
region = {AWS_REGION}'''

    config_block = f'''[default]
region = {AWS_REGION}
output = json'''

    return f'''# Innovatech Device Enrollment - Windows
# Employee: {name}
# Enrollment Code: {enrollment_code}

Write-Host "Innovatech Device Enrollment" -ForegroundColor Cyan
Write-Host "Employee: {name}" -ForegroundColor Yellow
Write-Host "Enrollment Code: {enrollment_code}" -ForegroundColor Green

# Configure AWS Credentials
$awsPath = "$env:USERPROFILE\\.aws"
New-Item -ItemType Directory -Path $awsPath -Force | Out-Null

@"
{credentials_block}
"@ | Out-File -FilePath "$awsPath\\credentials" -Encoding UTF8

@"
{config_block}
"@ | Out-File -FilePath "$awsPath\\config" -Encoding UTF8

Write-Host "✅ AWS credentials configured" -ForegroundColor Green

# Install SSM Agent
Write-Host "Installing SSM Agent..." -ForegroundColor Cyan
$ssmUrl = "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe"
$ssmInstaller = "$env:TEMP\\AmazonSSMAgentSetup.exe"
Invoke-WebRequest -Uri $ssmUrl -OutFile $ssmInstaller
Start-Process -FilePath $ssmInstaller -ArgumentList "/quiet" -Wait

# Register with SSM
Write-Host "Registering with AWS Systems Manager..." -ForegroundColor Cyan
& "C:\\Program Files\\Amazon\\SSM\\amazon-ssm-agent.exe" -register -code "{activation_code}" -id "{activation_id}" -region "{AWS_REGION}" -y

Start-Service AmazonSSMAgent

Write-Host "✅ Enrollment complete!" -ForegroundColor Green
pause
'''

def generate_linux_script(name, employee_id, department, access_key, secret_key, enrollment_code, activation_id, activation_code):
    """Generate Linux enrollment script"""
    return f'''#!/bin/bash
# Innovatech Device Enrollment - Linux
echo "Innovatech Device Enrollment"
echo "Employee: {name}"
echo "Enrollment Code: {enrollment_code}"

mkdir -p ~/.aws
cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id = {access_key}
aws_secret_access_key = {secret_key}
region = {AWS_REGION}
EOF

chmod 600 ~/.aws/credentials
echo "✅ AWS credentials configured"

# Install SSM Agent
if [ -f /etc/debian_version ]; then
    wget https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb
    sudo dpkg -i amazon-ssm-agent.deb
elif [ -f /etc/redhat-release ]; then
    sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
fi

sudo amazon-ssm-agent -register -code "{activation_code}" -id "{activation_id}" -region "{AWS_REGION}" -y
sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent

echo "✅ Enrollment complete!"
'''

def send_slack_notification_creation(employee_name, employee_email, department, role, iam_username, instance_id, private_ip, enrollment_code, activation_id, activation_code, windows_url, linux_url):
    """Send Slack notification for employee creation"""
    message = {
        "text": "🎉 New Employee Onboarded!",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "🎉 New Employee Onboarded!"}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Name:*\n{employee_name}"},
                    {"type": "mrkdwn", "text": f"*Email:*\n{employee_email}"},
                    {"type": "mrkdwn", "text": f"*Department:*\n{department}"},
                    {"type": "mrkdwn", "text": f"*Role:*\n{role}"}
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*IAM User:* `{iam_username}`\n*Workstation:* `{instance_id}`\n*Private IP:* `{private_ip}`\n*Enrollment Code:* `{enrollment_code}`"}
            },
            {
                "type": "actions",
                "elements": [
                    {"type": "button", "text": {"type": "plain_text", "text": "📥 Windows Script"}, "url": windows_url, "style": "primary"},
                    {"type": "button", "text": {"type": "plain_text", "text": "🐧 Linux Script"}, "url": linux_url}
                ]
            }
        ]
    }
    
    try:
        http.request('POST', SLACK_WEBHOOK, body=json.dumps(message).encode('utf-8'), headers={'Content-Type': 'application/json'})
        print("✅ Slack notification sent")
    except Exception as e:
        print(f"⚠️  Slack notification failed: {str(e)}")

def send_slack_notification_deletion(employee_name, employee_email, instance_id):
    """Send Slack notification for employee deletion"""
    message = {
        "text": "👋 Employee Offboarded",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "👋 Employee Offboarded"}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Name:*\n{employee_name}"},
                    {"type": "mrkdwn", "text": f"*Email:*\n{employee_email}"}
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"✅ Terminated workstation: `{instance_id}`\n✅ Deleted IAM user\n✅ Removed all access\n✅ Cleaned up resources"}
            }
        ]
    }
    
    try:
        http.request('POST', SLACK_WEBHOOK, body=json.dumps(message).encode('utf-8'), headers={'Content-Type': 'application/json'})
        print("✅ Slack notification sent")
    except Exception as e:
        print(f"⚠️  Slack notification failed: {str(e)}")