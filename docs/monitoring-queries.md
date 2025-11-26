# CloudWatch Logs Insights Queries

This document provides sample CloudWatch Logs Insights queries for monitoring and troubleshooting the Innovatech Employee Onboarding system.

## Lambda Function Queries

### Lambda Errors in Last 24 Hours
```
fields @timestamp, @message, @logStream
| filter @message like /ERROR/ or @message like /Exception/ or @message like /❌/
| sort @timestamp desc
| limit 100
```

### Employee Onboarding Events
```
fields @timestamp, @message
| filter @message like /Onboarding/ or @message like /🆕/
| parse @message "Onboarding: * (*)" as employee_name, employee_email
| sort @timestamp desc
| limit 50
```

### Successful Employee Onboarding Summary
```
fields @timestamp, @message
| filter @message like /Enterprise Onboarding Complete/ or @message like /🎉/
| stats count() as successful_onboardings by bin(1d)
| sort @timestamp desc
```

### Employee Offboarding Events
```
fields @timestamp, @message
| filter @message like /Offboarding/ or @message like /🗑️/
| parse @message "Offboarding: * (Employee ID: *)" as employee_name, employee_id
| sort @timestamp desc
| limit 50
```

### Lambda Duration Analysis
```
filter @type = "REPORT"
| stats avg(@duration), max(@duration), min(@duration), count(*) by bin(1h)
| sort @timestamp desc
```

### Lambda Cold Starts
```
filter @type = "REPORT"
| filter @message like /Init Duration/
| parse @message "Init Duration: * ms" as init_duration
| stats count() as cold_starts, avg(init_duration) as avg_init_duration by bin(1h)
```

## EC2 Workstation Queries

### Workstation Provisioning Events
```
fields @timestamp, @message
| filter @message like /Launching workstation/ or @message like /🖥️/
| parse @message "instance * " as instance_id
| sort @timestamp desc
| limit 50
```

### Workstation Provisioning Times
```
fields @timestamp, @message
| filter @message like /Instance .* is running/
| parse @message "Instance * is running" as instance_id
| sort @timestamp desc
| limit 50
```

### Failed Workstation Launches
```
fields @timestamp, @message
| filter @message like /Failed to launch EC2/ or @message like /Failed to launch workstation/
| sort @timestamp desc
| limit 50
```

### EC2 Termination Events
```
fields @timestamp, @message
| filter @message like /Terminating EC2 instance/ or @message like /Instance terminated/
| parse @message "instance: *" as instance_id
| sort @timestamp desc
| limit 50
```

## Active Directory Queries

### AD User Creation Events
```
fields @timestamp, @message
| filter @message like /Creating AD/ or @message like /AD user/ or @message like /Active Directory/
| sort @timestamp desc
| limit 50
```

### AD Connection Issues
```
fields @timestamp, @message
| filter @message like /Failed to/ and (@message like /AD/ or @message like /LDAP/ or @message like /directory/)
| sort @timestamp desc
| limit 50
```

### Failed Authentication Attempts
```
fields @timestamp, @message
| filter @message like /authentication/ or @message like /credential/ or @message like /password/
| filter @message like /failed/ or @message like /error/ or @message like /denied/
| sort @timestamp desc
| limit 50
```

### Connectivity Diagnostics
```
fields @timestamp, @message
| filter @message like /Diagnosing/ or @message like /DNS Resolution/ or @message like /TCP Reachable/ or @message like /TCP Unreachable/
| sort @timestamp desc
| limit 100
```

## IAM User Queries

### IAM User Creation Events
```
fields @timestamp, @message
| filter @message like /IAM user/ or @message like /create_iam_user/
| sort @timestamp desc
| limit 50
```

### IAM User Deletion Events
```
fields @timestamp, @message
| filter @message like /Deleting IAM user/ or @message like /IAM user deleted/
| sort @timestamp desc
| limit 50
```

## Error Analysis Queries

### All Errors by Type
```
fields @timestamp, @message
| filter @message like /ERROR/ or @message like /Exception/ or @message like /❌/ or @message like /Failed/
| stats count() as error_count by @message
| sort error_count desc
| limit 20
```

### Errors Over Time
```
fields @timestamp, @message
| filter @message like /ERROR/ or @message like /Exception/ or @message like /❌/ or @message like /Failed/
| stats count() as error_count by bin(1h)
| sort @timestamp desc
```

### Critical Errors
```
fields @timestamp, @message, @logStream
| filter @message like /Critical error/ or @message like /Critical:/ 
| sort @timestamp desc
| limit 50
```

## Slack Notification Queries

### Slack Notifications Sent
```
fields @timestamp, @message
| filter @message like /Slack/ or @message like /send_slack/
| sort @timestamp desc
| limit 50
```

## EKS Cluster Queries (if using Container Insights)

### Pod Start/Stop Events
```
fields @timestamp, @message, kubernetes.pod_name, kubernetes.namespace_name
| filter kubernetes.namespace_name = "innovatech-app"
| sort @timestamp desc
| limit 100
```

### Container Errors
```
fields @timestamp, @message, kubernetes.container_name, kubernetes.pod_name
| filter @message like /error/ or @message like /Error/ or @message like /ERROR/
| filter kubernetes.namespace_name = "innovatech-app"
| sort @timestamp desc
| limit 100
```

## Usage Tips

1. **Log Group Selection**: When running these queries, ensure you select the appropriate log group:
   - Lambda logs: `/aws/lambda/innovatech-onboarding-automation`
   - EKS logs: `/aws/eks/innovatech-cluster/cluster`
   - Container Insights: `/aws/containerinsights/innovatech-cluster/`

2. **Time Range**: Adjust the time range in the CloudWatch Logs Insights console based on your needs. Common ranges:
   - Last 1 hour: For recent issues
   - Last 24 hours: For daily analysis
   - Last 7 days: For trend analysis

3. **Export Results**: Use the "Export results" feature to download query results as CSV for further analysis.

4. **Create Dashboard Widgets**: Any of these queries can be saved as a CloudWatch Dashboard widget for continuous monitoring.

5. **Set Up Alarms**: Use metric filters based on these patterns to create CloudWatch Alarms for proactive alerting.
