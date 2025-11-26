# monitoring.tf - CloudWatch Dashboards, Log Groups, and Alarms
# Fulfills academic requirements REQ-05, REQ-12, and REQ-13

# ===== SNS Topic for Alarm Notifications =====
resource "aws_sns_topic" "monitoring_alerts" {
  name = "${var.project_name}-monitoring-alerts"

  tags = {
    Name = "${var.project_name}-monitoring-alerts"
  }
}

resource "aws_sns_topic_subscription" "monitoring_email" {
  topic_arn = aws_sns_topic.monitoring_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ===== CloudWatch Log Groups =====
# Note: Lambda automatically creates its log group on first invocation.
# The log group is not managed by Terraform to avoid conflicts.

# ===== CloudWatch Metric Alarms =====

# Lambda Error Rate Alarm (> 5%)
resource "aws_cloudwatch_metric_alarm" "lambda_error_rate" {
  alarm_name          = "${var.project_name}-lambda-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 5
  alarm_description   = "Lambda function error rate exceeds 5%"
  treat_missing_data  = "notBreaching"

  metric_query {
    id          = "error_rate"
    expression  = "(errors / invocations) * 100"
    label       = "Error Rate"
    return_data = true
  }

  metric_query {
    id = "errors"
    metric {
      metric_name = "Errors"
      namespace   = "AWS/Lambda"
      period      = 300
      stat        = "Sum"
      dimensions = {
        FunctionName = aws_lambda_function.onboarding.function_name
      }
    }
  }

  metric_query {
    id = "invocations"
    metric {
      metric_name = "Invocations"
      namespace   = "AWS/Lambda"
      period      = 300
      stat        = "Sum"
      dimensions = {
        FunctionName = aws_lambda_function.onboarding.function_name
      }
    }
  }

  alarm_actions = [aws_sns_topic.monitoring_alerts.arn]
  ok_actions    = [aws_sns_topic.monitoring_alerts.arn]

  tags = {
    Name = "${var.project_name}-lambda-error-rate-alarm"
  }
}

# EC2 CPU Utilization Alarm (> 80%)
resource "aws_cloudwatch_metric_alarm" "ec2_cpu_high" {
  alarm_name          = "${var.project_name}-ec2-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "EC2 CPU utilization exceeds 80%"
  treat_missing_data  = "notBreaching"

  dimensions = {
    AutoScalingGroupName = aws_eks_node_group.main.resources[0].autoscaling_groups[0].name
  }

  alarm_actions = [aws_sns_topic.monitoring_alerts.arn]
  ok_actions    = [aws_sns_topic.monitoring_alerts.arn]

  tags = {
    Name = "${var.project_name}-ec2-cpu-alarm"
  }
}

# DynamoDB Throttled Requests Alarm
resource "aws_cloudwatch_metric_alarm" "dynamodb_throttled_requests" {
  alarm_name          = "${var.project_name}-dynamodb-throttled"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ThrottledRequests"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "DynamoDB table has throttled requests"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = aws_dynamodb_table.employees.name
  }

  alarm_actions = [aws_sns_topic.monitoring_alerts.arn]
  ok_actions    = [aws_sns_topic.monitoring_alerts.arn]

  tags = {
    Name = "${var.project_name}-dynamodb-throttled-alarm"
  }
}

# EKS Cluster Node Failures Alarm
resource "aws_cloudwatch_metric_alarm" "eks_node_not_ready" {
  alarm_name          = "${var.project_name}-eks-node-not-ready"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "cluster_node_count"
  namespace           = "ContainerInsights"
  period              = 300
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "EKS cluster has no ready nodes"
  treat_missing_data  = "breaching"

  dimensions = {
    ClusterName = aws_eks_cluster.main.name
  }

  alarm_actions = [aws_sns_topic.monitoring_alerts.arn]
  ok_actions    = [aws_sns_topic.monitoring_alerts.arn]

  tags = {
    Name = "${var.project_name}-eks-node-alarm"
  }
}

# ===== CloudWatch Dashboard =====
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.project_name}-monitoring-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      # Row 1: EC2 Monitoring
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 1
        properties = {
          markdown = "# EC2 Workstation Monitoring"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 1
        width  = 6
        height = 6
        properties = {
          title  = "EC2 CPU Utilization"
          region = var.aws_region
          metrics = [
            ["AWS/EC2", "CPUUtilization", { stat = "Average", period = 300 }]
          ]
          view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 6
        y      = 1
        width  = 6
        height = 6
        properties = {
          title  = "EC2 Network In/Out"
          region = var.aws_region
          metrics = [
            ["AWS/EC2", "NetworkIn", { stat = "Sum", period = 300, label = "Network In" }],
            ["AWS/EC2", "NetworkOut", { stat = "Sum", period = 300, label = "Network Out" }]
          ]
          view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 1
        width  = 6
        height = 6
        properties = {
          title  = "EC2 Status Check Failed"
          region = var.aws_region
          metrics = [
            ["AWS/EC2", "StatusCheckFailed", { stat = "Sum", period = 300 }]
          ]
          view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 18
        y      = 1
        width  = 6
        height = 6
        properties = {
          title  = "Running EC2 Instances"
          region = var.aws_region
          metrics = [
            ["AWS/Usage", "ResourceCount", "Type", "Resource", "Resource", "RunningOnDemandInstances", "Service", "EC2", "Class", "Standard/OnDemand", { stat = "Average", period = 300 }]
          ]
          view                 = "singleValue"
          setPeriodToTimeRange = true
        }
      },

      # Row 2: Lambda Monitoring
      {
        type   = "text"
        x      = 0
        y      = 7
        width  = 24
        height = 1
        properties = {
          markdown = "# Lambda Function Monitoring (Onboarding Automation)"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 8
        width  = 6
        height = 6
        properties = {
          title  = "Lambda Invocations"
          region = var.aws_region
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.onboarding.function_name, { stat = "Sum", period = 300 }]
          ]
          view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 6
        y      = 8
        width  = 6
        height = 6
        properties = {
          title  = "Lambda Errors"
          region = var.aws_region
          metrics = [
            ["AWS/Lambda", "Errors", "FunctionName", aws_lambda_function.onboarding.function_name, { stat = "Sum", period = 300 }]
          ]
          view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 8
        width  = 6
        height = 6
        properties = {
          title  = "Lambda Duration (Avg/Max)"
          region = var.aws_region
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.onboarding.function_name, { stat = "Average", period = 300, label = "Average" }],
            ["AWS/Lambda", "Duration", "FunctionName", aws_lambda_function.onboarding.function_name, { stat = "Maximum", period = 300, label = "Maximum" }]
          ]
          view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 18
        y      = 8
        width  = 6
        height = 6
        properties = {
          title  = "Lambda Concurrent Executions"
          region = var.aws_region
          metrics = [
            ["AWS/Lambda", "ConcurrentExecutions", "FunctionName", aws_lambda_function.onboarding.function_name, { stat = "Maximum", period = 300 }]
          ]
          view = "timeSeries"
        }
      },

      # Row 3: DynamoDB Monitoring
      {
        type   = "text"
        x      = 0
        y      = 14
        width  = 24
        height = 1
        properties = {
          markdown = "# DynamoDB Monitoring (Employees & Workstations Tables)"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 15
        width  = 6
        height = 6
        properties = {
          title  = "DynamoDB Read Capacity"
          region = var.aws_region
          metrics = [
            ["AWS/DynamoDB", "ConsumedReadCapacityUnits", "TableName", aws_dynamodb_table.employees.name, { stat = "Sum", period = 300, label = "Employees" }],
            ["AWS/DynamoDB", "ConsumedReadCapacityUnits", "TableName", aws_dynamodb_table.workstations.name, { stat = "Sum", period = 300, label = "Workstations" }]
          ]
          view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 6
        y      = 15
        width  = 6
        height = 6
        properties = {
          title  = "DynamoDB Write Capacity"
          region = var.aws_region
          metrics = [
            ["AWS/DynamoDB", "ConsumedWriteCapacityUnits", "TableName", aws_dynamodb_table.employees.name, { stat = "Sum", period = 300, label = "Employees" }],
            ["AWS/DynamoDB", "ConsumedWriteCapacityUnits", "TableName", aws_dynamodb_table.workstations.name, { stat = "Sum", period = 300, label = "Workstations" }]
          ]
          view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 15
        width  = 6
        height = 6
        properties = {
          title  = "DynamoDB Throttled Requests"
          region = var.aws_region
          metrics = [
            ["AWS/DynamoDB", "ThrottledRequests", "TableName", aws_dynamodb_table.employees.name, { stat = "Sum", period = 300, label = "Employees" }],
            ["AWS/DynamoDB", "ThrottledRequests", "TableName", aws_dynamodb_table.workstations.name, { stat = "Sum", period = 300, label = "Workstations" }]
          ]
          view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 18
        y      = 15
        width  = 6
        height = 6
        properties = {
          title  = "DynamoDB Item Count"
          region = var.aws_region
          metrics = [
            ["AWS/DynamoDB", "ItemCount", "TableName", aws_dynamodb_table.employees.name, { stat = "Average", period = 3600, label = "Employees" }],
            ["AWS/DynamoDB", "ItemCount", "TableName", aws_dynamodb_table.workstations.name, { stat = "Average", period = 3600, label = "Workstations" }]
          ]
          view                 = "singleValue"
          setPeriodToTimeRange = true
        }
      },

      # Row 4: EKS/Kubernetes Monitoring
      {
        type   = "text"
        x      = 0
        y      = 21
        width  = 24
        height = 1
        properties = {
          markdown = "# EKS Cluster Monitoring"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 22
        width  = 6
        height = 6
        properties = {
          title  = "EKS Node Count"
          region = var.aws_region
          metrics = [
            ["ContainerInsights", "cluster_node_count", "ClusterName", aws_eks_cluster.main.name, { stat = "Average", period = 300 }]
          ]
          view                 = "singleValue"
          setPeriodToTimeRange = true
        }
      },
      {
        type   = "metric"
        x      = 6
        y      = 22
        width  = 6
        height = 6
        properties = {
          title  = "EKS Pod Count"
          region = var.aws_region
          metrics = [
            ["ContainerInsights", "pod_number_of_running_containers", "ClusterName", aws_eks_cluster.main.name, { stat = "Sum", period = 300 }]
          ]
          view                 = "singleValue"
          setPeriodToTimeRange = true
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 22
        width  = 6
        height = 6
        properties = {
          title  = "EKS CPU Utilization"
          region = var.aws_region
          metrics = [
            ["ContainerInsights", "node_cpu_utilization", "ClusterName", aws_eks_cluster.main.name, { stat = "Average", period = 300 }]
          ]
          view = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 18
        y      = 22
        width  = 6
        height = 6
        properties = {
          title  = "EKS Memory Utilization"
          region = var.aws_region
          metrics = [
            ["ContainerInsights", "node_memory_utilization", "ClusterName", aws_eks_cluster.main.name, { stat = "Average", period = 300 }]
          ]
          view = "timeSeries"
        }
      },

      # Row 5: Cost Monitoring
      # Note: AWS Billing metrics are only available in us-east-1 region
      {
        type   = "text"
        x      = 0
        y      = 28
        width  = 24
        height = 1
        properties = {
          markdown = "# Cost Monitoring"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 29
        width  = 12
        height = 6
        properties = {
          title = "Estimated AWS Charges (USD)"
          # AWS Billing metrics are only available in us-east-1 region
          region = "us-east-1"
          metrics = [
            ["AWS/Billing", "EstimatedCharges", "Currency", "USD", { stat = "Maximum", period = 86400 }]
          ]
          view                 = "singleValue"
          setPeriodToTimeRange = true
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 29
        width  = 12
        height = 6
        properties = {
          title = "Daily Cost Trend"
          # AWS Billing metrics are only available in us-east-1 region
          region = "us-east-1"
          metrics = [
            ["AWS/Billing", "EstimatedCharges", "Currency", "USD", { stat = "Maximum", period = 86400 }]
          ]
          view = "timeSeries"
        }
      }
    ]
  })
}
