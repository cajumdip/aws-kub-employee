# budgets.tf - AWS Budgets for Cost Management
# Fulfills academic requirement for cost monitoring and alerts
# Note: Uses data.aws_caller_identity.current from main.tf

# ===== Monthly AWS Budget =====
resource "aws_budgets_budget" "monthly" {
  name         = "${var.project_name}-monthly-budget"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_limit)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # Notification at 80% of budget (Actual)
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
    subscriber_sns_topic_arns  = [aws_sns_topic.monitoring_alerts.arn]
  }

  # Notification at 100% of budget (Actual)
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
    subscriber_sns_topic_arns  = [aws_sns_topic.monitoring_alerts.arn]
  }

  # Notification at 100% of budget (Forecasted)
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
    subscriber_sns_topic_arns  = [aws_sns_topic.monitoring_alerts.arn]
  }

  # Filter by linked account (optional, applies to the current account)
  cost_filter {
    name   = "LinkedAccount"
    values = [data.aws_caller_identity.current.account_id]
  }

  tags = {
    Name = "${var.project_name}-monthly-budget"
  }
}
