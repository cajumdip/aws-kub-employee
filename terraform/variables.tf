variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "eu-central-1"
}

variable "project_name" {
  description = "Project name prefix for all resources"
  type        = string
  default     = "innovatech"
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for onboarding notifications"
  type        = string
  sensitive   = true
}

variable "admin_ip_cidr" {
  description = "Admin IP CIDR for SSH/RDP access (e.g., '1.2.3.4/32')"
  type        = string
  default     = "0.0.0.0/0" # CHANGE THIS to your IP for security!
}

variable "workstation_instance_type" {
  description = "EC2 instance type for employee workstations"
  type        = string
  default     = "t3.medium"
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarms (optional)"
  type        = string
  default     = ""
}