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

variable "directory_name" {
  description = "The fully qualified name for the directory (e.g., innovatech.local)"
  type        = string
  default     = "innovatech.local"
}

variable "directory_password" {
  description = "The password for the directory administrator"
  type        = string
  sensitive   = true
  # Note: Password must be complex! (Upper, Lower, Number, Special)
}

variable "directory_edition" {
  description = "The edition of the directory (Standard or Enterprise)"
  type        = string
  default     = "Standard"
}

variable "enable_vpn" {
  description = "Enable VPN instance for secure RDP access to workstations"
  type        = bool
  default     = true
}

variable "vpn_instance_type" {
  description = "EC2 instance type for VPN server (t4g.nano for ARM-based cost savings)"
  type        = string
  default     = "t4g.nano"
}

variable "vpn_client_count" {
  description = "Number of VPN client configurations to generate"
  type        = number
  default     = 5
}

variable "admin_email" {
  description = "Email for initial Cognito admin user"
  type        = string
  default     = "admin@innovatech.com"
}