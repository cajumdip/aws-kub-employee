# cognito.tf - AWS Cognito User Pool for HR Portal Authentication

# ===== Random Password for Initial Admin =====
resource "random_password" "admin_initial_password" {
  length           = 16
  special          = true
  override_special = "!@#$%^&*"
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
}

# ===== Cognito User Pool =====
resource "aws_cognito_user_pool" "hr_portal" {
  name = "${var.project_name}-hr-portal"

  # Email-based username
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  # Password policy
  password_policy {
    minimum_length                   = 8
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 7
  }

  # Account recovery via email
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  # User attributes schema
  schema {
    name                     = "email"
    attribute_data_type      = "String"
    developer_only_attribute = false
    mutable                  = true
    required                 = true

    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }

  # Admin create user settings - email notifications are handled via Slack instead
  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  # MFA configuration (optional, can be enabled later)
  mfa_configuration = "OFF"

  # Email configuration - disabled, credentials sent via Slack
  email_configuration {
    email_sending_account = "DEVELOPER"
  }

  tags = {
    Name = "${var.project_name}-hr-portal-user-pool"
  }
}

# ===== Cognito User Pool Domain =====
resource "aws_cognito_user_pool_domain" "hr_portal" {
  domain       = "${var.project_name}-hr-portal-${data.aws_caller_identity.current.account_id}"
  user_pool_id = aws_cognito_user_pool.hr_portal.id
}

# ===== Cognito User Pool Client =====
resource "aws_cognito_user_pool_client" "hr_portal" {
  name         = "${var.project_name}-hr-portal-client"
  user_pool_id = aws_cognito_user_pool.hr_portal.id

  # Token validity settings (1 hour access token)
  access_token_validity  = 1
  id_token_validity      = 1
  refresh_token_validity = 30

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  # Auth flows
  explicit_auth_flows = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH"
  ]

  # Prevent client secret for browser-based apps
  generate_secret = false

  # Security settings
  prevent_user_existence_errors = "ENABLED"

  # Supported identity providers
  supported_identity_providers = ["COGNITO"]
}

# ===== HR-Admins Group =====
resource "aws_cognito_user_group" "hr_admins" {
  name         = "HR-Admins"
  user_pool_id = aws_cognito_user_pool.hr_portal.id
  description  = "HR Administrators with full access to the HR Portal"
  precedence   = 0
}

# ===== Initial Admin User =====
resource "aws_cognito_user" "admin" {
  user_pool_id = aws_cognito_user_pool.hr_portal.id
  username     = var.admin_email

  attributes = {
    email          = var.admin_email
    email_verified = true
  }

  temporary_password = random_password.admin_initial_password.result

  # Force password change on first login
  desired_delivery_mediums = ["EMAIL"]

  depends_on = [aws_cognito_user_pool.hr_portal]
}

# ===== Add Admin User to HR-Admins Group =====
resource "aws_cognito_user_in_group" "admin_in_hr_admins" {
  user_pool_id = aws_cognito_user_pool.hr_portal.id
  group_name   = aws_cognito_user_group.hr_admins.name
  username     = aws_cognito_user.admin.username

  depends_on = [
    aws_cognito_user.admin,
    aws_cognito_user_group.hr_admins
  ]
}
