output "eks_cluster_name" {
  description = "EKS cluster name"
  value       = aws_eks_cluster.main.name
}

output "eks_cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = aws_eks_cluster.main.endpoint
}

output "dynamodb_table_name" {
  description = "DynamoDB table name for employees"
  value       = aws_dynamodb_table.employees.name
}

output "backend_ecr_repository_url" {
  description = "ECR repository URL for backend"
  value       = aws_ecr_repository.backend.repository_url
}

output "frontend_ecr_repository_url" {
  description = "ECR repository URL for frontend"
  value       = aws_ecr_repository.frontend.repository_url
}

output "backend_iam_role_arn" {
  description = "IAM role ARN for backend service account"
  value       = aws_iam_role.backend_app.arn
}

output "aws_account_id" {
  description = "AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "configure_kubectl_command" {
  description = "Command to configure kubectl"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${aws_eks_cluster.main.name}"
}

output "lbc_iam_role_arn" {
  description = "IAM Role ARN for the AWS Load Balancer Controller"
  value       = aws_iam_role.lbc_role.arn
}

output "nat_instance_id" {
  description = "NAT Instance ID"
  value       = aws_instance.nat.id
}

output "nat_instance_public_ip" {
  description = "NAT Instance Public IP (for SSH troubleshooting)"
  value       = aws_eip.nat_instance.public_ip
}

output "nat_instance_private_ip" {
  description = "NAT Instance Private IP"
  value       = aws_instance.nat.private_ip
}

output "lambda_function_name" {
  description = "Lambda function name for onboarding automation"
  value       = aws_lambda_function.onboarding.function_name
}

output "enrollment_scripts_bucket" {
  description = "S3 bucket for enrollment scripts"
  value       = aws_s3_bucket.enrollment_scripts.bucket
}

# ... existing outputs ...

output "directory_id" {
  description = "The ID of the AWS Managed Microsoft AD"
  value       = aws_directory_service_directory.main.id
}

output "directory_dns_ips" {
  description = "The DNS IP addresses of the Domain Controllers"
  value       = aws_directory_service_directory.main.dns_ip_addresses
}

output "ssm_domain_join_document_name" {
  description = "The name of the SSM document for domain joining"
  value       = aws_ssm_document.domain_join.name
}

output "ad_secret_arn" {
  description = "The ARN of the AD Admin Secret"
  value       = aws_secretsmanager_secret.ad_password.arn
}

output "vpn_enabled" {
  description = "Whether VPN is enabled"
  value       = var.enable_vpn
}

output "vpn_public_ip" {
  description = "Public IP of the VPN server (connect to this IP)"
  value       = var.enable_vpn ? aws_eip.vpn[0].public_ip : "VPN not enabled"
}

output "vpn_instance_id" {
  description = "VPN server instance ID"
  value       = var.enable_vpn ? aws_instance.vpn[0].id : "VPN not enabled"
}

output "vpn_client_config_location" {
  description = "Location of VPN client configurations on the server"
  value       = var.enable_vpn ? "SSH to VPN server and find configs in /etc/wireguard/clients/" : "VPN not enabled"
}

output "vpn_setup_commands" {
  description = "Commands to retrieve VPN client configurations"
  value = var.enable_vpn ? "ssh ubuntu@${aws_eip.vpn[0].public_ip} and run: sudo cat /etc/wireguard/clients/client1.conf" : "VPN not enabled"
}

output "vpn_ssh_key_path" {
  description = "Path to VPN SSH private key"
  value       = var.enable_vpn ? abspath(local_file.vpn_private_key[0].filename) : "VPN not enabled"
  sensitive   = true
}