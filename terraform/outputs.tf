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