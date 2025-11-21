# main.tf - Enhanced with EC2 Workstations, RBAC, Zero Trust

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ===== Data Sources =====
data "aws_availability_zones" "available" {
  state = "available"
}

# Automatically zip the Lambda code AND libraries
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"      # <--- CHANGED FROM source_file
  output_path = "${path.module}/lambda_onboarding.zip"
  excludes    = ["test-event.json", "output.json", "__pycache__", "*.pyc"]
}

data "aws_caller_identity" "current" {}

# Find latest Windows Server AMI
data "aws_ami" "windows_server" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Find the latest Amazon Linux 2 AMI for NAT instance
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ===== VPC and Networking =====
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

# Public Subnets (for ALB and NAT)
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${count.index}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name                                           = "${var.project_name}-public-${count.index + 1}"
    "kubernetes.io/role/elb"                       = "1"
    "kubernetes.io/cluster/${var.project_name}-cluster" = "shared"
  }
}

# Private Subnets (for EKS nodes and Lambda)
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name                                           = "${var.project_name}-private-${count.index + 1}"
    "kubernetes.io/role/internal-elb"              = "1"
    "kubernetes.io/cluster/${var.project_name}-cluster" = "shared"
  }
}

# Workstation Subnet (for employee EC2 instances)
resource "aws_subnet" "workstations" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 20}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.project_name}-workstations-${count.index + 1}"
  }
}

# ===== NAT Instance =====
resource "aws_security_group" "nat_instance" {
  name        = "${var.project_name}-nat-instance-sg"
  description = "Security group for NAT instance"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.10.0/24", "10.0.11.0/24", "10.0.20.0/24", "10.0.21.0/24"]
    description = "Allow all from private subnets"
  }

  # Restrict SSH to your office IP or VPN
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip_cidr]
    description = "SSH access from admin IP only"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = {
    Name = "${var.project_name}-nat-instance-sg"
  }
}

resource "aws_eip" "nat_instance" {
  domain = "vpc"
  tags = {
    Name = "${var.project_name}-nat-instance-eip"
  }
  depends_on = [aws_internet_gateway.main]
}

resource "aws_instance" "nat" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type              = "t3.micro"
  subnet_id                  = aws_subnet.public[0].id
  vpc_security_group_ids     = [aws_security_group.nat_instance.id]
  associate_public_ip_address = true
  source_dest_check          = false

  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
              sysctl -p
              iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
              iptables -A FORWARD -i eth0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
              iptables -A FORWARD -i eth0 -o eth0 -j ACCEPT
              service iptables save
              systemctl enable iptables
              EOF

  tags = {
    Name = "${var.project_name}-nat-instance"
  }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_eip_association" "nat_instance" {
  instance_id   = aws_instance.nat.id
  allocation_id = aws_eip.nat_instance.id
}

# ===== Route Tables =====
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block           = "0.0.0.0/0"
    network_interface_id = aws_instance.nat.primary_network_interface_id
  }

  tags = {
    Name = "${var.project_name}-private-rt"
  }

  depends_on = [aws_instance.nat]
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "workstations" {
  count          = 2
  subnet_id      = aws_subnet.workstations[count.index].id
  route_table_id = aws_route_table.private.id
}

# ===== Security Groups =====
resource "aws_security_group" "eks_cluster" {
  name        = "${var.project_name}-eks-cluster-sg"
  description = "Security group for EKS cluster"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-eks-cluster-sg"
  }
}

resource "aws_security_group" "eks_nodes" {
  name        = "${var.project_name}-eks-nodes-sg"
  description = "Security group for EKS nodes"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    self        = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-eks-nodes-sg"
  }
}

# Security Group for Employee Workstations
resource "aws_security_group" "workstations" {
  name        = "${var.project_name}-workstations-sg"
  description = "Security group for employee workstations"
  vpc_id      = aws_vpc.main.id

  # RDP access from admin IP only
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip_cidr]
    description = "RDP from admin IP"
  }

  # Allow workstations to talk to each other
  ingress {
    from_port = 0
    to_port   = 65535
    protocol  = "tcp"
    self      = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-workstations-sg"
  }
}

# ===== DynamoDB for Employee Data =====
resource "aws_dynamodb_table" "employees" {
  name           = "${var.project_name}-employees"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "employee_id"
  stream_enabled = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "employee_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-employees-table"
  }
}

# DynamoDB for EC2 Workstation Tracking
resource "aws_dynamodb_table" "workstations" {
  name           = "${var.project_name}-workstations"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "employee_id"

  attribute {
    name = "employee_id"
    type = "S"
  }

  attribute {
    name = "instance_id"
    type = "S"
  }

  global_secondary_index {
    name            = "InstanceIdIndex"
    hash_key        = "instance_id"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-workstations-table"
  }
}

# ===== ECR Repositories =====
resource "aws_ecr_repository" "backend" {
  name                 = "${var.project_name}-backend-api"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Name = "${var.project_name}-backend-ecr"
  }
}

resource "aws_ecr_repository" "frontend" {
  name                 = "${var.project_name}-frontend-app"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Name = "${var.project_name}-frontend-ecr"
  }
}

# ===== EKS Cluster =====
resource "aws_eks_cluster" "main" {
  name     = "${var.project_name}-cluster"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.29"

  vpc_config {
    subnet_ids              = concat(aws_subnet.private[*].id, aws_subnet.public[*].id)
    endpoint_private_access = true
    endpoint_public_access  = true
    security_group_ids      = [aws_security_group.eks_cluster.id]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_resource_controller,
    aws_cloudwatch_log_group.eks_cluster,
  ]

  tags = {
    Name = "${var.project_name}-cluster"
  }
}

# CloudWatch Log Group for EKS
resource "aws_cloudwatch_log_group" "eks_cluster" {
  name              = "/aws/eks/${var.project_name}-cluster/cluster"
  retention_in_days = 7

  tags = {
    Name = "${var.project_name}-eks-logs"
  }
}

# EKS Node Group
resource "aws_eks_node_group" "main" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.project_name}-node-group"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = aws_subnet.private[*].id

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  instance_types = ["t3.medium"]

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.eks_container_registry_policy,
  ]

  tags = {
    Name = "${var.project_name}-node-group"
  }
}

# ===== IAM Roles for EKS =====
resource "aws_iam_role" "eks_cluster" {
  name = "${var.project_name}-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_iam_role_policy_attachment" "eks_vpc_resource_controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_iam_role" "eks_nodes" {
  name = "${var.project_name}-eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_iam_role_policy_attachment" "eks_container_registry_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_nodes.name
}

# CloudWatch Container Insights
resource "aws_iam_role_policy_attachment" "eks_cloudwatch_policy" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = aws_iam_role.eks_nodes.name
}

# ===== OIDC Provider for IRSA =====
data "tls_certificate" "eks" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
}



# ===== IAM Role for Backend App (IRSA) =====
data "aws_iam_policy_document" "backend_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:innovatech-app:backend-api-sa"]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "backend_app" {
  name               = "${var.project_name}-backend-api-role"
  assume_role_policy = data.aws_iam_policy_document.backend_assume_role.json
}

resource "aws_iam_role_policy" "backend_dynamodb" {
  name = "${var.project_name}-backend-dynamodb-policy"
  role = aws_iam_role.backend_app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Scan",
          "dynamodb:Query"
        ]
        Resource = [
          aws_dynamodb_table.employees.arn,
          aws_dynamodb_table.workstations.arn,
          "${aws_dynamodb_table.workstations.arn}/index/*"
        ]
      }
    ]
  })
}

# ===== IAM Role for AWS Load Balancer Controller =====
data "aws_iam_policy_document" "lbc_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-load-balancer-controller"]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lbc_role" {
  name               = "${var.project_name}-lbc-controller-role"
  assume_role_policy = data.aws_iam_policy_document.lbc_assume_role.json
}

resource "aws_iam_policy" "lbc_policy" {
  name        = "${var.project_name}-AWSLoadBalancerControllerIAMPolicy"
  description = "IAM policy for AWS Load Balancer Controller"

  policy = file("${path.module}/lbc-iam-policy.json")
}

resource "aws_iam_role_policy_attachment" "lbc_policy_attach" {
  policy_arn = aws_iam_policy.lbc_policy.arn
  role       = aws_iam_role.lbc_role.name
}

# ===== S3 Bucket for Enrollment Scripts =====
resource "aws_s3_bucket" "enrollment_scripts" {
  bucket = "${var.project_name}-enrollment-scripts-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${var.project_name}-enrollment-scripts"
  }
}

resource "aws_s3_bucket_versioning" "enrollment_scripts" {
  bucket = aws_s3_bucket.enrollment_scripts.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "enrollment_scripts" {
  bucket = aws_s3_bucket.enrollment_scripts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "enrollment_scripts" {
  bucket = aws_s3_bucket.enrollment_scripts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "enrollment_scripts" {
  bucket = aws_s3_bucket.enrollment_scripts.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "enrollment-scripts/"
}

# S3 Bucket for Logs
resource "aws_s3_bucket" "logs" {
  bucket = "${var.project_name}-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${var.project_name}-logs"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = 90
    }
  }
}

resource "aws_eks_addon" "cloudwatch_observability" {
  cluster_name = aws_eks_cluster.main.name
  addon_name   = "amazon-cloudwatch-observability"
}

# ===== IAM Role for Workstation EC2 Instances =====
resource "aws_iam_role" "workstation_role" {
  name = "${var.project_name}-workstation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "workstation_ssm" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.workstation_role.name
}

resource "aws_iam_role_policy_attachment" "workstation_cloudwatch" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = aws_iam_role.workstation_role.name
}

resource "aws_iam_instance_profile" "workstation_profile" {
  name = "${var.project_name}-workstation-profile"
  role = aws_iam_role.workstation_role.name
}

# ===== Lambda for Employee Onboarding & EC2 Creation =====
resource "aws_iam_role" "lambda_onboarding" {
  name = "${var.project_name}-lambda-onboarding-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_onboarding" {
  name = "${var.project_name}-lambda-onboarding-policy"
  role = aws_iam_role.lambda_onboarding.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeStream",
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator",
          "dynamodb:ListStreams",
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          "${aws_dynamodb_table.employees.arn}/stream/*",
          aws_dynamodb_table.employees.arn,
          aws_dynamodb_table.workstations.arn,
          "${aws_dynamodb_table.workstations.arn}/index/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:CreateTags",
          "ec2:DescribeTags",
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = [
          aws_iam_role.workstation_role.arn,
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/AmazonSSMManagedInstanceCore"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GetUser",
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:ListAccessKeys",
          "iam:AddUserToGroup",
          "iam:RemoveUserFromGroup",
          "iam:TagUser",
          "iam:CreateGroup",
          "iam:AttachUserPolicy",
          "iam:DetachUserPolicy",
          "iam:DeleteUserPolicy",
          "iam:ListUserPolicies",
          "iam:ListAttachedUserPolicies"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:CreateSecret",
          "secretsmanager:DeleteSecret",
          "secretsmanager:DescribeSecret",
          "secretsmanager:TagResource"
        ]
        Resource = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:innovatech/employee/*"
      },
      # NEW: Added permission for AD admin secret
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:innovatech/directory/admin-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:innovatech/employee/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:CreateActivation",
          "ssm:DeleteActivation",
          "ssm:DescribeActivations",
          "ssm:AddTagsToResource",
          "ssm:CreateAssociation",
          "ssm:DescribeAssociation"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.enrollment_scripts.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.enrollment_scripts.arn
      },
      # NEW: Added Directory Service permissions
      {
        Effect = "Allow"
        Action = [
          "ds:DescribeDirectories"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_security_group" "lambda" {
  name        = "${var.project_name}-lambda-sg"
  description = "Security group for Lambda function"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 636
    to_port     = 636
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "LDAPS to Active Directory"
  }

  egress {
    from_port   = 389
    to_port     = 389
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "LDAP to Active Directory"
  }

  egress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Kerberos to Active Directory"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS outbound"
  }

  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTP outbound"
  }

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow DNS queries"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS outbound"
  }

  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTP outbound"
  }

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow DNS queries"
  }

  tags = {
    Name = "${var.project_name}-lambda-sg"
  }
}

# ===== Store AD Password for Lambda =====
resource "aws_secretsmanager_secret" "ad_password" {
  name = "innovatech/directory/admin"
  tags = { Name = "${var.project_name}-ad-secret" }
}

resource "aws_secretsmanager_secret_version" "ad_password_val" {
  secret_id     = aws_secretsmanager_secret.ad_password.id
  secret_string = jsonencode({
    username = "Admin"
    password = var.directory_password
  })
}

resource "aws_security_group_rule" "ad_allow_lambda_ldaps" {
  type                     = "ingress"
  from_port                = 636
  to_port                  = 636
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.lambda.id
  security_group_id        = aws_directory_service_directory.main.security_group_id
  description              = "Allow LDAPS from Lambda"
}

resource "aws_security_group_rule" "ad_allow_lambda_ldap" {
  type                     = "ingress"
  from_port                = 389
  to_port                  = 389
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.lambda.id
  security_group_id        = aws_directory_service_directory.main.security_group_id
  description              = "Allow LDAP from Lambda"
}

resource "aws_security_group_rule" "ad_allow_lambda_kerberos" {
  type                     = "ingress"
  from_port                = 88
  to_port                  = 88
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.lambda.id
  security_group_id        = aws_directory_service_directory.main.security_group_id
  description              = "Allow Kerberos from Lambda"
}

resource "aws_security_group_rule" "ad_allow_lambda_dns" {
  type                     = "ingress"
  from_port                = 53
  to_port                  = 53
  protocol                 = "udp"
  source_security_group_id = aws_security_group.lambda.id
  security_group_id        = aws_directory_service_directory.main.security_group_id
  description              = "Allow DNS from Lambda"
}


resource "aws_lambda_function" "onboarding" {
  # Use the dynamic zip file created by the data source above
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  
  function_name    = "${var.project_name}-onboarding-automation"
  role             = aws_iam_role.lambda_onboarding.arn
  handler          = "index.handler"
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = 512

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      SLACK_WEBHOOK_URL         = var.slack_webhook_url
      TABLE_NAME                = aws_dynamodb_table.employees.name
      WORKSTATIONS_TABLE        = aws_dynamodb_table.workstations.name
      ENROLLMENT_BUCKET         = aws_s3_bucket.enrollment_scripts.bucket
      INNOVATECH_REGION         = var.aws_region
      AWS_ACCOUNT_ID            = data.aws_caller_identity.current.account_id
      WORKSTATION_AMI           = data.aws_ami.windows_server.id
      WORKSTATION_INSTANCE_TYPE = var.workstation_instance_type
      WORKSTATION_SUBNET_ID     = aws_subnet.workstations[0].id
      WORKSTATION_SG_ID         = aws_security_group.workstations.id
      WORKSTATION_PROFILE_NAME  = aws_iam_instance_profile.workstation_profile.name
      # --- NEW AD VARIABLES ---
      DIRECTORY_ID              = aws_directory_service_directory.main.id
      DIRECTORY_NAME            = var.directory_name
      AD_SECRET_ARN             = aws_secretsmanager_secret.ad_password.arn
      DOMAIN_JOIN_DOC           = aws_ssm_document.domain_join.name
    }
  }

  depends_on = [
    aws_iam_role_policy.lambda_onboarding,
    aws_instance.nat,
    data.archive_file.lambda_zip,
    aws_directory_service_directory.main
  ]
}

resource "aws_lambda_event_source_mapping" "dynamodb_trigger" {
  event_source_arn  = aws_dynamodb_table.employees.stream_arn
  function_name     = aws_lambda_function.onboarding.arn
  starting_position = "LATEST"
}

# ===== CloudWatch Alarms for Lambda =====
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.project_name}-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Alert when Lambda function has errors"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.onboarding.function_name
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
}

resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  alarm_name          = "${var.project_name}-lambda-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = "250000"
  alarm_description   = "Alert when Lambda duration exceeds 250 seconds"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.onboarding.function_name
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
}

# ===== SSM Document for Security Baseline =====
resource "aws_ssm_document" "security_baseline" {
  name            = "${var.project_name}-security-baseline"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: Apply Innovatech security baseline to managed devices
mainSteps:
  - action: aws:runPowerShellScript
    name: WindowsSecurityBaseline
    precondition:
      StringEquals:
        - platformType
        - Windows
    inputs:
      runCommand:
        - |
          # Enable Windows Firewall
          Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
          
          # Disable guest account
          Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
          
          # Enable automatic updates
          $AutoUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
          if (-not (Test-Path $AutoUpdatePath)) {
              New-Item -Path $AutoUpdatePath -Force
          }
          Set-ItemProperty -Path $AutoUpdatePath -Name "NoAutoUpdate" -Value 0
          Set-ItemProperty -Path $AutoUpdatePath -Name "AUOptions" -Value 4
          
          # Enable BitLocker check
          $BitLockerStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
          if ($BitLockerStatus) {
              Write-Output "BitLocker Status: $($BitLockerStatus.ProtectionStatus)"
          }
          
          Write-Output "Security baseline applied successfully"
  
  - action: aws:runShellScript
    name: LinuxSecurityBaseline
    precondition:
      StringEquals:
        - platformType
        - Linux
    inputs:
      runCommand:
        - |
          #!/bin/bash
          if command -v ufw &> /dev/null; then
              ufw --force enable
          fi
          
          if [ -f /etc/debian_version ]; then
              apt-get update
              apt-get install -y unattended-upgrades
              dpkg-reconfigure -plow unattended-upgrades
          fi
          
          if [ -f /etc/login.defs ]; then
              sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
              sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
              sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/' /etc/login.defs
          fi
DOC

  tags = {
    Name = "${var.project_name}-security-baseline"
  }
}

# ===== AWS Managed Microsoft AD =====
resource "aws_directory_service_directory" "main" {
  name     = var.directory_name
  password = var.directory_password
  edition  = var.directory_edition
  type     = "MicrosoftAD"

  vpc_settings {
    vpc_id     = aws_vpc.main.id
    # Use the private subnets for the Domain Controllers
    subnet_ids = aws_subnet.private[*].id
  }

  tags = {
    Name = "${var.project_name}-directory"
  }
}

# ===== DHCP Options (Crucial for Domain Joining) =====
# This tells the VPC to use the AD Domain Controllers as DNS servers
resource "aws_vpc_dhcp_options" "ad_dhcp" {
  domain_name          = var.directory_name
  domain_name_servers  = aws_directory_service_directory.main.dns_ip_addresses
  ntp_servers          = ["169.254.169.123"] # AWS Time Sync Service
  netbios_name_servers = aws_directory_service_directory.main.dns_ip_addresses
  netbios_node_type    = 2

  tags = {
    Name = "${var.project_name}-ad-dhcp"
  }
}

resource "aws_vpc_dhcp_options_association" "ad_dhcp_assoc" {
  vpc_id          = aws_vpc.main.id
  dhcp_options_id = aws_vpc_dhcp_options.ad_dhcp.id
}

# ===== SSM Document for Domain Join =====
# This defines the automation to join instances to the domain
resource "aws_ssm_document" "domain_join" {
  name          = "${var.project_name}-domain-join"
  document_type = "Command"
  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Join instances to the Innovatech Active Directory"
    mainSteps = [
      {
        action = "aws:domainJoin"
        name   = "domainJoin"
        inputs = {
          directoryId    = aws_directory_service_directory.main.id
          directoryName  = var.directory_name
          dnsIpAddresses = aws_directory_service_directory.main.dns_ip_addresses
        }
      }
    ]
  })
}