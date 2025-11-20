# Innovatech Complete Cleanup and Rebuild Script
# This script handles everything: Kubernetes cleanup, Terraform destroy/apply
# Run this from the terraform directory

param(
    [switch]$SkipTerraform,
    [switch]$CleanupOnly
)

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Innovatech Cleanup & Rebuild Script" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Continue"

# Function to wait for pods to be deleted (removed unused function)

# Step 1: Configure kubectl
Write-Host "Step 1: Configuring kubectl..." -ForegroundColor Cyan
try {
    aws eks update-kubeconfig --region eu-central-1 --name innovatech-cluster 2>&1 | Out-Null
    Write-Host "kubectl configured" -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not configure kubectl (cluster may not exist yet)" -ForegroundColor Yellow
}
Write-Host ""

# Step 2: Delete all Kubernetes resources and AWS Load Balancers
Write-Host "Step 2: Cleaning up Kubernetes resources..." -ForegroundColor Cyan

# Delete application namespace and all its resources (this is the most effective cleanup)
Write-Host "Deleting innovatech-app namespace (will cascade delete deployments/services/ingress)..." -ForegroundColor Yellow
kubectl delete namespace innovatech-app --ignore-not-found=true --timeout=300s
Start-Sleep -Seconds 10

# Delete Helm releases
Write-Host "Deleting Helm releases..." -ForegroundColor Yellow
helm list -A | Select-String "aws-load-balancer" | ForEach-Object {
    $release = ($_ -split '\s+')[0]
    $namespace = ($_ -split '\s+')[1]
    Write-Host "  Uninstalling $release from $namespace..." -ForegroundColor Gray
    helm uninstall $release -n $namespace 2>&1 | Out-Null
}

# Delete LBC Service Account (IRSA role reference)
Write-Host "Deleting AWS Load Balancer Controller ServiceAccount..." -ForegroundColor Yellow
kubectl delete serviceaccount aws-load-balancer-controller -n kube-system --ignore-not-found=true

# Wait for 30s to allow Ingress resource to fully unregister with the ALB Controller
Write-Host "Waiting 30 seconds for Ingress to deregister from ALB..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

# Delete AWS Load Balancers (these block Terraform destroy)
Write-Host "Deleting AWS Load Balancers..." -ForegroundColor Yellow
$lbs = aws elbv2 describe-load-balancers --query "LoadBalancers[?contains(LoadBalancerName, 'k8s-innovate')].LoadBalancerArn" --output text 2>&1
if ($lbs -and $lbs -notmatch "error") {
    $lbs -split '\s+' | ForEach-Object {
        if ($_ -and $_ -ne "") {
            Write-Host "  Deleting load balancer: $_" -ForegroundColor Gray
            aws elbv2 delete-load-balancer --load-balancer-arn $_ 2>&1 | Out-Null
        }
    }
}
Write-Host "Waiting 10 seconds for Load Balancers to fully enter deletion status..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Delete Target Groups
Write-Host "Deleting Target Groups..." -ForegroundColor Yellow
$tgs = aws elbv2 describe-target-groups --query "TargetGroups[?contains(TargetGroupName, 'k8s-innovate')].TargetGroupArn" --output text 2>&1
if ($tgs -and $tgs -notmatch "error") {
    $tgs -split '\s+' | ForEach-Object {
        if ($_ -and $_ -ne "") {
            Write-Host "  Deleting target group: $_" -ForegroundColor Gray
            aws elbv2 delete-target-group --target-group-arn $_ 2>&1 | Out-Null
        }
    }
}
Write-Host "Waiting 10 seconds for Target Groups to finalize deletion..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Delete Security Groups created by Load Balancer Controller
Write-Host "Deleting Load Balancer security groups..." -ForegroundColor Yellow
$sgs = aws ec2 describe-security-groups --filters "Name=tag:elbv2.k8s.aws/cluster,Values=innovatech-cluster" --query "SecurityGroups[].GroupId" --output text 2>&1
if ($sgs -and $sgs -notmatch "error") {
    $sgs -split '\s+' | ForEach-Object {
        if ($_ -and $_ -ne "") {
            Write-Host "  Deleting security group: $_" -ForegroundColor Gray
            # Note: Deletion might fail if dependencies are not fully gone yet
            aws ec2 delete-security-group --group-id $_ 2>&1 | Out-Null
        }
    }
}


Write-Host "Kubernetes and AWS LB cleanup complete" -ForegroundColor Green
Write-Host ""

if ($CleanupOnly) {
    Write-Host "Cleanup complete. Exiting (CleanupOnly mode)" -ForegroundColor Cyan
    exit 0
}

# Step 3: Terraform Destroy
if (-not $SkipTerraform) {
    Write-Host "Step 3: Running Terraform destroy..." -ForegroundColor Cyan
    Write-Host "Waiting 30 seconds for AWS resources to finalize deletion before destroy..." -ForegroundColor Yellow
    Start-Sleep -Seconds 30

    terraform destroy -auto-approve
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Terraform destroy encountered errors. Retrying with longer wait..." -ForegroundColor Yellow
        Start-Sleep -Seconds 60 # Longer wait for AWS propagation
        terraform destroy -auto-approve
    }
    
    Write-Host "Terraform destroy complete" -ForegroundColor Green
    Write-Host ""}