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

# Function to wait for pods to be deleted
function Wait-ForPodsDeleted {
    param([string]$Namespace)
    
    Write-Host "Waiting for pods in namespace $Namespace to be deleted..." -ForegroundColor Yellow
    $timeout = 120
    $elapsed = 0
    
    while ($elapsed -lt $timeout) {
        $pods = kubectl get pods -n $Namespace 2>&1
        if ($pods -match "No resources found") {
            Write-Host "All pods deleted" -ForegroundColor Green
            return $true
        }
        Start-Sleep -Seconds 5
        $elapsed += 5
        Write-Host "." -NoNewline
    }
    Write-Host ""
    Write-Host "Warning: Timeout waiting for pods to be deleted" -ForegroundColor Yellow
    return $false
}

# Step 1: Configure kubectl
Write-Host "Step 1: Configuring kubectl..." -ForegroundColor Cyan
try {
    aws eks update-kubeconfig --region eu-central-1 --name innovatech-cluster 2>&1 | Out-Null
    Write-Host "kubectl configured" -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not configure kubectl (cluster may not exist yet)" -ForegroundColor Yellow
}
Write-Host ""

# Step 2: Delete all Kubernetes resources
Write-Host "Step 2: Cleaning up Kubernetes resources..." -ForegroundColor Cyan

# Delete application namespace and all its resources
Write-Host "Deleting innovatech-app namespace..." -ForegroundColor Yellow
kubectl delete namespace innovatech-app --ignore-not-found=true --timeout=60s

# Delete Helm releases
Write-Host "Deleting Helm releases..." -ForegroundColor Yellow
helm list -A | Select-String "aws-load-balancer" | ForEach-Object {
    $release = ($_ -split '\s+')[0]
    $namespace = ($_ -split '\s+')[1]
    Write-Host "  Uninstalling $release from $namespace..." -ForegroundColor Gray
    helm uninstall $release -n $namespace 2>&1 | Out-Null
}

# Delete load balancer controller resources
Write-Host "Deleting AWS Load Balancer Controller resources..." -ForegroundColor Yellow
kubectl delete deployment aws-load-balancer-controller -n kube-system --ignore-not-found=true
kubectl delete service aws-load-balancer-webhook-service -n kube-system --ignore-not-found=true
kubectl delete serviceaccount aws-load-balancer-controller -n kube-system --ignore-not-found=true

# Delete webhooks and CRDs
Write-Host "Deleting webhooks and CRDs..." -ForegroundColor Yellow
kubectl delete mutatingwebhookconfiguration aws-load-balancer-webhook --ignore-not-found=true
kubectl delete validatingwebhookconfiguration aws-load-balancer-webhook --ignore-not-found=true

# Delete LBC cluster roles
kubectl delete clusterrole aws-load-balancer-controller-role --ignore-not-found=true
kubectl delete clusterrolebinding aws-load-balancer-controller-rolebinding --ignore-not-found=true

# Delete all LBC-related CRDs
Write-Host "Deleting Load Balancer Controller CRDs..." -ForegroundColor Yellow
kubectl get crd | Select-String "elbv2.k8s.aws" | ForEach-Object {
    $crd = ($_ -split '\s+')[0]
    Write-Host "  Deleting CRD: $crd" -ForegroundColor Gray
    kubectl delete crd $crd --ignore-not-found=true
}

kubectl get crd | Select-String "k8s.aws" | ForEach-Object {
    $crd = ($_ -split '\s+')[0]
    Write-Host "  Deleting CRD: $crd" -ForegroundColor Gray
    kubectl delete crd $crd --ignore-not-found=true
}

# Delete Helm secrets
Write-Host "Deleting Helm secrets..." -ForegroundColor Yellow
kubectl get secrets -n kube-system | Select-String "sh.helm.release" | ForEach-Object {
    $secret = ($_ -split '\s+')[0]
    Write-Host "  Deleting secret: $secret" -ForegroundColor Gray
    kubectl delete secret $secret -n kube-system --ignore-not-found=true
}

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

# Delete Target Groups
Write-Host "Deleting Target Groups..." -ForegroundColor Yellow
$tgs = aws elbv2 describe-target-groups --query "TargetGroups[?contains(TargetGroupName, 'k8s-innovate')].TargetGroupArn" --output text 2>&1
if ($tgs -and $tgs -notmatch "error") {
    Start-Sleep -Seconds 10  # Wait for LBs to be deleted first
    $tgs -split '\s+' | ForEach-Object {
        if ($_ -and $_ -ne "") {
            Write-Host "  Deleting target group: $_" -ForegroundColor Gray
            aws elbv2 delete-target-group --target-group-arn $_ 2>&1 | Out-Null
        }
    }
}

# Delete Security Groups created by Load Balancer Controller
Write-Host "Deleting Load Balancer security groups..." -ForegroundColor Yellow
$sgs = aws ec2 describe-security-groups --filters "Name=tag:elbv2.k8s.aws/cluster,Values=innovatech-cluster" --query "SecurityGroups[].GroupId" --output text 2>&1
if ($sgs -and $sgs -notmatch "error") {
    Start-Sleep -Seconds 15  # Wait for LBs and TGs to be deleted
    $sgs -split '\s+' | ForEach-Object {
        if ($_ -and $_ -ne "") {
            Write-Host "  Deleting security group: $_" -ForegroundColor Gray
            aws ec2 delete-security-group --group-id $_ 2>&1 | Out-Null
        }
    }
}

Write-Host "Kubernetes cleanup complete" -ForegroundColor Green
Write-Host ""

if ($CleanupOnly) {
    Write-Host "Cleanup complete. Exiting (CleanupOnly mode)" -ForegroundColor Cyan
    exit 0
}

# Step 3: Terraform Destroy
if (-not $SkipTerraform) {
    Write-Host "Step 3: Running Terraform destroy..." -ForegroundColor Cyan
    Write-Host "Waiting 30 seconds for AWS resources to finalize deletion..." -ForegroundColor Yellow
    Start-Sleep -Seconds 30
    
    terraform destroy -auto-approve
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Terraform destroy encountered errors. Retrying..." -ForegroundColor Yellow
        Start-Sleep -Seconds 30
        terraform destroy -auto-approve
    }
    
    Write-Host "Terraform destroy complete" -ForegroundColor Green
    Write-Host ""
    
    # Step 4: Terraform Apply
    Write-Host "Step 4: Running Terraform apply..." -ForegroundColor Cyan
    terraform apply -auto-approve
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Terraform apply failed!" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Terraform apply complete" -ForegroundColor Green
    Write-Host ""
}

# Step 5: Configure kubectl for new cluster
Write-Host "Step 5: Configuring kubectl for new cluster..." -ForegroundColor Cyan
Start-Sleep -Seconds 10
aws eks update-kubeconfig --region eu-central-1 --name innovatech-cluster
Write-Host ""

# Step 6: Wait for cluster to be ready
Write-Host "Step 6: Waiting for cluster to be ready..." -ForegroundColor Cyan
$timeout = 300
$elapsed = 0
while ($elapsed -lt $timeout) {
    $nodes = kubectl get nodes 2>&1
    if ($nodes -match "Ready") {
        Write-Host "Cluster is ready" -ForegroundColor Green
        break
    }
    Write-Host "." -NoNewline
    Start-Sleep -Seconds 10
    $elapsed += 10
}
Write-Host ""

# Step 7: Install CoreDNS addon
Write-Host "Step 7: Installing CoreDNS addon..." -ForegroundColor Cyan
$corednsExists = aws eks describe-addon --cluster-name innovatech-cluster --addon-name coredns --region eu-central-1 2>&1
if ($corednsExists -match "ResourceNotFoundException") {
    Write-Host "Creating CoreDNS addon..." -ForegroundColor Yellow
    aws eks create-addon --cluster-name innovatech-cluster --addon-name coredns --region eu-central-1
    Start-Sleep -Seconds 30
} else {
    Write-Host "CoreDNS addon already exists" -ForegroundColor Green
}

# Wait for CoreDNS to be ready
Write-Host "Waiting for CoreDNS pods..." -ForegroundColor Yellow
kubectl wait --for=condition=ready pod -l eks.amazonaws.com/component=coredns -n kube-system --timeout=120s
Write-Host "CoreDNS is ready" -ForegroundColor Green
Write-Host ""

# Step 8: Install VPC CNI
Write-Host "Step 8: Installing VPC CNI..." -ForegroundColor Cyan
$vpcCniExists = kubectl get daemonset aws-node -n kube-system 2>&1
if ($vpcCniExists -match "NotFound" -or $vpcCniExists -match "No resources found") {
    Write-Host "Installing VPC CNI..." -ForegroundColor Yellow
    kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/release-1.15/config/master/aws-k8s-cni.yaml
    Start-Sleep -Seconds 20
}

# Wait for VPC CNI to be ready
Write-Host "Waiting for VPC CNI pods..." -ForegroundColor Yellow
kubectl wait --for=condition=ready pod -l k8s-app=aws-node -n kube-system --timeout=120s
Write-Host "VPC CNI is ready" -ForegroundColor Green
Write-Host ""

# Step 9: Install AWS Load Balancer Controller
Write-Host "Step 9: Installing AWS Load Balancer Controller..." -ForegroundColor Cyan

# Get VPC ID
$vpcId = aws ec2 describe-vpcs --filters "Name=tag:Name,Values=innovatech-vpc" --query 'Vpcs[0].VpcId' --output text
Write-Host "VPC ID: $vpcId" -ForegroundColor Gray

# Add Helm repo
helm repo add eks https://aws.github.io/eks-charts 2>&1 | Out-Null
helm repo update 2>&1 | Out-Null

# Create service account
$lbcRoleArn = terraform output -raw lbc_iam_role_arn
Write-Host "LBC Role ARN: $lbcRoleArn" -ForegroundColor Gray

@"
apiVersion: v1
kind: ServiceAccount
metadata:
  name: aws-load-balancer-controller
  namespace: kube-system
  annotations:
    eks.amazonaws.com/role-arn: $lbcRoleArn
"@ | kubectl apply -f -

# Install Helm chart
Write-Host "Installing Load Balancer Controller Helm chart..." -ForegroundColor Yellow
helm install aws-load-balancer-controller eks/aws-load-balancer-controller `
  -n kube-system `
  --set clusterName=innovatech-cluster `
  --set serviceAccount.create=false `
  --set serviceAccount.name=aws-load-balancer-controller `
  --set region=eu-central-1 `
  --set vpcId=$vpcId

# Wait for LBC to be ready
Write-Host "Waiting for Load Balancer Controller pods..." -ForegroundColor Yellow
kubectl wait --for=condition=ready pod -l "app.kubernetes.io/name=aws-load-balancer-controller" -n kube-system --timeout=120s
Write-Host "Load Balancer Controller is ready" -ForegroundColor Green
Write-Host ""

# Step 10: Deploy application
Write-Host "Step 10: Deploying application..." -ForegroundColor Cyan

# Go back to parent directory where k8s folder is
Push-Location ..

kubectl apply -f k8s/00-namespace.yaml
Start-Sleep -Seconds 2

kubectl apply -f k8s/01-backend.yaml
Start-Sleep -Seconds 5

kubectl apply -f k8s/02-frontend.yaml
Start-Sleep -Seconds 5

Pop-Location

Write-Host "Application deployed" -ForegroundColor Green
Write-Host ""

# Step 11: Wait for application to be ready
Write-Host "Step 11: Waiting for application pods..." -ForegroundColor Cyan
kubectl wait --for=condition=ready pod -l app=backend-api -n innovatech-app --timeout=180s
kubectl wait --for=condition=ready pod -l app=frontend-app -n innovatech-app --timeout=180s
Write-Host ""

# Step 12: Get ingress information
Write-Host "Step 12: Getting application URL..." -ForegroundColor Cyan
Write-Host "Waiting for load balancer to be provisioned..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

$ingressInfo = kubectl get ingress -n innovatech-app -o json | ConvertFrom-Json
if ($ingressInfo.items.Count -gt 0) {
    $lbHostname = $ingressInfo.items[0].status.loadBalancer.ingress[0].hostname
    if ($lbHostname) {
        Write-Host ""
        Write-Host "======================================" -ForegroundColor Green
        Write-Host "DEPLOYMENT COMPLETE!" -ForegroundColor Green
        Write-Host "======================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Application URL: http://$lbHostname" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "It may take a few minutes for the load balancer to become fully operational." -ForegroundColor Yellow
        Write-Host ""
    } else {
        Write-Host "Load balancer hostname not available yet. Check with:" -ForegroundColor Yellow
        Write-Host "kubectl get ingress -n innovatech-app" -ForegroundColor White
    }
}

Write-Host "Use the following commands to check status:" -ForegroundColor Cyan
Write-Host "  kubectl get all -n innovatech-app" -ForegroundColor White
Write-Host "  kubectl get ingress -n innovatech-app" -ForegroundColor White
Write-Host "  kubectl logs -n innovatech-app -l app=frontend-app" -ForegroundColor White
Write-Host "  kubectl logs -n innovatech-app -l app=backend-api" -ForegroundColor White
Write-Host ""