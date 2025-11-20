function Run-Deployment {
    # This script automates the deployment of the EKS cluster, add-ons, 
    # and the application using Terraform and kubectl.
    
    # Check for required tools
    function Check-Tool {
        param(
            [Parameter(Mandatory=$true)][string]$Name,
            [Parameter(Mandatory=$true)][string]$FriendlyName
        )
        if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
            Write-Host "ERROR: $FriendlyName is not found. Please ensure it is installed and available in your PATH." -ForegroundColor Red
            exit 1
        }
    }

    Write-Host "--- Starting Innovatech EKS Deployment ---" -ForegroundColor Yellow
    Write-Host ""

    # Check for dependencies
    Check-Tool -Name "terraform" -FriendlyName "Terraform"
    Check-Tool -Name "aws" -FriendlyName "AWS CLI"
    Check-Tool -Name "kubectl" -FriendlyName "kubectl"
    Check-Tool -Name "helm" -FriendlyName "Helm"

    # Step 1: Initialize Terraform
    Write-Host "Step 1: Initializing Terraform..." -ForegroundColor Cyan
    terraform init

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Terraform initialization failed!" -ForegroundColor Red
        exit 1
    }

    Write-Host "Terraform init complete" -ForegroundColor Green
    Write-Host ""

    # Step 2: Validate Terraform configuration
    Write-Host "Step 2: Validating Terraform configuration..." -ForegroundColor Cyan
    terraform validate

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Terraform validation failed!" -ForegroundColor Red
        exit 1
    }

    Write-Host "Terraform validate complete" -ForegroundColor Green
    Write-Host ""
    
    # Step 3: Run Terraform plan (optional, for visibility)
    Write-Host "Step 3: Running Terraform plan (review changes)..." -ForegroundColor Cyan
    terraform plan
    Write-Host ""

    # Step 4: Run Terraform apply
    Write-Host "Step 4: Running Terraform apply..." -ForegroundColor Cyan
    terraform apply -auto-approve
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Terraform apply failed!" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Terraform apply complete" -ForegroundColor Green
    Write-Host ""
    
    # Step 5: Configure kubectl for new cluster
    Write-Host "Step 5: Configuring kubectl for new cluster..." -ForegroundColor Cyan
    # Small pause to allow EKS resources to stabilize slightly before config
    Start-Sleep -Seconds 10
    aws eks update-kubeconfig --region eu-central-1 --name innovatech-cluster
    Write-Host "kubectl configured successfully" -ForegroundColor Green
    Write-Host ""

    # Step 6: Wait for cluster nodes to be ready
    Write-Host "Step 6: Waiting for cluster nodes to be ready..." -ForegroundColor Cyan
    $timeout = 300
    $elapsed = 0
    $nodeReady = $false
    while ($elapsed -lt $timeout) {
        $nodes = kubectl get nodes 2>&1
        if ($nodes -match "Ready") {
            Write-Host "`nCluster nodes are ready" -ForegroundColor Green
            $nodeReady = $true
            break
        }
        Write-Host "." -NoNewline
        Start-Sleep -Seconds 10
        $elapsed += 10
    }
    if (-not $nodeReady) {
        Write-Host "`nERROR: Cluster nodes did not become ready within the timeout." -ForegroundColor Red
        exit 1
    }
    Write-Host ""

    # Step 7: Install CoreDNS addon
    Write-Host "Step 7: Installing CoreDNS addon..." -ForegroundColor Cyan
    $corednsExists = aws eks describe-addon --cluster-name innovatech-cluster --addon-name coredns --region eu-central-1 -ErrorAction SilentlyContinue
    if (-not $corednsExists) {
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
    $vpcCniExists = kubectl get daemonset aws-node -n kube-system -ErrorAction SilentlyContinue
    if (-not $vpcCniExists) {
        Write-Host "Installing VPC CNI..." -ForegroundColor Yellow
        kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/release-1.15/config/master/aws-k8s-cni.yaml
        Start-Sleep -Seconds 20
    } else {
        Write-Host "VPC CNI already exists" -ForegroundColor Green
    }

    # Wait for VPC CNI to be ready
    Write-Host "Waiting for VPC CNI pods..." -ForegroundColor Yellow
    kubectl wait --for=condition=ready pod -l k8s-app=aws-node -n kube-system --timeout=120s
    Write-Host "VPC CNI is ready" -ForegroundColor Green
    Write-Host ""

    # Step 9: Install AWS Load Balancer Controller
    Write-Host "Step 9: Installing AWS Load Balancer Controller..." -ForegroundColor Cyan

    # Get VPC ID
    $vpcId = (aws ec2 describe-vpcs --filters "Name=tag:Name,Values=innovatech-vpc" --query 'Vpcs[0].VpcId' --output text).Trim()
    Write-Host "VPC ID: $vpcId" -ForegroundColor Gray

    # Add Helm repo
    helm repo add eks https://aws.github.io/eks-charts 2>&1 | Out-Null
    helm repo update 2>&1 | Out-Null

    # Create service account
    $lbcRoleArn = (terraform output -raw lbc_iam_role_arn).Trim()
    Write-Host "LBC Role ARN: $lbcRoleArn" -ForegroundColor Gray

    $saYaml = @"
apiVersion: v1
kind: ServiceAccount
metadata:
  name: aws-load-balancer-controller
  namespace: kube-system
  annotations:
    eks.amazonaws.com/role-arn: $lbcRoleArn
"@
    $saYaml | kubectl apply -f -

    # Install Helm chart
    Write-Host "Installing Load Balancer Controller Helm chart..." -ForegroundColor Yellow
    helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller `
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

    Pop-Location # Return to Terraform directory

    Write-Host "Application deployment initiated" -ForegroundColor Green
    Write-Host ""

    # Step 11: Wait for application to be ready
    Write-Host "Step 11: Waiting for application pods..." -ForegroundColor Cyan
    Write-Host "Waiting for backend pods..." -ForegroundColor Yellow
    kubectl wait --for=condition=ready pod -l app=backend-api -n innovatech-app --timeout=180s
    Write-Host "Waiting for frontend pods..." -ForegroundColor Yellow
    kubectl wait --for=condition=ready pod -l app=frontend-app -n innovatech-app --timeout=180s
    Write-Host "Application pods are ready" -ForegroundColor Green
    Write-Host ""

    # Step 12: Get ingress information
    Write-Host "Step 12: Getting application URL..." -ForegroundColor Cyan
    Write-Host "Waiting for load balancer to be provisioned (30s)..." -ForegroundColor Yellow
    Start-Sleep -Seconds 30

    # Retrieve ingress hostname (retry logic recommended for production scripts, but using a simple check here)
    $lbHostname = $null
    $ingressInfo = kubectl get ingress -n innovatech-app -o json -ErrorAction Stop | ConvertFrom-Json
    if ($ingressInfo.items.Count -gt 0) {
        $ingress = $ingressInfo.items[0]
        if ($ingress.status -and $ingress.status.loadBalancer -and $ingress.status.loadBalancer.ingress -and $ingress.status.loadBalancer.ingress.Count -gt 0) {
            $lbHostname = $ingress.status.loadBalancer.ingress[0].hostname
        }
    }

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


    Write-Host "--- Deployment finished ---" -ForegroundColor Yellow
    Write-Host "Use the following commands to check status:" -ForegroundColor Cyan
    Write-Host "  kubectl get all -n innovatech-app" -ForegroundColor White
    Write-Host "  kubectl get ingress -n innovatech-app" -ForegroundColor White
    Write-Host "  kubectl logs -n innovatech-app -l app=frontend-app" -ForegroundColor White
    Write-Host "  kubectl logs -n innovatech-app -l app=backend-api" -ForegroundColor White
    Write-Host ""
}

# Execute the deployment function
Run-Deployment