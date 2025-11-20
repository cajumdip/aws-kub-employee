# Fixed ECR Login and Push Script
# Remove quotes from ECR URL to fix 400 Bad Request error

$AWS_REGION = "eu-central-1"
$AWS_ACCOUNT_ID = "143858013937"
$ECR_REGISTRY = "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

Write-Host "=== Innovatech ECR Image Push ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Logout first (clean slate)
Write-Host "Step 1: Clearing existing Docker credentials..." -ForegroundColor Yellow
docker logout $ECR_REGISTRY 2>&1 | Out-Null
Write-Host "✅ Logged out" -ForegroundColor Green
Write-Host ""

# Step 2: Login to ECR (WITHOUT QUOTES!)
# Step 2: Login to ECR (Using cmd /c to bypass PowerShell piping issues)
Write-Host "Step 2: Logging into ECR..." -ForegroundColor Yellow
cmd /c "aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ECR_REGISTRY"

Write-Host "✅ Successfully logged into ECR" -ForegroundColor Green
Write-Host ""

# Step 3: Build and Push Backend
Write-Host "Step 3: Building and pushing backend..." -ForegroundColor Yellow
$BACKEND_IMAGE = "$ECR_REGISTRY/innovatech-backend-api:latest"

Write-Host "Building backend image..." -ForegroundColor Cyan
docker build -t $BACKEND_IMAGE backend/

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Backend build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Pushing backend image..." -ForegroundColor Cyan
docker push $BACKEND_IMAGE

if ($LASTEXITCODE -ne 0) {
    Write-Host "Backend push failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Backend image pushed successfully" -ForegroundColor Green
Write-Host ""

# Step 4: Build and Push Frontend
Write-Host "Step 4: Building and pushing frontend..." -ForegroundColor Yellow
$FRONTEND_IMAGE = "$ECR_REGISTRY/innovatech-frontend-app:latest"

Write-Host "Building frontend image..." -ForegroundColor Cyan
docker build -t $FRONTEND_IMAGE frontend/

if ($LASTEXITCODE -ne 0) {
    Write-Host "Frontend build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Pushing frontend image..." -ForegroundColor Cyan
docker push $FRONTEND_IMAGE

if ($LASTEXITCODE -ne 0) {
    Write-Host "Frontend push failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Frontend image pushed successfully" -ForegroundColor Green
Write-Host ""

# Final Status
Write-Host "============================================" -ForegroundColor Green
Write-Host "ALL IMAGES PUSHED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Images:" -ForegroundColor Yellow
Write-Host "  Backend:  $BACKEND_IMAGE" -ForegroundColor White
Write-Host "  Frontend: $FRONTEND_IMAGE" -ForegroundColor White
Write-Host ""
Write-Host "Next step: Run the deployment script" -ForegroundColor Cyan
Write-Host "  .\deploy-k8s.ps1" -ForegroundColor White
Write-Host ""