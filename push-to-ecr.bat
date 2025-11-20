@echo off
REM ECR Push Script - Works with Windows Docker Desktop
REM Save this as push-to-ecr.bat and run it

echo === Innovatech ECR Image Push ===
echo.

set AWS_REGION=eu-central-1
set AWS_ACCOUNT_ID=143858013937
set ECR_REGISTRY=%AWS_ACCOUNT_ID%.dkr.ecr.%AWS_REGION%.amazonaws.com

echo Step 1: Logging into ECR...
echo Registry: %ECR_REGISTRY%
echo.

REM This command works better in CMD than PowerShell on Windows
aws ecr get-login-password --region %AWS_REGION% | docker login --username AWS --password-stdin %ECR_REGISTRY%

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Docker login failed!
    echo.
    echo Troubleshooting:
    echo 1. Make sure Docker Desktop is running
    echo 2. Check AWS credentials: aws sts get-caller-identity
    echo 3. Try running as Administrator
    exit /b 1
)

echo SUCCESS: Logged into ECR
echo.

echo Step 2: Building backend image...
docker build -t %ECR_REGISTRY%/innovatech-backend-api:latest backend/

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Backend build failed!
    exit /b 1
)

echo SUCCESS: Backend built
echo.

echo Step 3: Pushing backend image...
docker push %ECR_REGISTRY%/innovatech-backend-api:latest

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Backend push failed!
    exit /b 1
)

echo SUCCESS: Backend pushed
echo.

echo Step 4: Building frontend image...
docker build -t %ECR_REGISTRY%/innovatech-frontend-app:latest frontend/

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Frontend build failed!
    exit /b 1
)

echo SUCCESS: Frontend built
echo.

echo Step 5: Pushing frontend image...
docker push %ECR_REGISTRY%/innovatech-frontend-app:latest

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Frontend push failed!
    exit /b 1
)

echo SUCCESS: Frontend pushed
echo.
echo ============================================
echo SUCCESS: ALL IMAGES PUSHED TO ECR!
echo ============================================
echo.
echo Images:
echo   Backend:  %ECR_REGISTRY%/innovatech-backend-api:latest
echo   Frontend: %ECR_REGISTRY%/innovatech-frontend-app:latest
echo.
echo Verify with:
echo   aws ecr list-images --repository-name innovatech-backend-api --region %AWS_REGION%
echo   aws ecr list-images --repository-name innovatech-frontend-app --region %AWS_REGION%
echo.
echo Next step: Run deployment script
echo   .\deploy-k8s.ps1
echo.
pause