# ssm-documents.tf - Department-Based Application Deployment SSM Documents
# This file defines SSM documents to install department-specific software packages
# on Windows EC2 workstations using Chocolatey package manager.

# ===== SSM Document for Common Applications =====
# Installs applications required by ALL departments
resource "aws_ssm_document" "install_common_apps" {
  name            = "${var.project_name}-install-common-apps"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: Install common applications for all departments using Chocolatey
mainSteps:
  - action: aws:runPowerShellScript
    name: InstallCommonApps
    precondition:
      StringEquals:
        - platformType
        - Windows
    inputs:
      runCommand:
        - |
          # Install Chocolatey if not already installed
          if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
              Set-ExecutionPolicy Bypass -Scope Process -Force
              [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
              Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
          }
          
          # Refresh environment variables
          $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
          
          # Install common applications
          choco install -y slack
          choco install -y googlechrome
          choco install -y thunderbird
          
          Write-Output "Common applications installed successfully"
DOC

  tags = {
    Name       = "${var.project_name}-install-common-apps"
    Department = "ALL"
  }
}

# ===== SSM Document for Engineering Department =====
resource "aws_ssm_document" "install_engineering_apps" {
  name            = "${var.project_name}-install-engineering-apps"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: Install Engineering department applications using Chocolatey
mainSteps:
  - action: aws:runPowerShellScript
    name: InstallEngineeringApps
    precondition:
      StringEquals:
        - platformType
        - Windows
    inputs:
      runCommand:
        - |
          # Install Chocolatey if not already installed
          if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
              Set-ExecutionPolicy Bypass -Scope Process -Force
              [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
              Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
          }
          
          # Refresh environment variables
          $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
          
          # Install Engineering applications
          choco install -y vscode
          choco install -y git
          choco install -y python3
          choco install -y nodejs
          choco install -y docker-desktop
          choco install -y postman
          
          Write-Output "Engineering applications installed successfully"
DOC

  tags = {
    Name       = "${var.project_name}-install-engineering-apps"
    Department = "Engineering"
  }
}

# ===== SSM Document for Marketing Department =====
resource "aws_ssm_document" "install_marketing_apps" {
  name            = "${var.project_name}-install-marketing-apps"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: Install Marketing department applications using Chocolatey
mainSteps:
  - action: aws:runPowerShellScript
    name: InstallMarketingApps
    precondition:
      StringEquals:
        - platformType
        - Windows
    inputs:
      runCommand:
        - |
          # Install Chocolatey if not already installed
          if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
              Set-ExecutionPolicy Bypass -Scope Process -Force
              [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
              Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
          }
          
          # Refresh environment variables
          $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
          
          # Install Marketing applications
          choco install -y gimp
          choco install -y inkscape
          choco install -y obs-studio
          choco install -y vlc
          
          Write-Output "Marketing applications installed successfully"
DOC

  tags = {
    Name       = "${var.project_name}-install-marketing-apps"
    Department = "Marketing"
  }
}

# ===== SSM Document for Sales Department =====
resource "aws_ssm_document" "install_sales_apps" {
  name            = "${var.project_name}-install-sales-apps"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: Install Sales department applications using Chocolatey
mainSteps:
  - action: aws:runPowerShellScript
    name: InstallSalesApps
    precondition:
      StringEquals:
        - platformType
        - Windows
    inputs:
      runCommand:
        - |
          # Install Chocolatey if not already installed
          if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
              Set-ExecutionPolicy Bypass -Scope Process -Force
              [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
              Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
          }
          
          # Refresh environment variables
          $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
          
          # Install Sales applications
          choco install -y microsoft-edge
          choco install -y zoom
          choco install -y sumatrapdf
          choco install -y libreoffice-fresh
          
          Write-Output "Sales applications installed successfully"
DOC

  tags = {
    Name       = "${var.project_name}-install-sales-apps"
    Department = "Sales"
  }
}

# ===== SSM Document for HR Department =====
resource "aws_ssm_document" "install_hr_apps" {
  name            = "${var.project_name}-install-hr-apps"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: Install HR department applications using Chocolatey
mainSteps:
  - action: aws:runPowerShellScript
    name: InstallHRApps
    precondition:
      StringEquals:
        - platformType
        - Windows
    inputs:
      runCommand:
        - |
          # Install Chocolatey if not already installed
          if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
              Set-ExecutionPolicy Bypass -Scope Process -Force
              [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
              Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
          }
          
          # Refresh environment variables
          $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
          
          # Install HR applications
          choco install -y libreoffice-fresh
          choco install -y zoom
          choco install -y sumatrapdf
          choco install -y 7zip
          
          Write-Output "HR applications installed successfully"
DOC

  tags = {
    Name       = "${var.project_name}-install-hr-apps"
    Department = "HR"
  }
}

# ===== SSM Document for Finance Department =====
resource "aws_ssm_document" "install_finance_apps" {
  name            = "${var.project_name}-install-finance-apps"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: Install Finance department applications using Chocolatey
mainSteps:
  - action: aws:runPowerShellScript
    name: InstallFinanceApps
    precondition:
      StringEquals:
        - platformType
        - Windows
    inputs:
      runCommand:
        - |
          # Install Chocolatey if not already installed
          if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
              Set-ExecutionPolicy Bypass -Scope Process -Force
              [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
              Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
          }
          
          # Refresh environment variables
          $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
          
          # Install Finance applications
          # LibreOffice Calc is included in libreoffice-fresh package
          choco install -y libreoffice-fresh
          choco install -y sumatrapdf
          choco install -y 7zip
          choco install -y keepass
          
          Write-Output "Finance applications installed successfully"
DOC

  tags = {
    Name       = "${var.project_name}-install-finance-apps"
    Department = "Finance"
  }
}

# ===== SSM Document for Operations Department =====
resource "aws_ssm_document" "install_operations_apps" {
  name            = "${var.project_name}-install-operations-apps"
  document_type   = "Command"
  document_format = "YAML"

  content = <<DOC
schemaVersion: '2.2'
description: Install Operations department applications using Chocolatey
mainSteps:
  - action: aws:runPowerShellScript
    name: InstallOperationsApps
    precondition:
      StringEquals:
        - platformType
        - Windows
    inputs:
      runCommand:
        - |
          # Install Chocolatey if not already installed
          if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
              Set-ExecutionPolicy Bypass -Scope Process -Force
              [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
              Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
          }
          
          # Refresh environment variables
          $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
          
          # Install Operations applications
          choco install -y putty
          choco install -y winscp
          choco install -y notepadplusplus
          choco install -y 7zip
          
          Write-Output "Operations applications installed successfully"
DOC

  tags = {
    Name       = "${var.project_name}-install-operations-apps"
    Department = "Operations"
  }
}
