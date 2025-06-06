<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Abraham Tsuma
    LinkedIn        : https://www.linkedin.com/in/abraham-t-992ba810a/
    GitHub          : https://github.com/TsumaA
    Date Created    : 2025-06-06
    Last Modified   : 2025-06-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>

# PowerShell script to set Event Log Application MaxSize policy
# Compatible with Windows 10 (PowerShell 5.1)

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry path and values
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$valueName = "MaxSize"
$valueData = 0x00008000  # 32768 in decimal (32 KB)
$valueType = "DWord"

try {
    # Check if the registry path exists, create it if it doesn't
    if (!(Test-Path $registryPath)) {
        Write-Host "Creating registry path: $registryPath" -ForegroundColor Yellow
        New-Item -Path $registryPath -Force | Out-Null
    }
    
    # Set the registry value
    Write-Host "Setting registry value..." -ForegroundColor Green
    Set-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -Type $valueType
    
    # Verify the setting
    $currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
    if ($currentValue.$valueName -eq $valueData) {
        Write-Host "SUCCESS: Registry value set successfully!" -ForegroundColor Green
        Write-Host "Path: $registryPath" -ForegroundColor Cyan
        Write-Host "Name: $valueName" -ForegroundColor Cyan
        Write-Host "Value: $($currentValue.$valueName) (0x$($currentValue.$valueName.ToString('X8')))" -ForegroundColor Cyan
        Write-Host "Type: $valueType" -ForegroundColor Cyan
    } else {
        Write-Warning "Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "Failed to set registry value: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nNote: You may need to restart the Windows Event Log service or reboot for changes to take effect." -ForegroundColor Yellow
