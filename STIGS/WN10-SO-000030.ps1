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
    STIG-ID         : WN10-SO-000030

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
# PowerShell script to check SCENoApplyLegacyAuditPolicy registry setting
# Checks: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy
# Required: REG_DWORD = 1

function Test-SCEAuditPolicyRegistry {
    [CmdletBinding()]
    param()
    
    # Define registry parameters
    $registryHive = "HKEY_LOCAL_MACHINE"
    $registryPath = "SYSTEM\CurrentControlSet\Control\Lsa"
    $valueName = "SCENoApplyLegacyAuditPolicy"
    $expectedType = "REG_DWORD"
    $expectedValue = 1
    
    # Full registry path for PowerShell
    $fullPath = "HKLM:\$registryPath"
    
    try {
        Write-Host "Checking SCENoApplyLegacyAuditPolicy Registry Setting..." -ForegroundColor Yellow
        Write-Host "=" * 60
        Write-Host "Registry Hive: $registryHive" -ForegroundColor White
        Write-Host "Registry Path: \$registryPath" -ForegroundColor White
        Write-Host "Value Name: $valueName" -ForegroundColor White
        Write-Host "Expected Type: $expectedType" -ForegroundColor White
        Write-Host "Expected Value: $expectedValue" -ForegroundColor White
        Write-Host ""
        
        # Check if the registry path exists
        if (-not (Test-Path $fullPath)) {
            Write-Host "FINDING: Registry path does not exist" -ForegroundColor Red
            Write-Host "Path: $fullPath" -ForegroundColor Red
            return $false
        }
        
        Write-Host "Registry path exists: $fullPath" -ForegroundColor Green
        
        # Get the registry value
        try {
            $registryValue = Get-ItemProperty -Path $fullPath -Name $valueName -ErrorAction Stop
            $currentValue = $registryValue.$valueName
            
            Write-Host "Registry value found:" -ForegroundColor Green
            Write-Host "  Current Value: $currentValue" -ForegroundColor White
            
            # Check the value type
            $valueType = (Get-Item $fullPath).GetValueKind($valueName)
            Write-Host "  Current Type: $valueType" -ForegroundColor White
            
            # Validate type
            if ($valueType -ne "DWord") {
                Write-Host "`nFINDING: Incorrect value type" -ForegroundColor Red
                Write-Host "  Expected: DWord (REG_DWORD)" -ForegroundColor Red
                Write-Host "  Current: $valueType" -ForegroundColor Red
                return $false
            }
            
            # Validate value
            if ($currentValue -ne $expectedValue) {
                Write-Host "`nFINDING: Incorrect value" -ForegroundColor Red
                Write-Host "  Expected: $expectedValue" -ForegroundColor Red
                Write-Host "  Current: $currentValue" -ForegroundColor Red
                return $false
            }
            
            # All checks passed
            Write-Host "`nPASS: Registry setting is correctly configured" -ForegroundColor Green
            return $true
            
        }
        catch [System.Management.Automation.PSArgumentException] {
            Write-Host "FINDING: Registry value '$valueName' does not exist" -ForegroundColor Red
            return $false
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            Write-Host "FINDING: Registry value '$valueName' does not exist" -ForegroundColor Red
            return $false
        }
        catch {
            Write-Host "FINDING: Error accessing registry value '$valueName'" -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
        
    }
    catch {
        Write-Host "Error occurred during registry check: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to remediate the setting (optional)
function Set-SCEAuditPolicyRegistry {
    [CmdletBinding()]
    param(
        [switch]$WhatIf
    )
    
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $valueName = "SCENoApplyLegacyAuditPolicy"
    $value = 1
    
    try {
        if ($WhatIf) {
            Write-Host "What-If: Would set registry value:" -ForegroundColor Cyan
            Write-Host "  Path: $registryPath" -ForegroundColor White
            Write-Host "  Name: $valueName" -ForegroundColor White
            Write-Host "  Value: $value" -ForegroundColor White
            Write-Host "  Type: DWord" -ForegroundColor White
            return
        }
        
        Write-Host "Setting registry value..." -ForegroundColor Yellow
        
        # Ensure the path exists
        if (-not (Test-Path $registryPath)) {
            Write-Host "Creating registry path: $registryPath" -ForegroundColor Yellow
            New-Item -Path $registryPath -Force | Out-Null
        }
        
        # Set the registry value
        Set-ItemProperty -Path $registryPath -Name $valueName -Value $value -Type DWord -Force
        
        Write-Host "Registry value set successfully:" -ForegroundColor Green
        Write-Host "  $registryPath\$valueName = $value (DWord)" -ForegroundColor Green
        
        # Verify the setting
        Write-Host "`nVerifying the change..." -ForegroundColor Yellow
        Test-SCEAuditPolicyRegistry
        
    }
    catch {
        Write-Host "Error setting registry value: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function to display detailed information about the setting
function Show-SCEAuditPolicyInfo {
    Write-Host "`nAbout SCENoApplyLegacyAuditPolicy:" -ForegroundColor Cyan
    Write-Host "=" * 40
    Write-Host "This setting controls whether the Security Configuration Engine (SCE)" -ForegroundColor White
    Write-Host "applies legacy audit policy settings or uses the newer Advanced Audit" -ForegroundColor White
    Write-Host "Policy Configuration." -ForegroundColor White
    Write-Host ""
    Write-Host "When set to 1:" -ForegroundColor Green
    Write-Host "- Prevents legacy audit policy from overriding Advanced Audit Policy" -ForegroundColor White
    Write-Host "- Ensures Advanced Audit Policy settings are maintained" -ForegroundColor White
    Write-Host "- Required for proper audit policy enforcement" -ForegroundColor White
    Write-Host ""
    Write-Host "When set to 0 or missing:" -ForegroundColor Red
    Write-Host "- Legacy audit policy may override Advanced Audit Policy" -ForegroundColor White
    Write-Host "- Can result in audit policy conflicts" -ForegroundColor White
    Write-Host "- May cause compliance issues" -ForegroundColor White
}

# Main execution
Write-Host "SCENoApplyLegacyAuditPolicy Compliance Check" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Warning "This script should be run as Administrator for reliable results"
}

# Run the main check
$result = Test-SCEAuditPolicyRegistry

# Show additional information
Show-SCEAuditPolicyInfo

# Summary
Write-Host "`n" + "=" * 60
if ($result) {
    Write-Host "COMPLIANCE STATUS: COMPLIANT" -ForegroundColor Green
    Write-Host "The registry setting is correctly configured." -ForegroundColor Green
} else {
    Write-Host "COMPLIANCE STATUS: NON-COMPLIANT (FINDING)" -ForegroundColor Red
    Write-Host "The registry setting requires attention." -ForegroundColor Red
    
    # Offer remediation
    Write-Host "`nRemediation Options:" -ForegroundColor Yellow
    Write-Host "1. Run: Set-SCEAuditPolicyRegistry -WhatIf    # Preview changes" -ForegroundColor White
    Write-Host "2. Run: Set-SCEAuditPolicyRegistry            # Apply changes" -ForegroundColor White
    Write-Host "3. Manual: Set registry value via regedit.exe" -ForegroundColor White
}
Write-Host "=" * 60

# Example usage for remediation (commented out)
<#
# Uncomment the following lines to automatically remediate the finding:
if (-not $result) {
    Write-Host "`nAttempting automatic remediation..." -ForegroundColor Yellow
    Set-SCEAuditPolicyRegistry
}
#>
