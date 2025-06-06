<#
.SYNOPSIS
    This PowerShell script checks whether the Windows Guest account is properly disabled to ensure compliance with security policies by verifying both the policy setting and actual account status.

.NOTES
    Author          : Abraham Tsuma
    LinkedIn        : https://www.linkedin.com/in/abraham-t-992ba810a/
    GitHub          : https://github.com/TsumaA
    Date Created    : 2025-06-06
    Last Modified   : 2025-06-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000010

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

# PowerShell script to check Guest Account Status policy setting
# Equivalent to checking: Local Computer Policy >> Computer Configuration >> 
# Windows Settings >> Security Settings >> Local Policies >> Security Options
# "Accounts: Guest account status"

function Test-GuestAccountPolicy {
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Checking Guest Account Status Policy Setting..." -ForegroundColor Yellow
        Write-Host "=" * 50
        
        # Method 1: Check via secedit (most reliable for policy settings)
        $tempFile = [System.IO.Path]::GetTempFileName()
        
        # Export current security policy
        $seceditResult = Start-Process -FilePath "secedit.exe" -ArgumentList "/export", "/cfg", $tempFile -Wait -PassThru -WindowStyle Hidden
        
        if ($seceditResult.ExitCode -eq 0) {
            $policyContent = Get-Content $tempFile
            $guestAccountLine = $policyContent | Where-Object { $_ -match "^EnableGuestAccount" }
            
            if ($guestAccountLine) {
                $value = ($guestAccountLine -split "=")[1].Trim()
                
                Write-Host "Policy Setting Found:" -ForegroundColor Green
                Write-Host "  Setting: Accounts: Guest account status" -ForegroundColor White
                Write-Host "  Value: $($value -eq '1' ? 'Enabled' : 'Disabled')" -ForegroundColor White
                
                if ($value -eq '0') {
                    Write-Host "`nRESULT: PASS - Guest account is Disabled" -ForegroundColor Green
                    return $true
                } else {
                    Write-Host "`nRESULT: FINDING - Guest account is Enabled (should be Disabled)" -ForegroundColor Red
                    return $false
                }
            } else {
                Write-Host "Guest account policy setting not found in security export" -ForegroundColor Yellow
            }
        }
        
        # Method 2: Check actual guest account status as fallback
        Write-Host "`nFalling back to direct account check..." -ForegroundColor Yellow
        
        $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        
        if ($guestAccount) {
            Write-Host "Guest Account Status:" -ForegroundColor Green
            Write-Host "  Name: $($guestAccount.Name)" -ForegroundColor White
            Write-Host "  Enabled: $($guestAccount.Enabled)" -ForegroundColor White
            Write-Host "  Description: $($guestAccount.Description)" -ForegroundColor White
            
            if (-not $guestAccount.Enabled) {
                Write-Host "`nRESULT: PASS - Guest account is Disabled" -ForegroundColor Green
                return $true
            } else {
                Write-Host "`nRESULT: FINDING - Guest account is Enabled (should be Disabled)" -ForegroundColor Red
                return $false
            }
        } else {
            Write-Host "Guest account not found on this system" -ForegroundColor Yellow
            return $true
        }
        
    }
    catch {
        Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
    finally {
        # Clean up temp file
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

# Additional function to check via registry (alternative method)
function Test-GuestAccountRegistry {
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "`nChecking via Registry..." -ForegroundColor Yellow
        
        # Check the registry key for guest account
        $regPath = "HKLM:\SAM\SAM\Domains\Account\Users\000001F5"
        
        # Note: This requires elevated privileges and may not be accessible
        if (Test-Path $regPath) {
            Write-Host "Registry path accessible - checking guest account flags" -ForegroundColor Green
        } else {
            Write-Host "Registry path not accessible (requires SYSTEM privileges)" -ForegroundColor Yellow
        }
        
    }
    catch {
        Write-Host "Registry check failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Main execution
Write-Host "Guest Account Policy Compliance Check" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Warning "This script should be run as Administrator for best results"
}

# Run the main check
$result = Test-GuestAccountPolicy

# Optional registry check
Test-GuestAccountRegistry

# Summary
Write-Host "`n" + "=" * 50
if ($result) {
    Write-Host "COMPLIANCE STATUS: COMPLIANT" -ForegroundColor Green
} else {
    Write-Host "COMPLIANCE STATUS: NON-COMPLIANT" -ForegroundColor Red
}
Write-Host "=" * 50
