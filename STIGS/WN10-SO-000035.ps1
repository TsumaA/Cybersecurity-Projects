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
    STIG-ID         : WN10-SO-000035

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
# Registry Compliance Check for RequireSignOrSeal
# Checks HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal

$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$valueName = "RequireSignOrSeal"
$expectedValue = 1
$expectedType = "DWord"

try {
    # Check if the registry path exists
    if (-not (Test-Path $registryPath)) {
        Write-Host "FINDING: Registry path does not exist: $registryPath" -ForegroundColor Red
        exit 1
    }

    # Try to get the registry value
    $registryValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue

    if ($registryValue -eq $null) {
        Write-Host "FINDING: Registry value '$valueName' does not exist at path: $registryPath" -ForegroundColor Red
        exit 1
    }

    # Get the actual value and type
    $actualValue = $registryValue.$valueName
    $actualType = (Get-Item $registryPath).GetValueKind($valueName)

    # Check if value matches expected
    if ($actualValue -ne $expectedValue) {
        Write-Host "FINDING: Registry value '$valueName' is set to '$actualValue' but should be '$expectedValue'" -ForegroundColor Red
        exit 1
    }

    # Check if type matches expected (optional but good practice)
    if ($actualType -ne $expectedType) {
        Write-Host "WARNING: Registry value '$valueName' type is '$actualType' but expected '$expectedType'. Value is correct but type differs." -ForegroundColor Yellow
    }

    # If we get here, everything is compliant
    Write-Host "COMPLIANT: Registry value '$valueName' is correctly configured as '$actualValue' ($actualType)" -ForegroundColor Green
    exit 0

} catch {
    Write-Host "ERROR: Failed to check registry value - $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
