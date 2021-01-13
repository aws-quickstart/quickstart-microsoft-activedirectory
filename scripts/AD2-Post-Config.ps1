<#
    .SYNOPSIS
    AD2-Post-Config.ps1

    .DESCRIPTION
    This script is run on a domain controller after the final restart of forest creation.
    It sets some minor settings and cleans up the DSC configuration

    .EXAMPLE
    .\AD2-Post-Config -VPCCIDR '10.0.0.0/16'

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)][string]$VPCCIDR
)

#==================================================
# Main
#==================================================
Write-Output 'Enabling Certificate Auto-Enrollment Policy'
Try {
    Set-CertificateAutoEnrollmentPolicy -ExpirationPercentage 10 -PolicyState 'Enabled' -EnableTemplateCheck -EnableMyStoreManagement -StoreName 'MY' -Context 'Machine' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to enable Certificate Auto-Enrollment Policy $_"
}

Write-Output 'Enabling SMBv1 Auditing'
Try {
    Set-SmbServerConfiguration -AuditSmb1Access $true -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to enable SMBv1 Audit log $_"
}

Write-Output 'Re-enabling Windows Firewall'
Try {
    Get-NetFirewallProfile -ErrorAction Stop | Set-NetFirewallProfile -Enabled 'True' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to re-enable firewall $_"
}

Write-Output 'Setting Windows Firewall WinRM Public rule to allow VPC CIDR traffic'
Try {
    Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress $VPCCIDR
} Catch [System.Exception] {
    Write-Output "Failed allow WinRM Traffic from VPC CIDR $_"
}

Write-Output 'Removing DSC Configuration'
Try {    
    Remove-DscConfigurationDocument -Stage 'Current' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to remove DSC Configuration $_"
}

Write-Output 'Removing QuickStart build files'
Try {
    Remove-Item -Path 'C:\AWSQuickstart' -Recurse -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed remove QuickStart build files $_"
}

Write-Output 'Removing self signed cert'
Try {
    $SelfSignedThumb = Get-ChildItem -Path 'cert:\LocalMachine\My\' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
    Remove-Item -Path "cert:\LocalMachine\My\$SelfSignedThumb" -DeleteKey
} Catch [System.Exception] {
    Write-Output "Failed remove self signed cert $_"
}

Write-Output 'Running Group Policy update'
$AmIDomainMember = Get-CimInstance -ClassName 'Win32_ComputerSystem' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'PartOfDomain'
If ($AmIDomainMember) {
    Invoke-GPUpdate -RandomDelayInMinutes '0' -Force
}