<#
    .SYNOPSIS
    Invoke-MgmtInstancePostConfig.ps1

    .DESCRIPTION
    This script cleans up the and prepares the instance for use
    
    .EXAMPLE
    .\Invoke-MgmtInstancePostConfig

#>

Write-Output 'Removing DSC Configuration'
Try {    
    Remove-DscConfigurationDocument -Stage 'Current' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed build DSC Configuration $_"
}

Write-Output 'Re-enabling Windows Firewall'
Try {
    Get-NetFirewallProfile -ErrorAction Stop | Set-NetFirewallProfile -Enabled 'True' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed re-enable firewall $_"
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
    Remove-Item -Path "cert:\LocalMachine\My\$SelfSignedThumb" -DeleteKey -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed remove self signed cert $_"
}