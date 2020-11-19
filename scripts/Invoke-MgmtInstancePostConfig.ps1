<#
    .SYNOPSIS
    Invoke-MgmtInstancePostConfig.ps1

    .DESCRIPTION
    This script cleans up the and prepares the instance for use
    
    .EXAMPLE
    .\Invoke-MgmtInstancePostConfig

#>

[CmdletBinding()]
# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
param(
    [Parameter(Mandatory = $true)]
    [string]$DirectoryID,

    [Parameter(Mandatory = $true)]
    [string]$VPCCIDR
)

$Ip = $VPCCIDR.Split('/')[0]
[System.Collections.ArrayList]$IPArray = $IP -Split "\."
$IPArray[3] = 2
$VPCDNS = $IPArray -Join "."

Write-Output 'Creating Conditional Forwarder for amazonaws.com'
Try {
    New-DSConditionalForwarder -DirectoryId $DirectoryID -DnsIpAddr $VPCDNS -RemoteDomainName 'amazonaws.com' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to create DNS Conditional Forwarder for amazonaws.com $_"
}


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