<#
    .SYNOPSIS
    AddDNSForward.ps1

    .DESCRIPTION
    This script creates and AD integrated DS Conditional Forwarder for amazonaws.com pointing to the customer’s .2.
    
    .EXAMPLE
    .\AddDNSForward.ps1 -DirectoryID 'd-926708edcb' -VPCCIDR '10.255.0.0/24'

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]
    $DirectoryID,

    [Parameter(Mandatory=$true)]
    [string]
    $VPCCIDR
)

$Ip = $VPCCIDR.Split('/')[0]
[System.Collections.ArrayList]$IPArray = $IP -Split "\."
$IPArray[3] = 2
$VPCDNS = $IPArray -Join "."

Try {
    New-DSConditionalForwarder -DirectoryId $DirectoryID -DnsIpAddr $VPCDNS -RemoteDomainName 'amazonaws.com' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to create DNS Conditional Forwarder for amazonaws.com $_"
}