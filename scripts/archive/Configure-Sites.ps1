[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$PublicSubnet1CIDR,

    [Parameter(Mandatory=$true)]
    [string]$PublicSubnet2CIDR,

    [Parameter(Mandatory=$true)]
    [string]$PrivateSubnet1CIDR,

    [Parameter(Mandatory=$true)]
    [string]$PrivateSubnet2CIDR,
    
    [Parameter(Mandatory=$false)]
    [string]$PublicSubnet3CIDR,

    [Parameter(Mandatory=$false)]
    [string]$PrivateSubnet3CIDR,

    [Parameter(Mandatory=$true)]
    [string]$Region   
)


$timeoutInSeconds = 300
$elapsedSeconds = 0
$intervalSeconds = 1
$startTime = Get-Date
$running = $false

try {
    While (($elapsedSeconds -lt $timeoutInSeconds )) {
        try {
            $adws = Get-Process -Name Microsoft.ActiveDirectory.WebServices
            if ($adws) {
                $ErrorActionPreference = "Stop"
                Start-Transcript -Path C:\cfn\log\$($MyInvocation.MyCommand.Name).log -Append

                Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -filter {Name -eq 'Default-First-Site-Name'} | Rename-ADObject -NewName $Region
                New-ADReplicationSubnet -Name $PublicSubnet1CIDR -Site $Region
                New-ADReplicationSubnet -Name $PublicSubnet2CIDR -Site $Region
                New-ADReplicationSubnet -Name $PrivateSubnet1CIDR -Site $Region
                New-ADReplicationSubnet -Name $PrivateSubnet2CIDR -Site $Region

                # AZ3 scenarios only; add 3rd AZ subnets to site1
                if (!$PrivateSubnet3CIDR ) {
                    echo "No 3rd Private AZ"
                } else {
                    New-ADReplicationSubnet -Name $PrivateSubnet3CIDR -Site $Region
                }

                if (!$PrivateSubnet3CIDR ) {
                    echo "No 3rd Private AZ"
                } else {
                    New-ADReplicationSubnet -Name $PublicSubnet3CIDR -Site $Region
                }

                echo "Successfully Configured the AD Sites..."
                break
            }           
        }
        catch {
            Start-Sleep -Seconds $intervalSeconds
            $elapsedSeconds = ($(Get-Date) - $startTime).TotalSeconds
            echo "Elapse Seconds" $elapsedSeconds 
            
        }
        if ($elapsedSeconds -ge $timeoutInSeconds) {
            Throw "ADWS did not start or is unreachable in $timeoutInSeconds seconds..."
        }
    }

}
catch {
    $_ | Write-AWSQuickStartException
}