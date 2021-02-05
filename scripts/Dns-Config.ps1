<#
    .SYNOPSIS
    Dns-Config.ps1

    .DESCRIPTION
    This script is run on a domain controller after the final restart of forest creation.
    It sets some minor settings and cleans up the DSC configuration

    .EXAMPLE
    .\Dns-Config -ADServer1NetBIOSName 'DC1' -ADServer2NetBIOSName 'DC2' -ADServer1PrivateIP '10.0.0.10' -ADServer2PrivateIP '10.32.0.10' -DomainDNSName 'example.com'-ADAdminSecParam 'arn:aws:secretsmanager:us-west-2:############:secret:example'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ADServer1NetBIOSName,
    [Parameter(Mandatory=$true)][string]$ADServer2NetBIOSName,
    [Parameter(Mandatory=$true)][string]$ADServer1PrivateIP,
    [Parameter(Mandatory=$true)][string]$ADServer2PrivateIP,
    [Parameter(Mandatory=$true)][string]$DomainDNSName,
    [Parameter(Mandatory=$true)][string]$ADAdminSecParam
)

#Requires -Modules NetworkingDsc

#==================================================
# Main
#==================================================

# PowerShell DSC Configuration Block to config DNS Settings on DC1 and DC2
Configuration DnsConfig {

    # Importing All DSC Resources needed for Configuration
    Import-DscResource -ModuleName 'NetworkingDsc'
    
    # DNS Settings for First Domain Controller
    Node $ADServer1 {

        DnsServerAddress DnsServerAddress {
            Address        = $ADServer2PrivateIP, $ADServer1PrivateIP, '127.0.0.1'
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
        }
        DnsConnectionSuffix DnsConnectionSuffix {
            InterfaceAlias = 'Primary'
            ConnectionSpecificSuffix  = (Get-ADDomain | Select-Object -ExpandProperty 'DNSRoot')
            RegisterThisConnectionsAddress = $True
            UseSuffixWhenRegistering = $False
        }
    }

    # DNS Settings for Second Domain Controller
    Node $ADServer2 {
        
        DnsServerAddress DnsServerAddress {
            Address        = $ADServer1PrivateIP, $ADServer2PrivateIP, '127.0.0.1'
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
        }
        DnsConnectionSuffix DnsConnectionSuffix {
            InterfaceAlias = 'Primary'
            ConnectionSpecificSuffix  = (Get-ADDomain | Select-Object -ExpandProperty 'DNSRoot')
            RegisterThisConnectionsAddress = $True
            UseSuffixWhenRegistering = $False
        }
    }
}

Write-Output 'Formatting Computer names as FQDN'
$ADServer1 = "$ADServer1NetBIOSName.$DomainDNSName"
$ADServer2 = "$ADServer2NetBIOSName.$DomainDNSName"

Write-Output "Getting $ADAdminSecParam Secret"
Try {
    $AdminSecret = Get-SECSecretValue -SecretId $ADAdminSecParam -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString'
} Catch [System.Exception] {
    Write-Output "Failed to get $ADAdminSecParam Secret $_"
    Exit 1
}

Write-Output "Converting $AdminSecret from JSON"
Try {
    $ADAdminPassword = ConvertFrom-Json -InputObject $AdminSecret -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to convert $AdminSecret from JSON $_"
    Exit 1
}

Write-Output 'Creating Credential Object for Administrator'
$AdminUserName = $ADAdminPassword.UserName
$AdminUserPW = ConvertTo-SecureString ($ADAdminPassword.Password) -AsPlainText -Force
$Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ($AdminUserName, $AdminUserPW)

Write-Output 'Setting Cim Sessions for Each Host'
Try {
    $VMSession1 = New-CimSession -Credential $Credentials -ComputerName $ADServer1 -Verbose -ErrorAction Stop
    $VMSession2 = New-CimSession -Credential $Credentials -ComputerName $ADServer2 -Verbose -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to set Cim Sessions for Each Host $_"
    Exit 1
}

Write-Output 'Generating MOF File'
DnsConfig -OutputPath 'C:\AWSQuickstart\DnsConfig'

Write-Output 'Processing Configuration from Script utilizing pre-created Cim Sessions'
Try {
    Start-DscConfiguration -Path 'C:\AWSQuickstart\DnsConfig' -CimSession $VMSession1 -Wait -Verbose -Force
    Start-DscConfiguration -Path 'C:\AWSQuickstart\DnsConfig' -CimSession $VMSession2 -wait -Verbose -Force
} Catch [System.Exception] {
    Write-Output "Failed to set DSC $_"
}