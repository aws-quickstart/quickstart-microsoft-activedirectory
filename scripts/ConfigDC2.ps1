<#
    .SYNOPSIS
    ConfigDC2.ps1

    .DESCRIPTION
    This script is run on an additional domain controller after the final restart of forest creation.

    .EXAMPLE
    .\ConfigDC2 -ADServer2NetBIOSName 'DC2' -DomainNetBIOSName 'example' -DomainDNSName 'example.com' -ADServer1PrivateIP '10.0.0.10' -ADAdminSecParam 'arn:aws:secretsmanager:us-west-2:############:secret:example' -RestoreModeSecParam 'arn:aws:secretsmanager:us-west-2:############:secret:example'
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][string]$ADServer2NetBIOSName,
    [Parameter(Mandatory = $true)][string]$DomainNetBIOSName,
    [Parameter(Mandatory = $true)][string]$DomainDNSName,
    [Parameter(Mandatory = $true)][string]$ADServer1PrivateIP,
    [Parameter(Mandatory = $true)][string]$ADAdminSecParam,
    [Parameter(Mandatory = $true)][string]$RestoreModeSecParam
)

#Requires -Modules PSDesiredStateConfiguration, NetworkingDsc, ComputerManagementDsc, xDnsServer, ActiveDirectoryDsc

#==================================================
# Main
#==================================================

Write-Output "Getting network configuration $_"
Try {
    $NetIpConfig = Get-NetIPConfiguration
} Catch [System.Exception] {
    Write-Output "Failed to set network configuration $_"
    Exit 1
}

Write-Output 'Grabbing the Current Gateway Address in order to Static IP Correctly'
$GatewayAddress = $NetIpConfig | Select-Object -ExpandProperty 'IPv4DefaultGateway' | Select-Object -ExpandProperty 'NextHop'

Write-Output 'Formatting IP Address in format needed for IPAdress DSC Resource'
$IP = $NetIpConfig | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'IpAddress'
$Prefix = $NetIpConfig | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'PrefixLength'
$IPADDR = 'IP/CIDR' -replace 'IP', $IP -replace 'CIDR', $Prefix

Write-Output 'Getting MAC address'
Try {
    $MacAddress = Get-NetAdapter | Select-Object -ExpandProperty 'MacAddress'
} Catch [System.Exception] {
    Write-Output "Failed to get MAC address $_"
    Exit 1
}

Write-Output "Getting $ADAdminSecParam Secret"
Try {
    $AdminSecret = Get-SECSecretValue -SecretId $ADAdminSecParam -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString'
} Catch [System.Exception] {
    Write-Output "Failed to get $ADAdminSecParam Secret $_"
    Exit 1
}

Write-Output 'Converting AdminSecret from JSON'
Try {
    $ADAdminPassword = ConvertFrom-Json -InputObject $AdminSecret -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to convert $AdminSecret from JSON $_"
    Exit 1
}

Write-Output 'Creating Credential Object for Administrator'
$AdminUserName = $ADAdminPassword.UserName
$AdminUserPW = ConvertTo-SecureString ($ADAdminPassword.Password) -AsPlainText -Force
$Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ("$DomainNetBIOSName\$AdminUserName", $AdminUserPW)


Write-Output "Getting $RestoreModeSecParam Secret"
Try {
    $RestoreModeSecret = Get-SECSecretValue -SecretId $RestoreModeSecParam -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString'
} Catch [System.Exception] {
    Write-Output "Failed to get $RestoreModeSecParam Secret $_"
    Exit 1
}

Write-Output "Converting $RestoreModeSecret from JSON"
Try {
    $RestoreModePassword = ConvertFrom-Json -InputObject $RestoreModeSecret -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to convert $RestoreModeSecret from JSON $_"
    Exit 1
}

Write-Output 'Creating Credential Object for Restore Mode Password'
$RestoreUserName = $RestoreModePassword.UserName
$RestoreUserPW = ConvertTo-SecureString ($ADAdminPassword.Password) -AsPlainText -Force
$RestoreCredentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ($RestoreUserName, $RestoreUserPW)

Write-Output 'Getting the DSC Cert Encryption Thumbprint to Secure the MOF File'
Try {
    $DscCertThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
} Catch [System.Exception] {
    Write-Output "Failed to get local machine certificates $_"
    Exit 1
}

Write-Output 'Creating Configuration Data Block that has the Certificate Information for DSC Configuration Processing'
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName             = '*'
            CertificateFile      = 'C:\AWSQuickstart\publickeys\AWSQSDscPublicKey.cer'
            Thumbprint           = $DscCertThumbprint
            PSDscAllowDomainUser = $true
        },
        @{
            NodeName = 'localhost'
        }
    )
}

# PowerShell DSC Configuration Block for Domain Controller 2
Configuration ConfigDC2 {
    # Credential Objects being passed in
    Param
    (
        [Parameter(Mandatory = $true)][PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][PSCredential]$RestoreCredentials
    )
    
    # Importing All DSC Resources needed for Configuration
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration', 'NetworkingDsc', 'ComputerManagementDsc', 'xDnsServer', 'ActiveDirectoryDsc'
    
    # Node Configuration block, since processing directly on DC using localhost
    Node LocalHost {
        NetAdapterName RenameNetAdapterPrimary {
            NewName    = 'Primary'
            MacAddress = $MacAddress
        }
        NetIPInterface DisableDhcp {
            Dhcp           = 'Disabled'
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[NetAdapterName]RenameNetAdapterPrimary'
        }
        IPAddress SetIP {
            IPAddress      = $IPADDR
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[NetAdapterName]RenameNetAdapterPrimary'
        }
        DefaultGatewayAddress SetDefaultGateway {
            Address        = $GatewayAddress
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[IPAddress]SetIP'
        }
        DnsServerAddress DnsServerAddress {
            Address        = $ADServer1PrivateIP
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[NetAdapterName]RenameNetAdapterPrimary'
        }
        WaitForADDomain WaitForPrimaryDC {
            DomainName  = $DomainDnsName
            Credential = $Credentials
            WaitTimeout = 600
            DependsOn   = '[DnsServerAddress]DnsServerAddress'
        }
        Computer JoinDomain {
            Name       = $ADServer2NetBIOSName
            DomainName = $DomainDnsName
            Credential = $Credentials
            DependsOn  = '[WaitForADDomain]WaitForPrimaryDC'
        }
        WindowsFeature DNS {
            Ensure = 'Present'
            Name   = 'DNS'
        }
        WindowsFeature AD-Domain-Services {
            Ensure    = 'Present'
            Name      = 'AD-Domain-Services'
            DependsOn = '[WindowsFeature]DNS'
        }
        WindowsFeature DnsTools {
            Ensure    = 'Present'
            Name      = 'RSAT-DNS-Server'
            DependsOn = '[WindowsFeature]DNS'
        }
        WindowsFeature RSAT-AD-Tools {
            Ensure    = 'Present'
            Name      = 'RSAT-AD-Tools'
            DependsOn = '[WindowsFeature]AD-Domain-Services'
        }
        WindowsFeature RSAT-ADDS {
            Ensure    = 'Present'
            Name      = 'RSAT-ADDS'
            DependsOn = '[WindowsFeature]AD-Domain-Services'
        }
        Service ActiveDirectoryWebServices {
            Name        = "ADWS"
            StartupType = "Automatic"
            State       = "Running"
            DependsOn = "[WindowsFeature]AD-Domain-Services"
        }
        WindowsFeature GPMC {
            Ensure    = 'Present'
            Name      = 'GPMC'
            DependsOn = '[WindowsFeature]AD-Domain-Services'
        }
        ADDomainController SecondaryDC {
            DomainName                    = $DomainDnsName
            Credential                    = $Credentials
            SafemodeAdministratorPassword = $RestoreCredentials
            DatabasePath                  = 'D:\NTDS'
            LogPath                       = 'D:\NTDS'
            SysvolPath                    = 'D:\SYSVOL'
            DependsOn                     = @('[WindowsFeature]AD-Domain-Services', '[Computer]JoinDomain', '[Service]ActiveDirectoryWebServices')
        }
    }
}

Write-Output 'Generating MOF File'
ConfigDC2 -OutputPath 'C:\AWSQuickstart\ConfigDC2' -Credentials $Credentials -RestoreCredentials $RestoreCredentials -ConfigurationData $ConfigurationData