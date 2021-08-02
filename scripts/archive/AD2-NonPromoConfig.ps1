<#
    .SYNOPSIS
    AD2-NonPromoConfig.ps1

    .DESCRIPTION
    This script installs the active directory binaries but does not promote the server to a domain controller.

    .EXAMPLE
    .\AD2-NonPromoConfig -ADServerNetBIOSName 'DC3' -DomainNetBIOSName 'example' -DomainDNSName 'example.com' -ADServer1PrivateIP '10.0.0.10' -ADServer2PrivateIP '10.32.0.10'
#>


[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][string]$ADServerNetBIOSName,
    [Parameter(Mandatory = $true)][string]$DomainNetBIOSName,
    [Parameter(Mandatory = $true)][string]$DomainDNSName,
    [Parameter(Mandatory = $true)][string]$ADServer1PrivateIP,
    [Parameter(Mandatory = $true)][string]$ADServer2PrivateIP
)

#Requires -Modules PSDesiredStateConfiguration, NetworkingDsc, ComputerManagementDsc, xDnsServer, ActiveDirectoryDsc

#==================================================
# Main
#==================================================

Write-Output 'Getting network configuration'
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

Write-Output 'Getting the DSC Cert Encryption Thumbprint to Secure the MOF File'
Try {
    $DscCertThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
} Catch [System.Exception] {
    Write-Output "Failed to get DSC Cert Encryption Thumbprint $_"
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
Configuration NonPromoConfig {   
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
            Address        = $ADServer1PrivateIP, $ADServer2PrivateIP, '169.254.169.253'
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[NetAdapterName]RenameNetAdapterPrimary'
        }
        DnsConnectionSuffix DnsConnectionSuffix {
            InterfaceAlias = 'Primary'
            ConnectionSpecificSuffix  = $DomainDNSName
            RegisterThisConnectionsAddress = $True
            UseSuffixWhenRegistering = $False
        }
        Computer Rename {
            Name       = $ADServerNetBIOSName
            DependsOn   = '[DnsServerAddress]DnsServerAddress'
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
    }
}

Write-Output 'Generating MOF File'
NonPromoConfig -OutputPath 'C:\AWSQuickstart\NonPromoConfig' -ConfigurationData $ConfigurationData