[CmdletBinding()]
# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
Param (
    [Parameter(Mandatory = $true)][string]$ADServerNetBIOSName,
    [Parameter(Mandatory = $true)][string]$DomainNetBIOSName,
    [Parameter(Mandatory = $true)][string]$DomainDNSName,
    [Parameter(Mandatory = $true)][string]$ADServer1PrivateIP,
    [Parameter(Mandatory = $true)][string]$ADServer2PrivateIP
)

#Requires -Modules PSDesiredStateConfiguration, NetworkingDsc, ComputerManagementDsc, xDnsServer, ActiveDirectoryDsc

# Getting Network Configuration
Try {
    $NetIpConfig = Get-NetIPConfiguration
} Catch [System.Exception] {
    Write-Output "Failed to set network configuration $_"
    Exit 1
}

# Grabbing the Current Gateway Address in order to Static IP Correctly
$GatewayAddress = $NetIpConfig | Select-Object -ExpandProperty 'IPv4DefaultGateway' | Select-Object -ExpandProperty 'NextHop'

# Formatting IP Address in format needed for IPAdress DSC Resource
$IP = $NetIpConfig | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'IpAddress'
$Prefix = $NetIpConfig | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'PrefixLength'
$IPADDR = 'IP/CIDR' -replace 'IP', $IP -replace 'CIDR', $Prefix

# Grabbing Mac Address for Primary Interface to Rename Interface
Try {
    $MacAddress = Get-NetAdapter | Select-Object -ExpandProperty 'MacAddress'
} Catch [System.Exception] {
    Write-Output "Failed to get MAC address $_"
    Exit 1
}

# Getting the DSC Cert Encryption Thumbprint to Secure the MOF File
$DscCertThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'

# Creating Configuration Data Block that has the Certificate Information for DSC Configuration Processing
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

        # Renaming Primary Adapter in order to Static the IP for AD installation
        NetAdapterName RenameNetAdapterPrimary {
            NewName    = 'Primary'
            MacAddress = $MacAddress
        }

        # Disabling DHCP on the Primary Interface
        NetIPInterface DisableDhcp {
            Dhcp           = 'Disabled'
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[NetAdapterName]RenameNetAdapterPrimary'
        }

        # Setting the IP Address on the Primary Interface
        IPAddress SetIP {
            IPAddress      = $IPADDR
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[NetAdapterName]RenameNetAdapterPrimary'
        }

        # Setting Default Gateway on Primary Interface
        DefaultGatewayAddress SetDefaultGateway {
            Address        = $GatewayAddress
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[IPAddress]SetIP'
        }

        # Setting DNS Server on Primary Interface to point to DC1
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
        
        # Rename Computer and Join Domain
        Computer Rename {
            Name       = $ADServerNetBIOSName
            DependsOn   = '[DnsServerAddress]DnsServerAddress'
        }
        
        # Adding Needed Windows Features
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

# Generating MOF File
NonPromoConfig -OutputPath 'C:\AWSQuickstart\NonPromoConfig' -ConfigurationData $ConfigurationData