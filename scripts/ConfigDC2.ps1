[CmdletBinding()]
# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
param(
    [Parameter(Mandatory=$true)]
    [string]$ADServer2NetBIOSName,

    [Parameter(Mandatory=$true)]
    [string]$DomainNetBIOSName,

    [Parameter(Mandatory=$true)]
    [string]$DomainDNSName,

    [Parameter(Mandatory=$true)]
    [string]$ADServer1PrivateIP,

    [Parameter(Mandatory=$true)]
    [string]$ADAdminSecParam
)

# Grabbing the Current Gateway Address in order to Static IP Correctly
$GatewayAddress = (Get-NetIPConfiguration).IPv4DefaultGateway.NextHop
# Formatting IP Address in format needed for IPAdress DSC Resource
$IPADDR = 'IP/CIDR' -replace 'IP',(Get-NetIPConfiguration).IPv4Address.IpAddress -replace 'CIDR',(Get-NetIPConfiguration).IPv4Address.PrefixLength
# Grabbing Mac Address for Primary Interface to Rename Interface
$MacAddress = (Get-NetAdapter).MacAddress
# Getting Secrets Information for Domain Administrator
$ADAdminPassword = ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId $ADAdminSecParam).SecretString
# Formatting AD Admin User to proper format for JoinDomain DSC Resources in this Script
$DomainAdmin = 'Domain\User' -replace 'Domain',$DomainNetBIOSName -replace 'User',$ADAdminPassword.UserName
# Creating Credential Object for Domain Admin User
$Credentials = (New-Object PSCredential($DomainAdmin,(ConvertTo-SecureString $ADAdminPassword.Password -AsPlainText -Force)))
# Getting the DSC Cert Encryption Thumbprint to Secure the MOF File
$DscCertThumbprint = (get-childitem -path cert:\LocalMachine\My | where { $_.subject -eq "CN=AWSQSDscEncryptCert" }).Thumbprint

# Creating Configuration Data Block that has the Certificate Information for DSC Configuration Processing
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName="*"
            CertificateFile = "C:\AWSQuickstart\publickeys\AWSQSDscPublicKey.cer"
            Thumbprint = $DscCertThumbprint
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
    param
    (
        [PSCredential] $Credentials
    )
    
    # Importing DSC Modules needed for Configuration
    Import-Module -Name PSDesiredStateConfiguration
    Import-Module -Name xActiveDirectory
    Import-Module -Name NetworkingDsc
    Import-Module -Name ActiveDirectoryCSDsc
    Import-Module -Name ComputerManagementDsc
    Import-Module -Name xDnsServer
    
    # Importing All DSC Resources needed for Configuration
    Import-DscResource -Module PSDesiredStateConfiguration
    Import-DscResource -Module NetworkingDsc
    Import-DscResource -Module xActiveDirectory
    Import-DscResource -Module ActiveDirectoryCSDsc
    Import-DscResource -Module ComputerManagementDsc
    Import-DscResource -Module xDnsServer
    
    # Node Configuration block, since processing directly on DC using localhost
    Node 'localhost' {

        # Renaming Primary Adapter in order to Static the IP for AD installation
        NetAdapterName RenameNetAdapterPrimary {
            NewName    = 'Primary'
            MacAddress = $MacAddress
        }

        # Disabling DHCP on the Primary Interface
        DhcpClient DisableDhcpClient {
            State          = 'Disabled'
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn = '[NetAdapterName]RenameNetAdapterPrimary'
        }

        # Setting the IP Address on the Primary Interface
        IPAddress SetIP {
            IPAddress = $IPADDR
            InterfaceAlias = 'Primary'
            AddressFamily = 'IPv4'
            DependsOn = '[NetAdapterName]RenameNetAdapterPrimary'
        }

        # Setting Default Gateway on Primary Interface
        DefaultGatewayAddress SetDefaultGateway {
            Address        = $GatewayAddress
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn = '[IPAddress]SetIP'
        }

        # Setting DNS Server on Primary Interface to point to DC1
        DnsServerAddress DnsServerAddress {
            Address = $ADServer1PrivateIP
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn = '[NetAdapterName]RenameNetAdapterPrimary'
        }
            
        # Wait for AD Domain to be up and running
        xWaitForADDomain WaitForPrimaryDC {
            DomainName = $DomainDnsName
            RetryCount = 600
            RetryIntervalSec = 30
            RebootRetryCount = 10
            DependsOn = '[DnsServerAddress]DnsServerAddress'
        }
        
        # Rename Computer and Join Domain
        Computer JoinDomain {
            Name = $ADServer2NetBIOSName
            DomainName = $DomainDnsName
            Credential = $Credentials
            DependsOn = "[xWaitForADDomain]WaitForPrimaryDC"
        }
        
        # Adding Needed Windows Features
        WindowsFeature DNS {
            Ensure = "Present"
            Name = "DNS"
        }
        
        WindowsFeature AD-Domain-Services {
            Ensure = "Present"
            Name = "AD-Domain-Services"
            DependsOn = "[WindowsFeature]DNS"
        }
        
        WindowsFeature DnsTools {
            Ensure = "Present"
            Name = "RSAT-DNS-Server"
            DependsOn = "[WindowsFeature]DNS"
        }
        
        WindowsFeature RSAT-AD-Tools {
            Name = 'RSAT-AD-Tools'
            Ensure = 'Present'
            DependsOn = "[WindowsFeature]AD-Domain-Services"
        }
        
        WindowsFeature RSAT-ADDS {
            Ensure = "Present"
            Name = "RSAT-ADDS"
            DependsOn = "[WindowsFeature]AD-Domain-Services"
        }
        
        WindowsFeature RSAT-ADDS-Tools {
            Name = 'RSAT-ADDS-Tools'
            Ensure = 'Present'
            DependsOn = "[WindowsFeature]RSAT-ADDS"
        }
        
        WindowsFeature RSAT-AD-AdminCenter {
            Name = 'RSAT-AD-AdminCenter'
            Ensure = 'Present'
            DependsOn = "[WindowsFeature]AD-Domain-Services"
        }

        WindowsFeature ADCS-Cert-Authority { 
               Ensure = 'Present' 
               Name = 'ADCS-Cert-Authority'
               DependsOn = '[xADDomainController]SecondaryDC' 
        }

        ADCSCertificationAuthority ADCS { 
            Ensure = 'Present'
            IsSingleInstance = 'Yes' 
            Credential = $Credentials
            CAType = 'EnterpriseRootCA' 
            DependsOn = '[WindowsFeature]ADCS-Cert-Authority'               
        }

        WindowsFeature ADCS-Web-Enrollment { 
            Ensure = 'Present' 
            Name = 'ADCS-Web-Enrollment' 
            DependsOn = '[WindowsFeature]ADCS-Cert-Authority' 
        } 

        WindowsFeature RSAT-ADCS { 
            Ensure = 'Present' 
            Name = 'RSAT-ADCS' 
            DependsOn = '[WindowsFeature]ADCS-Cert-Authority' 
        } 
        
        WindowsFeature RSAT-ADCS-Mgmt { 
            Ensure = 'Present' 
            Name = 'RSAT-ADCS-Mgmt' 
            DependsOn = '[WindowsFeature]ADCS-Cert-Authority' 
        }

        # Promoting Node as Secondary DC
        xADDomainController SecondaryDC {
            DomainName = $DomainDnsName
            DomainAdministratorCredential = $Credentials
            SafemodeAdministratorPassword = $Credentials
            DependsOn = @("[WindowsFeature]AD-Domain-Services","[Computer]JoinDomain")
        }

        ADCSWebEnrollment CertSrv { 
            Ensure = 'Present' 
            IsSingleInstance = 'Yes'
            Credential = $Credentials
            DependsOn = '[WindowsFeature]ADCS-Web-Enrollment','[ADCSCertificationAuthority]ADCS'
        }  
    }
}

# Generating MOF File
ConfigDC2 -OutputPath 'C:\AWSQuickstart\ConfigDC2' -Credentials $Credentials -ConfigurationData $ConfigurationData