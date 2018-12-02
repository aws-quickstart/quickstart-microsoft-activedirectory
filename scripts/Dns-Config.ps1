[CmdletBinding()]
# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
param(
    [Parameter(Mandatory=$true)]
    [string]$ADServer1NetBIOSName,
    
    [Parameter(Mandatory=$true)]
    [string]$ADServer2NetBIOSName,

    [Parameter(Mandatory=$true)]
    [string]$ADServer1PrivateIP,

    [Parameter(Mandatory=$true)]
    [string]$ADServer2PrivateIP,

    [Parameter(Mandatory=$true)]
    [string]$DomainDNSName,

    [Parameter(Mandatory=$true)]
    [string]$ADAdminSecParam
)

# PowerShell DSC Configuration Block to config DNS Settings on DC1 and DC2
Configuration DnsConfig {
    
    # Importing DSC Modules needed for Configuration
    Import-Module -Name PSDesiredStateConfiguration
    Import-Module -Name NetworkingDsc
    Import-Module -Name ComputerManagementDsc
    
    # Importing All DSC Resources needed for Configuration
    Import-DscResource -Module PSDesiredStateConfiguration
    Import-DscResource -Module NetworkingDsc
    Import-DscResource -Module ComputerManagementDsc
    
    # DNS Settings for First Domain Controller
    Node $ADServer1 {

        DnsServerAddress DnsServerAddress {
            Address        = $ADServer2PrivateIP, $ADServer1PrivateIP
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
        }
    }

    # DNS Settings for Second Domain Controller
    Node $ADServer2 {
        
        DnsServerAddress DnsServerAddress {
            Address        = $ADServer1PrivateIP, $ADServer2PrivateIP
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
        }
    }
}

# Formatting Computer names as FQDN
$ADServer1 = $ADServer1NetBIOSName + "." + $DomainDNSName
$ADServer2 = $ADServer2NetBIOSName + "." + $DomainDNSName

# Getting Password from Secrets Manager for AD Admin User
$ADAdminPassword = ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId $ADAdminSecParam).SecretString
# Creating Credential Object
$Credentials = (New-Object PSCredential($ADAdminPassword.UserName,(ConvertTo-SecureString $ADAdminPassword.Password -AsPlainText -Force)))

# Setting Cim Sessions for Each Host
$VMSession1 = New-CimSession -Credential $Credentials -ComputerName $ADServer1 -Verbose
$VMSession2 = New-CimSession -Credential $Credentials -ComputerName $ADServer2 -Verbose

# Generating MOF File
DnsConfig -OutputPath 'C:\AWSQuickstart\DnsConfig'

# No Reboot Needed, Processing Configuration from Script utilizing pre-created Cim Sessions
Start-DscConfiguration -Path 'C:\AWSQuickstart\DnsConfig' -CimSession $VMSession1 -Wait -Verbose -Force
Start-DscConfiguration -Path 'C:\AWSQuickstart\DnsConfig' -CimSession $VMSession2 -wait -Verbose -Force

