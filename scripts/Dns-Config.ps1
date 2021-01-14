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

#Requires -Modules NetworkingDsc

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

# Formatting Computer names as FQDN
$ADServer1 = "$ADServer1NetBIOSName.$DomainDNSName"
$ADServer2 = "$ADServer2NetBIOSName.$DomainDNSName"

# Getting Password from Secrets Manager for AD Admin User
Try {
    $AdminSecret = Get-SECSecretValue -SecretId $ADAdminSecParam -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString'
} Catch [System.Exception] {
    Write-Output "Failed to get $ADAdminSecParam Secret $_"
    Exit 1
}

Try {
    $ADAdminPassword = ConvertFrom-Json -InputObject $AdminSecret -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to convert AdminSecret from JSON $_"
    Exit 1
}

# Creating Credential Object for Administrator
$AdminUserName = $ADAdminPassword.UserName
$AdminUserPW = ConvertTo-SecureString ($ADAdminPassword.Password) -AsPlainText -Force
$Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ($AdminUserName, $AdminUserPW)

# Setting Cim Sessions for Each Host
$VMSession1 = New-CimSession -Credential $Credentials -ComputerName $ADServer1 -Verbose
$VMSession2 = New-CimSession -Credential $Credentials -ComputerName $ADServer2 -Verbose

# Generating MOF File
DnsConfig -OutputPath 'C:\AWSQuickstart\DnsConfig'

# No Reboot Needed, Processing Configuration from Script utilizing pre-created Cim Sessions
Start-DscConfiguration -Path 'C:\AWSQuickstart\DnsConfig' -CimSession $VMSession1 -Wait -Verbose -Force
Start-DscConfiguration -Path 'C:\AWSQuickstart\DnsConfig' -CimSession $VMSession2 -wait -Verbose -Force