<#
    .SYNOPSIS
    ConfigDC1.ps1

    .DESCRIPTION
    This script is run on the first domain controller after the final restart of forest creation.

    .EXAMPLE
    .\ConfigDC1 -ADServer1NetBIOSName 'DC1' --DomainNetBIOSName 'example' -DomainDNSName 'example.com' -ADAdminSecParam 'arn:aws:secretsmanager:us-west-2:############:secret:example' -ADAltUserSecParam 'arn:aws:secretsmanager:us-west-2:############:secret:example' -RestoreModeSecParam 'arn:aws:secretsmanager:us-west-2:############:secret:example' -SiteName 'us-east-1' -VPCCIDR '10.0.0.0/16'
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][string]$ADServer1NetBIOSName,
    [Parameter(Mandatory = $true)][string]$DomainNetBIOSName,
    [Parameter(Mandatory = $true)][string]$DomainDNSName,
    [Parameter(Mandatory = $true)][string]$ADAdminSecParam,
    [Parameter(Mandatory = $true)][string]$ADAltUserSecParam,
    [Parameter(Mandatory = $true)][string]$RestoreModeSecParam,
    [Parameter(Mandatory = $true)][string]$SiteName,
    [Parameter(Mandatory = $true)][string]$VPCCIDR
)

#Requires -Modules PSDesiredStateConfiguration, NetworkingDsc, ComputerManagementDsc, xDnsServer, ActiveDirectoryDsc

#==================================================
# Variables
#==================================================

# VPC DNS IP for DNS Forwarder
$VPCDNS = '169.254.169.253'

#==================================================
# Main
#==================================================

Write-Output "Getting network configuration $_"
Try {
    $NetIpConfig = Get-NetIPConfiguration -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to get network configuration $_"
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
    $MacAddress = Get-NetAdapter -ErrorAction Stop | Select-Object -ExpandProperty 'MacAddress'
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
$Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ($AdminUserName, $AdminUserPW)

Write-Output "Getting $ADAltUserSecParam Secret"
Try {
    $AltAdminSecret = Get-SECSecretValue -SecretId $ADAltUserSecParam -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString'
} Catch [System.Exception] {
    Write-Output "Failed to get $ADAltUserSecParam Secret $_"
    Exit 1
}

Write-Output "Converting AltAdminSecret from JSON"
Try {
    $AltUserPassword = ConvertFrom-Json -InputObject $AltAdminSecret -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to convert $AltAdminSecret from JSON $_"
    Exit 1
}

Write-Output 'Creating Credential Object for Alternate Administrator'
$AltAdminUserName = $AltUserPassword.UserName
$AltAdminUserPW = ConvertTo-SecureString ($AltUserPassword.Password) -AsPlainText -Force
$AltCredentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ($AltAdminUserName, $AltAdminUserPW)

Write-Output "Getting $RestoreModeSecParam Secret"
Try {
    $RestoreModeSecret = Get-SECSecretValue -SecretId $RestoreModeSecParam -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString'
} Catch [System.Exception] {
    Write-Output "Failed to get $RestoreModeSecParam Secret $_"
    Exit 1
}

Write-Output "Converting RestoreModeSecret from JSON"
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

Write-Output 'Caculating the name of the DNS Reverse Lookup zone'
$AClass = 0..8
$BClass = 9..16
$CClass = 17..24
$DClass = 25..32
$IP = $VPCCIDR.Split('/')[0]
[System.Collections.ArrayList]$IPArray = $IP -Split "\."
$Range = $VPCCIDR.Split('/')[1]
If ($AClass -contains $Range) {
    [System.Array]$Number = $IPArray[0] 
} Elseif ($BClass -contains $Range) {
    [System.Array]$Number = $IPArray[0, 1]
} Elseif ($CClass -contains $Range) {
    [System.Array]$Number = $IPArray[0, 1, 2] 
} Elseif ($DClass -contains $Range) {
    [System.Array]$Number = $IPArray[0, 1, 2, 3] 
} 
[System.Array]::Reverse($Number)
$IpRev = $Number -Join "."
$ZoneName = $IpRev + '.in-addr.arpa'

Write-Output 'Creating Configuration Data Block that has the Certificate Information for DSC Configuration Processing'
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName        = '*'
            CertificateFile = 'C:\AWSQuickstart\publickeys\AWSQSDscPublicKey.cer'
            Thumbprint      = $DscCertThumbprint
        },
        @{
            NodeName = 'localhost'
        }
    )
}

# PowerShell DSC Configuration Block for Domain Controller 1
Configuration ConfigDC1 {
    # Credential Objects being passed in
    Param
    (
        [Parameter(Mandatory = $true)][PSCredential]$Credentials,
        [Parameter(Mandatory = $true)][PSCredential]$AltCredentials,
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
        User AdministratorPassword {
            UserName = 'Administrator'
            Password = $Credentials
        }
        Computer NewName {
            Name = $ADServer1NetBIOSName
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
            DependsOn      = '[NetAdapterName]RenameNetAdapterPrimary'
        }
        DnsServerAddress DnsServerAddress {
            Address        = '127.0.0.1'
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[WindowsFeature]DNS'
        }
        WindowsFeature DNS {
            Ensure = 'Present'
            Name   = 'DNS'
        }
        WindowsFeature AD-Domain-Services {
            Ensure = 'Present'
            Name   = 'AD-Domain-Services'
        }
        WindowsFeature RSAT-DNS-Server {
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
            DependsOn = '[WindowsFeature]AD-Domain-Services'
        }
        WindowsFeature GPMC {
            Ensure    = 'Present'
            Name      = 'GPMC'
            DependsOn = '[WindowsFeature]AD-Domain-Services'
        }
        ADDomain PrimaryDC {
            DomainName                    = $DomainDnsName
            DomainNetBIOSName             = $DomainNetBIOSName
            Credential                    = $Credentials
            SafemodeAdministratorPassword = $RestoreCredentials
            DatabasePath                  = 'D:\NTDS'
            LogPath                       = 'D:\NTDS'
            SysvolPath                    = 'D:\SYSVOL'
            DependsOn = '[WindowsFeature]AD-Domain-Services', '[WindowsFeature]RSAT-AD-Tools'
        }
        WaitForADDomain WaitForPrimaryDC {
            DomainName = $DomainDnsName
            WaitTimeout = 600
            DependsOn = '[ADDomain]PrimaryDC'
        }
        ADReplicationSite RegionSite {
            Name                       = $SiteName
            RenameDefaultFirstSiteName = $true
            DependsOn = '[WaitForADDomain]WaitForPrimaryDC', '[Service]ActiveDirectoryWebServices'
        }
        ADReplicationSubnet VPCCIDR {
            Name      = $VPCCIDR
            Site      = $SiteName
            DependsOn = '[ADReplicationSite]RegionSite'
        }
        ADUser AlternateAdminUser {
            Ensure                 = 'Present'
            DomainName             = $DomainDnsName
            UserName               = $AltUserPassword.UserName
            Password               = $AltCredentials # Uses just the password
            DisplayName            = $AltUserPassword.UserName
            PasswordAuthentication = 'Negotiate'
            Credential             = $Credentials
            DependsOn              = '[ADDomain]PrimaryDC'
        }
        ADGroup AddAdminToDomainAdminsGroup {
            Ensure           = 'Present'
            GroupName        = 'Domain Admins'
            GroupScope       = 'Global'
            Category         = 'Security'
            MembersToInclude = @($AltUserPassword.UserName, 'Administrator')
            Credential       = $Credentials
            DependsOn        = '[ADUser]AlternateAdminUser'
        }
        ADGroup AddAdminToEnterpriseAdminsGroup {
            Ensure           = 'Present'
            GroupName        = 'Enterprise Admins'
            GroupScope       = 'Universal'
            Category         = 'Security'
            MembersToInclude = @($AltUserPassword.UserName, 'Administrator')
            Credential       = $Credentials
            DependsOn        = '[ADUser]AlternateAdminUser'
        }
        ADGroup AddAdminToSchemaAdminsGroup {
            Ensure           = 'Present'
            GroupName        = 'Schema Admins'
            GroupScope       = 'Universal'
            Category         = 'Security'
            MembersToExclude = @($AltUserPassword.UserName, 'Administrator')
            Credential       = $Credentials
            DependsOn        = '[ADUser]AlternateAdminUser'
        }
        xDnsServerForwarder ForwardtoVPCDNS {
            IsSingleInstance = 'Yes'
            IPAddresses      = $VPCDNS
        }
        xDnsServerADZone CreateReverseLookupZone {
            Ensure           = 'Present'
            Name             = $ZoneName
            DynamicUpdate    = 'Secure'
            ReplicationScope = 'Forest'
            DependsOn        = '[ADDomain]PrimaryDC'
        }
        ADOptionalFeature RecycleBin {
            FeatureName                       = 'Recycle Bin Feature'
            EnterpriseAdministratorCredential = $Credentials
            ForestFQDN                        = $DomainDnsName
            DependsOn                         = '[ADDomain]PrimaryDC'
        }
        ADKDSKey KdsKey {
            Ensure                   = 'Present'
            EffectiveTime            = ((get-date).addhours(-10))
            AllowUnsafeEffectiveTime = $True
            DependsOn                = '[ADDomain]PrimaryDC'
        }
    }
}

Write-Output 'Generating MOF File'
ConfigDC1 -OutputPath 'C:\AWSQuickstart\ConfigDC1' -Credentials $Credentials -AltCredentials $AltCredentials -RestoreCredentials $RestoreCredentials -ConfigurationData $ConfigurationData