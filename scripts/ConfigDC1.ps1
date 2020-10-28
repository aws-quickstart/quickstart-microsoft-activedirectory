[CmdletBinding()]
# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
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

# VPC DNS IP for DNS Forwarder
$VPCDNS = '169.254.169.253'

# Getting Network Configuration
Try {
    $NetIpConfig = Get-NetIPConfiguration -ErrorAction Stop
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
    $MacAddress = Get-NetAdapter -ErrorAction Stop | Select-Object -ExpandProperty 'MacAddress'
} Catch [System.Exception] {
    Write-Output "Failed to get MAC address $_"
    Exit 1
}

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

# Getting Password from Secrets Manager for AD Alternate User
Try {
    $AltAdminSecret = Get-SECSecretValue -SecretId $ADAltUserSecParam -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString'
} Catch [System.Exception] {
    Write-Output "Failed to get $ADAltUserSecParam Secret $_"
    Exit 1
}

Try {
    $AltUserPassword = ConvertFrom-Json -InputObject $AltAdminSecret -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to convert AltAdminSecret from JSON $_"
    Exit 1
}

# Creating Credential Object for Alternate Domain Admin
$AltAdminUserName = $AltUserPassword.UserName
$AltAdminUserPW = ConvertTo-SecureString ($AltUserPassword.Password) -AsPlainText -Force
$AltCredentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ($AltAdminUserName, $AltAdminUserPW)

# Getting Password from Secrets Manager for AD Restore Mode User
Try {
    $RestoreModeSecret = Get-SECSecretValue -SecretId $RestoreModeSecParam -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString'
} Catch [System.Exception] {
    Write-Output "Failed to get $RestoreModeSecParam Secret $_"
    Exit 1
}

Try {
    $RestoreModePassword = ConvertFrom-Json -InputObject $RestoreModeSecret -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to convert RestoreModeSecret from JSON $_"
    Exit 1
}

# Creating Credential Object for Restore Mode Password
$RestoreUserName = $RestoreModePassword.UserName
$RestoreUserPW = ConvertTo-SecureString ($ADAdminPassword.Password) -AsPlainText -Force
$RestoreCredentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ($RestoreUserName, $RestoreUserPW)

# Getting the DSC Cert Encryption Thumbprint to Secure the MOF File
Try {
    $DscCertThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
} Catch [System.Exception] {
    Write-Output "Failed to get local machine certificates $_"
    Exit 1
}

# Caculating the getting the name of the DNS Reverse Lookup zone 
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

# Creating Configuration Data Block that has the Certificate Information for DSC Configuration Processing
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

        # Renaming Primary Adapter in order to Static the IP for AD installation
        NetAdapterName RenameNetAdapterPrimary {
            NewName    = 'Primary'
            MacAddress = $MacAddress
        }

        # Changing the Local Administrator Password, this account will be a Domain Admin
        User AdministratorPassword {
            UserName = 'Administrator'
            Password = $Credentials
        }

        # Renaming Computer to ADServer2NetBIOSName Parameter
        Computer NewName {
            Name = $ADServer1NetBIOSName
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
            DependsOn      = '[NetAdapterName]RenameNetAdapterPrimary'
        }
        
        # Setting DNS Server on Primary Interface to point to itself
        DnsServerAddress DnsServerAddress {
            Address        = '127.0.0.1'
            InterfaceAlias = 'Primary'
            AddressFamily  = 'IPv4'
            DependsOn      = '[WindowsFeature]DNS'
        }

        # Adding Needed Windows Features
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
        
        # Creating Primary DC in new AD Forest
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

        # Wait for AD Domain to be up and running
        WaitForADDomain WaitForPrimaryDC {
            DomainName = $DomainDnsName
            WaitTimeout = 600
            DependsOn = '[ADDomain]PrimaryDC'
        }

        # Renaming Default AD Site to Region Name
        ADReplicationSite RegionSite {
            Name                       = $SiteName
            RenameDefaultFirstSiteName = $true
            DependsOn = '[WaitForADDomain]WaitForPrimaryDC', '[Service]ActiveDirectoryWebServices'
        }

        # Adding AZ Subnets to AD Site
        ADReplicationSubnet VPCCIDR {
            Name      = $VPCCIDR
            Site      = $SiteName
            DependsOn = '[ADReplicationSite]RegionSite'
        }
        
        # Creating Alternative AD Admin User
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
        
        # Ensuring Alternative User is added to Domain Admins Group
        ADGroup AddAdminToDomainAdminsGroup {
            Ensure           = 'Present'
            GroupName        = 'Domain Admins'
            GroupScope       = 'Global'
            Category         = 'Security'
            MembersToInclude = @($AltUserPassword.UserName, 'Administrator')
            Credential       = $Credentials
            DependsOn        = '[ADUser]AlternateAdminUser'
        }
        
        # Ensuring Alternative User is added to Enterprise Admins Group
        ADGroup AddAdminToEnterpriseAdminsGroup {
            Ensure           = 'Present'
            GroupName        = 'Enterprise Admins'
            GroupScope       = 'Universal'
            Category         = 'Security'
            MembersToInclude = @($AltUserPassword.UserName, 'Administrator')
            Credential       = $Credentials
            DependsOn        = '[ADUser]AlternateAdminUser'
        }

        # Ensuring Alternative User is added to Schema Admins Group
        ADGroup AddAdminToSchemaAdminsGroup {
            Ensure           = 'Present'
            GroupName        = 'Schema Admins'
            GroupScope       = 'Universal'
            Category         = 'Security'
            MembersToExclude = @($AltUserPassword.UserName, 'Administrator')
            Credential       = $Credentials
            DependsOn        = '[ADUser]AlternateAdminUser'
        }

        # Setting VPC DNS as a forwarder for AD DNS
        xDnsServerForwarder ForwardtoVPCDNS {
            IsSingleInstance = 'Yes'
            IPAddresses      = $VPCDNS
        }
        
        # Creating Reverse Lookup Zone based on VPC CIDR for AD DNS
        xDnsServerADZone CreateReverseLookupZone {
            Ensure           = 'Present'
            Name             = $ZoneName
            DynamicUpdate    = 'Secure'
            ReplicationScope = 'Forest'
            DependsOn        = '[ADDomain]PrimaryDC'
        }

        # Enable Recycle Bin.
        ADOptionalFeature RecycleBin {
            FeatureName                       = 'Recycle Bin Feature'
            EnterpriseAdministratorCredential = $Credentials
            ForestFQDN                        = $DomainDnsName
            DependsOn                         = '[ADDomain]PrimaryDC'
        }

        # Create KDS Root Key for managed service accounts.
        ADKDSKey KdsKey {
            Ensure                   = 'Present'
            EffectiveTime            = ((get-date).addhours(-10))
            AllowUnsafeEffectiveTime = $True
            DependsOn                = '[ADDomain]PrimaryDC'
        }
    }
}

# Generating MOF File
ConfigDC1 -OutputPath 'C:\AWSQuickstart\ConfigDC1' -Credentials $Credentials -AltCredentials $AltCredentials -RestoreCredentials $RestoreCredentials -ConfigurationData $ConfigurationData