Function New-VolumeFromRawDisk {

    #==================================================
    # Main
    #==================================================

    Write-Output 'Finding RAW Disk'
    $Counter = 0
    Do {
        Try {
            $BlankDisks = Get-Disk -ErrorAction Stop | Where-Object { $_.PartitionStyle -eq 'RAW' } | Select-Object -ExpandProperty 'Number'
        } Catch [System.Exception] {
            Write-Output "Failed to get disk $_"
            $BlankDisks = $Null
        }    
        If (-not $BlankDisks) {
            $Counter ++
            Write-Output 'RAW Disk not found sleeping 10 seconds and will try again.'
            Start-Sleep -Seconds 10
        }
    } Until ($BlankDisks -or $Counter -eq 12)

    If ($Counter -ge 12) {
        Write-Output 'RAW Disk not found exiting'
        Return
    }

    Foreach ($BlankDisk in $BlankDisks) {
        Write-Output 'Data Volume not initialized attempting to bring online'
        Try {
            Initialize-Disk -Number $BlankDisk -PartitionStyle 'GPT' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed attempting to bring Data Volume online $_"
            Exit 1
        }

        Start-Sleep -Seconds 5

        Write-Output 'Creating new partition for Data Volume'
        Try {
            $DriveLetter = New-Partition -DiskNumber $BlankDisk -AssignDriveLetter -UseMaximumSize -ErrorAction Stop | Select-Object -ExpandProperty 'DriveLetter'
        } Catch [System.Exception] {
            Write-Output "Failed creating new partition for Data Volume $_"
            Exit 1
        }

        Start-Sleep -Seconds 5

        Write-Output 'Formatting partition on Data Volume'
        Try {
            $Null = Format-Volume -DriveLetter $DriveLetter -FileSystem 'NTFS' -NewFileSystemLabel 'Data' -Confirm:$false -Force -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to format partition on Data Volume $_"
            Exit 1
        }

        Write-Output 'Turning off Data Volume indexing'
        Try {
            $Null = Get-CimInstance -ClassName 'Win32_Volume' -Filter "DriveLetter='$($DriveLetter):'" -ErrorAction Stop | Set-CimInstance -Arguments @{ IndexingEnabled = $False }
        } Catch [System.Exception] {
            Write-Output "Failed to turn off Data Volume indexing $_"
            Exit 1
        }
    }
}

Function Invoke-PreConfig {
    #==================================================
    # Main
    #==================================================
    Write-Output 'Temporarily disabling Windows Firewall'
    Try {
        Get-NetFirewallProfile -ErrorAction Stop | Set-NetFirewallProfile -Enabled False -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to disable Windows Firewall $_"
        Exit 1
    }
    
    Write-Output 'Creating file directory for DSC public cert'
    Try {
        $Null = New-Item -Path 'C:\AWSQuickstart\publickeys' -ItemType 'Directory' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create file directory for DSC public cert $_"
        Exit 1
    }
    
    Write-Output 'Creating certificate to encrypt credentials in MOF file'
    Try {
        $cert = New-SelfSignedCertificate -Type 'DocumentEncryptionCertLegacyCsp' -DnsName 'AWSQSDscEncryptCert' -HashAlgorithm 'SHA256' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create certificate to encrypt credentials in MOF file $_"
        Exit 1
    }
    
    Write-Output 'Exporting the self signed public key certificate'
    Try {
        $Null = $cert | Export-Certificate -FilePath 'C:\AWSQuickstart\publickeys\AWSQSDscPublicKey.cer' -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to copy self signed cert to publickeys directory $_"
        Exit 1
    }    
}

Function Invoke-LcmConfig {
    #==================================================
    # Main
    #==================================================

    Write-Output 'Getting the DSC cert thumbprint to secure the MOF file'
    Try {
        $DscCertThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
    } Catch [System.Exception] {
        Write-Output "Failed to get DSC cert thumbprint $_"
        Exit 1
    } 
    
    [DSCLocalConfigurationManager()]
    Configuration LCMConfig
    {
        Node 'localhost' {
            Settings {
                RefreshMode                    = 'Push'
                ConfigurationModeFrequencyMins = 15
                ActionAfterReboot              = 'StopConfiguration'                      
                RebootNodeIfNeeded             = $false
                ConfigurationMode              = 'ApplyAndAutoCorrect'
                CertificateId                  = $DscCertThumbprint  
            }
        }
    }
    
    Write-Output 'Generating MOF file for DSC LCM'
    LCMConfig -OutputPath 'C:\AWSQuickstart\LCMConfig'
        
    Write-Output 'Setting the DSC LCM configuration from the MOF generated in previous command'
    Try {
        Set-DscLocalConfigurationManager -Path 'C:\AWSQuickstart\LCMConfig' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to set LCM configuration $_"
        Exit 1
    } 
}

Function Get-EniConfig {
    #==================================================
    # Main
    #==================================================

    Write-Output 'Getting network configuration'
    Try {
        $NetIpConfig = Get-NetIPConfiguration -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get network configuration $_"
        Exit 1
    }

    Write-Output 'Grabbing the current gateway address in order to static IP correctly'
    $GatewayAddress = $NetIpConfig | Select-Object -ExpandProperty 'IPv4DefaultGateway' | Select-Object -ExpandProperty 'NextHop'

    Write-Output 'Formatting IP address in format needed for IPAdress DSC resource'
    $IpAddress = $NetIpConfig | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'IpAddress'
    $Prefix = $NetIpConfig | Select-Object -ExpandProperty 'IPv4Address' | Select-Object -ExpandProperty 'PrefixLength'
    $IpAddr = 'IP/CIDR' -replace 'IP', $IpAddress -replace 'CIDR', $Prefix

    Write-Output 'Getting MAC address'
    Try {
        $MacAddress = Get-NetAdapter -ErrorAction Stop | Select-Object -ExpandProperty 'MacAddress'
    } Catch [System.Exception] {
        Write-Output "Failed to get MAC address $_"
        Exit 1
    }

    $Output = [PSCustomObject][Ordered]@{
        'GatewayAddress' = $GatewayAddress
        'IpAddress'      = $IpAddr
        'DnsIpAddress'   = $IpAddress
        'MacAddress'     = $MacAddress
    }
    Return $Output
}

Function Get-SecretInfo {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)][String]$Domain,
        [Parameter(Mandatory = $True)][String]$SecretArn
    )

    #==================================================
    # Main
    #==================================================

    Write-Output "Getting $SecretArn Secret"
    Try {
        $SecretContent = Get-SECSecretValue -SecretId $SecretArn -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString' | ConvertFrom-Json -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get $SecretArn Secret $_"
        Exit 1
    }
       
    Write-Output 'Creating PSCredential object from Secret'
    $Username = $SecretContent.username
    $UserPassword = ConvertTo-SecureString ($SecretContent.password) -AsPlainText -Force
    $DomainCredentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ("$Domain\$Username", $UserPassword)
    $Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ($Username, $UserPassword)

    $Output = [PSCustomObject][Ordered]@{
        'Credentials'       = $Credentials
        'DomainCredentials' = $DomainCredentials
        'Username'          = $Username
        'UserPassword'      = $UserPassword
    }

    Return $Output
}

Function Invoke-DscStatusCheck {

    #==================================================
    # Main
    #==================================================

    $LCMState = Get-DscLocalConfigurationManager -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'LCMState'
    If ($LCMState -eq 'PendingConfiguration' -Or $LCMState -eq 'PendingReboot') {
        Exit 3010
    } Else {
        Write-Output 'DSC configuration completed'
    }
}

Function Set-DscConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][PSCredential]$AltAdminCredentials,
        [Parameter(Mandatory = $false)][String]$AltAdminUserName,
        [Parameter(Mandatory = $false)][PSCredential]$DaCredentials,
        [Parameter(Mandatory = $true)][ValidateSet('FirstDc', 'SecondaryDC', 'NonPromo', 'MemberServer')][string]$DeploymentType,
        [Parameter(Mandatory = $true)][string]$DomainDNSName,
        [Parameter(Mandatory = $true)][string]$DomainNetBIOSName,
        [Parameter(Mandatory = $false)][string]$ExistingDcIP01,
        [Parameter(Mandatory = $false)][string]$ExistingDcIP02,
        [Parameter(Mandatory = $true)][string]$GatewayAddress,
        [Parameter(Mandatory = $true)][string]$InstanceIP,
        [Parameter(Mandatory = $false)][string]$InstanceIPDns,
        [Parameter(Mandatory = $true)][string]$InstanceNetBIOSName,
        [Parameter(Mandatory = $false)][PSCredential]$LaCredentials,
        [Parameter(Mandatory = $true)][string]$MacAddress,
        [Parameter(Mandatory = $false)][PSCredential]$RestoreModeCredentials,
        [Parameter(Mandatory = $false)][string]$SiteName,
        [Parameter(Mandatory = $false)][string]$VPCCIDR
    )

    #==================================================
    # Variables
    #==================================================
    
    # VPC DNS IP for DNS Forwarder
    $VPCDNS = '169.254.169.253'
    
    #==================================================
    # Main
    #==================================================

    Write-Output 'Getting the DSC encryption certificate thumbprint to secure the MOF file'
    Try {
        $DscCertThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
    } Catch [System.Exception] {
        Write-Output "Failed to get DSC encryption certificate thumbprint $_"
        Exit 1
    }
    
    Write-Output 'Creating configuration data block that has the certificate information for DSC configuration processing'
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
    
    Configuration ConfigInstance {
        Import-DscResource -ModuleName 'PSDesiredStateConfiguration', 'NetworkingDsc', 'ComputerManagementDsc', 'DnsServerDsc', 'ActiveDirectoryDsc'
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
                IPAddress      = $InstanceIP
                InterfaceAlias = 'Primary'
                AddressFamily  = 'IPv4'
                DependsOn      = '[NetIPInterface]DisableDhcp'
            }
            DefaultGatewayAddress SetDefaultGateway {
                Address        = $GatewayAddress
                InterfaceAlias = 'Primary'
                AddressFamily  = 'IPv4'
                DependsOn      = '[IPAddress]SetIP'
            }
            Switch ($DeploymentType) {
                'FirstDc' {
                    DnsServerAddress DnsServerAddress {
                        Address        = '127.0.0.1', '169.254.169.253'
                        InterfaceAlias = 'Primary'
                        AddressFamily  = 'IPv4'
                        DependsOn      = '[DefaultGatewayAddress]SetDefaultGateway'
                    }
                }
                'SecondaryDC' {
                    DnsServerAddress DnsServerAddress {
                        Address        = $ExistingDcIP01, $InstanceIPDns, '127.0.0.1', '169.254.169.253'
                        InterfaceAlias = 'Primary'
                        AddressFamily  = 'IPv4'
                        DependsOn      = '[DefaultGatewayAddress]SetDefaultGateway'
                    }
                }
                'NonPromo' {
                    DnsServerAddress DnsServerAddress {
                        Address        = $ExistingDcIP01, $ExistingDcIP02, $InstanceIPDns, '127.0.0.1', '169.254.169.253'
                        InterfaceAlias = 'Primary'
                        AddressFamily  = 'IPv4'
                        DependsOn      = '[DefaultGatewayAddress]SetDefaultGateway'
                    }
                }
                'MemberServer' {
                    DnsServerAddress DnsServerAddress {
                        Address        = $ExistingDcIP01, $ExistingDcIP02, '169.254.169.253'
                        InterfaceAlias = 'Primary'
                        AddressFamily  = 'IPv4'
                        DependsOn      = '[DefaultGatewayAddress]SetDefaultGateway'
                    }
                }
            }
            DnsConnectionSuffix DnsConnectionSuffix {
                InterfaceAlias                 = 'Primary'
                ConnectionSpecificSuffix       = $DomainDNSName
                RegisterThisConnectionsAddress = $True
                UseSuffixWhenRegistering       = $False
                DependsOn                      = '[DnsServerAddress]DnsServerAddress'
            }
            WindowsFeature DnsTools {
                Ensure    = 'Present'
                Name      = 'RSAT-DNS-Server'
                DependsOn = '[DnsConnectionSuffix]DnsConnectionSuffix'
            }
            WindowsFeature RSAT-AD-Tools {
                Ensure    = 'Present'
                Name      = 'RSAT-AD-Tools'
                DependsOn = '[WindowsFeature]DnsTools'
            }
            WindowsFeature RSAT-ADDS {
                Ensure    = 'Present'
                Name      = 'RSAT-ADDS'
                DependsOn = '[WindowsFeature]RSAT-AD-Tools'
            }
            WindowsFeature GPMC {
                Ensure    = 'Present'
                Name      = 'GPMC'
                DependsOn = '[WindowsFeature]RSAT-ADDS'
            }
            If ($DeploymentType -eq 'FirstDc' -or $DeploymentType -eq 'SecondaryDC' -or $DeploymentType -eq 'NonPromo' ) {
                WindowsFeature DNS {
                    Ensure    = 'Present'
                    Name      = 'DNS'
                    DependsOn = '[WindowsFeature]GPMC'
                }
                WindowsFeature AD-Domain-Services {
                    Ensure    = 'Present'
                    Name      = 'AD-Domain-Services'
                    DependsOn = '[WindowsFeature]DNS'
                }
                Service ActiveDirectoryWebServices {
                    Name        = 'ADWS'
                    StartupType = 'Automatic'
                    State       = 'Running'
                    DependsOn   = '[WindowsFeature]AD-Domain-Services'
                }
            }
            Switch ($DeploymentType) {
                'FirstDc' {
                    Computer Rename {
                        Name      = $InstanceNetBIOSName
                        DependsOn = '[WindowsFeature]AD-Domain-Services'
                    }
                    User AdministratorPassword {
                        UserName  = 'Administrator'
                        Password  = $LaCredentials
                        DependsOn = '[Computer]Rename'
                    }
                    ADDomain PrimaryDC {
                        DomainName                    = $DomainDnsName
                        DomainNetBIOSName             = $DomainNetBIOSName
                        Credential                    = $DaCredentials
                        SafemodeAdministratorPassword = $RestoreModeCredentials
                        DatabasePath                  = 'D:\NTDS'
                        LogPath                       = 'D:\NTDS'
                        SysvolPath                    = 'D:\SYSVOL'
                        DependsOn                     = '[User]AdministratorPassword'
                    }
                    WaitForADDomain WaitForPrimaryDC {
                        DomainName  = $DomainDnsName
                        WaitTimeout = 600
                        DependsOn   = '[ADDomain]PrimaryDC'
                    }
                    ADReplicationSite RegionSite {
                        Name                       = $SiteName
                        RenameDefaultFirstSiteName = $true
                        DependsOn                  = '[WaitForADDomain]WaitForPrimaryDC', '[Service]ActiveDirectoryWebServices'
                    }
                    ADReplicationSubnet VPCCIDR {
                        Name      = $VPCCIDR
                        Site      = $SiteName
                        DependsOn = '[ADReplicationSite]RegionSite'
                    }
                    ADUser AlternateAdminUser {
                        Ensure                 = 'Present'
                        DomainName             = $DomainDnsName
                        UserName               = $AltAdminUserName
                        Password               = $AltAdminCredentials
                        DisplayName            = $AltAdminUserName
                        PasswordAuthentication = 'Negotiate'
                        UserPrincipalName      = "$AltAdminUserName@$DomainDnsName"
                        Credential             = $DaCredentials
                        DependsOn              = '[ADReplicationSite]RegionSite'
                    }
                    ADGroup AddAdminToDomainAdminsGroup {
                        Ensure           = 'Present'
                        GroupName        = 'Domain Admins'
                        GroupScope       = 'Global'
                        Category         = 'Security'
                        MembersToInclude = @($AltAdminUserName, 'Administrator')
                        Credential       = $DaCredentials
                        DependsOn        = '[ADUser]AlternateAdminUser'
                    }
                    ADGroup AddAdminToEnterpriseAdminsGroup {
                        Ensure           = 'Present'
                        GroupName        = 'Enterprise Admins'
                        GroupScope       = 'Universal'
                        Category         = 'Security'
                        MembersToInclude = @($AltAdminUserName, 'Administrator')
                        Credential       = $DaCredentials
                        DependsOn        = '[ADUser]AlternateAdminUser'
                    }
                    ADGroup AddAdminToSchemaAdminsGroup {
                        Ensure           = 'Present'
                        GroupName        = 'Schema Admins'
                        GroupScope       = 'Universal'
                        Category         = 'Security'
                        MembersToExclude = @($AltAdminUserName, 'Administrator')
                        Credential       = $DaCredentials
                        DependsOn        = '[ADUser]AlternateAdminUser'
                    }
                    DnsServerForwarder ForwardtoVPCDNS {
                        IsSingleInstance = 'Yes'
                        IPAddresses      = $VPCDNS
                        DependsOn        = '[WaitForADDomain]WaitForPrimaryDC'
                    }
                    ADOptionalFeature RecycleBin {
                        FeatureName                       = 'Recycle Bin Feature'
                        EnterpriseAdministratorCredential = $DaCredentials
                        ForestFQDN                        = $DomainDnsName
                        DependsOn                         = '[WaitForADDomain]WaitForPrimaryDC'
                    }
                    ADKDSKey KdsKey {
                        Ensure                   = 'Present'
                        EffectiveTime            = ((Get-Date).addhours(-10))
                        AllowUnsafeEffectiveTime = $True
                        DependsOn                = '[WaitForADDomain]WaitForPrimaryDC'
                    }
                }
                'SecondaryDC' {
                    WaitForADDomain WaitForPrimaryDC {
                        DomainName  = $DomainDnsName
                        Credential  = $DaCredentials
                        WaitTimeout = 600
                        DependsOn   = '[WindowsFeature]AD-Domain-Services'
                    }
                    Computer JoinDomain {
                        Name       = $InstanceNetBIOSName
                        DomainName = $DomainDnsName
                        Credential = $DaCredentials
                        DependsOn  = '[WaitForADDomain]WaitForPrimaryDC'
                    }
                    ADDomainController SecondaryDC {
                        DomainName                    = $DomainDnsName
                        Credential                    = $DaCredentials
                        SafemodeAdministratorPassword = $RestoreModeCredentials
                        DatabasePath                  = 'D:\NTDS'
                        LogPath                       = 'D:\NTDS'
                        SysvolPath                    = 'D:\SYSVOL'
                        DependsOn                     = '[Computer]JoinDomain'
                    }
                }
                'NonPromo' {
                    Computer Rename {
                        Name      = $InstanceNetBIOSName
                        DependsOn = '[WindowsFeature]AD-Domain-Services'
                    }
                }
                'MemberServer' {
                    Computer JoinDomain {
                        Name       = $InstanceNetBIOSName
                        DomainName = $DomainDnsName
                        Credential = $DaCredentials
                        DependsOn  = '[WindowsFeature]GPMC'
                    }
                }
            }
        }
    }
    Write-Output 'Generating MOF file'
    ConfigInstance -OutputPath 'C:\AWSQuickstart\ConfigInstance' -ConfigurationData $ConfigurationData
}

Function Set-DnsDscConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][switch]$AD1Deployment,
        [Parameter(Mandatory = $true)][string]$ADServer1NetBIOSName,
        [Parameter(Mandatory = $true)][string]$ADServer2NetBIOSName,
        [Parameter(Mandatory = $true)][string]$ADServer1PrivateIP,
        [Parameter(Mandatory = $true)][string]$ADServer2PrivateIP,
        [Parameter(Mandatory = $true)][PSCredential]$DaCredentials,
        [Parameter(Mandatory = $true)][string]$DomainDNSName,
        [Parameter(Mandatory = $false)][string]$VPCCIDR
    )

    #==================================================
    # Variables
    #==================================================

    If ($AD1Deployment) {
        # Caculating the name of the DNS Reverse Lookup zone
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
    }

    
    #==================================================
    # Main
    #==================================================
    
    Configuration DnsConfig {
    
        Import-DscResource -ModuleName 'NetworkingDsc', 'DnsServerDsc'
        
        Node $ADServer1 {
            DnsServerAddress DnsServerAddress {
                Address        = $ADServer2PrivateIP, $ADServer1PrivateIP, '127.0.0.1'
                InterfaceAlias = 'Primary'
                AddressFamily  = 'IPv4'
            }
            DnsConnectionSuffix DnsConnectionSuffix {
                InterfaceAlias                 = 'Primary'
                ConnectionSpecificSuffix       = (Get-ADDomain | Select-Object -ExpandProperty 'DNSRoot')
                RegisterThisConnectionsAddress = $True
                UseSuffixWhenRegistering       = $False
                DependsOn                      = '[DnsServerAddress]DnsServerAddress'
            }
            If ($AD1Deployment) {
                DnsServerADZone CreateReverseLookupZone {
                    Ensure           = 'Present'
                    Name             = $ZoneName
                    DynamicUpdate    = 'Secure'
                    ReplicationScope = 'Forest'
                    DependsOn        = '[DnsConnectionSuffix]DnsConnectionSuffix'
                }
                DnsServerScavenging SetServerScavenging {
                    DnsServer          = 'localhost'
                    ScavengingState    = $true
                    ScavengingInterval = '7.00:00:00'
                    RefreshInterval    = '7.00:00:00'
                    NoRefreshInterval  = '7.00:00:00'
                    DependsOn          = '[DnsServerADZone]CreateReverseLookupZone'
                }
            }
        }
    
        Node $ADServer2 {
            DnsServerAddress DnsServerAddress {
                Address        = $ADServer1PrivateIP, $ADServer2PrivateIP, '127.0.0.1'
                InterfaceAlias = 'Primary'
                AddressFamily  = 'IPv4'
            }
            DnsConnectionSuffix DnsConnectionSuffix {
                InterfaceAlias                 = 'Primary'
                ConnectionSpecificSuffix       = (Get-ADDomain | Select-Object -ExpandProperty 'DNSRoot')
                RegisterThisConnectionsAddress = $True
                UseSuffixWhenRegistering       = $False
            }
        }
    }
    
    Write-Output 'Formatting Computer names as FQDN'
    $ADServer1 = "$ADServer1NetBIOSName.$DomainDNSName"
    $ADServer2 = "$ADServer2NetBIOSName.$DomainDNSName"

    Write-Output 'Setting Cim Sessions for Each Host'
    Try {
        $VMSession1 = New-CimSession -Credential $DaCredentials -ComputerName $ADServer1 -Verbose -ErrorAction Stop
        $VMSession2 = New-CimSession -Credential $DaCredentials -ComputerName $ADServer2 -Verbose -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to set Cim Sessions for Each Host $_"
        Exit 1
    }
    
    Write-Output 'Generating MOF File'
    DnsConfig -OutputPath 'C:\AWSQuickstart\DnsConfig'
    
    Write-Output 'Processing Configuration from Script utilizing pre-created Cim Sessions'
    Try {
        Start-DscConfiguration -Path 'C:\AWSQuickstart\DnsConfig' -CimSession $VMSession1 -Wait -Verbose -Force
        Start-DscConfiguration -Path 'C:\AWSQuickstart\DnsConfig' -CimSession $VMSession2 -Wait -Verbose -Force
    } Catch [System.Exception] {
        Write-Output "Failed to set DSC $_"
    }
}

Function Set-PostPromoConfig {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][string]$S3BucketName,
        [Parameter(Mandatory = $true)][string]$S3BucketRegion,
        [Parameter(Mandatory = $true)][string]$S3KeyPrefix,
        [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][string]$CreateDefaultOUs,
        [Parameter(Mandatory = $true)][int]$TombstoneLifetime,
        [Parameter(Mandatory = $true)][int]$DeletedObjectLifetime
    )
    
    #==================================================
    # Variables
    #==================================================
    
    $ComputerName = $Env:ComputerName
    
    Write-Output 'Getting AD domain'
    Try {
        $Domain = Get-ADDomain -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get AD domain $_"
        Exit 1
    }

    # Future Use $DomainDNSName = $Domain | Select-Object -ExpandProperty 'DNSRoot'
    
    $BaseDn = $Domain | Select-Object -ExpandProperty 'DistinguishedName'
    $WMIFilters = @(
        @{
            FilterName        = 'PDCe Role Filter'
            FilterDescription = 'PDCe Role Filter'
            FilterExpression  = 'Select * From Win32_ComputerSystem where (DomainRole = 5)'
        },
        @{
            FilterName        = 'Non PDCe Role Filter'
            FilterDescription = 'Non PDCe Role Filter'
            FilterExpression  = 'Select * From Win32_ComputerSystem where (DomainRole <= 4)'
        }
    )
    $GPOs = @(
        @{
            BackupGpoName = 'PDCe Time Policy'
            BackUpGpoPath = 'C:\AWSQuickstart\GPOs\'
            LinkEnabled   = 'Yes'
            WMIFilterName = 'PDCe Role Filter'
            Targets       = @(
                @{
                    Location = "OU=Domain Controllers,$BaseDn"
                    Order    = '2'
                }
            )
        },
        @{
            BackupGpoName = 'NT5DS Time Policy'
            BackUpGpoPath = 'C:\AWSQuickstart\GPOs\'
            LinkEnabled   = 'Yes'
            WMIFilterName = 'Non PDCe Role Filter'
            Targets       = @(
                @{
                    Location = "OU=Domain Controllers,$BaseDn"
                    Order    = '3'
                }
            )
        }
    )
    $OUs = @(
        'Domain Elevated Accounts',
        'Domain Users',
        'Domain Computers',
        'Domain Servers',
        'Domain Service Accounts',
        'Domain Groups'
    )

    #==================================================
    # Main
    #==================================================
    
    Write-Output 'Enabling certificate auto-enrollment policy'
    Try {
        Set-CertificateAutoEnrollmentPolicy -ExpirationPercentage 10 -PolicyState 'Enabled' -EnableTemplateCheck -EnableMyStoreManagement -StoreName 'MY' -context 'Machine' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to enable certificate auto-enrollment policy $_"
    }
    
    Write-Output 'Enabling SMBv1 auditing'
    Try {
        Set-SmbServerConfiguration -AuditSmb1Access $true -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to enable SMBv1 auditing $_"
    }

    Write-Output 'Getting PDCe for domain'
    Try {
        $Pdce = Get-ADDomainController -Service 'PrimaryDC' -Discover | Select-Object -ExpandProperty 'Name'
    } Catch [System.Exception] {
        Write-Output "Failed to get PDCe $_"
        Exit 1
    }
    If ($ComputerName -eq $Pdce) {
    
        Write-Output 'Installing default CA templates'
        Try {
            & certutil.exe -InstallDefaultTemplates > $null
        } Catch [Exception] {
            Write-Output "Failed to install default CA templates $_"
        }       
    
        Write-Output 'Enabling DNS scavenging on all DNS zones'
        Set-DnsScavengingAllZones 
    
        # Future Use Write-Output 'Updating GPO Migration Table'
        # Future Use Update-PolMigTable -DomainDNSName $DomainDNSName 
    
        Write-Output 'Importing GPO WMI filters'
        Foreach ($WMIFilter in $WMIFilters) {
            Import-WMIFilter @WMIFilter
        }
    
        Write-Output 'Downloading GPO zip file'
        Try {
            $Null = Read-S3Object -BucketName $S3BucketName -Key "$($S3KeyPrefix)scripts/GPOs.zip" -File 'C:\AWSQuickstart\GPOs.zip' -Region $S3BucketRegion
        } Catch [System.Exception] {
            Write-Output "Failed to read and download GPO from S3 $_"
            Exit 1
        }
    
        Write-Output 'Unzipping GPO zip file'
        Try {
            Expand-Archive -Path 'C:\AWSQuickstart\GPOs.zip' -DestinationPath 'C:\AWSQuickstart\GPOs' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to expand GPO zip file $_"
            Exit 1
        }
    
        Write-Output 'Importing GPOs'
        Foreach ($GPO in $GPOS) {
            Import-GroupPolicy @GPO
            ForEach ($Target in $GPO.Targets) {
                Set-GroupPolicyLink -BackupGpoName $GPO.BackupGpoName -Target $Target.Location -LinkEnabled $Gpo.LinkEnabled -Order $Target.Order 
            }
        }
    
        If ($CreateDefaultOUs -eq 'Yes') {
            Write-Output 'Creating default OUs'
            Foreach ($OU in $OUs) {
                Try {
                    $OuPresent = Get-ADOrganizationalUnit -Identity "OU=$OU,$BaseDn" -ErrorAction SilentlyContinue
                } Catch {
                    $OuPresent = $Null
                }
                If (-not $OuPresent) {
                    Try {
                        New-ADOrganizationalUnit -Name $OU -Path $BaseDn -ProtectedFromAccidentalDeletion $True -ErrorAction Stop
                    } Catch [System.Exception] {
                        Write-Output "Failed to create $OU $_"
                    }
                }
            }
            Write-Output 'Setting default User and Computers container to Domain Users and Domain Computers OUs'
            Set-DefaultContainer -ComputerDN "OU=Domain Computers,$BaseDn" -UserDN "OU=Domain Users,$BaseDn" -DomainDn $BaseDn
        }
    
        If ($TombstoneLifetime -ne 180) {
            Write-Output "Setting TombstoneLifetime to $TombstoneLifetime"
            Try {
                Set-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$BaseDN" -Partition "CN=Configuration,$BaseDN" -Replace:@{'tombstonelifetime' = $TombstoneLifetime } -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to set TombstoneLifetime $_"
            }
        }
    
        If ($DeletedObjectLifetime -ne 180) {
            Write-Output "Setting DeletedObjectLifetime to $DeletedObjectLifetime"
            Try {
                Set-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$BaseDN" -Partition "CN=Configuration,$BaseDN" -Replace:@{'msDS-DeletedObjectLifetime' = $DeletedObjectLifetime } -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to set DeletedObjectLifetime $_"
            }
        }
    }
    
    Write-Output 'Running Group Policy update'
    Invoke-GPUpdate -RandomDelayInMinutes '0' -Force
    
    Write-Output 'Restarting time service'
    Restart-Service -Name 'W32Time'
    
    Write-Output 'Resyncing time service'
    & w32tm.exe /resync > $null
    
    Write-Output 'Registering DNS client'
    Register-DnsClient
}

Function Set-AD2PostConfig {   
    #==================================================
    # Main
    #==================================================
    
    Write-Output 'Enabling certificate auto-enrollment policy'
    Try {
        Set-CertificateAutoEnrollmentPolicy -ExpirationPercentage 10 -PolicyState 'Enabled' -EnableTemplateCheck -EnableMyStoreManagement -StoreName 'MY' -context 'Machine' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to enable certificate auto-enrollment policy $_"
    }
    
    Write-Output 'Enabling SMBv1 auditing'
    Try {
        Set-SmbServerConfiguration -AuditSmb1Access $true -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to enable SMBv1 auditing $_"
    }
    
    Write-Output 'Checking domain membership'
    Try {
        $AmIDomainMember = Get-CimInstance -ClassName 'Win32_ComputerSystem' -ErrorAction Stop | Select-Object -ExpandProperty 'PartOfDomain'
    } Catch [System.Exception] {
        Write-Output "Failed checking domain membership $_"
    }
    
    If ($AmIDomainMember) {
        Write-Output 'Running Group Policy update'
        Invoke-GPUpdate -RandomDelayInMinutes '0' -Force

        Write-Output 'Restarting time service'
        Restart-Service -Name 'W32Time'
        
        Write-Output 'Resyncing time service'
        & w32tm.exe /resync > $null
        
        Write-Output 'Registering DNS client'
        Register-DnsClient
    }
}

Function Set-MgmtPostConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DirectoryID,
        [Parameter(Mandatory = $true)][string]$VPCCIDR
    )
    
    #==================================================
    # Variables
    #==================================================
    
    Write-Output 'Getting VPC DNS IP'
    $Ip = $VPCCIDR.Split('/')[0]
    [System.Collections.ArrayList]$IPArray = $IP -Split "\."
    $IPArray[3] = 2
    $VPCDNS = $IPArray -Join "."
    
    #==================================================
    # Main
    #==================================================
    
    Write-Output 'Creating DNS conditional forwarder for amazonaws.com'
    Try {
        New-DSConditionalForwarder -DirectoryId $DirectoryID -DnsIpAddr $VPCDNS -RemoteDomainName 'amazonaws.com' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create DNS conditional forwarder for amazonaws.com $_"
    }
}

Function Invoke-Cleanup {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)][String]$VPCCIDR
    )

    #==================================================
    # Main
    #==================================================

    Write-Output 'Setting Windows Firewall WinRM public rule to allow VPC CIDR traffic'
    Try {
        Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress $VPCCIDR -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed allow WinRM traffic from VPC CIDR $_"
    }

    Write-Output 'Removing DSC configuration'
    Try {    
        Remove-DscConfigurationDocument -Stage 'Current' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed remove DSC configuration $_"
    }

    Write-Output 'Re-enabling Windows Firewall'
    Try {
        Get-NetFirewallProfile -ErrorAction Stop | Set-NetFirewallProfile -Enabled 'True' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed re-enable Windows Firewall $_"
    }

    Write-Output 'Removing QuickStart build files'
    Try {
        Remove-Item -Path 'C:\AWSQuickstart' -Recurse -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed remove QuickStart build files $_"
    }

    Write-Output 'Removing self signed certificate'
    Try {
        $SelfSignedThumb = Get-ChildItem -Path 'cert:\LocalMachine\My\' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
        Remove-Item -Path "cert:\LocalMachine\My\$SelfSignedThumb" -DeleteKey -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed remove self signed certificate $_"
    }
}

Function Set-DnsScavengingAllZones {

    #==================================================
    # Main
    #==================================================

    Try {
        Import-Module -Name 'DnsServer' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to import DNS PS module $_"
        Exit 1
    }
    
    Try {
        Set-DnsServerScavenging -ApplyOnAllZones -RefreshInterval '7.00:00:00' -NoRefreshInterval '7.00:00:00' -ScavengingState $True -ScavengingInterval '7.00:00:00' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to set DNS scavenging on all zones $_"
        Exit 1
    }
}

Function Get-GPWmiFilter {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)][string]$Name
    )  

    #==================================================
    # Variables
    #==================================================

    $Properties = 'msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2', 'msWMI-ID'
    $ldapFilter = "(&(objectClass=msWMI-Som)(msWMI-Name=$Name))"

    #==================================================
    # Main
    #==================================================

    Try {
        $WmiObject = Get-ADObject -LDAPFilter $ldapFilter -Properties $Properties -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get WMI Object $_"
        Exit 1
    }

    If ($WmiObject) { 
        $GpoDomain = New-Object -Type 'Microsoft.GroupPolicy.GPDomain'
        $WmiObject | ForEach-Object {
            $Path = 'MSFT_SomFilter.Domain="' + $GpoDomain.DomainName + '",ID="' + $WmiObject.Name + '"'
            $Filter = $GpoDomain.GetWmiFilter($Path)
            If ($Filter) {
                [Guid]$Guid = $_.Name.Substring(1, $_.Name.Length - 2)
                $Filter | Add-Member -MemberType 'NoteProperty' -Name 'Guid' -Value $Guid -PassThru | Add-Member -MemberType 'NoteProperty' -Name 'Content' -Value $_.'msWMI-Parm2' -PassThru
            }
        }
    }
}

Function New-GPWmiFilter {
    [CmdletBinding()] 
    Param
    (
        [Parameter(Mandatory = $True)][string]$Name,
        [Parameter(Mandatory = $True)][string]$Expression,
        [Parameter(Mandatory = $False)][string]$Description
    )

    #==================================================
    # Main
    #==================================================

    Try {
        $DefaultNamingContext = Get-ADRootDSE -ErrorAction Stop | Select-Object -ExpandProperty 'DefaultNamingContext'
    } Catch [System.Exception] {
        Write-Output "Failed to get RootDSE $_"
        Exit 1
    }

    $CreationDate = (Get-Date).ToUniversalTime().ToString('yyyyMMddhhmmss.ffffff-000')
    $GUID = "{$([System.Guid]::NewGuid())}"
    $DistinguishedName = "CN=$GUID,CN=SOM,CN=WMIPolicy,CN=System,$DefaultNamingContext"
    $Parm1 = $Description + ' '
    $Parm2 = "1;3;10;$($Expression.Length);WQL;root\CIMv2;$Expression;"

    $Attributes = @{
        'msWMI-Name'             = $Name
        'msWMI-Parm1'            = $Parm1
        'msWMI-Parm2'            = $Parm2
        'msWMI-ID'               = $GUID
        'instanceType'           = 4
        'showInAdvancedViewOnly' = 'TRUE'
        'distinguishedname'      = $DistinguishedName
        'msWMI-ChangeDate'       = $CreationDate
        'msWMI-CreationDate'     = $CreationDate
    }
    $Path = ("CN=SOM,CN=WMIPolicy,CN=System,$DefaultNamingContext")

    If ($GUID -and $DefaultNamingContext) {
        Try {
            New-ADObject -Name $GUID -Type 'msWMI-Som' -Path $Path -OtherAttributes $Attributes -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to create WMI Filter $_"
            Exit 1
        }
    }
}

Function Import-WmiFilter {
    [CmdletBinding()]
    Param (
        [String]$FilterName,
        [String]$FilterDescription,
        [String]$FilterExpression
    )

    #==================================================
    # Main
    #==================================================

    $WmiExists = Get-GPWmiFilter -Name $FilterName
    If (-Not $WmiExists) {
        New-GPWmiFilter -Name $FilterName -Description $FilterDescription -Expression $FilterExpression -ErrorAction Stop
    } Else {
        Write-Output "GPO WMI Filter '$FilterName' already exists. Skipping creation."
    }
}

Function Import-GroupPolicy {
    Param (
        [String]$BackupGpoName,
        [String]$WmiFilterName,
        [String]$BackUpGpoPath
    )
  
    #==================================================
    # Main
    #==================================================

    Try {
        $Gpo = Get-GPO -Name $BackupGpoName -ErrorAction SilentlyContinue
    } Catch [System.Exception] {
        Write-Output "Failed to get Group Policy $BackupGpoName $_"
        Exit 1
    }

    If (-Not $Gpo) {
        Try {
            $Gpo = New-GPO $BackupGpoName -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to create Group Policy $BackupGpoName $_"
            Exit 1
        }
    } Else {
        Write-Output "GPO '$BackupGpoName' already exists. Skipping creation."
    }

    If ($WmiFilterName) {
        $WmiFilter = Get-GPWmiFilter -Name $WmiFilterName -ErrorAction SilentlyContinue
        If ($WmiFilter) {
            $Gpo.WmiFilter = $WmiFilter
        } Else {
            Write-Output "WMI Filter '$WmiFilterName' does not exist."
        }
    }

    Try {
        Import-GPO -BackupGpoName $BackupGpoName -TargetName $BackupGpoName -Path $BackUpGpoPath -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to import Group Policy $BackupGpoName $_"
        Exit 1
    }
}

Function Set-GroupPolicyLink {
    Param (
        [String]$BackupGpoName,
        [String]$Target,
        [String][ValidateSet('Yes', 'No')]$LinkEnabled = 'Yes',
        [Parameter(Mandatory = $True)][Int32][ValidateRange(0, 10)]$Order
    )

    #==================================================
    # Main
    #==================================================

    Try {
        $GpLinks = Get-ADObject -Filter { DistinguishedName -eq $Target } -Properties 'gplink' -ErrorAction SilentlyContinue
    } Catch [System.Exception] {
        Write-Output "Failed to get Group Policy links for $Target $_"
        Exit 1
    }

    Try {
        $BackupGpo = Get-GPO -Name $BackupGpoName -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get GPO $BackupGpoName $_"
        Exit 1
    }

    $BackupGpoId = $BackupGpo.ID.Guid

    If ($GpLinks.gplink -notlike "*CN={$BackupGpoId},CN=Policies,CN=System,$BaseDn*") {
        Try {
            New-GPLink -Name $BackupGpoName -Target $Target -Order $Order -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to create Group Policy link for $BackupGpoName $_"
            Exit 1
        }
    } Else {
        Try {
            Set-GPLink -Name $BackupGpoName -Target $Target -LinkEnabled $LinkEnabled -Order $Order -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to set Group Policy link for $BackupGpoName $_"
            Exit 1
        }
    }
}

Function Set-DefaultContainer {
    [CmdletBinding()]
    Param (
        [String]$ComputerDN,
        [String]$UserDN,
        [String]$DomainDn
    )

    #==================================================
    # Main
    #==================================================

    Try {
        $WellKnownObjects = Get-ADObject -Identity $DomainDn -Properties 'wellKnownObjects' -ErrorAction Stop | Select-Object -ExpandProperty 'wellKnownObjects'
    } Catch [System.Exception] {
        Write-Output "Failed to get get Well Known Objects $_"
        Exit 1
    }
    $CurrentUserWko = $WellKnownObjects | Where-Object { $_ -match 'Users' }
    $CurrentComputerWko = $WellKnownObjects | Where-Object { $_ -match 'Computer' }
    If ($CurrentUserWko -and $CurrentComputerWko) {
        $DataUsers = $CurrentUserWko.split(':')
        $DataComputers = $CurrentComputerWko.split(':')
        $NewUserWko = $DataUsers[0] + ':' + $DataUsers[1] + ':' + $DataUsers[2] + ':' + $UserDN 
        $NewComputerWko = $DataComputers[0] + ':' + $DataComputers[1] + ':' + $DataComputers[2] + ':' + $ComputerDN
        Try {
            Set-ADObject $DomainDn -Add @{wellKnownObjects = $NewUserWko } -Remove @{wellKnownObjects = $CurrentUserWko } -ErrorAction Stop
            Set-ADObject $DomainDn -Add @{wellKnownObjects = $NewComputerWko } -Remove @{wellKnownObjects = $CurrentComputerWko } -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get set default user and / or computer container $_"
            Exit 1
        }
    } Else {
        & redircmp.exe $ComputerDN
        & redirusr.exe $UserDN
    }
}

Function Update-PolMigTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DomainDNSName
    )

    #==================================================
    # Main
    #==================================================

    $PolMigTablePath = 'C:\AWSQuickstart\GPOs\PolMigTable.migtable'

    Write-Output "Getting GPO migration table content $_"
    Try {
        [xml]$PolMigTable = Get-Content -Path $PolMigTablePath -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get GPO migration table content $_"
        Exit 1
    }
    #$PolMigTableContentExample = $PolMigTable.MigrationTable.Mapping | Where-Object { $_.Source -eq 'Example@model.com' }
    #$PolMigTableContentExample.destination = "Example@$DomainDNSName"
    $PolMigTable.Save($PolMigTablePath)
}