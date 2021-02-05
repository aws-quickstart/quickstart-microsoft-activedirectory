<#
    .SYNOPSIS
    Post-Config.ps1

    .DESCRIPTION
    This script is run on a domain controller after the final restart of forest creation.
    It sets some minor settings and cleans up the DSC configuration

    .EXAMPLE
    .\Post-Config -S3BucketName 'example' -S3KeyPrefix 'prefix' -VPCCIDR 10.0.0.0/16 -CreateDefaultOUs 'Yes' -TombstoneLifetime 30 -DeletedObjectLifetime 30
#>

[CmdletBinding()]
# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
Param(
    [Parameter(Mandatory = $true)][string]$S3BucketName,
    [Parameter(Mandatory = $true)][string]$S3KeyPrefix,
    [Parameter(Mandatory = $true)][string]$VPCCIDR,
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
# Functions
#==================================================

Function Set-DnsScavengingAllZones {
    Import-Module -Name 'DnsServer'
    
    Try {
        Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval '7.00:00:00' -ErrorAction Stop
        Set-DnsServerScavenging -ApplyOnAllZones -RefreshInterval '7.00:00:00' -NoRefreshInterval '7.00:00:00' -ScavengingState $True -ScavengingInterval '7.00:00:00' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to set DNS Scavenging $_"
        Exit 1
    }
}

Function Get-GPWmiFilter {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)][string]$Name
    )  

    $Properties = 'msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2', 'msWMI-ID'
    $ldapFilter = "(&(objectClass=msWMI-Som)(msWMI-Name=$Name))"
    
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

    Try {
        $GpLinks = Get-ADObject -Filter { DistinguishedName -eq $Target } -Properties 'gplink' -ErrorAction SilentlyContinue
    } Catch [System.Exception] {
        Write-Output "Failed to get Group Policy Links for $Target $_"
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
            Write-Output "Failed to create Group Policy Link for $BackupGpoName $_"
            Exit 1
        }
    } Else {
        Try {
            Set-GPLink -Name $BackupGpoName -Target $Target -LinkEnabled $LinkEnabled -Order $Order -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to set Group Policy Link for $BackupGpoName $_"
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
            Set-ADObject $DomainDn -add @{wellKnownObjects = $NewUserWko } -Remove @{wellKnownObjects = $CurrentUserWko } -ErrorAction Stop
            Set-ADObject $DomainDn -add @{wellKnownObjects = $NewComputerWko } -Remove @{wellKnownObjects = $CurrentComputerWko } -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get set default user and or computer container $_"
            Exit 1
        }
    } Else {
        & redircmp.exe $ComputerDN
        & redirusr.exe $UserDN
    }
}

Function Update-PolMigTable {
    $FQDN = $Domain | Select-Object -ExpandProperty 'Forest'
    $PolMigTablePath = 'C:\AWSQuickstart\GPOs\PolMigTable.migtable'

    Write-Output "Getting GPO Migration Table content $_"
    Try {
        [xml]$PolMigTable = Get-Content -Path $PolMigTablePath -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to get GPO Migration Table content $_"
        Exit 1
    }
    #$PolMigTableContentExample = $PolMigTable.MigrationTable.Mapping | Where-Object { $_.Source -eq 'Example@model.com' }
    #$PolMigTableContentExample.destination = "Example@$FQDN"
    $PolMigTable.Save($PolMigTablePath)
}

#==================================================
# Main
#==================================================

Write-Output 'Enabling Certificate Auto-Enrollment Policy'
Try {
    Set-CertificateAutoEnrollmentPolicy -ExpirationPercentage 10 -PolicyState 'Enabled' -EnableTemplateCheck -EnableMyStoreManagement -StoreName 'MY' -Context 'Machine' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to enable Certificate Auto-Enrollment Policy $_"
}

Write-Output 'Enabling SMBv1 Auditing'
Try {
    Set-SmbServerConfiguration -AuditSmb1Access $true -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to enable SMBv1 Audit log $_"
}

Write-Output 'On PDCe configuring DNS scavenging, importing GPOs / WMI Filters, and installing default CA templates'
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

    Write-Output 'Enabling DNS Scavenging on all DNS zones'
    Set-DnsScavengingAllZones 

    # Future Use Write-Output 'Updating GPO Migration Table'
    # Future Use Update-PolMigTable

    Write-Output 'Importing GPO WMI filters'
    Foreach ($WMIFilter in $WMIFilters) {
        Import-WMIFilter @WMIFilter
    }

    Write-Output 'Downloading GPO Zip File'
    Try {
        $Null = Read-S3Object -BucketName $S3BucketName -Key "$($S3KeyPrefix)scripts/GPOs.zip" -File 'C:\AWSQuickstart\GPOs.zip'
    } Catch [System.Exception] {
        Write-Output "Failed to read and download GPO from S3 $_"
        Exit 1
    }

    Write-Output 'Unzipping GPO zip file'
    Try {
        Expand-Archive -Path 'C:\AWSQuickstart\GPOs.zip' -DestinationPath 'C:\AWSQuickstart\GPOs' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to expand GPO Zip $_"
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
        Write-Output 'Creating Default OUs'
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
        Write-Output 'Setting Default User and Computers Container to Domain Users and Domain Computers OUs'
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

Write-Output 'Restarting Time Service'
Restart-Service -Name 'W32Time'

Write-Output 'Resyncing Time Service'
& w32tm.exe /resync > $null

Write-Output 'Registering DNS Client'
Register-DnsClient

Write-Output 'Re-enabling Windows Firewall'
Try {
    Get-NetFirewallProfile -ErrorAction Stop | Set-NetFirewallProfile -Enabled 'True' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to re-enable firewall $_"
}

Write-Output 'Setting Windows Firewall WinRM Public rule to allow VPC CIDR traffic'
Try {
    Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress $VPCCIDR
} Catch [System.Exception] {
    Write-Output "Failed allow WinRM Traffic from VPC CIDR $_"
}

Write-Output 'Removing DSC Configuration'
Try {    
    Remove-DscConfigurationDocument -Stage 'Current' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to remove DSC Configuration $_"
}

Write-Output 'Removing QuickStart build files'
Try {
    Remove-Item -Path 'C:\AWSQuickstart' -Recurse -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed remove QuickStart build files $_"
}

Write-Output 'Removing self signed cert'
Try {
    $SelfSignedThumb = Get-ChildItem -Path 'cert:\LocalMachine\My\' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
    Remove-Item -Path "cert:\LocalMachine\My\$SelfSignedThumb" -DeleteKey
} Catch [System.Exception] {
    Write-Output "Failed remove self signed cert $_"
}