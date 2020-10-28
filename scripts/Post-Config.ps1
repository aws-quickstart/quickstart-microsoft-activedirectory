<#
    .SYNOPSIS
    Post-Config.ps1

    .DESCRIPTION
    This script is run on a domain controller after the final restart of forest creation.
    It sets some minor settings and cleans up the DSC configuration

    .EXAMPLE
    .\Post-Config

#>

[CmdletBinding()]
# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
Param(
    [Parameter(Mandatory = $true)][string]$S3BucketName,
    [Parameter(Mandatory = $true)][string]$S3KeyPrefix,
    [Parameter(Mandatory = $true)][string]$VPCCIDR
)

#==================================================
# Variables
#==================================================
$ComputerName = $Env:ComputerName
$Domain = Get-ADDomain
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

#==================================================
# Functions
#==================================================
Function Set-DnsScavengingAllZones {
    Trap [System.Exception] {
        Write-Output "Failed set scavenging $_.FullyQualifiedErrorId"
        Write-Output "Failed set scavenging $_.Exception.Message"
        Write-Output "Failed set scavenging $_.ScriptStackTrace"
        Break
    }

    Import-Module -Name 'DnsServer'
    Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval '7.00:00:00'
    Set-DnsServerScavenging -ApplyOnAllZones -RefreshInterval '7.00:00:00' -NoRefreshInterval '7.00:00:00' -ScavengingState $True -ScavengingInterval '7.00:00:00'
}

Function Get-GPWmiFilter {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)][string]$Name
    )
    Trap [System.Exception] {
        Write-Output "Failed to get WMI Filter $_.FullyQualifiedErrorId"
        Write-Output "Failed to get WMI Filter $_.Exception.Message"
        Write-Output "Failed to get WMI Filter $_.ScriptStackTrace"
        Break
    }
    
    $Properties = 'msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2', 'msWMI-ID'
    $ldapFilter = "(&(objectClass=msWMI-Som)(msWMI-Name=$Name))"
    $WmiObject = Get-ADObject -LDAPFilter $ldapFilter -Properties $Properties -ErrorAction Stop
    If ($WmiObject) { 
        $GpoDomain = New-Object -Type Microsoft.GroupPolicy.GPDomain
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
    Trap [System.Exception] {
        Write-Output "Failed to create WMI Filter $_.FullyQualifiedErrorId"
        Write-Output "Failed to create WMI Filter $_.Exception.Message"
        Write-Output "Failed to create WMI Filter $_.ScriptStackTrace"
        Break
    }
    $DefaultNamingContext = (Get-ADRootDSE -ErrorAction Stop).DefaultNamingContext 
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
        New-ADObject -Name $GUID -Type 'msWMI-Som' -Path $Path -OtherAttributes $Attributes -ErrorAction Stop
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
    Trap [System.Exception] {
        Write-Output "Failed to import GPO $_.FullyQualifiedErrorId"
        Write-Output "Failed to import GPO $_.Exception.Message"
        Write-Output "Failed to import GPO $_.ScriptStackTrace"
        Break
    }
    
    $Gpo = Get-GPO -Name $BackupGpoName -ErrorAction SilentlyContinue
    If (-Not $Gpo) {
        $Gpo = New-GPO $BackupGpoName -ErrorAction Stop
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
    Import-GPO -BackupGpoName $BackupGpoName -TargetName $BackupGpoName -Path $BackUpGpoPath -ErrorAction Stop
}

Function Set-GroupPolicyLink {
    Param (
        [String]$BackupGpoName,
        [String]$Target,
        [String][ValidateSet('Yes', 'No')]$LinkEnabled = 'Yes',
        [Parameter(Mandatory = $True)][Int32][ValidateRange(0, 10)]$Order
    )
    Trap [System.Exception] {
        Write-Output "Failed to set GPO link $_.FullyQualifiedErrorId"
        Write-Output "Failed to set GPO link $_.Exception.Message"
        Write-Output "Failed to set GPO link $_.ScriptStackTrace"
        Break
    }
    $DomainInfo = Get-ADDomain -ErrorAction Stop
    $BaseDn = $DomainInfo.DistinguishedName
    $GpLinks = Get-ADObject -Filter { DistinguishedName -eq $Target } -Properties 'gplink' -ErrorAction SilentlyContinue
    $BackupGpo = Get-GPO -Name $BackupGpoName -ErrorAction Stop
    $BackupGpoId = $BackupGpo.ID.Guid
    If ($GpLinks.gplink -notlike "*CN={$BackupGpoId},CN=Policies,CN=System,$BaseDn*") {
        New-GPLink -Name $BackupGpoName -Target $Target -Order $Order -ErrorAction Stop 
    } Else {
        Set-GPLink -Name $BackupGpoName -Target $Target -LinkEnabled $LinkEnabled -Order $Order -ErrorAction Stop
    }
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
        & certutil.exe -InstallDefaultTemplates
    } Catch [Exception] {
        Write-Output "Failed to install default CA templates $_"
    }       

    Write-Output 'Enabling DNS Scavenging on all DNS zones'
    Set-DnsScavengingAllZones 

    Write-Output 'Importing GPO WMI filters'
    Foreach ($WMIFilter in $WMIFilters) {
        Import-WMIFilter @WMIFilter
    }

    Write-Output 'Downloading GPO Zip File'
    Try {
        Read-S3Object -BucketName $S3BucketName -Key "$($S3KeyPrefix)scripts/GPOs.zip" -File 'C:\AWSQuickstart\GPOs.zip'
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
}

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

Write-Output 'Running Group Policy update'
Invoke-GPUpdate -RandomDelayInMinutes '0' -Force

Write-Output 'Restarting Time Service'
Restart-Service -Name 'W32Time'

Write-Output 'Resynching Time Service'
& w32tm.exe /resync