<#
    .SYNOPSIS
    Invoke-TwoTierSubCaInstall.ps1

    .DESCRIPTION
    This script makes the instance an Enterpise Subordinate CA.  
    
    .EXAMPLE
    .\Invoke-TwoTierSubCaInstall -SubCaCommonName 'CA01' -SubCaKeyLength '2048' -SubCaHashAlgorithm 'SHA256' -SubCaValidityPeriodUnits '5' -ADAdminSecParam 'arn:aws:secretsmanager:us-west-2:############:secret:example-VX5fcW' -UseS3ForCRL 'Yes' -S3CRLBucketName 'examplebucketname' -DirectoryType 'AWSManaged'

#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String]$SubCaCommonName,
    [Parameter(Mandatory = $true)][ValidateSet('2048', '4096')][String]$SubCaKeyLength,
    [Parameter(Mandatory = $true)][ValidateSet('SHA256', 'SHA384', 'SHA512')][String]$SubCaHashAlgorithm,
    [Parameter(Mandatory = $true)][String]$SubCaValidityPeriodUnits,
    [Parameter(Mandatory = $true)][String]$ADAdminSecParam,
    [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL,
    [Parameter(Mandatory = $true)][String]$S3CRLBucketName,
    [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType
)

$CompName = $env:COMPUTERNAME

Write-Output 'Getting AD domain information'
Try {
    $Domain = Get-ADDomain -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to get AD domain $_"
    Exit 1
}

Write-Output 'Getting a Domain Controller to perform actions against'
Try{
    $DC = Get-ADDomainController -Discover -ForceDiscover -ErrorAction Stop | Select-Object -ExpandProperty 'HostName'
} Catch [System.Exception] {
    Write-Output "Failed to get a Domain Controller $_"
    Exit 1
}

$FQDN = $Domain | Select-Object -ExpandProperty 'DNSRoot'
$Netbios = $Domain | Select-Object -ExpandProperty 'NetBIOSName'

Write-Output "Getting $ADAdminSecParam Secret"
Try {
    $AdminSecret = Get-SECSecretValue -SecretId $ADAdminSecParam -ErrorAction Stop | Select-Object -ExpandProperty 'SecretString'
} Catch [System.Exception] {
    Write-Output "Failed to get $ADAdminSecParam Secret $_"
    Exit 1
}

Write-Output "Converting $ADAdminSecParam Secret from JSON"
Try {
    $ADAdminPassword = ConvertFrom-Json -InputObject $AdminSecret -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to convert AdminSecret from JSON $_"
    Exit 1
}

Write-Output 'Creating Credential Object for Administrator'
$AdminUserName = $ADAdminPassword.UserName
$AdminUserPW = ConvertTo-SecureString ($ADAdminPassword.Password) -AsPlainText -Force
$Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ("$Netbios\$AdminUserName", $AdminUserPW)

Write-Output 'Adding computer account to elevated permission group for install'
If ($DirectoryType -eq 'SelfManaged') {
    Try {
        Add-ADGroupMember -Identity 'Enterprise Admins' -Members (Get-ADComputer -Identity $CompName -Credential $Credentials -ErrorAction Stop | Select-Object -ExpandProperty 'DistinguishedName') -Credential $Credentials -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to add computer account to Enteprise Admins $_"
        Exit 1
    }
} Else {
    Try {
        Add-ADGroupMember -Identity 'AWS Delegated Enterprise Certificate Authority Administrators' -Members (Get-ADComputer -Identity $CompName -Credential $Credentials -ErrorAction Stop | Select-Object -ExpandProperty 'DistinguishedName') -Credential $Credentials -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to add computer account to AWS Delegated Enterprise Certificate Authority Administrators $_"
        Exit 1
    }
}

Write-Output 'Sleeping to ensure replication of group membership has completed'
Start-Sleep -Seconds 60 

Write-Output 'Clearing all SYSTEM kerberos tickets'
& Klist.exe -li 0x3e7 purge > $null
Start-Sleep -Seconds 5

If ($UseS3ForCRL -eq 'No' -and $DirectoryType -eq 'SelfManaged') {
    $Counter = 0
    Do {
        $ARecordPresent = Resolve-DnsName -Name "$CompName.$FQDN" -DnsOnly -Server $DC -ErrorAction SilentlyContinue
        If (-not $ARecordPresent) {
            $Counter ++
            Write-Output 'A record missing.'
            Register-DnsClient
            If ($Counter -gt '1') {
                Start-Sleep -Seconds 10
            }
        }
    } Until ($ARecordPresent -or $Counter -eq 12)

    If ($Counter -ge 12) {
        Write-Output 'A record never created'
        Exit 1
    }

    Write-Output 'Creating PKI CNAME record'
    $Counter = 0
    Do {
        $CnameRecordPresent = Resolve-DnsName -Name "PKI.$FQDN" -DnsOnly -Server $DC -ErrorAction SilentlyContinue
        If (-not $CnameRecordPresent) {
            $Counter ++
            Write-Output 'CNAME record missing.'
            $HostNameAlias = "$CompName.$FQDN"
            Invoke-Command -ComputerName $DC -Credential $Credentials -ScriptBlock { Add-DnsServerResourceRecordCName -Name 'PKI' -HostNameAlias $using:HostNameAlias -ZoneName $using:FQDN }
            If ($Counter -gt '1') {
                Start-Sleep -Seconds 10
            }
        }
    } Until ($CnameRecordPresent -or $Counter -eq 12)

    If ($Counter -ge 12) {
        Write-Output 'CNAME record never created'
        Exit 1
    }
}

Write-Output 'Creating PKI folders'
$Folders = @(
    'D:\Pki\Req',
    'D:\ADCS\DB',
    'D:\ADCS\Log'
)
Foreach ($Folder in $Folders) {
    $PathPresent = Test-Path -Path $Folder -ErrorAction SilentlyContinue
    If (-not $PathPresent) {
        Try {
            $Null = New-Item -Path $Folder -Type 'Directory' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to create $Folder Directory $_"
            Exit 1
        }
    } 
}

Write-Output 'Example CPS statement' | Out-File 'D:\Pki\cps.txt'

If ($UseS3ForCRL -eq 'No') {
    Write-Output 'Sharing PKI folder'
    $SharePresent = Get-SmbShare -Name 'Pki' -ErrorAction SilentlyContinue
    If (-not $SharePresent) {
        Try {
            $Null = New-Smbshare -Name 'Pki' -Path 'D:\Pki' -FullAccess 'SYSTEM', "$Netbios\Domain Admins" -ChangeAccess "$Netbios\Cert Publishers" -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to create PKI SMB Share $_"
            Exit 1
        }
    }

    Write-Output 'Creating PKI IIS virtual directory'
    $VdPresent = Get-WebVirtualDirectory -Name 'Pki'
    If (-not $VdPresent) {
        Try {
            $Null = New-WebVirtualDirectory -Site 'Default Web Site' -Name 'Pki' -PhysicalPath 'D:\Pki' -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to create IIS virtual directory  $_"
            Exit 1
        }
    }

    Write-Output 'Setting PKI IIS virtual directory requestFiltering'
    Try {
        $Null = Set-WebConfigurationProperty -Filter '/system.webServer/security/requestFiltering' -Name 'allowDoubleEscaping' -Value 'true' -PSPath 'IIS:\Sites\Default Web Site\Pki' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to set IIS requestFiltering  $_"
        Exit 1
    }

    Write-Output 'Setting PKI IIS virtual directory directoryBrowse'
    Try {
        $Null = Set-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -Name 'enabled' -Value 'true' -PSPath 'IIS:\Sites\Default Web Site\Pki' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to set IIS directoryBrowse  $_"
        Exit 1
    }

    $Principals = @(
        'ANONYMOUS LOGON',
        'EVERYONE'
    )

    Write-Output 'Setting PKI folder file system ACLs'
    $FilePath = 'D:\Pki'
    Foreach ($Princ in $Principals) {
        $Principal = New-Object -TypeName 'System.Security.Principal.NTAccount'($Princ)
        $Perms = [System.Security.AccessControl.FileSystemRights]'Read, ReadAndExecute, ListDirectory'
        $Inheritance = [System.Security.AccessControl.InheritanceFlags]::'ContainerInherit', 'ObjectInherit'
        $Propagation = [System.Security.AccessControl.PropagationFlags]::'None'
        $Access = [System.Security.AccessControl.AccessControlType]::'Allow'
        $AccessRule = New-Object -TypeName 'System.Security.AccessControl.FileSystemAccessRule'($Principal, $Perms, $Inheritance, $Propagation, $Access) 
        Try {
            $Acl = Get-Acl -Path $FilePath -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to get ACL for PKI directory  $_"
            Exit 1
        }
        $Acl.AddAccessRule($AccessRule)
        Try {
            Set-ACL -Path $FilePath -AclObject $Acl -ErrorAction Stop
        } Catch [System.Exception] {
            Write-Output "Failed to set ACL for PKI directory  $_"
            Exit 1
        }
    }

    Write-Output 'Resetting IIS'
    Try {
        & iisreset.exe > $null
    } Catch [System.Exception] {
        Write-Output "Failed to reset IIS service  $_"
        Exit 1
    }

    If ($DirectoryType -eq 'SelfManaged') {
        $URL = "URL=http://pki.$FQDN/pki/cps.txt"
    } Else {
        $URL = "URL=http://$CompName.$FQDN/pki/cps.txt"
    }
} Else {
    $BucketRegion = Get-S3BucketLocation -BucketName $S3CRLBucketName | Select-Object -ExpandProperty 'Value'
    If ($BucketRegion -eq ''){
        $S3BucketUrl = "$S3CRLBucketName.s3.amazonaws.com"
    } Else {
        $S3BucketUrl = "$S3CRLBucketName.s3-$BucketRegion.amazonaws.com"
    }
    $URL = "URL=http://$S3BucketUrl/SubCa/cps.txt"

    Write-S3Object -BucketName $S3CRLBucketName -Folder 'D:\Pki\' -KeyPrefix "$CompName\" -SearchPattern 'cps.txt' -PublicReadOnly
}

$Inf = @(
    '[Version]',
    'Signature="$Windows NT$"',
    '[PolicyStatementExtension]',
    'Policies=InternalPolicy',
    '[InternalPolicy]',
    'OID=1.2.3.4.1455.67.89.5', 
    'Notice="Legal Policy Statement"',
    $URL
    '[Certsrv_Server]',
    "RenewalKeyLength=$SubCaKeyLength",
    'RenewalValidityPeriod=Years',
    "RenewalValidityPeriodUnits=$SubCaValidityPeriodUnits",
    'CRLPeriod=Weeks',
    'CRLPeriodUnits=1',
    'CRLDeltaPeriod=Days',  
    'CRLDeltaPeriodUnits=0',
    'LoadDefaultTemplates=0',
    'AlternateSignatureAlgorithm=0',
    '[CRLDistributionPoint]',
    '[AuthorityInformationAccess]'
)

Write-Output 'Creating CAPolicy.inf'
Try {
    $Inf | Out-File -FilePath 'C:\Windows\CAPolicy.inf' -Encoding 'ascii'
} Catch [System.Exception] {
    Write-Output "Failed to create CAPolicy.inf $_"
    Exit 1
}

Write-Output 'Creating SubPkiSysvolPSDrive'
If ($DirectoryType -eq 'SelfManaged') {
    $SysvolPath = "\\$FQDN\SYSVOL\$FQDN"
} Else {
    $SysvolPath = "\\$FQDN\SYSVOL\$FQDN\Policies"
}

Try {
    $Null = New-PSDrive -Name 'SubPkiSysvolPSDrive' -PSProvider 'FileSystem' -Root $SysvolPath -Credential $Credentials -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to create SubPkiSysvolPSDrive $_"
    Exit 1
}

Write-Output 'Creating the PkiSubCA SYSVOL folder'
Try {
    $Null = New-Item -ItemType 'Directory' -Path 'SubPkiSysvolPSDrive:\PkiSubCA' -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to create PkiSubCA SYSVOL folder $_"
    Exit 1
}

Write-Output 'Copying the SYSVOL PkiRootCA Contents to local folder'
Try {
    Copy-Item -Path 'SubPkiSysvolPSDrive:\PkiRootCA\*.cr*' -Destination 'D:\Pki' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to copy PkiRootCA SYSVOL folder contents $_"
    Exit 1
}

$OrcaCert = Get-ChildItem -Path 'D:\Pki\*.crt' -ErrorAction Stop
$OrcaCertFn = $OrcaCert | Select-Object -ExpandProperty 'FullName'
$OrcaCertName = $OrcaCert | Select-Object -ExpandProperty 'Name'
$OrcaCrlFn = Get-ChildItem -Path 'D:\Pki\*.crl' | Select-Object -ExpandProperty 'FullName'
$SVolPath = "\\$FQDN\SYSVOL\$FQDN\PkiRootCA\$OrcaCertName"

Write-Output 'Publishing Offline CA Certs and CRLs'
& certutil.exe -dspublish -f $OrcaCertFn RootCA > $null
& certutil.exe -addstore -f root $OrcaCertFn > $null
& certutil.exe -addstore -f root $OrcaCrlFn > $null

Write-Output 'Installing Subordinate CA'
Try {
    Install-AdcsCertificationAuthority -CAType 'EnterpriseSubordinateCA' -CACommonName $SubCaCommonName -KeyLength $SubCaKeyLength -HashAlgorithm $SubCaHashAlgorithm -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -OutputCertRequestFile 'D:\Pki\Req\SubCa.req' -DatabaseDirectory 'D:\ADCS\DB' -LogDirectory 'D:\ADCS\Log' -Force -WarningAction SilentlyContinue -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to create install Subordinate CA $_"
}

Write-Output 'Copying SubCa.req to PkiSubCA SYSVOL folder'
Try {
    Copy-Item -Path 'D:\Pki\Req\SubCa.req' -Destination 'SubPkiSysvolPSDrive:\PkiSubCA\SubCa.req'
} Catch [System.Exception] {
    Write-Output "Failed to copy SubCa.req to PkiSubCA SYSVOL folder $_"
    Exit 1
}

Write-Output 'Removing SubPkiSysvolPSDrive'
Try {
    Remove-PSDrive -Name 'SubPkiSysvolPSDrive' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to remove SubPkiSysvolPSDrive $_"
    Exit 1
}