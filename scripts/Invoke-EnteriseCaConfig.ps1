<#
    .SYNOPSIS
    Invoke-EnteriseCaConfig.ps1

    .DESCRIPTION
    This script make the instance an Enterprise CA along with hosting the CRL in IIS.  
    
    .EXAMPLE
    .\Invoke-EnteriseCaConfig -EntCaCommonName 'CA01' -EntCaKeyLength '2048' -EntCaHashAlgorithm 'SHA256' -EntCaValidityPeriodUnits '5' -ADAdminSecParam 'arn:aws:secretsmanager:us-west-2:############:secret:example-VX5fcW'

#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String]$EntCaCommonName,
    [Parameter(Mandatory = $true)][ValidateSet('2048', '4096')][String]$EntCaKeyLength,
    [Parameter(Mandatory = $true)][ValidateSet('SHA256', 'SHA384', 'SHA512')][String]$EntCaHashAlgorithm,
    [Parameter(Mandatory = $true)][String]$EntCaValidityPeriodUnits,
    [Parameter(Mandatory = $true)][String]$ADAdminSecParam,
    [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL,
    [Parameter(Mandatory = $true)][String]$S3CRLBucketName,
    [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType
)

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
$CompName = $env:COMPUTERNAME

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
$Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ("$Netbios\$AdminUserName", $AdminUserPW)

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
        Set-WebConfigurationProperty -Filter '/system.webServer/security/requestFiltering' -Name 'allowDoubleEscaping' -Value 'true' -PSPath 'IIS:\Sites\Default Web Site\Pki' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to set IIS requestFiltering  $_"
        Exit 1
    }

    Write-Output 'Setting PKI IIS virtual directory directoryBrowse'
    Try {
        Set-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -Name 'enabled' -Value 'true' -PSPath 'IIS:\Sites\Default Web Site\Pki' -ErrorAction Stop
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
    $URL = "URL=http://$S3BucketUrl/$CompName/cps.txt"

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
    "RenewalKeyLength=$EntCaKeyLength",
    'RenewalValidityPeriod=Years',
    "RenewalValidityPeriodUnits=$EntCaValidityPeriodUnits",
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

Write-Output 'Installing CA'
Try {
    $Null = Install-AdcsCertificationAuthority -CAType 'EnterpriseRootCA' -CACommonName $EntCaCommonName -KeyLength $EntCaKeyLength -HashAlgorithm $EntCaHashAlgorithm -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -ValidityPeriod 'Years' -ValidityPeriodUnits $EntCaValidityPeriodUnits -DatabaseDirectory 'D:\ADCS\DB' -LogDirectory 'D:\ADCS\Log' -Force -ErrorAction Stop -Credential $Credentials
} Catch [System.Exception] {
    Write-Output "Failed to install CA $_"
    Exit 1
}

If ($UseS3ForCRL -eq 'No') {
    If ($DirectoryType -eq 'SelfManaged') {
        $CDP = "http://pki.$FQDN/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
        $AIA = "http://pki.$FQDN/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
    } Else {
        $CDP = "http://$CompName.$FQDN/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
        $AIA = "http://$CompName.$FQDN/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
    }
} Else {
    $CDP = "http://$S3BucketUrl/$CompName/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
    $AIA = "http://$S3BucketUrl/$CompName/<ServerDNSName>_<CaName><CertificateName>.crt"
}

Write-Output 'Configuring CRL distro points'
Try {
    $Null = Get-CACRLDistributionPoint | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CACRLDistributionPoint -Force -ErrorAction Stop
    $Null = Add-CACRLDistributionPoint -Uri $CDP -AddToCertificateCDP -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed set CRL Distro $_"
    Exit 1
}

Write-Output 'Configuring AIA distro points'
Try {
    $Null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CAAuthorityInformationAccess -Force -ErrorAction Stop
    $Null = Add-CAAuthorityInformationAccess -AddToCertificateAia -Uri $AIA -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed set AIA Distro $_"
    Exit 1
}

Write-Output 'Configuring Enterprise CA'
& certutil.exe -setreg CA\CRLOverlapPeriodUnits '12' > $null
& certutil.exe -setreg CA\CRLOverlapPeriod 'Hours' > $null
& certutil.exe -setreg CA\ValidityPeriodUnits '5' > $null
& certutil.exe -setreg CA\ValidityPeriod 'Years' > $null
& certutil.exe -setreg CA\AuditFilter '127' > $null
& auditpol.exe /set /subcategory:'Certification Services' /failure:enable /success:enable > $null

Write-Output 'Restarting CA service'
Try {
    Restart-Service -Name 'certsvc' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed restart CA service $_"
    Exit 1
}

Start-Sleep -Seconds 10

Write-Output 'Publishing CRL'
& certutil.exe -crl > $null

Write-Output 'Copying CRL to PKI folder'
Try {
    Copy-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll\*.cr*' -Destination 'D:\Pki\' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to copy CRL to PKI folder  $_"
    Exit 1
}

If ($UseS3ForCRL -eq 'Yes') {
    Write-S3Object -BucketName $S3CRLBucketName -Folder 'C:\Windows\System32\CertSrv\CertEnroll\' -KeyPrefix "$CompName\" -SearchPattern '*.cr*' -PublicReadOnly
}

Write-Output 'Restarting CA service'
Try {
    Restart-Service -Name 'certsvc' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed restart CA service $_"
}

If ($DirectoryType -eq 'SelfManaged') {
    Write-Output 'Publishing KerberosAuthentication template'
    $Counter = 0
    Do {
        $KerbTempPresent = $Null
        Try {
            $KerbTempPresent = Get-CATemplate -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq 'KerberosAuthentication'}
        } Catch [System.Exception] {
            Write-Output 'KerberosAuthentication Template missing'
            $KerbTempPresent = $Null
        }
        If (-not $KerbTempPresent) {
            $Counter ++
            Write-Output 'KerberosAuthentication Template missing adding it.'
            Try {
                Add-CATemplate -Name 'KerberosAuthentication' -Force -ErrorAction Stop
            } Catch [System.Exception] {
                Write-Output "Failed to add publish KerberosAuthentication template $_"
            }
            If ($Counter -gt '1') {
                Start-Sleep -Seconds 10
            }
        }
    } Until ($KerbTempPresent -or $Counter -eq 12)
}

Write-Output 'Removing DSC Configuration'
Try {    
    Remove-DscConfigurationDocument -Stage 'Current' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed build DSC Configuration $_"
}

Write-Output 'Re-enabling Windows Firewall'
Try {
    Get-NetFirewallProfile -ErrorAction Stop | Set-NetFirewallProfile -Enabled 'True' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed re-enable firewall $_"
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
    Remove-Item -Path "cert:\LocalMachine\My\$SelfSignedThumb" -DeleteKey -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed remove self signed cert $_"
}

If ($DirectoryType -eq 'SelfManaged') {
    Write-Output 'Running Group Policy update'
    $BaseDn = $Domain.DistinguishedName
    $DomainControllers = Get-ADComputer -SearchBase "OU=Domain Controllers,$BaseDn" -Filter * | Select-Object -ExpandProperty 'DNSHostName'
    Foreach ($DomainController in $DomainControllers) {
        Invoke-Command -ComputerName $DomainController -Credential $Credentials -ScriptBlock { Invoke-GPUpdate -RandomDelayInMinutes '0' -Force }
    }
} 

Write-Output 'Creating Update CRL Scheduled Task'
Try {
    If ($UseS3ForCRL -eq 'No') {
        $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '& certutil.exe -crl; Copy-Item -Path C:\Windows\System32\CertSrv\CertEnroll\*.cr* -Destination D:\Pki\'
    } Else {
        $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "& certutil.exe -crl; Write-S3Object -BucketName $S3CRLBucketName -Folder C:\Windows\System32\CertSrv\CertEnroll\ -KeyPrefix $CompName\ -SearchPattern *.cr* -PublicReadOnly"
    }
    $ScheduledTaskTrigger = New-ScheduledTaskTrigger -Daily -DaysInterval '5' -At '12am' -ErrorAction Stop
    $ScheduledTaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType 'ServiceAccount' -RunLevel 'Highest' -ErrorAction Stop
    $ScheduledTaskSettingsSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Compatibility 'Win8' -ExecutionTimeLimit (New-TimeSpan -Hours '1') -ErrorAction Stop
    $ScheduledTask = New-ScheduledTask -Action $ScheduledTaskAction -Principal $ScheduledTaskPrincipal -Trigger $ScheduledTaskTrigger -Settings $ScheduledTaskSettingsSet -Description 'Updates CRL to Local Pki Folder' -ErrorAction Stop
    $Null = Register-ScheduledTask 'Update CRL' -InputObject $ScheduledTask -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed register Update CRL Scheduled Task $_"
}

Start-ScheduledTask -TaskName 'Update CRL' -ErrorAction SilentlyContinue

Write-Output 'Restarting CA service'
Try {
    Restart-Service -Name 'certsvc' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed restart CA service $_"
}