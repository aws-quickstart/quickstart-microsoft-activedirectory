<#
    .SYNOPSIS
    Invoke-TwoTierSubCaConfig.ps1

    .DESCRIPTION
    This script finalizes the an Enterprise CA configuration.  
    
    .EXAMPLE
    .\Invoke-TwoTierSubCaConfig -ADAdminSecParam 'arn:aws:secretsmanager:us-west-2:############:secret:example-VX5fcW' -UseS3ForCRL 'Yes' -S3CRLBucketName 'examplebucketname' -DirectoryType 'AWSManaged' -VPCCIDR '10.0.0.0/16'

#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String]$ADAdminSecParam,
    [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL,
    [Parameter(Mandatory = $true)][String]$S3CRLBucketName,
    [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType,
    [Parameter(Mandatory = $true)][String]$VPCCIDR
)

Try {
    $Domain = Get-ADDomain -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to get AD domain $_"
    Exit 1
}

$DC = Get-ADDomainController -Discover -ForceDiscover | Select-Object -ExpandProperty 'HostName'
$FQDN = $Domain | Select-Object -ExpandProperty 'DNSRoot'
$Netbios = $Domain | Select-Object -ExpandProperty 'NetBIOSName'
$CompName = $env:COMPUTERNAME
$ADComputerName = Get-ADComputer -Identity $CompName | Select-Object -ExpandProperty 'DNSHostName'
$CaConfig = "$ADComputerName\$env:COMPUTERNAME"


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

Write-Output 'Creating CertPkiSysvolPSDrive'
If ($DirectoryType -eq 'SelfManaged') {
    $SysvolPath = "\\$FQDN\SYSVOL\$FQDN"
} Else {
    $SysvolPath = "\\$FQDN\SYSVOL\$FQDN\Policies"
}

Try {
    $Null = New-PSDrive -Name 'CertPkiSysvolPSDrive' -PSProvider 'FileSystem' -Root $SysvolPath -Credential $Credentials -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to create CertPkiSysvolPSDrive $_"
    Exit 1
}

Write-Output 'Copying SubCa.cer from PkiSubCA SYSVOL folder'
Try {
    Copy-Item -Path 'CertPkiSysvolPSDrive:\PkiSubCA\SubCa.cer' -Destination 'D:\Pki\Req\SubCa.cer' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to copy SubCa.cer from PkiSubCA SYSVOL folder $_"
    Exit 1
}

Write-Output 'Installing SubCA certificate'
& certutil.exe -f -silent -installcert 'D:\Pki\Req\SubCa.cer' > $null

Start-Sleep -Seconds 5

Write-Output 'Starting CA service'
Try {
    Restart-Service -Name 'certsvc' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed restart CA service $_"
    Exit 1
}

If ($UseS3ForCRL -eq 'Yes') {
    $BucketRegion = Get-S3BucketLocation -BucketName $S3CRLBucketName | Select-Object -ExpandProperty 'Value'
    If ($BucketRegion -eq ''){
        $S3BucketUrl = "$S3CRLBucketName.s3.amazonaws.com"
    } Else {
        $S3BucketUrl = "$S3CRLBucketName.s3-$BucketRegion.amazonaws.com"
    }
    $CDP = "http://$S3BucketUrl/$CompName/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
    $AIA = "http://$S3BucketUrl/$CompName/<ServerDNSName>_<CaName><CertificateName>.crt"
} Else {
    If ($DirectoryType -eq 'SelfManaged') {
        $CDP = "http://pki.$FQDN/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
        $AIA = "http://pki.$FQDN/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
    } Else {
        $CDP = "http://$CompName.$FQDN/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
        $AIA = "http://$CompName.$FQDN/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
    }
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
    $Templates = @(
        'KerberosAuthentication',
        'WebServer'
    )
    Foreach ($Template in $Templates) {
        Write-Output "Publishing $Template template"
        $Counter = 0
        Do {
            $TempPresent = $Null
            Try {
                $TempPresent = Get-CATemplate -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $Template }
            } Catch [System.Exception] {
                Write-Output "$Template Template missing"
                $TempPresent = $Null
            }
            If (-not $TempPresent) {
                $Counter ++
                Write-Output "$Template Template missing adding it."
                Try {
                    Add-CATemplate -Name $Template -Force -ErrorAction Stop
                } Catch [System.Exception] {
                    Write-Output "Failed to add publish $Template template $_"
                }
                If ($Counter -gt '1') {
                    Start-Sleep -Seconds 10
                }
            }
        } Until ($TempPresent -or $Counter -eq 12)
    }
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
    If ($UseS3ForCRL -eq 'Yes') {
        $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "& certutil.exe -crl; Write-S3Object -BucketName $S3CRLBucketName -Folder C:\Windows\System32\CertSrv\CertEnroll\ -KeyPrefix $CompName\ -SearchPattern *.cr* -PublicReadOnly"
    } Else {
        $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '& certutil.exe -crl; Copy-Item -Path C:\Windows\System32\CertSrv\CertEnroll\*.cr* -Destination D:\Pki\'
    }
    $ScheduledTaskTrigger = New-ScheduledTaskTrigger -Daily -DaysInterval '5' -At '12am' -ErrorAction Stop
    $ScheduledTaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType 'ServiceAccount' -RunLevel 'Highest' -ErrorAction Stop
    $ScheduledTaskSettingsSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Compatibility 'Win8' -ExecutionTimeLimit (New-TimeSpan -Hours '1') -ErrorAction Stop
    $ScheduledTask = New-ScheduledTask -Action $ScheduledTaskAction -Principal $ScheduledTaskPrincipal -Trigger $ScheduledTaskTrigger -Settings $ScheduledTaskSettingsSet -Description 'Updates CRL to Local Pki Folder' -ErrorAction Stop
    $Null = Register-ScheduledTask 'Update CRL' -InputObject $ScheduledTask -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed register Update CRL Scheduled Task $_"
}

Write-Output 'Starting Update CRL Scheduled Task'
Start-ScheduledTask -TaskName 'Update CRL' -ErrorAction SilentlyContinue

Write-Output 'Restarting CA service'
Try {
    Restart-Service -Name 'certsvc' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed restart CA service $_"
}

Write-Output 'Removing RootCA Cert request files'
Try {
    Remove-Item -Path 'D:\Pki\Req' -Recurse -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed remove QuickStart build files $_"
}
 
Write-Output 'Removing the PkiSubCA and PKIRootCA SYSVOL folders'

$SvolFolders = @(
    'CertPkiSysvolPSDrive:\PkiSubCA',
    'CertPkiSysvolPSDrive:\PkiRootCA'
)

Foreach ($SvolFolder in $SvolFolders) {
    Try {
        Remove-Item -Path $SvolFolder -Recurse -Force -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to remove PkiSubCA and PKIRootCA SYSVOL folders $_"
        Exit 1
    }
}

Write-Output 'Removing computer account from elevated groups'
If ($DirectoryType -eq 'SelfManaged') {
    Try {
        Remove-ADGroupMember -Identity 'Enterprise Admins' -Members (Get-ADComputer -Identity $CompName | Select-Object -ExpandProperty 'DistinguishedName') -Confirm:$false -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to remove computer account from Enterprise Admins $_"
        Exit 1
    }
} Else {
    Try {
        Remove-ADGroupMember -Identity 'AWS Delegated Enterprise Certificate Authority Administrators' -Members (Get-ADComputer -Identity $CompName -Credential $Credentials | Select-Object -ExpandProperty 'DistinguishedName') -Confirm:$false -ErrorAction Stop -Credential $Credentials
    } Catch [System.Exception] {
        Write-Output "Failed to remove computer account from AWS Delegated Enterprise Certificate Authority Administrators $_"
        Exit 1
    }
}

Write-Output 'Clearing all SYSTEM kerberos tickets'
& Klist.exe -li 0x3e7 purge > $null

Write-Output 'Setting Windows Firewall WinRM Public rule to allow VPC CIDR traffic'
Try {
    Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress $VPCCIDR -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed allow WinRM Traffic from VPC CIDR $_"
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