<#
    .SYNOPSIS
    Invoke-TwoTierOrCaConfig.ps1

    .DESCRIPTION
    This script makes the instance an Offline Root CA.  
    
    .EXAMPLE
    .\Invoke-TwoTierOrCaConfig -DomainDNSName 'example.com' -OrCaCommonName 'CA01' -OrCaKeyLength '2048' -OrCaHashAlgorithm 'SHA256' -OrCaValidityPeriodUnits '5' -$ADAdminSecParam 'arn:aws:secretsmanager:us-west-2:############:secret:example-VX5fcW' -UseS3ForCRL 'Yes' -S3CRLBucketName 'examplebucketname' -DirectoryType 'AWSManaged' -VPCCIDR '10.0.0.0/16' -SubCaServerNetBIOSName 'SUBCA01'

#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String]$DomainDNSName,
    [Parameter(Mandatory = $true)][String]$OrCaCommonName,
    [Parameter(Mandatory = $true)][ValidateSet('2048', '4096')][String]$OrCaKeyLength,
    [Parameter(Mandatory = $true)][ValidateSet('SHA256', 'SHA384', 'SHA512')][String]$OrCaHashAlgorithm,
    [Parameter(Mandatory = $true)][String]$OrCaValidityPeriodUnits,
    [Parameter(Mandatory = $true)][String]$ADAdminSecParam,
    [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL,
    [Parameter(Mandatory = $true)][String]$S3CRLBucketName,
    [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType,
    [Parameter(Mandatory = $true)][String]$VPCCIDR,
    [Parameter(Mandatory = $true)][String]$SubCaServerNetBIOSName
)

$CompName = $env:COMPUTERNAME

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
$Credentials = New-Object -TypeName 'System.Management.Automation.PSCredential' ("$DomainDNSName\$AdminUserName", $AdminUserPW)

Write-Output 'Creating PKI folders'
$Folders = @(
    'D:\Pki\SubCA',
    'D:\ADCS\DB',
    'D:\ADCS\Log'
)
Foreach ($Folder in $Folders) {
    $PathPresent = Test-Path -Path $Folder
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
    If ($DirectoryType -eq 'SelfManaged') {
        $URL = "URL=http://pki.$DomainDNSName/pki/cps.txt"
    } Else {
        $URL = "URL=http://$SubCaServerNetBIOSName.$DomainDNSName/pki/cps.txt"
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
    "RenewalKeyLength=$OrCaKeyLength",
    'RenewalValidityPeriod=Years',
    "RenewalValidityPeriodUnits=$OrCaValidityPeriodUnits",
    'CRLPeriod=Weeks',
    'CRLPeriodUnits=26',
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

Write-Output 'Installing Offline Root CA'
Try {
    $Null = Install-AdcsCertificationAuthority -CAType 'StandaloneRootCA' -CACommonName $OrCaCommonName -KeyLength $OrCaKeyLength -HashAlgorithm $OrCaHashAlgorithm -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -ValidityPeriod 'Years' -ValidityPeriodUnits $OrCaValidityPeriodUnits -DatabaseDirectory 'D:\ADCS\DB' -LogDirectory 'D:\ADCS\Log' -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to install CA $_"
    Exit 1
}

If ($UseS3ForCRL -eq 'No') {
    If ($DirectoryType -eq 'SelfManaged') {
        $CDP = "http://pki.$DomainDNSName/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
        $AIA = "http://pki.$DomainDNSName/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
    } Else {
        $CDP = "http://$SubCaServerNetBIOSName.$DomainDNSName/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl"
        $AIA = "http://$SubCaServerNetBIOSName.$DomainDNSName/pki/<ServerDNSName>_<CaName><CertificateName>.crt"
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

Write-Output 'Configuring Offline Root CA'
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

Write-Output 'Creating Update CRL Scheduled Task'
Try {
    If ($UseS3ForCRL -eq 'No') {
        $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '& certutil.exe -crl; Copy-Item -Path C:\Windows\System32\CertSrv\CertEnroll\*.cr* -Destination D:\Pki\'
    } Else {
        $ScheduledTaskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "& certutil.exe -crl; Write-S3Object -BucketName $S3CRLBucketName -Folder C:\Windows\System32\CertSrv\CertEnroll\ -KeyPrefix $CompName\ -SearchPattern *.cr* -PublicReadOnly"
    }
    $ScheduledTaskTrigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval '25' -DaysOfWeek 'Sunday' -At '12am' -ErrorAction Stop
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

Write-Output 'Creating PkiSysvolPSDrive'
If ($DirectoryType -eq 'SelfManaged') {
    $SysvolPath = "\\$DomainDNSName\SYSVOL\$DomainDNSName"
} Else {
    $SysvolPath = "\\$DomainDNSName\SYSVOL\$DomainDNSName\Policies"
}
Try {
    $Null = New-PSDrive -Name 'PkiSysvolPSDrive' -PSProvider 'FileSystem' -Root $SysvolPath -Credential $Credentials -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to create PkiSysvolPSDrive $_"
    Exit 1
}

Write-Output 'Creating the PkiRootCA SYSVOL folder'
Try {
    $Null =  New-Item -ItemType 'Directory' -Path 'PkiSysvolPSDrive:\PkiRootCA' -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to create PkiRootCA SYSVOL folder $_"
    Exit 1
}

Write-Output 'Copying CertEnroll contents to SYSVOL PkiRootCA folder'
Try {
    Copy-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll\*.cr*' -Destination 'PkiSysvolPSDrive:\PkiRootCA' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to copy CertEnroll contents to SYSVOL PkiRootCA folder $_"
    Exit 1
}

Write-Output 'Setting Windows Firewall WinRM Public rule to allow VPC CIDR traffic'
Try {
    Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress $VPCCIDR -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed allow WinRM Traffic from VPC CIDR $_"
}

Write-Output 'Removing PkiSysvolPSDrive'
Try {
    Remove-PSDrive -Name 'PkiSysvolPSDrive' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to remove PkiSysvolPSDrive $_"
    Exit 1
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