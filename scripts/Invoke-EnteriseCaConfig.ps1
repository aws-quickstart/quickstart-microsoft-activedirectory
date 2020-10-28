[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String]$EntCaCommonName,
    [Parameter(Mandatory = $true)][String]$EntCaKeyLength,
    [Parameter(Mandatory = $true)][String]$EntCaHashAlgorithm,
    [Parameter(Mandatory = $true)][String]$EntCaValidityPeriodUnits,
    [Parameter(Mandatory = $true)][String]$ADAdminSecParam
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

Write-Output 'Creating PKI folder'
$PathPresent = Test-Path -Path 'D:\Pki'
If (-not $PathPresent) {
    Try {
        New-Item -Path 'D:\Pki' -Type 'Directory' -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create PKI Directory $_"
        Exit 1
    }
}

Write-Output 'Example CPS statement' | Out-File 'D:\Pki\cps.txt'

Write-Output 'Sharing PKI folder'
$SharePresent = Get-SmbShare -Name 'Pki' -ErrorAction SilentlyContinue
If (-not $SharePresent) {
    Try {
        New-Smbshare -Name 'Pki' -Path 'D:\Pki' -FullAccess 'SYSTEM', "$Netbios\Domain Admins" -ChangeAccess "$Netbios\Cert Publishers" -ErrorAction Stop
    } Catch [System.Exception] {
        Write-Output "Failed to create PKI SMB Share $_"
        Exit 1
    }
}

Write-Output 'Creating PKI IIS virtual directory'
$VdPresent = Get-WebVirtualDirectory -Name 'Pki'
If (-not $VdPresent) {
    Try {
        New-WebVirtualDirectory -Site 'Default Web Site' -Name 'Pki' -PhysicalPath 'D:\Pki' -ErrorAction Stop
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
    Start-Process 'iisreset.exe' -NoNewWindow -Wait -ErrorAction Stop
    Restart-Service -name 'W3SVC' -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to reset IIS service  $_"
    Exit 1
}

$Inf = @(
    '[Version]',
    'Signature="$Windows NT$"',
    '[PolicyStatementExtension]',
    'Policies=InternalPolicy',
    '[InternalPolicy]',
    'OID=1.2.3.4.1455.67.89.5', 
    'Notice="Legal Policy Statement"',
    "URL=http://pki.$FQDN/pki/cps.txt",
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
    Install-AdcsCertificationAuthority -CAType 'EnterpriseRootCA' -CACommonName $EntCaCommonName -KeyLength $EntCaKeyLength -HashAlgorithm $EntCaHashAlgorithm -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -ValidityPeriod 'Years' -ValidityPeriodUnits $EntCaValidityPeriodUnits -Force -ErrorAction Stop -Credential $Credentials
} Catch [System.Exception] {
    Write-Output "Failed to install CA $_"
    Exit 1
}

Write-Output 'Configuring CRL distro points'
Try {
    Get-CACRLDistributionPoint | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CACRLDistributionPoint -Force -ErrorAction Stop
    Add-CACRLDistributionPoint -Uri "http://pki.$FQDN/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -AddToCertificateCDP -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed set CRL Distro $_"
    Exit 1
}

Write-Output 'Configuring AIA distro points'
Try {
    Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } -ErrorAction Stop | Remove-CAAuthorityInformationAccess -Force
    Add-CAAuthorityInformationAccess -AddToCertificateAia -Uri "http://pki.$FQDN/pki/<ServerDNSName>_<CaName><CertificateName>.crt" -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed set AIA Distro $_"
    Exit 1
}

Write-Output 'Configuring Enterprise CA'
& certutil.exe -setreg CA\CRLOverlapPeriodUnits '12'
& certutil.exe -setreg CA\CRLOverlapPeriod 'Hours'
& certutil.exe -setreg CA\ValidityPeriodUnits '5'
& certutil.exe -setreg CA\ValidityPeriod 'Years'
& certutil.exe -setreg CA\AuditFilter '127'
& auditpol.exe /set /subcategory:'Certification Services' /failure:enable /success:enable  

Write-Output 'Restarting CA service'
Try {
    Restart-Service -Name 'certsvc' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed restart CA service $_"
    Exit 1
}

Start-Sleep -Seconds 10

Write-Output 'Publishing CRL'
& certutil.exe -crl >$null

Write-Output 'Copying CRL to PKI folder'
Try {
    Copy-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll\*.cr*' -Destination 'D:\Pki\' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to copy CRL to PKI folder  $_"
    Exit 1
}

Write-Output 'Restarting CA service'
Try {
    Restart-Service -Name 'certsvc' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed restart CA service $_"
}

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

Write-Output 'Running Group Policy update'
$BaseDn = $Domain.DistinguishedName
$DomainControllers = Get-ADComputer -SearchBase "OU=Domain Controllers,$BaseDn" -Filter * | Select-Object -ExpandProperty 'DNSHostName'
Foreach ($DomainController in $DomainControllers) {
    Invoke-Command -ComputerName $DomainController -Credential $Credentials -ScriptBlock { Invoke-GPUpdate -RandomDelayInMinutes '0' -Force }
}