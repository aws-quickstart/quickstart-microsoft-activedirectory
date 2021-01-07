<#
    .SYNOPSIS
    Invoke-TwoTierSubCaCertIssue.ps1

    .DESCRIPTION
    This script issues the the certificate to the Subordinate CA  
    
    .EXAMPLE
    .\Invoke-TwoTierSubCaCertIssue -DomainDNSName 'example.com' -ADAdminSecParam 'arn:aws:secretsmanager:us-west-2:############:secret:example-VX5fcW' -UseS3ForCRL 'Yes' -DirectoryType 'AWSManaged'

#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)][String]$ADAdminSecParam,
    [Parameter(Mandatory = $true)][String]$DomainDNSName,
    [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][String]$UseS3ForCRL,
    [Parameter(Mandatory = $true)][ValidateSet('AWSManaged', 'SelfManaged')][String]$DirectoryType
)

$CAComputerName = "$env:COMPUTERNAME\$env:COMPUTERNAME"

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

Write-Output 'Creating IssuePkiSysvolPSDrive'
If ($DirectoryType -eq 'SelfManaged') {
    $SysvolPath = "\\$DomainDNSName\SYSVOL\$DomainDNSName"
} Else {
    $SysvolPath = "\\$DomainDNSName\SYSVOL\$DomainDNSName\Policies"
}

Try {
    $Null = New-PSDrive -Name 'IssuePkiSysvolPSDrive' -PSProvider 'FileSystem' -Root $SysvolPath -Credential $Credentials -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to create IssuePkiSysvolPSDrive $_"
    Exit 1
}

Write-Output 'Copying SubCa.req from PkiSubCA SYSVOL folder'
Try {
    Copy-Item -Path 'IssuePkiSysvolPSDrive:\PkiSubCA\SubCa.req' -Destination 'D:\Pki\SubCA\SubCa.req' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to copy SubCa.req from PkiSubCA SYSVOL folder $_"
    Exit 1
}

Write-Output 'Submitting, Issuing and Retrieving the SubCA certificate'
$SubReq = 'D:\Pki\SubCA\SubCa.req'
$Request = & Certreq.exe -f -q -config $CAComputerName -Submit $SubReq 'D:\Pki\SubCA\SubCa.cer'
$RequestString = $Request | Select-String -Pattern 'RequestId:.\d$'
$RequestId = $RequestString -replace ('RequestId: ', '')
& Certutil.exe -config $CAComputerName -Resubmit $RequestId > $null
& Certreq.exe -f -q -config $CAComputerName -Retrieve $RequestId 'D:\Pki\SubCA\SubCa.cer' > $null

Write-Output 'Copying SubCa.cer to PkiSubCA SYSVOL folder'
Try{
    Copy-Item -Path 'D:\Pki\SubCA\SubCa.cer' -Destination 'IssuePkiSysvolPSDrive:\PkiSubCA\SubCa.cer' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to copy SubCa.req from PkiSubCA SYSVOL folder $_"
    Exit 1
}

Write-Output 'Removing IssuePkiSysvolPSDrive'
Try {
    Remove-PSDrive -Name 'IssuePkiSysvolPSDrive' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to remove IssuePkiSysvolPSDrive $_"
    Exit 1
}

Write-Output 'Removing SubCA Cert request files'
Try {
    Remove-Item -Path 'D:\Pki\SubCA' -Recurse -Force -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed remove QuickStart build files $_"
}