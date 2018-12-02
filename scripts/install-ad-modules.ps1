[CmdletBinding()]
param()

"Setting Execution Policy to Remote Signed"
Set-ExecutionPolicy RemoteSigned -Force

"Setting up Powershell Gallery to Install DSC Modules"
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5 -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

"Installing the needed Powershell DSC modules for this Quick Start"
Install-Module NetworkingDsc
Install-Module -Name "xActiveDirectory"
Install-Module ComputerManagementDsc
Install-Module -Name "xDnsServer"
Install-Module -Name "ActiveDirectoryCSDsc"

"Disabling Windows Firewall"
Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False

"Creating Directory for DSC Public Cert"
New-Item -Path C:\AWSQuickstart\publickeys -ItemType directory 

"Setting up DSC Certificate to Encrypt Credentials in MOF File"
$cert = New-SelfSignedCertificate -Type DocumentEncryptionCertLegacyCsp -DnsName 'AWSQSDscEncryptCert' -HashAlgorithm SHA256
# Exporting the public key certificate
$cert | Export-Certificate -FilePath "C:\AWSQuickstart\publickeys\AWSQSDscPublicKey.cer" -Force


