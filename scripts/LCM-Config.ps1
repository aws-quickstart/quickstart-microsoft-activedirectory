# This block sets the LCM configuration to what we need for QS
[DSCLocalConfigurationManager()]
configuration LCMConfig
{
    Node 'localhost' {
        Settings {
            RefreshMode = 'Push'
            ActionAfterReboot = 'StopConfiguration'                      
            RebootNodeIfNeeded = $false
            CertificateId = $DscCertThumbprint  
        }
    }
}

$DscCertThumbprint = (get-childitem -path cert:\LocalMachine\My | where { $_.subject -eq "CN=AWSQSDscEncryptCert" }).Thumbprint
    
#Generates MOF File for LCM
LCMConfig -OutputPath 'C:\AWSQuickstart\LCMConfig'
    
# Sets LCM Configuration to MOF generated in previous command
Set-DscLocalConfigurationManager -Path 'C:\AWSQuickstart\LCMConfig' 
