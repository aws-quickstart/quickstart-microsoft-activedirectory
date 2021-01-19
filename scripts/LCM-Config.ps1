<#
    .SYNOPSIS
    LCM-Config.ps1

    .DESCRIPTION
    This script configures the DS Local Configuration Manager
    
    .EXAMPLE
    .\LCM-Config
#>

#==================================================
# Main
#==================================================

Write-Output 'Getting the DSC Cert Encryption Thumbprint to Secure the MOF File'
Try {
    $DscCertThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
} Catch [System.Exception] {
    Write-Output "Failed to get DSC Cert Encryption Thumbprint $_"
    Exit 1
} 

# This block sets the LCM configuration to what we need for QS
[DSCLocalConfigurationManager()]
Configuration LCMConfig
{
    Node 'localhost' {
        Settings {
            RefreshMode                    = 'Push'
            ConfigurationModeFrequencyMins = 15
            ActionAfterReboot              = 'StopConfiguration'                      
            RebootNodeIfNeeded             = $false
            ConfigurationMode              = 'ApplyAndAutoCorrect'
            CertificateId                  = $DscCertThumbprint  
        }
    }
}

Write-Output 'Generating MOF File for LCM'
LCMConfig -OutputPath 'C:\AWSQuickstart\LCMConfig'
    
Write-Output 'Sets LCM Configuration to MOF generated in previous command'
Try {
    Set-DscLocalConfigurationManager -Path 'C:\AWSQuickstart\LCMConfig' -ErrorAction Stop
} Catch [System.Exception] {
    Write-Output "Failed to set LCM Configuration $_"
    Exit 1
} 