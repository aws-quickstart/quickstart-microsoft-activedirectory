<#
    .SYNOPSIS
    LCM-Config.ps1

    .DESCRIPTION
    This script configures the DS Local Configuration Manager
    
    .EXAMPLE
    .\LCM-Config

#>

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

$DscCertThumbprint = Get-ChildItem -Path 'cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Subject -eq 'CN=AWSQSDscEncryptCert' } | Select-Object -ExpandProperty 'Thumbprint'
    
# Generates MOF File for LCM
LCMConfig -OutputPath 'C:\AWSQuickstart\LCMConfig'
    
# Sets LCM Configuration to MOF generated in previous command
Set-DscLocalConfigurationManager -Path 'C:\AWSQuickstart\LCMConfig' 