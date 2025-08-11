<#
.SYNOPSIS
    Get-ADFSReport - Comprehensive ADFS Environment Analysis and Health Check

.DESCRIPTION
    This script performs a comprehensive analysis of an Active Directory Federation Services (ADFS) environment.
    It analyzes configuration, security settings, certificates, performance, and provides detailed recommendations.
    
    Supports ADFS versions:
    - ADFS 2012 R2 (Windows Server 2012 R2)
    - ADFS 2016 (Windows Server 2016) 
    - ADFS 2019 (Windows Server 2019)
    - ADFS 2022 (Windows Server 2022)
    
    Modern features analyzed include:
    - OAuth 2.0 and OpenID Connect support
    - Azure MFA integration
    - Certificate-based authentication
    - Extranet smart lockout
    - Banned password protection
    - FIDO2/WebAuthn (ADFS 2022+)
    - Conditional access policies

.PARAMETER OutputPath
    Path for the JSON analysis report. Default: Creates timestamped file in Documents folder
    CSV export is automatically included.

.PARAMETER IncludePerformanceCounters
    Switch to include performance counter analysis (may take additional time)

.PARAMETER EventLogDays
    Number of days of event logs to analyze. Default: 7 days

.PARAMETER SanitizeOutput
    Switch to sanitize sensitive information in the output

.EXAMPLE
    .\Get-ADFSReport.ps1
    Run basic analysis with default timestamped output in Documents folder

.EXAMPLE
    .\Get-ADFSReport.ps1 -OutputPath "C:\Reports\ADFS_Health.json" -IncludePerformanceCounters
    Run comprehensive analysis with custom path and performance counters

.EXAMPLE
    .\Get-ADFSReport.ps1 -EventLogDays 30 -SanitizeOutput
    Run analysis with 30 days of logs and sanitized output

.EXAMPLE
    Copy and paste the entire script into PowerShell:
    Get-ADFSReport
    
    This runs the function directly without saving to a file first!

.EXAMPLE
    Run directly from GitHub (no download needed):
    iex (irm 'https://raw.githubusercontent.com/kevinblumenfeld/adfs-6vms-private/main/Get-ADFSReport.ps1')
    
    This downloads and executes the script in one command. Perfect for quick analysis!

.NOTES
    Author: ADFS Health Check Script
    Version: 2.0
    Requires: PowerShell 5.0+, ADFS PowerShell Module
    Permissions: Local Administrator on ADFS server
    
    Run this script on an ADFS server with appropriate permissions.
    The script will analyze the local ADFS installation and configuration.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePerformanceCounters,
    
    [Parameter(Mandatory = $false)]
    [int]$EventLogDays = 7,
    
    [Parameter(Mandatory = $false)]
    [switch]$SanitizeOutput
)

# =============================================================================
# SCRIPT VARIABLES AND INITIALIZATION
# =============================================================================

# Set default output path if not specified
if ([string]::IsNullOrEmpty($OutputPath)) {
    $timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
    $OutputPath = Join-Path -Path ([Environment]::GetFolderPath('MyDocuments')) -ChildPath "ADFS-Analysis-$timestamp.json"
}

# Script-scoped variables
$script:AnalysisResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:ADFSVersionMajor = 0
$script:ADFSVersionMinor = 0

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

function New-AnalysisResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $true)]
        [string]$Property,
        
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value,
        
        [Parameter(Mandatory = $true)]
        [string]$Relevance,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("OK", "WARNING", "CRITICAL", "ERROR", "INFO")]
        [string]$Status,
        
        [Parameter(Mandatory = $false)]
        [string]$Recommendation = ""
    )
    
    return [PSCustomObject]@{
        Category       = $Category
        Property       = $Property
        Value          = $Value
        Relevance      = $Relevance
        Status         = $Status
        Recommendation = $Recommendation
        Timestamp      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Get-SanitizedValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value,
        
        [Parameter(Mandatory = $false)]
        [string]$SanitizedText = "***REDACTED***"
    )
    
    if ($SanitizeOutput) {
        return $SanitizedText
    } else {
        return $Value
    }
}

function Initialize-ADFSAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "=== ADFS COMPREHENSIVE ANALYSIS TOOL ===" -ForegroundColor Cyan
    Write-Host "Starting ADFS environment analysis..." -ForegroundColor Green
    Write-Host "Analysis Time: $(Get-Date)" -ForegroundColor White
    Write-Host ""
    
    # Check if running on Windows
    if (-not ($PSVersionTable.PSVersion.Major -ge 5 -and [Environment]::OSVersion.Platform -eq "Win32NT")) {
        Write-Error "This script requires Windows PowerShell 5.0 or later on Windows."
        return $false
    }
    
    # Check if ADFS PowerShell module is available
    try {
        Import-Module ADFS -ErrorAction Stop
        Write-Host "✓ ADFS PowerShell module loaded successfully" -ForegroundColor Green
    } catch {
        Write-Error "ADFS PowerShell module not available. This script must run on an ADFS server."
        return $false
    }
    
    # Check if running as administrator
    try {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Warning "Script is not running as Administrator. Some checks may fail."
        } else {
            Write-Host "✓ Running with Administrator privileges" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Could not verify administrator privileges."
    }
    
    # Detect ADFS version from Farm Behavior Level (more reliable than registry)
    try {
        $farmInfo = Get-AdfsFarmInformation -ErrorAction Stop
        $script:ADFSFarmBehaviorLevel = $farmInfo.FarmBehavior
        
        # Map Farm Behavior Level to ADFS version
        switch ($script:ADFSFarmBehaviorLevel) {
            1 { $adfsVersionName = "ADFS 2012 R2"; $script:ADFSVersionMajor = 3 }
            3 { $adfsVersionName = "ADFS 2016"; $script:ADFSVersionMajor = 4 }
            4 { $adfsVersionName = "ADFS 2019"; $script:ADFSVersionMajor = 5 }
            5 { $adfsVersionName = "ADFS 2022"; $script:ADFSVersionMajor = 6 }
            default { $adfsVersionName = "Unknown ADFS Version"; $script:ADFSVersionMajor = 0 }
        }
        
        Write-Host "✓ ADFS Version detected: $adfsVersionName (Farm Behavior Level $script:ADFSFarmBehaviorLevel)" -ForegroundColor Green
    } catch {
        Write-Warning "Could not detect ADFS version: $($_.Exception.Message)"
        # Fallback to registry method
        try {
            $adfsVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ADFS" -Name "CurrentVersion" -ErrorAction SilentlyContinue).CurrentVersion
            if ($adfsVersion) {
                $versionParts = $adfsVersion.Split('.')
                $script:ADFSVersionMajor = [int]$versionParts[0]
                Write-Host "✓ ADFS Version from registry: $adfsVersion" -ForegroundColor Yellow
            }
        } catch {
            Write-Warning "Error with fallback version detection: $($_.Exception.Message)"
        }
    }
    
    Write-Host ""
    return $true
}

# =============================================================================
# ANALYSIS FUNCTIONS
# =============================================================================

function Get-ADFSServiceAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing ADFS Service and Farm Information..." -ForegroundColor Yellow
    
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    
    try {
        $adfsService = Get-Service -Name "adfssrv"
        $results.Add((New-AnalysisResult -Category "Service" -Property "ADFS Service Status" -Value $adfsService.Status -Relevance "Critical - ADFS must be running for federation to work" -Status $(if ($adfsService.Status -eq "Running") { "OK" } else { "CRITICAL" })))
        
        $adfsServiceAccount = (Get-WmiObject -Class Win32_Service -Filter "Name='adfssrv'").StartName
        $results.Add((New-AnalysisResult -Category "Service" -Property "Service Account" -Value $adfsServiceAccount -Relevance "Service account determines permissions and security context for ADFS operations" -Status "INFO"))
    } catch {
        $results.Add((New-AnalysisResult -Category "Service" -Property "ADFS Service" -Value "Error: $($_.Exception.Message)" -Relevance "Critical - Cannot analyze ADFS without service access" -Status "ERROR"))
    }
    
    try {
        $farmInfo = Get-AdfsFarmInformation
        $results.Add((New-AnalysisResult -Category "Farm" -Property "Farm Behavior Level" -Value $farmInfo.FarmBehavior -Relevance "Determines available features and compatibility with ADFS versions" -Status "INFO"))
        $results.Add((New-AnalysisResult -Category "Farm" -Property "Current Farm Node" -Value $farmInfo.CurrentFarmNode -Relevance "Identifies which server in the farm you're analyzing" -Status "INFO"))
        $results.Add((New-AnalysisResult -Category "Farm" -Property "Farm Nodes" -Value ($farmInfo.FarmNodes -join ", ") -Relevance "Shows all servers in the ADFS farm for redundancy and load balancing" -Status "INFO"))
        
        if ($farmInfo.FarmNodes.Count -eq 1) {
            $results.Add((New-AnalysisResult -Category "Farm" -Property "High Availability" -Value "Single Node" -Relevance "Single point of failure - consider adding more farm nodes" -Status "WARNING" -Recommendation "Add additional ADFS servers for redundancy"))
        } else {
            $results.Add((New-AnalysisResult -Category "Farm" -Property "High Availability" -Value "Multi-Node ($($farmInfo.FarmNodes.Count) nodes)" -Relevance "Good redundancy setup with multiple ADFS servers" -Status "OK"))
        }
    } catch {
        $results.Add((New-AnalysisResult -Category "Farm" -Property "Farm Information" -Value "Error: $($_.Exception.Message)" -Relevance "Farm information shows topology and health" -Status "ERROR"))
    }
    
    return $results
}

function Get-ADFSPropertiesAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing ADFS Properties and Global Settings..." -ForegroundColor Yellow
    
    try {
        $adfsProperties = Get-AdfsProperties
        
        Add-AnalysisResult -Category "Properties" -Property "Hostname" -Value $adfsProperties.HostName -Relevance "Public FQDN for ADFS - must match SSL certificate and DNS" -Status "INFO"
        Add-AnalysisResult -Category "Properties" -Property "HTTPS Port" -Value $adfsProperties.HttpsPort -Relevance "Port for HTTPS communications - typically 443" -Status "INFO"
        Add-AnalysisResult -Category "Properties" -Property "HTTP Port" -Value $adfsProperties.HttpPort -Relevance "HTTP port - should be disabled for security" -Status $(if ($adfsProperties.HttpPort -eq 80) { "WARNING" } else { "INFO" }) -Recommendation $(if ($adfsProperties.HttpPort -eq 80) { "Consider disabling HTTP for security" } else { "" })
        
        Add-AnalysisResult -Category "Properties" -Property "Federation Service Name" -Value $adfsProperties.FederationServiceName -Relevance "Identifier for the federation service in trust relationships" -Status "INFO"
        Add-AnalysisResult -Category "Properties" -Property "Federation Service Display Name" -Value $adfsProperties.FederationServiceDisplayName -Relevance "User-friendly name shown in sign-in pages" -Status "INFO"
        
        # Token Lifetime Settings
        Add-AnalysisResult -Category "Tokens" -Property "Access Token Lifetime" -Value "$($adfsProperties.AccessTokenLifetime) minutes" -Relevance "How long access tokens are valid - affects security vs usability" -Status "INFO"
        Add-AnalysisResult -Category "Tokens" -Property "ID Token Lifetime" -Value "$($adfsProperties.IdTokenLifetime) minutes" -Relevance "How long ID tokens are valid for OpenID Connect" -Status "INFO"
        
        # Security Settings  
        Add-AnalysisResult -Category "Security" -Property "Extended Protection Mode" -Value $adfsProperties.ExtendedProtectionTokenCheck -Relevance "Protection against token replay attacks" -Status "INFO"
        Add-AnalysisResult -Category "Security" -Property "Browser SSO Enabled" -Value $adfsProperties.BrowserSsoEnabled -Relevance "Enables single sign-on across browser sessions" -Status "INFO"
        Add-AnalysisResult -Category "Security" -Property "Browser SSO Lifetime" -Value "$($adfsProperties.BrowserSsoLifetime) minutes" -Relevance "How long browser SSO sessions last" -Status "INFO"
        
    } catch {
        Add-AnalysisResult -Category "Properties" -Property "ADFS Properties" -Value "Error: $($_.Exception.Message)" -Relevance "Global settings affect all ADFS operations" -Status "ERROR"
    }
}

function Get-ADFSCertificatesAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing ADFS Certificates..." -ForegroundColor Yellow
    
    try {
        $certificates = Get-AdfsCertificate
        
        foreach ($cert in $certificates) {
            $daysUntilExpiry = ($cert.Certificate.NotAfter - (Get-Date)).Days
            $status = if ($daysUntilExpiry -lt 30) { "CRITICAL" } elseif ($daysUntilExpiry -lt 90) { "WARNING" } else { "OK" }
            
            $certInfo = @{
                Type            = $cert.CertificateType
                IsPrimary       = $cert.IsPrimary
                Subject         = $cert.Certificate.Subject
                Issuer          = $cert.Certificate.Issuer
                NotBefore       = $cert.Certificate.NotBefore
                NotAfter        = $cert.Certificate.NotAfter
                DaysUntilExpiry = $daysUntilExpiry
                Thumbprint      = Get-SanitizedValue -Value $cert.Certificate.Thumbprint
                SerialNumber    = Get-SanitizedValue -Value $cert.Certificate.SerialNumber
                HasPrivateKey   = $cert.Certificate.HasPrivateKey
                KeySize         = $cert.Certificate.PublicKey.Key.KeySize
            }
            
            Add-AnalysisResult -Category "Certificates" -Property "$($cert.CertificateType) Certificate" -Value ($certInfo | ConvertTo-Json -Compress) -Relevance "$(if($cert.CertificateType -eq 'Token-Signing') {'Critical for token validation'} elseif($cert.CertificateType -eq 'Token-Decrypting') {'Required for encrypted token processing'} elseif($cert.CertificateType -eq 'Service-Communications') {'Secures HTTPS communications'} else {'Various ADFS operations'})" -Status $status -Recommendation $(if ($daysUntilExpiry -lt 90) { "Certificate expires in $daysUntilExpiry days - plan renewal" } else { "" })
        }
        
        # Check for auto-certificate rollover
        $tokenSigningCerts = $certificates | Where-Object { $_.CertificateType -eq "Token-Signing" }
        if ($tokenSigningCerts.Count -gt 1) {
            Add-AnalysisResult -Category "Certificates" -Property "Auto Certificate Rollover" -Value "Multiple token signing certificates detected" -Relevance "Indicates certificate rollover capability for zero-downtime renewal" -Status "OK"
        }
        
    } catch {
        Add-AnalysisResult -Category "Certificates" -Property "Certificate Analysis" -Value "Error: $($_.Exception.Message)" -Relevance "Certificates are critical for ADFS security and trust" -Status "ERROR"
    }
}

function Get-SSLConfigurationAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing SSL/TLS Configuration..." -ForegroundColor Yellow
    
    try {
        $sslBindings = Get-AdfsSslCertificate
        
        foreach ($binding in $sslBindings) {
            $sslInfo = @{
                HostName        = $binding.HostName
                PortNumber      = $binding.PortNumber
                CertificateHash = Get-SanitizedValue -Value $binding.CertificateHash
            }
            
            Add-AnalysisResult -Category "SSL" -Property "SSL Binding" -Value ($sslInfo | ConvertTo-Json -Compress) -Relevance "SSL bindings secure HTTPS traffic to ADFS" -Status "INFO"
        }
    } catch {
        Add-AnalysisResult -Category "SSL" -Property "SSL Configuration" -Value "Error: $($_.Exception.Message)" -Relevance "SSL configuration secures client communications" -Status "ERROR"
    }
}

function Get-ADFSEndpointsAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing ADFS Endpoints..." -ForegroundColor Yellow
    
    try {
        $endpoints = Get-AdfsEndpoint
        
        Add-AnalysisResult -Category "Endpoints" -Property "Endpoint Count" -Value $endpoints.Count -Relevance "Number of available service endpoints" -Status "INFO"
        Add-AnalysisResult -Category "Endpoints" -Property "Enabled Endpoints" -Value ($endpoints | Where-Object { $_.Enabled }).Count -Relevance "Number of active endpoints serving requests" -Status "INFO"
        
        # Check critical endpoints
        $criticalEndpoints = @(
            "/adfs/services/trust/2005/usernamemixed",
            "/adfs/ls/",
            "/adfs/services/trust/mex",
            "/adfs/services/trusttcp/mex"
        )
        
        foreach ($criticalPath in $criticalEndpoints) {
            $endpoint = $endpoints | Where-Object { $_.AddressPath -eq $criticalPath }
            if ($endpoint) {
                $status = if ($endpoint.Enabled) { "OK" } else { "WARNING" }
                Add-AnalysisResult -Category "Endpoints" -Property "Critical Endpoint: $criticalPath" -Value "Enabled: $($endpoint.Enabled)" -Relevance "Essential endpoint for federation operations" -Status $status
            } else {
                Add-AnalysisResult -Category "Endpoints" -Property "Critical Endpoint: $criticalPath" -Value "Not Found" -Relevance "Essential endpoint missing" -Status "WARNING"
            }
        }
        
    } catch {
        Add-AnalysisResult -Category "Endpoints" -Property "Endpoint Analysis" -Value "Error: $($_.Exception.Message)" -Relevance "Endpoints provide ADFS services to clients" -Status "ERROR"
    }
}

function Get-RelyingPartyTrustsAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing Relying Party Trusts..." -ForegroundColor Yellow
    
    try {
        $relyingParties = Get-AdfsRelyingPartyTrust
        
        Add-AnalysisResult -Category "Relying Parties" -Property "Total Relying Party Trusts" -Value $relyingParties.Count -Relevance "Number of applications trusting this ADFS for authentication" -Status "INFO"
        
        $enabledRPs = $relyingParties | Where-Object { $_.Enabled }
        Add-AnalysisResult -Category "Relying Parties" -Property "Enabled Relying Party Trusts" -Value $enabledRPs.Count -Relevance "Number of active application trusts" -Status "INFO"
        
        foreach ($rp in $relyingParties) {
            $rpInfo = @{
                Name               = $rp.Name
                Identifier         = $rp.Identifier
                Enabled            = $rp.Enabled
                SignatureAlgorithm = $rp.SignatureAlgorithm
                SamlEndpoints      = $rp.SamlEndpoints.Count
                WSFedEndpoint      = $rp.WSFedEndpoint
                MonitoringEnabled  = $rp.MonitoringEnabled
                AutoUpdateEnabled  = $rp.AutoUpdateEnabled
                MetadataUrl        = Get-SanitizedValue -Value $rp.MetadataUrl -SanitizedText "***CONFIGURED***"
            }
            
            $status = if ($rp.Enabled) { "OK" } else { "INFO" }
            Add-AnalysisResult -Category "Relying Parties" -Property "RP: $($rp.Name)" -Value ($rpInfo | ConvertTo-Json -Compress) -Relevance "Application trust configuration for $($rp.Name)" -Status $status
            
            # Check for security concerns
            if ($rp.SignatureAlgorithm -eq "http://www.w3.org/2000/09/xmldsig#rsa-sha1") {
                Add-AnalysisResult -Category "Security" -Property "Weak Signature Algorithm" -Value "$($rp.Name) uses SHA1" -Relevance "SHA1 is deprecated and should be upgraded to SHA256" -Status "WARNING" -Recommendation "Upgrade to SHA256 signature algorithm"
            }
        }
        
    } catch {
        Add-AnalysisResult -Category "Relying Parties" -Property "Relying Party Analysis" -Value "Error: $($_.Exception.Message)" -Relevance "Relying parties are applications that trust ADFS" -Status "ERROR"
    }
}

function Get-ClaimsProviderTrustsAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing Claims Provider Trusts..." -ForegroundColor Yellow
    
    try {
        $claimsProviders = Get-AdfsClaimsProviderTrust
        
        Add-AnalysisResult -Category "Claims Providers" -Property "Total Claims Provider Trusts" -Value $claimsProviders.Count -Relevance "Number of identity providers trusted by this ADFS" -Status "INFO"
        
        foreach ($cp in $claimsProviders) {
            $cpInfo = @{
                Name               = $cp.Name
                Identifier         = $cp.Identifier
                Enabled            = $cp.Enabled
                SignatureAlgorithm = $cp.SignatureAlgorithm
                WSFedEndpoint      = $cp.WSFedEndpoint
                MonitoringEnabled  = $cp.MonitoringEnabled
                AutoUpdateEnabled  = $cp.AutoUpdateEnabled
            }
            
            Add-AnalysisResult -Category "Claims Providers" -Property "CP: $($cp.Name)" -Value ($cpInfo | ConvertTo-Json -Compress) -Relevance "Identity provider trust configuration" -Status "INFO"
        }
        
    } catch {
        Add-AnalysisResult -Category "Claims Providers" -Property "Claims Provider Analysis" -Value "Error: $($_.Exception.Message)" -Relevance "Claims providers are trusted identity sources" -Status "ERROR"
    }
}

function Get-AuthenticationPoliciesAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing Authentication Policies..." -ForegroundColor Yellow
    
    try {
        $globalAuthPolicy = Get-AdfsGlobalAuthenticationPolicy
        
        Add-AnalysisResult -Category "Authentication" -Property "Primary Intranet Auth Methods" -Value ($globalAuthPolicy.PrimaryIntranetAuthenticationProvider -join ", ") -Relevance "Authentication methods for internal network users" -Status "INFO"
        Add-AnalysisResult -Category "Authentication" -Property "Primary Extranet Auth Methods" -Value ($globalAuthPolicy.PrimaryExtranetAuthenticationProvider -join ", ") -Relevance "Authentication methods for external network users" -Status "INFO"
        Add-AnalysisResult -Category "Authentication" -Property "Additional Intranet Auth Methods" -Value ($globalAuthPolicy.AdditionalAuthenticationProvider -join ", ") -Relevance "MFA methods available for internal users" -Status "INFO"
        Add-AnalysisResult -Category "Authentication" -Property "Additional Extranet Auth Methods" -Value ($globalAuthPolicy.AdditionalAuthenticationProvider -join ", ") -Relevance "MFA methods available for external users" -Status "INFO"
        
        Add-AnalysisResult -Category "Authentication" -Property "Device Authentication Enabled" -Value $globalAuthPolicy.DeviceAuthenticationEnabled -Relevance "Whether device-based authentication is enabled" -Status "INFO"
        Add-AnalysisResult -Category "Authentication" -Property "Windows Integrated Auth Enabled" -Value $globalAuthPolicy.WindowsIntegratedFallbackEnabled -Relevance "Fallback to Windows authentication when other methods fail" -Status "INFO"
        
        # Additional authentication rules (ADFS 2016+)
        if ($script:ADFSFarmBehaviorLevel -ge 3) {
            try {
                $additionalAuthRules = Get-AdfsAdditionalAuthenticationRule
                if ($additionalAuthRules) {
                    Add-AnalysisResult -Category "Authentication" -Property "Additional Auth Rules" -Value $additionalAuthRules -Relevance "Custom rules that trigger MFA based on conditions" -Status "INFO"
                }
            } catch {
                Add-AnalysisResult -Category "Authentication" -Property "Additional Auth Rules" -Value "Error: $($_.Exception.Message)" -Relevance "Failed to retrieve MFA rules" -Status "ERROR"
            }
        }
        
    } catch {
        Add-AnalysisResult -Category "Authentication" -Property "Authentication Policy Analysis" -Value "Error: $($_.Exception.Message)" -Relevance "Authentication policies control how users authenticate" -Status "ERROR"
    }
}

function Get-DeviceRegistrationAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing Device Registration Service..." -ForegroundColor Yellow
    
    try {
        $deviceRegistration = Get-AdfsDeviceRegistration
        
        Add-AnalysisResult -Category "Device Registration" -Property "Service State" -Value $deviceRegistration.IsEnabled -Relevance "Whether device registration service is enabled for hybrid Azure AD join" -Status "INFO"
        Add-AnalysisResult -Category "Device Registration" -Property "Maximum Devices Per User" -Value $deviceRegistration.MaximumRegistrationInactivityPeriod -Relevance "Limit on devices each user can register" -Status "INFO"
        
        $upnSuffixes = Get-AdfsDeviceRegistrationUpnSuffix
        Add-AnalysisResult -Category "Device Registration" -Property "UPN Suffixes" -Value ($upnSuffixes -join ", ") -Relevance "UPN suffixes allowed for device registration" -Status "INFO"
        
    } catch {
        Add-AnalysisResult -Category "Device Registration" -Property "Device Registration Analysis" -Value "Error: $($_.Exception.Message)" -Relevance "Device registration enables modern authentication scenarios" -Status "ERROR"
    }
}

function Get-ModernAuthenticationFeaturesAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing Modern Authentication Features..." -ForegroundColor Yellow
    
    # OAuth 2.0 and OpenID Connect settings (ADFS 2016+)
    if ($script:ADFSFarmBehaviorLevel -ge 3) {
        try {
            $appGroups = Get-AdfsApplicationGroup
            Add-AnalysisResult -Category "Modern Auth" -Property "Application Groups" -Value $appGroups.Count -Relevance "OAuth 2.0/OpenID Connect application groups for modern authentication" -Status "INFO"
            
            foreach ($group in $appGroups) {
                $groupInfo = @{
                    Name        = $group.Name
                    Description = $group.Description
                    Enabled     = $group.Enabled
                }
                Add-AnalysisResult -Category "Modern Auth" -Property "App Group: $($group.Name)" -Value ($groupInfo | ConvertTo-Json -Compress) -Relevance "Modern authentication application configuration" -Status "INFO"
            }
        } catch {
            Add-AnalysisResult -Category "Modern Auth" -Property "Application Groups" -Value "Error: $($_.Exception.Message)" -Relevance "Application groups enable OAuth 2.0 and OpenID Connect" -Status "ERROR"
        }
    }
    
    # Password Protection (ADFS 2019+)
    if ($script:ADFSFarmBehaviorLevel -ge 4) {
        try {
            $passwordProtection = Get-AdfsBannedPasswordProtection
            Add-AnalysisResult -Category "Security" -Property "Banned Password Protection" -Value $passwordProtection.Enabled -Relevance "Prevents use of common/banned passwords" -Status $(if ($passwordProtection.Enabled) { "OK" } else { "WARNING" }) -Recommendation $(if (-not $passwordProtection.Enabled) { "Enable banned password protection for better security" } else { "" })
        } catch {
            Add-AnalysisResult -Category "Security" -Property "Banned Password Protection" -Value "Error: $($_.Exception.Message)" -Relevance "Failed to retrieve password protection settings" -Status "ERROR"
        }
    }
    
    # Extranet Smart Lockout (ADFS 2016+)
    if ($script:ADFSFarmBehaviorLevel -ge 3) {
        try {
            $lockoutProtection = Get-AdfsAccountLockoutProtection
            Add-AnalysisResult -Category "Security" -Property "Extranet Lockout Protection" -Value $lockoutProtection.EnableExtranetLockoutProtection -Relevance "Protects against brute force attacks from extranet" -Status $(if ($lockoutProtection.EnableExtranetLockoutProtection) { "OK" } else { "WARNING" }) -Recommendation $(if (-not $lockoutProtection.EnableExtranetLockoutProtection) { "Enable extranet lockout protection" } else { "" })
            
            if ($lockoutProtection.EnableExtranetLockoutProtection) {
                Add-AnalysisResult -Category "Security" -Property "Extranet Lockout Threshold" -Value $lockoutProtection.ExtranetLockoutThreshold -Relevance "Number of failed attempts before lockout" -Status "INFO"
                Add-AnalysisResult -Category "Security" -Property "Extranet Observation Window" -Value "$($lockoutProtection.ExtranetObservationWindow) minutes" -Relevance "Time window for counting failed attempts" -Status "INFO"
            }
        } catch {
            Add-AnalysisResult -Category "Security" -Property "Extranet Lockout Protection" -Value "Not Available" -Relevance "Feature available in ADFS 2016+" -Status "INFO"
        }
    }
    
    # FIDO2/WebAuthn (ADFS 2022+)
    if ($script:ADFSFarmBehaviorLevel -ge 5) {
        try {
            $fido2Config = Get-AdfsFido2Configuration
            Add-AnalysisResult -Category "Modern Auth" -Property "FIDO2/WebAuthn Support" -Value $fido2Config.Enabled -Relevance "Modern passwordless authentication using security keys" -Status $(if ($fido2Config.Enabled) { "OK" } else { "INFO" }) -Recommendation $(if (-not $fido2Config.Enabled) { "Consider enabling FIDO2 for passwordless authentication" } else { "" })
        } catch {
            Add-AnalysisResult -Category "Modern Auth" -Property "FIDO2/WebAuthn Support" -Value "Error: $($_.Exception.Message)" -Relevance "Failed to retrieve FIDO2 configuration" -Status "ERROR"
        }
    }
}

function Get-ADFSFarmHealthAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing ADFS Farm Health..." -ForegroundColor Yellow
    
    try {
        # Get comprehensive farm information
        $farmInfo = Get-AdfsFarmInformation
        
        # Farm redundancy analysis
        if ($farmInfo.FarmNodes.Count -gt 1) {
            Add-AnalysisResult -Category "Farm Health" -Property "Farm Redundancy" -Value "Multi-node farm ($($farmInfo.FarmNodes.Count) nodes)" -Relevance "Farm has redundancy for high availability" -Status "OK"
            Add-AnalysisResult -Category "Farm Health" -Property "Farm Nodes" -Value ($farmInfo.FarmNodes -join ", ") -Relevance "All servers in the ADFS farm" -Status "INFO"
        } else {
            Add-AnalysisResult -Category "Farm Health" -Property "Farm Redundancy" -Value "Single node farm" -Relevance "No redundancy - single point of failure" -Status "WARNING" -Recommendation "Consider adding additional farm nodes for high availability"
        }
        
        # Farm behavior level analysis
        $behaviorLevel = $farmInfo.FarmBehavior
        $maxSupportedLevel = switch ($script:ADFSVersionMajor) {
            3 { 1 }  # ADFS 2012 R2
            4 { 3 }  # ADFS 2016  
            5 { 4 }  # ADFS 2019
            6 { 5 }  # ADFS 2022
            default { 0 }
        }
        
        Add-AnalysisResult -Category "Farm Health" -Property "Current Behavior Level" -Value $behaviorLevel -Relevance "Current farm functional level determines available features" -Status "INFO"
        
        if ($behaviorLevel -lt $maxSupportedLevel) {
            Add-AnalysisResult -Category "Farm Health" -Property "Behavior Level Upgrade Available" -Value "Can upgrade from $behaviorLevel to $maxSupportedLevel" -Relevance "Higher behavior level enables more features" -Status "INFO" -Recommendation "Consider upgrading farm behavior level to access newer features (test thoroughly first)"
        } else {
            Add-AnalysisResult -Category "Farm Health" -Property "Behavior Level Status" -Value "At maximum supported level" -Relevance "Farm is using the latest features for this ADFS version" -Status "OK"
        }
        
    } catch {
        Add-AnalysisResult -Category "Farm Health" -Property "Farm Health Analysis" -Value "Error: $($_.Exception.Message)" -Relevance "Basic farm health validation" -Status "ERROR"
    }
}

function Get-AccessControlPoliciesAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing Access Control Policies..." -ForegroundColor Yellow
    
    try {
        $accessPolicies = Get-AdfsAccessControlPolicy
        Add-AnalysisResult -Category "Access Control" -Property "Total Access Control Policies" -Value $accessPolicies.Count -Relevance "Number of conditional access policies configured" -Status "INFO"
        
        foreach ($policy in $accessPolicies) {
            $policyInfo = @{
                Name           = $policy.Name
                Identifier     = $policy.Identifier
                PolicyMetadata = $policy.PolicyMetadata
            }
            Add-AnalysisResult -Category "Access Control" -Property "Policy: $($policy.Name)" -Value ($policyInfo | ConvertTo-Json -Compress) -Relevance "Access control policy for conditional access" -Status "INFO"
        }
    } catch {
        Add-AnalysisResult -Category "Access Control" -Property "Access Control Policies" -Value "Error: $($_.Exception.Message)" -Relevance "Access control policies enhance security" -Status "ERROR"
    }
}

function Get-AuthenticationProvidersAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing Authentication Providers..." -ForegroundColor Yellow
    
    try {
        $authProviders = Get-AdfsAuthenticationProvider
        Add-AnalysisResult -Category "Authentication Providers" -Property "Total Authentication Providers" -Value $authProviders.Count -Relevance "Number of authentication methods available" -Status "INFO"
        
        foreach ($provider in $authProviders) {
            $providerInfo = @{
                Name                  = $provider.Name
                DisplayName           = $provider.DisplayName
                Enabled               = $provider.Enabled
                ConfigurationFilePath = Get-SanitizedValue -Value $provider.ConfigurationFilePath
            }
            Add-AnalysisResult -Category "Authentication Providers" -Property "Provider: $($provider.Name)" -Value ($providerInfo | ConvertTo-Json -Compress) -Relevance "Authentication provider configuration" -Status $(if ($provider.Enabled) { "OK" } else { "INFO" })
        }
    } catch {
        Add-AnalysisResult -Category "Authentication Providers" -Property "Authentication Providers" -Value "Error: $($_.Exception.Message)" -Relevance "Authentication providers enable different auth methods" -Status "ERROR"
    }
}

function Get-FederationPartnersAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing Trusted Federation Partners..." -ForegroundColor Yellow
    
    try {
        try {
            $federationPartners = Get-AdfsTrustedFederationPartner
            Add-AnalysisResult -Category "Federation Partners" -Property "Total Federation Partners" -Value $federationPartners.Count -Relevance "Number of trusted federation partnerships" -Status "INFO"
            
            foreach ($partner in $federationPartners) {
                $partnerInfo = @{
                    Name                      = $partner.Name
                    Enabled                   = $partner.Enabled
                    FederationPartnerHostName = Get-SanitizedValue -Value $partner.FederationPartnerHostName
                }
                Add-AnalysisResult -Category "Federation Partners" -Property "Partner: $($partner.Name)" -Value ($partnerInfo | ConvertTo-Json -Compress) -Relevance "Federated partnership configuration" -Status "INFO"
            }
        } catch {
            Add-AnalysisResult -Category "Federation Partners" -Property "Federation Partners" -Value "Error: $($_.Exception.Message)" -Relevance "Failed to retrieve federation partner information" -Status "ERROR"
        }
    } catch {
        Add-AnalysisResult -Category "Federation Partners" -Property "Federation Partners" -Value "Error: $($_.Exception.Message)" -Relevance "Federation partners enable cross-organization trust" -Status "ERROR"
    }
}

function Get-WebCustomizationAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing Web Customization Settings..." -ForegroundColor Yellow
    
    try {
        # Web Configuration
        try {
            $webConfig = Get-AdfsWebConfig
            Add-AnalysisResult -Category "Web Customization" -Property "Active Theme" -Value $webConfig.ActiveThemeName -Relevance "Currently active web theme" -Status "INFO"
            Add-AnalysisResult -Category "Web Customization" -Property "Customization File Path" -Value $webConfig.CustomizationFilePath -Relevance "Path to customization files" -Status "INFO"
        } catch {
            Add-AnalysisResult -Category "Web Customization" -Property "Web Config" -Value "Error: $($_.Exception.Message)" -Relevance "Failed to retrieve web configuration" -Status "ERROR"
        }
        
        # Authentication Provider Web Content
        try {
            $authWebContent = Get-AdfsAuthenticationProviderWebContent
            if ($authWebContent) {
                Add-AnalysisResult -Category "Web Customization" -Property "Auth Provider Web Content" -Value "Customized" -Relevance "Custom authentication provider UI elements" -Status "INFO"
            }
        } catch {
            Add-AnalysisResult -Category "Web Customization" -Property "Auth Web Content" -Value "Error: $($_.Exception.Message)" -Relevance "Failed to retrieve authentication web content" -Status "ERROR"
        }
        
        # Relying Party Web Content
        try {
            $rpWebContent = Get-AdfsRelyingPartyWebContent
            Add-AnalysisResult -Category "Web Customization" -Property "RP Web Content Items" -Value $rpWebContent.Count -Relevance "Custom UI elements per relying party" -Status "INFO"
        } catch {
            Add-AnalysisResult -Category "Web Customization" -Property "RP Web Content" -Value "Error: $($_.Exception.Message)" -Relevance "Failed to retrieve relying party web content" -Status "ERROR"
        }
        
        # Relying Party Web Themes
        try {
            $rpWebThemes = Get-AdfsRelyingPartyWebTheme
            Add-AnalysisResult -Category "Web Customization" -Property "RP-Specific Themes" -Value $rpWebThemes.Count -Relevance "Themes applied to specific relying parties" -Status "INFO"
        } catch {
            Add-AnalysisResult -Category "Web Customization" -Property "RP Web Themes" -Value "Error: $($_.Exception.Message)" -Relevance "Failed to retrieve relying party web themes" -Status "ERROR"
        }
    } catch {
        Add-AnalysisResult -Category "Web Customization" -Property "Web Customization Analysis" -Value "Error: $($_.Exception.Message)" -Relevance "Web customization affects user experience" -Status "ERROR"
    }
}

function Get-AttributeStoresAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing Attribute Stores..." -ForegroundColor Yellow
    
    try {
        $attributeStores = Get-AdfsAttributeStore
        
        Add-AnalysisResult -Category "Attribute Stores" -Property "Total Attribute Stores" -Value $attributeStores.Count -Relevance "Number of configured attribute sources for claims" -Status "INFO"
        
        foreach ($store in $attributeStores) {
            $storeInfo = @{
                Name              = $store.Name
                TypeQualifiedName = $store.TypeQualifiedName
                Configuration     = Get-SanitizedValue -Value ($store.Configuration | ConvertTo-Json -Compress)
            }
            
            Add-AnalysisResult -Category "Attribute Stores" -Property "Store: $($store.Name)" -Value ($storeInfo | ConvertTo-Json -Compress) -Relevance "Attribute store providing claims data" -Status "INFO"
        }
        
    } catch {
        Add-AnalysisResult -Category "Attribute Stores" -Property "Attribute Store Analysis" -Value "Error: $($_.Exception.Message)" -Relevance "Attribute stores provide data for claims processing" -Status "ERROR"
    }
}

function Get-ClaimDescriptionsAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing Claim Descriptions..." -ForegroundColor Yellow
    
    try {
        $claimDescriptions = Get-AdfsClaimDescription
        
        Add-AnalysisResult -Category "Claims" -Property "Total Claim Descriptions" -Value $claimDescriptions.Count -Relevance "Number of defined claim types available for rules" -Status "INFO"
        
        # Check for common claim types
        $commonClaims = @("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role")
        
        foreach ($claimType in $commonClaims) {
            $claim = $claimDescriptions | Where-Object { $_.ClaimType -eq $claimType }
            $status = if ($claim) { "OK" } else { "INFO" }
            Add-AnalysisResult -Category "Claims" -Property "Common Claim: $(Split-Path $claimType -Leaf)" -Value $(if ($claim) { "Available" } else { "Not Defined" }) -Relevance "Standard claim type used by many applications" -Status $status
        }
        
    } catch {
        Add-AnalysisResult -Category "Claims" -Property "Claim Description Analysis" -Value "Error: $($_.Exception.Message)" -Relevance "Claim descriptions define available claim types" -Status "ERROR"
    }
}

function Get-WebThemesAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Analyzing Web Themes and Customization..." -ForegroundColor Yellow
    
    try {
        $webThemes = Get-AdfsWebTheme
        
        Add-AnalysisResult -Category "Web Themes" -Property "Total Web Themes" -Value $webThemes.Count -Relevance "Number of customized sign-in page themes" -Status "INFO"
        
        foreach ($theme in $webThemes) {
            $themeInfo = @{
                Name           = $theme.Name
                IsBuiltinTheme = $theme.IsBuiltinTheme
                StyleSheet     = if ($theme.StyleSheet) { "Customized" } else { "Default" }
                Logo           = if ($theme.Logo) { "Customized" } else { "Default" }
                Illustration   = if ($theme.Illustration) { "Customized" } else { "Default" }
            }
            
            Add-AnalysisResult -Category "Web Themes" -Property "Theme: $($theme.Name)" -Value ($themeInfo | ConvertTo-Json -Compress) -Relevance "Visual customization for sign-in pages" -Status "INFO"
        }
        
        # Global web content
        $globalWebContent = Get-AdfsGlobalWebContent
        if ($globalWebContent) {
            Add-AnalysisResult -Category "Web Content" -Property "Global Web Content" -Value "Customized" -Relevance "Global customizations applied to all sign-in pages" -Status "INFO"
        }
        
    } catch {
        Add-AnalysisResult -Category "Web Themes" -Property "Web Theme Analysis" -Value "Error: $($_.Exception.Message)" -Relevance "Web themes customize the user sign-in experience" -Status "ERROR"
    }
}

function Get-HealthAndMonitoringAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Performing Health Checks..." -ForegroundColor Yellow
    
    # Event Log Analysis
    try {
        $startTime = (Get-Date).AddDays(-$EventLogDays)
        $adfsAdminLogs = Get-WinEvent -FilterHashtable @{LogName = 'AD FS/Admin'; StartTime = $startTime } -MaxEvents 1000 -ErrorAction SilentlyContinue
        
        if ($adfsAdminLogs) {
            $errorCount = ($adfsAdminLogs | Where-Object { $_.LevelDisplayName -eq "Error" }).Count
            $warningCount = ($adfsAdminLogs | Where-Object { $_.LevelDisplayName -eq "Warning" }).Count
            $totalEvents = $adfsAdminLogs.Count
            
            Add-AnalysisResult -Category "Health" -Property "Total Events ($EventLogDays day(s))" -Value $totalEvents -Relevance "Total ADFS admin log events indicate activity level" -Status "INFO"
            Add-AnalysisResult -Category "Health" -Property "Errors ($EventLogDays day(s))" -Value $errorCount -Relevance "Error events in ADFS admin log indicate issues" -Status $(if ($errorCount -gt 0) { "WARNING" } else { "OK" })
            Add-AnalysisResult -Category "Health" -Property "Warnings ($EventLogDays day(s))" -Value $warningCount -Relevance "Warning events may indicate potential issues" -Status $(if ($warningCount -gt 10) { "WARNING" } else { "INFO" })
            
            # Analyze most common error IDs
            $errorEvents = $adfsAdminLogs | Where-Object { $_.LevelDisplayName -eq "Error" }
            if ($errorEvents) {
                $topErrors = $errorEvents | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5
                $errorSummary = $topErrors | ForEach-Object { "ID $($_.Name): $($_.Count) occurrences" }
                Add-AnalysisResult -Category "Health" -Property "Top Error IDs" -Value ($errorSummary -join "; ") -Relevance "Most frequent error patterns" -Status "WARNING"
            }
        } else {
            Add-AnalysisResult -Category "Health" -Property "Event Log Access" -Value "No events found or access denied" -Relevance "May indicate permissions issue or very quiet period" -Status "WARNING"
        }
    } catch {
        Add-AnalysisResult -Category "Health" -Property "Event Log Analysis" -Value "Error accessing event logs: $($_.Exception.Message)" -Relevance "Event logs provide operational health information" -Status "WARNING"
    }
    
    # Performance Counter Analysis (if requested)
    if ($IncludePerformanceCounters) {
        try {
            Write-Host "Collecting Performance Counters..." -ForegroundColor Yellow
            
            $perfCounters = @(
                "\AD FS\Token Requests/Sec",
                "\AD FS\Federation Metadata Requests/Sec", 
                "\AD FS\Artifact Resolution Requests/Sec",
                "\AD FS\Extranet Account Lockouts/Sec",
                "\AD FS\SQL Failures/Sec"
            )
            
            foreach ($counter in $perfCounters) {
                try {
                    $value = (Get-Counter $counter -SampleInterval 1 -MaxSamples 3 -ErrorAction SilentlyContinue | 
                        Select-Object -ExpandProperty CounterSamples | 
                        Measure-Object -Property CookedValue -Average).Average
                    
                    if ($null -ne $value) {
                        Add-AnalysisResult -Category "Performance" -Property (Split-Path $counter -Leaf) -Value ([math]::Round($value, 2)) -Relevance "Performance metric for ADFS operations" -Status "INFO"
                    }
                } catch {
                    Add-AnalysisResult -Category "Performance" -Property (Split-Path $counter -Leaf) -Value "Not Available" -Relevance "Performance counter may not exist in this ADFS version" -Status "INFO"
                }
            }
        } catch {
            Add-AnalysisResult -Category "Performance" -Property "Performance Counter Analysis" -Value "Error: $($_.Exception.Message)" -Relevance "Performance counters provide operational metrics" -Status "WARNING"
        }
    }
    
    # Database connectivity
    try {
        $syncProperties = Get-AdfsSyncProperties
        Add-AnalysisResult -Category "Health" -Property "Primary Computer" -Value $syncProperties.PrimaryComputerName -Relevance "Primary node for configuration database synchronization" -Status "INFO"
        Add-AnalysisResult -Category "Health" -Property "Sync Interval" -Value "$($syncProperties.PollDuration) seconds" -Relevance "How often configuration changes are synchronized" -Status "INFO"
    } catch {
        Add-AnalysisResult -Category "Health" -Property "Database Sync" -Value "Error: $($_.Exception.Message)" -Relevance "Database synchronization is critical for farm consistency" -Status "ERROR"
    }
}

function Get-SecurityConfigurationAnalysis {
    [CmdletBinding()]
    param()
    
    Write-Host "Performing Security Analysis..." -ForegroundColor Yellow
    
    # Check for deprecated protocols and algorithms
    $securityIssues = @()
    
    try {
        # Get data for security analysis
        $relyingParties = Get-AdfsRelyingPartyTrust -ErrorAction SilentlyContinue
        $endpoints = Get-AdfsEndpoint -ErrorAction SilentlyContinue
        $certificates = Get-AdfsCertificate -ErrorAction SilentlyContinue
        
        # Check for weak algorithms in relying parties
        foreach ($rp in $relyingParties) {
            if ($rp.SignatureAlgorithm -eq "http://www.w3.org/2000/09/xmldsig#rsa-sha1") {
                $securityIssues += "Relying Party '$($rp.Name)' uses deprecated SHA1 signature algorithm"
            }
        }
        
        # Check for HTTP endpoints
        $httpEndpoints = $endpoints | Where-Object { $_.SecurityMode -eq "None" -or $_.Protocol -eq "http" }
        if ($httpEndpoints) {
            $securityIssues += "Insecure HTTP endpoints detected: $($httpEndpoints.AddressPath -join ', ')"
        }
        
        # Check certificate expiry
        $expiringCerts = $certificates | Where-Object { ($_.Certificate.NotAfter - (Get-Date)).Days -lt 30 }
        if ($expiringCerts) {
            $securityIssues += "Certificates expiring within 30 days: $($expiringCerts.CertificateType -join ', ')"
        }
        
        if ($securityIssues.Count -gt 0) {
            Add-AnalysisResult -Category "Security" -Property "Security Issues Found" -Value ($securityIssues -join "; ") -Relevance "Security issues that should be addressed" -Status "WARNING" -Recommendation "Review and remediate security issues"
        } else {
            Add-AnalysisResult -Category "Security" -Property "Security Status" -Value "No immediate security issues detected" -Relevance "Overall security posture assessment" -Status "OK"
        }
        
    } catch {
        Add-AnalysisResult -Category "Security" -Property "Security Analysis" -Value "Error: $($_.Exception.Message)" -Relevance "Security analysis protects against vulnerabilities" -Status "ERROR"
    }
}

function Export-AnalysisResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCustomObject]$ConfigurationExport = $null
    )
    
    Write-Host "Analysis Complete! Generating Report..." -ForegroundColor Green
    
    # Create summary statistics
    $totalItems = $script:AnalysisResults.Count
    $criticalItems = ($script:AnalysisResults | Where-Object { $_.Status -eq "CRITICAL" }).Count
    $warningItems = ($script:AnalysisResults | Where-Object { $_.Status -eq "WARNING" }).Count
    $errorItems = ($script:AnalysisResults | Where-Object { $_.Status -eq "ERROR" }).Count
    $okItems = ($script:AnalysisResults | Where-Object { $_.Status -eq "OK" }).Count
    $infoItems = ($script:AnalysisResults | Where-Object { $_.Status -eq "INFO" }).Count
    
    # Create summary object
    $summaryReport = [PSCustomObject]@{
        AnalysisTimestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        AnalysisServer      = $env:COMPUTERNAME
        TotalItemsAnalyzed  = $totalItems
        CriticalIssues      = $criticalItems
        Warnings            = $warningItems
        Errors              = $errorItems
        OKStatus            = $okItems
        InformationalItems  = $infoItems
        OverallHealthScore  = [math]::Round((($okItems + $infoItems) / $totalItems) * 100, 2)
        RecommendationCount = ($script:AnalysisResults | Where-Object { $_.Recommendation -ne "" }).Count
    }
    
    # Display summary
    Write-Host "`n=== ADFS ANALYSIS SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Analysis Timestamp: $($summaryReport.AnalysisTimestamp)" -ForegroundColor White
    Write-Host "Analysis Server: $($summaryReport.AnalysisServer)" -ForegroundColor White
    Write-Host "Total Items Analyzed: $($summaryReport.TotalItemsAnalyzed)" -ForegroundColor White
    Write-Host "Overall Health Score: $($summaryReport.OverallHealthScore)%" -ForegroundColor $(if ($summaryReport.OverallHealthScore -gt 80) { "Green" } elseif ($summaryReport.OverallHealthScore -gt 60) { "Yellow" } else { "Red" })
    Write-Host ""
    Write-Host "Status Breakdown:" -ForegroundColor Cyan
    Write-Host "  Critical Issues: $($summaryReport.CriticalIssues)" -ForegroundColor $(if ($summaryReport.CriticalIssues -gt 0) { "Red" } else { "Green" })
    Write-Host "  Warnings: $($summaryReport.Warnings)" -ForegroundColor $(if ($summaryReport.Warnings -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Errors: $($summaryReport.Errors)" -ForegroundColor $(if ($summaryReport.Errors -gt 0) { "Red" } else { "Green" })
    Write-Host "  OK Status: $($summaryReport.OKStatus)" -ForegroundColor Green
    Write-Host "  Informational: $($summaryReport.InformationalItems)" -ForegroundColor Cyan
    Write-Host "  Recommendations: $($summaryReport.RecommendationCount)" -ForegroundColor Yellow
    
    # Create comprehensive report object
    $comprehensiveReport = [PSCustomObject]@{
        Summary             = $summaryReport
        DetailedAnalysis    = $script:AnalysisResults
        CategoryBreakdown   = ($script:AnalysisResults | Group-Object Category | Sort-Object Name | ForEach-Object {
                [PSCustomObject]@{
                    Category  = $_.Name
                    ItemCount = $_.Count
                    Critical  = ($_.Group | Where-Object { $_.Status -eq "CRITICAL" }).Count
                    Warnings  = ($_.Group | Where-Object { $_.Status -eq "WARNING" }).Count
                    Errors    = ($_.Group | Where-Object { $_.Status -eq "ERROR" }).Count
                    OK        = ($_.Group | Where-Object { $_.Status -eq "OK" }).Count
                    Info      = ($_.Group | Where-Object { $_.Status -eq "INFO" }).Count
                }
            })
        CriticalFindings    = ($script:AnalysisResults | Where-Object { $_.Status -eq "CRITICAL" })
        WarningFindings     = ($script:AnalysisResults | Where-Object { $_.Status -eq "WARNING" })
        ErrorFindings       = ($script:AnalysisResults | Where-Object { $_.Status -eq "ERROR" })
        Recommendations     = ($script:AnalysisResults | Where-Object { $_.Recommendation -ne "" } | Select-Object Category, Property, Recommendation)
        SecurityFindings    = ($script:AnalysisResults | Where-Object { $_.Category -eq "Security" })
        ConfigurationExport = $ConfigurationExport
    }
    
    # Display critical findings
    if ($comprehensiveReport.CriticalFindings.Count -gt 0) {
        Write-Host "`n=== CRITICAL FINDINGS ===" -ForegroundColor Red
        foreach ($finding in $comprehensiveReport.CriticalFindings) {
            Write-Host "[$($finding.Category)] $($finding.Property): $($finding.Value)" -ForegroundColor Red
            Write-Host "  Relevance: $($finding.Relevance)" -ForegroundColor White
            if ($finding.Recommendation) {
                Write-Host "  Recommendation: $($finding.Recommendation)" -ForegroundColor Yellow
            }
            Write-Host ""
        }
    }
    
    # Display warnings
    if ($comprehensiveReport.WarningFindings.Count -gt 0) {
        Write-Host "=== WARNING FINDINGS ===" -ForegroundColor Yellow
        foreach ($finding in $comprehensiveReport.WarningFindings) {
            Write-Host "[$($finding.Category)] $($finding.Property): $($finding.Value)" -ForegroundColor Yellow
            Write-Host "  Relevance: $($finding.Relevance)" -ForegroundColor White
            if ($finding.Recommendation) {
                Write-Host "  Recommendation: $($finding.Recommendation)" -ForegroundColor Cyan
            }
            Write-Host ""
        }
    }
    
    # Display category breakdown
    Write-Host "=== CATEGORY BREAKDOWN ===" -ForegroundColor Cyan
    $comprehensiveReport.CategoryBreakdown | Format-Table -AutoSize
    
    # Export results
    try {
        # Export to JSON
        $comprehensiveReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "Detailed analysis exported to: $OutputPath" -ForegroundColor Green
        
        # Export to CSV (always included)
        $csvPath = $OutputPath -replace '\.json', '.csv'
        $script:AnalysisResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "Analysis results exported to CSV: $csvPath" -ForegroundColor Green
        
        # Create executive summary report
        $execSummaryPath = $OutputPath -replace '\.json', '_ExecutiveSummary.txt'
        $execSummary = @"
ADFS ENVIRONMENT ANALYSIS - EXECUTIVE SUMMARY
============================================
Analysis Date: $($summaryReport.AnalysisTimestamp)
Server Analyzed: $($summaryReport.AnalysisServer)
Overall Health Score: $($summaryReport.OverallHealthScore)%

CRITICAL ITEMS REQUIRING IMMEDIATE ATTENTION: $($summaryReport.CriticalIssues)
$(if($comprehensiveReport.CriticalFindings.Count -gt 0) {
    $comprehensiveReport.CriticalFindings | ForEach-Object { "- [$($_.Category)] $($_.Property): $($_.Value)" }
} else { "None identified" })

WARNING ITEMS REQUIRING ATTENTION: $($summaryReport.Warnings)
$(if($comprehensiveReport.WarningFindings.Count -gt 0) {
    $comprehensiveReport.WarningFindings | ForEach-Object { "- [$($_.Category)] $($_.Property): $($_.Value)" }
} else { "None identified" })

KEY RECOMMENDATIONS: $($summaryReport.RecommendationCount)
$(if($comprehensiveReport.Recommendations.Count -gt 0) {
    $comprehensiveReport.Recommendations | ForEach-Object { "- [$($_.Category)] $($_.Property): $($_.Recommendation)" }
} else { "None at this time" })

NEXT STEPS:
1. Address all critical findings immediately
2. Plan remediation for warning items
3. Review recommendations for optimization
4. Schedule regular health assessments
5. Monitor certificate expiration dates

For detailed technical information, refer to the complete analysis report: $OutputPath
"@
        
        $execSummary | Out-File -FilePath $execSummaryPath -Encoding UTF8
        Write-Host "Executive summary exported to: $execSummaryPath" -ForegroundColor Green
        
    } catch {
        Write-Warning "Error exporting results: $($_.Exception.Message)"
    }
    
    # Display final recommendations
    Write-Host "`n=== FINAL RECOMMENDATIONS ===" -ForegroundColor Yellow
    Write-Host "1. IMMEDIATE: Address any critical findings listed above" -ForegroundColor Red
    Write-Host "2. PRIORITY: Review and resolve warning items" -ForegroundColor Yellow
    Write-Host "3. SECURITY: Implement security recommendations" -ForegroundColor Orange
    Write-Host "4. MONITORING: Set up automated monitoring for certificate expiration" -ForegroundColor Cyan
    Write-Host "5. DOCUMENTATION: Keep this analysis for compliance and audit purposes" -ForegroundColor Cyan
    Write-Host "6. SCHEDULE: Re-run this analysis monthly or after configuration changes" -ForegroundColor Cyan
    
    Write-Host "`n=== ANALYSIS COMPLETE ===" -ForegroundColor Green
    Write-Host "Use the following PowerShell commands to work with the results:" -ForegroundColor Cyan
    Write-Host "`$report = Get-Content '$OutputPath' | ConvertFrom-Json" -ForegroundColor Gray
    Write-Host "`$report.DetailedAnalysis | Where-Object { `$_.Status -eq 'CRITICAL' } | Format-Table" -ForegroundColor Gray
    Write-Host "`$report.DetailedAnalysis | Where-Object { `$_.Category -eq 'Security' } | Format-Table" -ForegroundColor Gray
    Write-Host "`$report.Recommendations | Format-Table -AutoSize" -ForegroundColor Gray
    
    # Return the comprehensive report object for further PowerShell manipulation
    return $comprehensiveReport
}

function Export-ADFSConfiguration {
    [CmdletBinding()]
    param()
    
    Write-Host "Exporting Complete ADFS Configuration..." -ForegroundColor Green
    
    # Create shared timestamp for all exports in this run
    $exportTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    Write-Host "Export timestamp: $exportTimestamp" -ForegroundColor Cyan
    
    # Create exports directory
    $exportPath = $OutputPath -replace '\.json$', '_Exports'
    if (-not (Test-Path $exportPath)) {
        New-Item -Path $exportPath -ItemType Directory -Force | Out-Null
    }
    
    $exports = @()
    
    # 1. RELYING PARTY TRUSTS (Export Current Configuration)
    try {
        Write-Host "  Exporting Relying Party Trusts..." -ForegroundColor Yellow
        $relyingParties = Get-AdfsRelyingPartyTrust
        
        # PRIMARY: FULL BACKUP - Raw XML export (Microsoft's native format) - ALWAYS GET THIS FIRST
        $rpXmlPath = Join-Path $exportPath "RelyingPartyTrusts_Full_Backup_$exportTimestamp.xml"
        $relyingParties | Export-Clixml -Path $rpXmlPath -Encoding UTF8
        
        # SECONDARY: HUMAN-READABLE CSV - Enhanced CSV export using PSCustomObject for better formatting
        $rpCsvPath = Join-Path $exportPath "RelyingPartyTrusts_Summary_$exportTimestamp.csv"
        $rpCsvData = foreach ($rp in $relyingParties) {
            [PSCustomObject]@{
                Name                  = $rp.Name
                Identifier            = ($rp.Identifier -join '; ')
                Enabled               = $rp.Enabled
                SignatureAlgorithm    = $rp.SignatureAlgorithm
                WSFedEndpoint         = $rp.WSFedEndpoint
                MetadataUrl           = $rp.MetadataUrl
                MonitoringEnabled     = $rp.MonitoringEnabled
                AutoUpdateEnabled     = $rp.AutoUpdateEnabled
                SamlEndpointsCount    = if ($rp.SamlEndpoints) { $rp.SamlEndpoints.Count } else { 0 }
                HasIssuanceRules      = -not [string]::IsNullOrEmpty($rp.IssuanceTransformRules)
                HasAuthorizationRules = -not [string]::IsNullOrEmpty($rp.IssuanceAuthorizationRules)
                ExportTimestamp       = $exportTimestamp
            }
        }
        $rpCsvData | Export-Csv -Path $rpCsvPath -NoTypeInformation -Encoding UTF8
        
        # TERTIARY: JSON backup for reference
        $rpJsonPath = Join-Path $exportPath "RelyingPartyTrusts_Complete.json"
        $relyingParties | ConvertTo-Json -Depth 10 | Out-File -FilePath $rpJsonPath -Encoding UTF8
        
        # DETAILED: Individual RP exports with claim rules for analysis
        $rpDetailPath = Join-Path $exportPath "RelyingPartyTrusts_Detailed"
        if (-not (Test-Path $rpDetailPath)) {
            New-Item -Path $rpDetailPath -ItemType Directory -Force | Out-Null
        }
        
        foreach ($rp in $relyingParties) {
            $rpDetail = [PSCustomObject]@{
                ExportTimestamp              = $exportTimestamp
                Name                         = $rp.Name
                Identifier                   = $rp.Identifier
                FullConfiguration            = $rp
                IssuanceTransformRules       = $rp.IssuanceTransformRules
                IssuanceAuthorizationRules   = $rp.IssuanceAuthorizationRules
                DelegationAuthorizationRules = $rp.DelegationAuthorizationRules
            }
            
            $sanitizedName = $rp.Name -replace '[\\/:*?"<>|]', '_'
            $rpDetailFile = Join-Path $rpDetailPath "RP_$sanitizedName.json"
            $rpDetail | ConvertTo-Json -Depth 10 | Out-File -FilePath $rpDetailFile -Encoding UTF8
        }
        
        $exports += "Relying Party Trusts (Raw XML): $rpXmlPath"
        $exports += "Relying Party Trusts (CSV Summary): $rpCsvPath"
        $exports += "Relying Party Trusts (JSON): $rpJsonPath"
        $exports += "Relying Party Trusts (Individual): $rpDetailPath"
        
    } catch {
        Write-Warning "Error exporting Relying Party Trusts: $($_.Exception.Message)"
    }
    
    # 2. CLAIMS PROVIDER TRUSTS
    try {
        Write-Host "  Exporting Claims Provider Trusts..." -ForegroundColor Yellow
        $claimsProviders = Get-AdfsClaimsProviderTrust
        
        # PRIMARY: FULL BACKUP - Raw XML export (Microsoft's native format)
        $cpXmlPath = Join-Path $exportPath "ClaimsProviderTrusts_Full_Backup_$exportTimestamp.xml"
        $claimsProviders | Export-Clixml -Path $cpXmlPath -Encoding UTF8
        
        # SECONDARY: HUMAN-READABLE CSV
        $cpCsvPath = Join-Path $exportPath "ClaimsProviderTrusts_Summary_$exportTimestamp.csv"
        $cpCsvData = foreach ($cp in $claimsProviders) {
            [PSCustomObject]@{
                Name               = $cp.Name
                Identifier         = ($cp.Identifier -join '; ')
                Enabled            = $cp.Enabled
                AutoUpdateEnabled  = $cp.AutoUpdateEnabled
                MonitoringEnabled  = $cp.MonitoringEnabled
                MetadataUrl        = $cp.MetadataUrl
                EndpointsCount     = if ($cp.SamlEndpoints) { $cp.SamlEndpoints.Count } else { 0 }
                HasAcceptanceRules = -not [string]::IsNullOrEmpty($cp.AcceptanceTransformRules)
                ExportTimestamp    = $exportTimestamp
            }
        }
        $cpCsvData | Export-Csv -Path $cpCsvPath -NoTypeInformation -Encoding UTF8
        
        $exports += "Claims Provider Trusts (Full Backup): $cpXmlPath"
        $exports += "Claims Provider Trusts (CSV Summary): $cpCsvPath"
        
    } catch {
        Write-Warning "Error exporting Claims Provider Trusts: $($_.Exception.Message)"
    }
    
    # 3. CLAIM RULES (Issuance and Authorization)
    try {
        Write-Host "  Exporting Claim Rules..." -ForegroundColor Yellow
        $claimRules = @()
        
        foreach ($rp in (Get-AdfsRelyingPartyTrust)) {
            $issuanceRules = Get-AdfsRelyingPartyTrust -Name $rp.Name | Select-Object -ExpandProperty IssuanceTransformRules
            $authorizationRules = Get-AdfsRelyingPartyTrust -Name $rp.Name | Select-Object -ExpandProperty IssuanceAuthorizationRules
            
            $claimRules += [PSCustomObject]@{
                RelyingPartyName             = $rp.Name
                IssuanceTransformRules       = $issuanceRules
                IssuanceAuthorizationRules   = $authorizationRules
                DelegationAuthorizationRules = $rp.DelegationAuthorizationRules
            }
        }
        
        $rulesJsonPath = Join-Path $exportPath "ClaimRules_Complete.json"
        $claimRules | ConvertTo-Json -Depth 10 | Out-File -FilePath $rulesJsonPath -Encoding UTF8
        
        $exports += "Claim Rules: $rulesJsonPath"
        
    } catch {
        Write-Warning "Error exporting Claim Rules: $($_.Exception.Message)"
    }
    
    # 4. CERTIFICATES (Microsoft recommended export)
    try {
        Write-Host "  Exporting Certificates..." -ForegroundColor Yellow
        $certificates = Get-AdfsCertificate
        
        $certData = @()
        foreach ($cert in $certificates) {
            $certData += [PSCustomObject]@{
                CertificateType = $cert.CertificateType
                Thumbprint      = $cert.Certificate.Thumbprint
                Subject         = $cert.Certificate.Subject
                Issuer          = $cert.Certificate.Issuer
                NotBefore       = $cert.Certificate.NotBefore
                NotAfter        = $cert.Certificate.NotAfter
                IsPrimary       = $cert.IsPrimary
                StoreLocation   = $cert.StoreLocation
                StoreName       = $cert.StoreName
            }
        }
        
        $certJsonPath = Join-Path $exportPath "Certificates_Info.json"
        $certData | ConvertTo-Json -Depth 5 | Out-File -FilePath $certJsonPath -Encoding UTF8
        
        $exports += "Certificate Information: $certJsonPath"
        
    } catch {
        Write-Warning "Error exporting Certificate information: $($_.Exception.Message)"
    }
    
    # 5. ADFS PROPERTIES (Global Configuration)
    try {
        Write-Host "  Exporting ADFS Properties..." -ForegroundColor Yellow
        $adfsProperties = Get-AdfsProperties
        
        $propsJsonPath = Join-Path $exportPath "ADFSProperties_Complete.json"
        $adfsProperties | ConvertTo-Json -Depth 10 | Out-File -FilePath $propsJsonPath -Encoding UTF8
        
        $exports += "ADFS Properties: $propsJsonPath"
        
    } catch {
        Write-Warning "Error exporting ADFS Properties: $($_.Exception.Message)"
    }
    
    # 6. AUTHENTICATION POLICIES
    try {
        Write-Host "  Exporting Authentication Policies..." -ForegroundColor Yellow
        $authPolicies = @{
            GlobalAuthenticationPolicy = Get-AdfsGlobalAuthenticationPolicy
            AccessControlPolicies      = Get-AdfsAccessControlPolicy
        }
        
        if ($script:ADFSFarmBehaviorLevel -ge 3) {
            try {
                $authPolicies.AdditionalAuthenticationRules = Get-AdfsAdditionalAuthenticationRule
            } catch { }
        }
        
        $authJsonPath = Join-Path $exportPath "AuthenticationPolicies_Complete.json"
        $authPolicies | ConvertTo-Json -Depth 10 | Out-File -FilePath $authJsonPath -Encoding UTF8
        
        $exports += "Authentication Policies: $authJsonPath"
        
    } catch {
        Write-Warning "Error exporting Authentication Policies: $($_.Exception.Message)"
    }
    
    # 7. ENDPOINTS CONFIGURATION
    try {
        Write-Host "  Exporting Endpoints..." -ForegroundColor Yellow
        $endpoints = Get-AdfsEndpoint
        
        $endpointsJsonPath = Join-Path $exportPath "Endpoints_Complete.json"
        $endpoints | ConvertTo-Json -Depth 10 | Out-File -FilePath $endpointsJsonPath -Encoding UTF8
        
        $exports += "Endpoints: $endpointsJsonPath"
        
    } catch {
        Write-Warning "Error exporting Endpoints: $($_.Exception.Message)"
    }
    
    # 8. APPLICATION GROUPS (ADFS 2016+)
    if ($script:ADFSFarmBehaviorLevel -ge 3) {
        try {
            Write-Host "  Exporting Application Groups..." -ForegroundColor Yellow
            $appGroups = Get-AdfsApplicationGroup
            
            $appGroupsJsonPath = Join-Path $exportPath "ApplicationGroups_Complete.json"
            $appGroups | ConvertTo-Json -Depth 10 | Out-File -FilePath $appGroupsJsonPath -Encoding UTF8
            
            $exports += "Application Groups: $appGroupsJsonPath"
            
        } catch {
            Write-Warning "Error exporting Application Groups: $($_.Exception.Message)"
        }
    }
    
    # 9. ATTRIBUTE STORES
    try {
        Write-Host "  Exporting Attribute Stores..." -ForegroundColor Yellow
        $attributeStores = Get-AdfsAttributeStore
        
        $storesJsonPath = Join-Path $exportPath "AttributeStores_Complete.json"
        $attributeStores | ConvertTo-Json -Depth 10 | Out-File -FilePath $storesJsonPath -Encoding UTF8
        
        $exports += "Attribute Stores: $storesJsonPath"
        
    } catch {
        Write-Warning "Error exporting Attribute Stores: $($_.Exception.Message)"
    }
    
    # 10. WEB THEMES AND CUSTOMIZATION
    try {
        Write-Host "  Exporting Web Themes..." -ForegroundColor Yellow
        $webConfig = @{
            WebConfig              = Get-AdfsWebConfig
            WebThemes              = Get-AdfsWebTheme
            GlobalWebContent       = Get-AdfsGlobalWebContent
            RelyingPartyWebContent = Get-AdfsRelyingPartyWebContent
        }
        
        $webJsonPath = Join-Path $exportPath "WebCustomization_Complete.json"
        $webConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $webJsonPath -Encoding UTF8
        
        $exports += "Web Customization: $webJsonPath"
        
    } catch {
        Write-Warning "Error exporting Web Themes: $($_.Exception.Message)"
    }
    
    # 11. MICROSOFT RECOMMENDED: Full Configuration Backup
    try {
        Write-Host "  Creating Microsoft-recommended configuration backup..." -ForegroundColor Yellow
        
        # This creates a comprehensive backup reference using Microsoft's approach
        $backupData = @{
            ExportDate        = $exportTimestamp
            ADFSVersion       = "$script:ADFSVersionMajor.$script:ADFSVersionMinor"
            FarmBehaviorLevel = $script:ADFSFarmBehaviorLevel
            ExportFiles       = @{
                # FULL BACKUPS (Microsoft Standard - Import-ready)
                RelyingPartyTrusts            = "RelyingPartyTrusts_Full_Backup_$exportTimestamp.xml"
                ClaimsProviderTrusts          = "ClaimsProviderTrusts_Full_Backup_$exportTimestamp.xml"
                Properties                    = "ADFSProperties_Full_Backup_$exportTimestamp.xml"
                Certificates                  = "Certificates_Full_Backup_$exportTimestamp.xml"
                Endpoints                     = "Endpoints_Full_Backup_$exportTimestamp.xml"
                AttributeStores               = "AttributeStores_Full_Backup_$exportTimestamp.xml"
                ClaimDescriptions             = "ClaimDescriptions_Full_Backup_$exportTimestamp.xml"
                AuthenticationPolicies        = "AuthenticationPolicies_Full_Backup_$exportTimestamp.xml"
                WebCustomization              = "WebCustomization_Full_Backup_$exportTimestamp.xml"
                
                # HUMAN-READABLE SUMMARIES
                RelyingPartyTrustsSummary     = "RelyingPartyTrusts_Summary_$exportTimestamp.csv"
                ClaimsProviderTrustsSummary   = "ClaimsProviderTrusts_Summary_$exportTimestamp.csv"
                PropertiesSummary             = "ADFSProperties_Summary_$exportTimestamp.csv"
                CertificatesSummary           = "Certificates_Summary_$exportTimestamp.csv"
                EndpointsSummary              = "Endpoints_Summary_$exportTimestamp.csv"
                AttributeStoresSummary        = "AttributeStores_Summary_$exportTimestamp.csv"
                ClaimDescriptionsSummary      = "ClaimDescriptions_Summary_$exportTimestamp.csv"
                AuthenticationPoliciesSummary = "AuthenticationPolicies_Summary_$exportTimestamp.csv"
                WebCustomizationSummary       = "WebCustomization_Summary_$exportTimestamp.csv"
            }
            Summary           = @{
                RelyingPartyCount   = ($relyingParties.Count)
                ClaimsProviderCount = (Get-AdfsClaimsProviderTrust).Count
                CertificateCount    = (Get-AdfsCertificate).Count
                EndpointCount       = (Get-AdfsEndpoint).Count
            }
        }
        
        if ($script:ADFSFarmBehaviorLevel -ge 3) {
            $backupData.ApplicationGroups = Get-AdfsApplicationGroup
        }
        
        $backupJsonPath = Join-Path $exportPath "ADFS_Complete_Backup.json"
        $backupData | ConvertTo-Json -Depth 15 | Out-File -FilePath $backupJsonPath -Encoding UTF8
        
        $exports += "Complete ADFS Backup: $backupJsonPath"
        
    } catch {
        Write-Warning "Error creating complete backup: $($_.Exception.Message)"
    }
    
    # 12. CREATE EXPORT SUMMARY
    $exportSummary = @"
ADFS CONFIGURATION EXPORT SUMMARY
=================================
Export Date: $exportTimestamp
Export Location: $exportPath
ADFS Version: $script:ADFSVersionMajor.$script:ADFSVersionMinor
Farm Behavior Level: $script:ADFSFarmBehaviorLevel

FILES CREATED:
$(foreach ($export in $exports) { "- $export" })

MICROSOFT RECOMMENDED RESTORE PROCESS:
1. Install ADFS on target server
2. Configure certificates manually
3. Run RelyingPartyTrusts_Import.ps1 to restore applications
4. Import claim rules from ClaimRules_Complete.json
5. Configure authentication policies from AuthenticationPolicies_Complete.json
6. Review and apply web customizations

IMPORTANT NOTES:
- Certificate private keys are NOT exported for security
- Review all imported configurations before enabling
- Test thoroughly in non-production environment first
- Some configurations may need manual adjustment for new environment

"@
    
    $summaryPath = Join-Path $exportPath "EXPORT_README.txt"
    $exportSummary | Out-File -FilePath $summaryPath -Encoding UTF8
    
    Write-Host "`nConfiguration export completed!" -ForegroundColor Green
    Write-Host "Export location: $exportPath" -ForegroundColor Cyan
    Write-Host "Files created: $($exports.Count + 1)" -ForegroundColor Cyan
    Write-Host "See EXPORT_README.txt for restore instructions" -ForegroundColor Yellow
    
    return [PSCustomObject]@{
        ExportPath    = $exportPath
        FilesCreated  = $exports.Count + 1
        ExportSummary = $exportSummary
    }
}

# =============================================================================
# MAIN FUNCTION - ORCHESTRATES ALL ANALYSIS
# =============================================================================

function Get-ADFSReport {
    [CmdletBinding()]
    param()
    
    try {
        # Initialize the analysis
        if (-not (Initialize-ADFSAnalysis)) {
            return $null
        }
        
        # Execute all analysis functions and collect results
        $script:AnalysisResults.AddRange((Get-ADFSServiceAnalysis))
        $script:AnalysisResults.AddRange((Get-ADFSPropertiesAnalysis))
        $script:AnalysisResults.AddRange((Get-ADFSCertificatesAnalysis))
        $script:AnalysisResults.AddRange((Get-SSLConfigurationAnalysis))
        $script:AnalysisResults.AddRange((Get-ADFSEndpointsAnalysis))
        $script:AnalysisResults.AddRange((Get-RelyingPartyTrustsAnalysis))
        $script:AnalysisResults.AddRange((Get-ClaimsProviderTrustsAnalysis))
        $script:AnalysisResults.AddRange((Get-AuthenticationPoliciesAnalysis))
        $script:AnalysisResults.AddRange((Get-DeviceRegistrationAnalysis))
        $script:AnalysisResults.AddRange((Get-ModernAuthenticationFeaturesAnalysis))
        $script:AnalysisResults.AddRange((Get-ADFSFarmHealthAnalysis))
        $script:AnalysisResults.AddRange((Get-AccessControlPoliciesAnalysis))
        $script:AnalysisResults.AddRange((Get-AuthenticationProvidersAnalysis))
        $script:AnalysisResults.AddRange((Get-FederationPartnersAnalysis))
        $script:AnalysisResults.AddRange((Get-WebCustomizationAnalysis))
        $script:AnalysisResults.AddRange((Get-AttributeStoresAnalysis))
        $script:AnalysisResults.AddRange((Get-ClaimDescriptionsAnalysis))
        $script:AnalysisResults.AddRange((Get-WebThemesAnalysis))
        $script:AnalysisResults.AddRange((Get-HealthAndMonitoringAnalysis))
        $script:AnalysisResults.AddRange((Get-SecurityConfigurationAnalysis))
        
        # Export complete ADFS configuration
        $configExport = Export-ADFSConfiguration
            
        # Export and display results with configuration export information
        $report = Export-AnalysisResults -ConfigurationExport $configExport
        
        return $report
        
    } catch {
        Write-Error "Error during analysis: $($_.Exception.Message)"
        Add-AnalysisResult -Category "Error" -Property "Analysis Error" -Value $_.Exception.Message -Relevance "Critical error prevented complete analysis" -Status "CRITICAL"
        return $null
    }
}


# =============================================================================
# SCRIPT EXECUTION - CALL MAIN FUNCTION
# =============================================================================

# Execute the main analysis function
Get-ADFSReport | Out-Null
