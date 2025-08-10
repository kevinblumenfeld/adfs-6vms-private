# 🏢 ADFS Infrastructure Build Guide

> **Complete step-by-step guide to deploy a 6-VM ADFS infrastructure in Azure**

##  Quick Start - Customize for Your Environment

**IMPORTANT**: Before running these scripts, you MUST customize the following values for your environment:

### 1. 🌐 Domain Configuration
- **Find & Replace**: domain.cc → yourdomain.com
- This affects: AD forest, DNS records, ADFS federation service name, certificates

### 2. 🏷️ Resource Group Configuration
- **Find & Replace**: KevinLab → YourResourceGroupName (across all files)

### 3. 🔐 SSL Certificate Setup

**For Cloudflare DNS:**
- Get your API token from: https://dash.cloudflare.com/profile/api-tokens
- Replace YOUR_CLOUDFLARE_API_TOKEN with your actual Cloudflare API token

**For other DNS providers:**
- Posh-ACME supports many DNS providers (GoDaddy, Route53, etc.)
- See full list and setup instructions: https://poshac.me/docs/v4/Plugins/
- Update the -Plugin and -PluginArgs parameters accordingly

**Required replacements:**
- **Email Address**: Replace your-email@domain.com with your actual email
- **Certificate Password**: Replace YourCertificatePassword! with a strong password

### 4. 🌍 DNS Configuration
**⚠️ Complete this AFTER Azure deployment (see deployment section below):**
1. Get the WAP load balancer public IP:
   ```powershell
   Get-AzPublicIpAddress -ResourceGroupName "KevinLab" | Where-Object {$_.Name -like "*wap*"}
   ```
2. Create DNS A record in your public DNS: **adfs.domain.cc** → **[Public IP from step 1]**
3. Wait 5-10 minutes for DNS propagation

### 5. 🔧 Network Settings
- **Default IP ranges**: 
  - Internal subnet: 10.0.0.0/24
  - DMZ subnet: 10.0.1.0/24
- Modify IP addresses in ARM template parameters if needed

### 6. 📋 Certificate Thumbprint Process
**IMPORTANT**: When you run the ADFS1 configuration (Step 3 below), you'll see this output:

Write-Host "Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green

**Record that thumbprint value and use it to replace REPLACE_WITH_YOUR_CERTIFICATE_THUMBPRINT in all the remaining server configurations (ADFS2, WAP1, WAP2).**

### 7. 🖥️ Remote Desktop Management
1. Get jumpbox IP: `Get-AzPublicIpAddress -ResourceGroupName "KevinLab" | Where-Object {$_.Name -like "*jumpBox*"}`
2. RDP to jumpbox using the IP above
3. Copy RDCMan.zip to jumpbox, unzip, then File > Open > adfs-lab.rdg

---

## 🚀 Azure Deployment

Deploy the infrastructure using PowerShell:

```powershell
# Create resource group
New-AzResourceGroup -Name "KevinLab" -Location "East US"

New-AzResourceGroupDeployment -ResourceGroupName "KevinLab" -TemplateUri "https://raw.githubusercontent.com/kevinblumenfeld/adfs-6vms-private/main/azuredeploy.json" -Location "East US" -TemplateParameterObject @{ adminUsername = 'kevin'; adminPassword = 'YourAdminPassword!' }
```

---

## 🔧 Additional Servers (Optional)

Deploy these servers AFTER the main 6-server infrastructure is complete:

```powershell
# Deploy additional servers to existing infrastructure
New-AzResourceGroupDeployment -ResourceGroupName "KevinLab" -TemplateUri "https://raw.githubusercontent.com/kevinblumenfeld/adfs-6vms-private/main/deployAdditionalServers.json" -TemplateParameterObject @{ adminUsername = 'kevin'; adminPassword = 'YourAdminPassword!'; existingResourceGroupName = 'KevinLab' }
```

### Additional Infrastructure:

| **Server** | **Role** | **Subnet** | **Private IP** | **Purpose** |
|------------|----------|------------|----------------|-------------|
| 🖥️ **JumpBox2** | Jump Box | Internal | 10.0.0.11 | Secondary jump box with public IP |
| 🔗 **EntraConnect** | Entra Connect | Internal | 10.0.0.20 | Hybrid identity sync |

### Configure Additional Servers:

**After deployment, configure each additional server:**

#### JumpBox2 Configuration:
```powershell
# Set DNS to point to DC1 and join domain
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.0.0.101
Add-Computer -DomainName "domain.cc" -Restart
```

#### EntraConnect Configuration:
```powershell
# Set DNS to point to DC1 and join domain
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.0.0.101
Add-Computer -DomainName "domain.cc" -Restart
```


---

## 🏗️ Complete Infrastructure Overview

Main 6-server + jumpbox deployment creates:

| **Server** | **Role** | **Subnet** | **Private IP** | **Purpose** |
|------------|----------|------------|----------------|-------------|
| 🖥️ **JumpBox** | Jump Box | Internal | 10.0.0.10 | Primary jump box with public IP |
| 🖥️ **DC1** | Domain Controller | Internal | 10.0.0.101 | Primary DC, DNS |
| 🖥️ **DC2** | Domain Controller | Internal | 10.0.0.102 | Secondary DC, DNS backup |
| 🔐 **ADFS1** | ADFS Server | Internal | 10.0.0.201 | Federation services |
| 🔐 **ADFS2** | ADFS Server | Internal | 10.0.0.202 | Federation services (HA) |
| 🌐 **WAP1** | Web Application Proxy | DMZ | 10.0.1.101 | External ADFS proxy |
| 🌐 **WAP2** | Web Application Proxy | DMZ | 10.0.1.102 | External ADFS proxy (HA) |

---

## 🖥️ Server Configuration Guide

> ⚠️ **Important**: Execute these commands in the exact order shown below.

### 🏢 Step 1: Domain Controller Setup (DC1)

Connect to **DC1** and run:

```powershell
# Install Active Directory Domain Services
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Create new forest
$forestSplat = @{
    DomainName                    = "domain.cc"
    DomainNetbiosName             = "CORP"
    ForestMode                    = 'WinThreshold'
    DomainMode                    = 'WinThreshold'
    InstallDNS                    = $true
    DatabasePath                  = "C:\Windows\NTDS"
    LogPath                       = "C:\Windows\NTDS"
    SYSVOLPath                    = "C:\Windows\SYSVOL"
    SafeModeAdministratorPassword = (Read-Host -Prompt "Enter DSRM Password" -AsSecureString)
}

Install-ADDSForest @forestSplat

# Add DNS record for ADFS (points to internal load balancer)
Add-DnsServerResourceRecordA -Name "adfs" -ZoneName "domain.cc" -IPv4Address 10.0.0.200

# Create ADFS service account
New-ADUser -Name "adfssvc" -UserPrincipalName "adfssvc@domain.cc" -AccountPassword (Read-Host "Enter ADFS Service Account Password" -AsSecureString) -Enabled $true
Add-ADGroupMember -Identity "Domain Admins" -Members "adfssvc"
```

> 🔄 **Server will restart automatically after domain creation**

---

### 🏢 Step 2: Secondary Domain Controller (DC2)

Connect to **DC2** and run:

```powershell
# Install Active Directory Domain Services
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Join domain and restart
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.0.0.101
Add-Computer -DomainName "domain.cc" -Restart

# After reboot, promote to domain controller
$dc2Splat = @{
    DomainName                    = "domain.cc"
    InstallDNS                    = $true
    Credential                    = Get-Credential
    SafeModeAdministratorPassword = (Read-Host -Prompt "Enter DSRM Password" -AsSecureString)
    DatabasePath                  = "C:\Windows\NTDS"
    LogPath                       = "C:\Windows\NTDS"
    SYSVOLPath                    = "C:\Windows\SYSVOL"
    Confirm                       = $false
}

Install-ADDSDomainController @dc2Splat
```

> 🔄 **Server will restart automatically after domain controller promotion**

---

### 🔐 Step 3: Primary ADFS Server (ADFS1)

Connect to **ADFS1** and run:

```powershell
# Install Posh-ACME module for Let's Encrypt certificates
Install-Module Posh-ACME -Force

# Set DNS and join domain
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.0.0.101
Add-Computer -DomainName "domain.cc" -Restart

# After reboot, generate SSL certificate
$CFToken = ConvertTo-SecureString "YOUR_CLOUDFLARE_API_TOKEN" -AsPlainText -Force
$CFEmail = 'your-email@domain.com'
$certPassword = ConvertTo-SecureString "YourCertificatePassword!" -AsPlainText -Force
$CloudflareArgs = @{ CFToken = $CFToken }

$cert = New-PACertificate -Domain 'adfs.domain.cc' -Plugin Cloudflare -PluginArgs $CloudflareArgs -AcceptTOS -Contact $CFEmail -PfxPassSecure $certPassword -Verbose

Write-Host "Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
# IMPORTANT: Record the certificate thumbprint from the output above!

# Copy certificate to standard location
$pfxPath = $cert.PfxFullChain
New-Item -Path "C:\certs" -ItemType Directory -Force
Copy-Item -Path $pfxPath -Destination "C:\certs\adfs.pfx"

# Import certificate
Import-PfxCertificate -FilePath "C:\certs\adfs.pfx" -CertStoreLocation Cert:\LocalMachine\My -Password $certPassword -Exportable

# Install ADFS role
Install-WindowsFeature ADFS-Federation -IncludeManagementTools

# Configure ADFS farm (use the thumbprint from above and the service account created on DC1)
$thumbprint = "REPLACE_WITH_YOUR_CERTIFICATE_THUMBPRINT"
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumbprint }

$adfsSplat = @{
    FederationServiceName    = "adfs.domain.cc"
    CertificateThumbprint    = $cert.Thumbprint
    ServiceAccountCredential = Get-Credential  # Use: domain.cc\adfssvc
    OverwriteConfiguration   = $true
}

Install-AdfsFarm @adfsSplat

# Enable IdP-initiated sign-on page
Set-AdfsProperties -EnableIdPInitiatedSignonPage $true
```

> 🎯 **Key Step**: Copy the certificate thumbprint displayed in green text - you'll need it for the remaining servers!

---

### 🔐 Step 4: Secondary ADFS Server (ADFS2)

Connect to **ADFS2** and run:

```powershell
# Set DNS and join domain
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.0.0.101
Add-Computer -DomainName "domain.cc" -Restart

# After reboot, import certificate (copy from ADFS1)
Import-PfxCertificate -FilePath "C:\certs\adfs.pfx" -CertStoreLocation Cert:\LocalMachine\My -Password (Read-Host "PFX Password" -AsSecureString) -Exportable

# Install ADFS role
Install-WindowsFeature ADFS-Federation -IncludeManagementTools

# Join ADFS farm (use thumbprint from ADFS1 and same service account)
$thumbprint = "REPLACE_WITH_YOUR_CERTIFICATE_THUMBPRINT"
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumbprint }

$adfsJoinSplat = @{
    PrimaryComputerName         = "adfs1.domain.cc"
    CertificateThumbprint       = $cert.Thumbprint
    ServiceAccountCredential    = Get-Credential  # Use: domain.cc\adfssvc
    OverwriteConfiguration      = $true
}

Add-AdfsFarmNode @adfsJoinSplat
```

---

### 🌐 Step 5: Primary Web Application Proxy (WAP1)

Connect to **WAP1** and run:

```powershell
# Set DNS (no domain join required for WAP)
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.0.0.101

# Import certificate (copy from ADFS1)
Import-PfxCertificate -FilePath "C:\certs\adfs.pfx" -CertStoreLocation Cert:\LocalMachine\My -Password (Read-Host "PFX Password" -AsSecureString) -Exportable

# Install Web Application Proxy role
Install-WindowsFeature Web-Application-Proxy -IncludeManagementTools

# Configure WAP (use thumbprint from ADFS1)
$thumbprint = "REPLACE_WITH_YOUR_CERTIFICATE_THUMBPRINT"
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumbprint }

$wapSplat = @{
    FederationServiceName             = "adfs.domain.cc"
    CertificateThumbprint             = $cert.Thumbprint
    FederationServiceTrustCredential  = Get-Credential
}

Install-WebApplicationProxy @wapSplat
```

---

### 🌐 Step 6: Secondary Web Application Proxy (WAP2)

Connect to **WAP2** and run:

```powershell
# Set DNS (no domain join required for WAP)
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.0.0.101

# Import certificate (copy from ADFS1)
Import-PfxCertificate -FilePath "C:\certs\adfs.pfx" -CertStoreLocation Cert:\LocalMachine\My -Password (Read-Host "PFX Password" -AsSecureString) -Exportable

# Install Web Application Proxy role
Install-WindowsFeature Web-Application-Proxy -IncludeManagementTools

# Configure WAP (use thumbprint from ADFS1)
$thumbprint = "REPLACE_WITH_YOUR_CERTIFICATE_THUMBPRINT"
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumbprint }

$wapSplat = @{
    FederationServiceName             = "adfs.domain.cc"
    CertificateThumbprint             = $cert.Thumbprint
    FederationServiceTrustCredential  = Get-Credential
}

Install-WebApplicationProxy @wapSplat
```

---

## 🎯 Testing Your Deployment

After completing all server configurations and DNS setup:

1. **Internal Access**: https://adfs.domain.cc/adfs/ls/idpinitiatedsignon.aspx
2. **External Access**: https://adfs.domain.cc/adfs/ls/idpinitiatedsignon.aspx  
3. **Load Balancer Health**: Check Azure portal for green health probe status

---

## 🔧 Troubleshooting

### Common Issues:

**Certificate Import Errors**
- Ensure the PFX password is correct
- Verify the certificate file exists in C:\certs\adfs.pfx

**ADFS Farm Join Failures**
- Verify thumbprint matches exactly (no spaces)
- Ensure service account has proper permissions
- Check network connectivity between ADFS servers

**WAP Configuration Issues**
- Verify DNS resolution of adfs.domain.cc from WAP servers
- Ensure federation service trust credential is correct
- Check firewall rules between WAP and ADFS servers

### 📊 Monitoring:

- **Event Logs**: Check ADFS Admin and Security logs
- **Performance Counters**: Monitor ADFS performance counters
- **Azure Monitor**: Set up monitoring for load balancer health

---

## 📚 Additional Resources

- **ADFS Documentation**: https://docs.microsoft.com/en-us/windows-server/identity/active-directory-federation-services
- **Posh-ACME Documentation**: https://poshac.me/docs/
- **Azure Load Balancer**: https://docs.microsoft.com/en-us/azure/load-balancer/

---

## 🚀 ADFS Federation Automation Script

**Optional**: After completing your ADFS infrastructure setup, use this PowerShell script to automatically configure federation with Microsoft Entra ID. This script handles the complete federation setup process including certificate management and validation.

**When to use**: Run this script from your ADFS1 server after completing all the manual configuration steps above.


```powershell
# ADFS FEDERATION SETUP FOR domain.CC - PRODUCTION READY
# =========================================================
# This script configures ADFS federation with Microsoft Entra ID
# Domain: domain.cc
# ADFS Server: adfs.domain.cc

#Requires -Version 5.1
#Requires -RunAsAdministrator

# SCRIPT CONFIGURATION
# ====================
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName = "domain.cc",
    
    [Parameter(Mandatory=$false)]
    [string]$ADFSHostname = "adfs.domain.cc",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("acceptIfMfaDoneByFederatedIdp", "rejectMfaByFederatedIdp", "enforceMfaByFederatedIdp")]
    [string]$MfaBehavior = "acceptIfMfaDoneByFederatedIdp",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# INITIALIZE LOGGING
# ==================
$LogFile = "ADFS_Federation_Setup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry -ForegroundColor $(
        switch($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            "INFO" { "Cyan" }
            default { "White" }
        }
    )
    Add-Content -Path $LogFile -Value $LogEntry
}

Write-Log "Starting ADFS Federation Setup for $DomainName" "INFO"
Write-Log "ADFS Server: $ADFSHostname" "INFO"
Write-Log "Log file: $LogFile" "INFO"

# STEP 1: PREREQUISITES VALIDATION
# =================================
Write-Log "=== STEP 1: PREREQUISITES VALIDATION ===" "INFO"

# Validate PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Log "PowerShell 5.1 or higher is required. Current version: $($PSVersionTable.PSVersion)" "ERROR"
    exit 1
}
Write-Log "PowerShell version validated: $($PSVersionTable.PSVersion)" "SUCCESS"

# Validate Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "Script must be run as Administrator" "ERROR"
    exit 1
}
Write-Log "Administrator privileges confirmed" "SUCCESS"

# Validate ADFS service is running
try {
    $ADFSService = Get-Service -Name "adfssrv" -ErrorAction Stop
    if ($ADFSService.Status -ne "Running") {
        Write-Log "ADFS service is not running. Current status: $($ADFSService.Status)" "ERROR"
        exit 1
    }
    Write-Log "ADFS service is running" "SUCCESS"
} catch {
    Write-Log "Cannot access ADFS service. Ensure you're running on the ADFS server. Error: $($_.Exception.Message)" "ERROR"
    exit 1
}

# STEP 2: EXTRACT ADFS CONFIGURATION
# ===================================
Write-Log "=== STEP 2: EXTRACT ADFS CONFIGURATION ===" "INFO"

# Extract primary token signing certificate
try {
    $TokenSigningCert = Get-AdfsCertificate -CertificateType "Token-Signing" | Where-Object {$_.IsPrimary -eq $true}
    if (-not $TokenSigningCert) {
        Write-Log "No primary token signing certificate found" "ERROR"
        exit 1
    }
    
    # Validate certificate expiration
    $ExpiryDate = $TokenSigningCert.Certificate.NotAfter
    $DaysUntilExpiry = ($ExpiryDate - (Get-Date)).Days
    
    if ($DaysUntilExpiry -lt 30) {
        Write-Log "WARNING: Token signing certificate expires in $DaysUntilExpiry days ($ExpiryDate)" "WARNING"
        if (-not $Force) {
            $continue = Read-Host "Certificate expires soon. Continue? (y/N)"
            if ($continue -ne "y" -and $continue -ne "Y") {
                Write-Log "Operation cancelled due to certificate expiry warning" "INFO"
                exit 0
            }
        }
    }
    
    $CertificateBase64 = [System.Convert]::ToBase64String($TokenSigningCert.Certificate.RawData)
    Write-Log "Primary token signing certificate extracted successfully" "SUCCESS"
    Write-Log "Certificate expires: $ExpiryDate ($DaysUntilExpiry days)" "INFO"
    Write-Log "Certificate thumbprint: $($TokenSigningCert.Certificate.Thumbprint)" "INFO"
    
} catch {
    Write-Log "Failed to extract token signing certificate: $($_.Exception.Message)" "ERROR"
    exit 1
}

# Build ADFS URIs
$ADFSConfig = @{
    IssuerUri = "http://$ADFSHostname/adfs/services/trust"
    ActiveSignInUri = "https://$ADFSHostname/adfs/services/trust/2005/usernamemixed"
    PassiveSignInUri = "https://$ADFSHostname/adfs/ls/"
    SignOutUri = "https://$ADFSHostname/adfs/ls/?wa=wsignout1.0"
    MetadataExchangeUri = "https://$ADFSHostname/adfs/services/trust/mex"
    SigningCertificate = $CertificateBase64
}

Write-Log "ADFS Configuration URLs built:" "INFO"
foreach ($key in $ADFSConfig.Keys) {
    if ($key -ne "SigningCertificate") {
        Write-Log "  $key`: $($ADFSConfig[$key])" "INFO"
    }
}

# Validate ADFS endpoints accessibility
Write-Log "Validating ADFS endpoints accessibility..." "INFO"
$EndpointsToTest = @($ADFSConfig.MetadataExchangeUri, $ADFSConfig.PassiveSignInUri)

foreach ($endpoint in $EndpointsToTest) {
    try {
        $response = Invoke-WebRequest -Uri $endpoint -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        Write-Log "✓ $endpoint - Accessible (Status: $($response.StatusCode))" "SUCCESS"
    } catch {
        Write-Log "✗ $endpoint - Not accessible: $($_.Exception.Message)" "WARNING"
        Write-Log "This may prevent federation from working properly" "WARNING"
    }
}

# STEP 3: MICROSOFT GRAPH CONNECTION
# ===================================
Write-Log "=== STEP 3: MICROSOFT GRAPH CONNECTION ===" "INFO"

# Install required modules
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.DirectoryManagement"
)

foreach ($module in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Log "Installing module: $module" "INFO"
        try {
            Install-Module $module -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Write-Log "Successfully installed $module" "SUCCESS"
        } catch {
            Write-Log "Failed to install $module`: $($_.Exception.Message)" "ERROR"
            exit 1
        }
    } else {
        Write-Log "Module $module is already installed" "INFO"
    }
    
    Import-Module $module -Force -ErrorAction Stop
    Write-Log "Imported module: $module" "SUCCESS"
}

# Connect to Microsoft Graph
$RequiredScopes = @("Domain.ReadWrite.All", "Directory.ReadWrite.All")
try {
    Write-Log "Connecting to Microsoft Graph with scopes: $($RequiredScopes -join ', ')" "INFO"
    Connect-MgGraph -Scopes $RequiredScopes -NoWelcome -ErrorAction Stop
    
    $Context = Get-MgContext
    Write-Log "Successfully connected to Microsoft Graph" "SUCCESS"
    Write-Log "Tenant ID: $($Context.TenantId)" "INFO"
    Write-Log "Account: $($Context.Account)" "INFO"
    Write-Log "Scopes: $($Context.Scopes -join ', ')" "INFO"
    
} catch {
    Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" "ERROR"
    exit 1
}

# STEP 4: DOMAIN VALIDATION
# ==========================
Write-Log "=== STEP 4: DOMAIN VALIDATION ===" "INFO"

try {
    $Domain = Get-MgDomain -DomainId $DomainName -ErrorAction Stop
    
    if ($Domain.IsVerified -eq $false) {
        Write-Log "Domain $DomainName is not verified in Entra ID" "ERROR"
        Write-Log "You must verify domain ownership before setting up federation" "ERROR"
        Disconnect-MgGraph
        exit 1
    }
    
    Write-Log "Domain validation successful:" "SUCCESS"
    Write-Log "  Name: $($Domain.Id)" "INFO"
    Write-Log "  Is Verified: $($Domain.IsVerified)" "INFO"
    Write-Log "  Current Auth Type: $($Domain.AuthenticationType)" "INFO"
    Write-Log "  Is Default: $($Domain.IsDefault)" "INFO"
    
} catch {
    Write-Log "Domain $DomainName not found in Entra ID: $($_.Exception.Message)" "ERROR"
    Disconnect-MgGraph
    exit 1
}

# Check for existing federation configuration
$ExistingFederation = $null
try {
    $ExistingFederation = Get-MgDomainFederationConfiguration -DomainId $DomainName -ErrorAction SilentlyContinue
    if ($ExistingFederation) {
        Write-Log "Existing federation configuration detected:" "WARNING"
        Write-Log "  Federation ID: $($ExistingFederation.Id)" "INFO"
        Write-Log "  Display Name: $($ExistingFederation.DisplayName)" "INFO"
        Write-Log "  Issuer URI: $($ExistingFederation.IssuerUri)" "INFO"
        
        if (-not $Force) {
            $confirm = Read-Host "Existing federation found. Update it? (y/N)"
            if ($confirm -ne "y" -and $confirm -ne "Y") {
                Write-Log "Operation cancelled by user" "INFO"
                Disconnect-MgGraph
                exit 0
            }
        }
        Write-Log "Will update existing federation configuration" "INFO"
    } else {
        Write-Log "No existing federation configuration found - will create new" "INFO"
    }
} catch {
    Write-Log "Error checking existing federation: $($_.Exception.Message)" "WARNING"
}

# STEP 5: PREPARE FEDERATION PARAMETERS
# ======================================
Write-Log "=== STEP 5: PREPARE FEDERATION PARAMETERS ===" "INFO"

$FederationParams = @{
    DomainId = $DomainName
    DisplayName = "$DomainName ADFS Federation"
    IssuerUri = $ADFSConfig.IssuerUri
    ActiveSignInUri = $ADFSConfig.ActiveSignInUri
    PassiveSignInUri = $ADFSConfig.PassiveSignInUri
    SignOutUri = $ADFSConfig.SignOutUri
    MetadataExchangeUri = $ADFSConfig.MetadataExchangeUri
    SigningCertificate = $ADFSConfig.SigningCertificate
    PreferredAuthenticationProtocol = "wsFed"
    FederatedIdpMfaBehavior = $MfaBehavior
}

Write-Log "Federation parameters prepared:" "INFO"
foreach ($key in $FederationParams.Keys) {
    if ($key -ne "SigningCertificate") {
        Write-Log "  $key`: $($FederationParams[$key])" "INFO"
    } else {
        Write-Log "  $key`: [Base64 Certificate - $(($FederationParams[$key]).Length) characters]" "INFO"
    }
}

# STEP 6: CREATE OR UPDATE FEDERATION
# ====================================
Write-Log "=== STEP 6: CREATE OR UPDATE FEDERATION ===" "INFO"

if ($WhatIf) {
    Write-Log "WHATIF MODE: Would perform the following action:" "INFO"
    if ($ExistingFederation) {
        Write-Log "  Update existing federation configuration for $DomainName" "INFO"
        Write-Log "  Federation ID: $($ExistingFederation.Id)" "INFO"
    } else {
        Write-Log "  Create new federation configuration for $DomainName" "INFO"
    }
    Write-Log "WHATIF MODE: No changes will be made" "WARNING"
    Disconnect-MgGraph
    exit 0
}

try {
    if ($ExistingFederation) {
        Write-Log "Updating existing federation configuration..." "INFO"
        $FederationConfig = Update-MgDomainFederationConfiguration -DomainId $DomainName -InternalDomainFederationId $ExistingFederation.Id -BodyParameter $FederationParams -ErrorAction Stop
        Write-Log "Federation configuration updated successfully!" "SUCCESS"
    } else {
        Write-Log "Creating new federation configuration..." "INFO"
        $FederationConfig = New-MgDomainFederationConfiguration @FederationParams -ErrorAction Stop
        Write-Log "Federation configuration created successfully!" "SUCCESS"
    }
    
    # Display configuration summary
    Write-Log "Federation Configuration Summary:" "INFO"
    Write-Log "  ID: $($FederationConfig.Id)" "INFO"
    Write-Log "  Display Name: $($FederationConfig.DisplayName)" "INFO"
    Write-Log "  Issuer URI: $($FederationConfig.IssuerUri)" "INFO"
    Write-Log "  Passive Sign-In URI: $($FederationConfig.PassiveSignInUri)" "INFO"
    Write-Log "  MFA Behavior: $($FederationConfig.FederatedIdpMfaBehavior)" "INFO"
    
} catch {
    Write-Log "Failed to create/update federation: $($_.Exception.Message)" "ERROR"
    
    # Enhanced error troubleshooting
    $ErrorMessage = $_.Exception.Message
    if ($ErrorMessage -like "*409*" -or $ErrorMessage -like "*already exists*" -or $ErrorMessage -like "*duplicate*") {
        Write-Log "TROUBLESHOOTING: IssuerUri conflict detected" "WARNING"
        Write-Log "The IssuerUri '$($ADFSConfig.IssuerUri)' may already be in use" "WARNING"
        Write-Log "Consider using a unique IssuerUri like: http://$ADFSHostname/adfs/services/trust/$DomainName" "WARNING"
    }
    if ($ErrorMessage -like "*certificate*") {
        Write-Log "TROUBLESHOOTING: Certificate issue detected" "WARNING"
        Write-Log "Verify the certificate is valid and properly formatted" "WARNING"
    }
    if ($ErrorMessage -like "*permission*" -or $ErrorMessage -like "*unauthorized*") {
        Write-Log "TROUBLESHOOTING: Permission issue detected" "WARNING"
        Write-Log "Ensure your account has Domain.ReadWrite.All permissions" "WARNING"
    }
    
    Disconnect-MgGraph
    exit 1
}

# STEP 7: VERIFY FEDERATION CONFIGURATION
# ========================================
Write-Log "=== STEP 7: VERIFY FEDERATION CONFIGURATION ===" "INFO"

# Allow time for propagation
Start-Sleep -Seconds 5

try {
    $UpdatedDomain = Get-MgDomain -DomainId $DomainName -ErrorAction Stop
    Write-Log "Domain federation status verification:" "INFO"
    Write-Log "  Authentication Type: $($UpdatedDomain.AuthenticationType)" "INFO"
    
    if ($UpdatedDomain.AuthenticationType -eq "Federated") {
        Write-Log "✓ Federation is ACTIVE" "SUCCESS"
    } else {
        Write-Log "⚠ Domain is not federated. Status: $($UpdatedDomain.AuthenticationType)" "WARNING"
        Write-Log "This may take a few minutes to propagate" "INFO"
    }
} catch {
    Write-Log "Could not verify domain status: $($_.Exception.Message)" "WARNING"
}

# Get detailed federation configuration
try {
    $FinalFedConfig = Get-MgDomainFederationConfiguration -DomainId $DomainName -ErrorAction Stop
    Write-Log "Detailed Federation Configuration:" "INFO"
    Write-Log "  Display Name: $($FinalFedConfig.DisplayName)" "INFO"
    Write-Log "  Issuer URI: $($FinalFedConfig.IssuerUri)" "INFO"
    Write-Log "  Passive Sign-In URI: $($FinalFedConfig.PassiveSignInUri)" "INFO"
    Write-Log "  Active Sign-In URI: $($FinalFedConfig.ActiveSignInUri)" "INFO"
    Write-Log "  Sign-Out URI: $($FinalFedConfig.SignOutUri)" "INFO"
    Write-Log "  Metadata Exchange URI: $($FinalFedConfig.MetadataExchangeUri)" "INFO"
    Write-Log "  MFA Behavior: $($FinalFedConfig.FederatedIdpMfaBehavior)" "INFO"
    Write-Log "  Protocol: $($FinalFedConfig.PreferredAuthenticationProtocol)" "INFO"
} catch {
    Write-Log "Could not retrieve federation details: $($_.Exception.Message)" "WARNING"
}

# STEP 8: POST-CONFIGURATION VALIDATION
# ======================================
Write-Log "=== STEP 8: POST-CONFIGURATION VALIDATION ===" "INFO"

# Re-test ADFS endpoints
Write-Log "Re-testing ADFS endpoints..." "INFO"
foreach ($endpoint in $EndpointsToTest) {
    try {
        $response = Invoke-WebRequest -Uri $endpoint -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        Write-Log "✓ $endpoint - Still accessible" "SUCCESS"
    } catch {
        Write-Log "✗ $endpoint - Not accessible: $($_.Exception.Message)" "ERROR"
    }
}

# Certificate validation
try {
    $CurrentCert = Get-AdfsCertificate -CertificateType "Token-Signing" | Where-Object {$_.IsPrimary -eq $true}
    $CurrentCertBase64 = [System.Convert]::ToBase64String($CurrentCert.Certificate.RawData)
    
    if ($CurrentCertBase64 -eq $CertificateBase64) {
        Write-Log "✓ Certificate in ADFS matches federation configuration" "SUCCESS"
    } else {
        Write-Log "⚠ Certificate mismatch detected" "WARNING"
        Write-Log "ADFS and Entra ID certificates don't match - federation may fail" "WARNING"
    }
} catch {
    Write-Log "Could not validate ADFS certificate: $($_.Exception.Message)" "WARNING"
}

# STEP 9: CLEANUP AND SUMMARY
# ============================
Write-Log "=== STEP 9: CLEANUP AND SUMMARY ===" "INFO"

# Disconnect from Microsoft Graph
try {
    Disconnect-MgGraph
    Write-Log "Disconnected from Microsoft Graph" "INFO"
} catch {
    Write-Log "Error disconnecting from Graph: $($_.Exception.Message)" "WARNING"
}

# Final summary
Write-Log "=== FEDERATION SETUP COMPLETE ===" "SUCCESS"
Write-Log "Domain: $DomainName" "INFO"
Write-Log "ADFS Server: $ADFSHostname" "INFO"
Write-Log "Federation ID: $($FederationConfig.Id)" "INFO"
Write-Log "Certificate Expires: $ExpiryDate" "INFO"
Write-Log "Log File: $LogFile" "INFO"

Write-Log "NEXT STEPS:" "INFO"
Write-Log "1. Test user authentication from external network" "INFO"
Write-Log "2. Monitor ADFS logs: Event Viewer > Applications and Services Logs > AD FS > Admin" "INFO"
Write-Log "3. Configure conditional access policies as needed" "INFO"
Write-Log "4. Set up certificate auto-renewal monitoring" "INFO"
Write-Log "5. Test federation with: https://login.microsoftonline.com/common/oauth2/authorize?client_id=00000002-0000-0000-c000-000000000000&response_type=id_token&redirect_uri=https://account.activedirectory.windowsazure.com/&response_mode=form_post&nonce=test&domain_hint=$DomainName" "INFO"

Write-Log "TROUBLESHOOTING COMMANDS:" "INFO"
Write-Log "# Check ADFS service: Get-Service -Name 'adfssrv'" "INFO"
Write-Log "# View ADFS certificates: Get-AdfsCertificate" "INFO"
Write-Log "# Check federation: Get-MgDomainFederationConfiguration -DomainId '$DomainName'" "INFO"
Write-Log "# Remove federation: Update-MgDomain -DomainId '$DomainName' -AuthenticationType 'Managed'" "INFO"

Write-Log "Federation setup completed successfully!" "SUCCESS"
```

**Credit**: Based on Paulo Marques templates
