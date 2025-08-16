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

## 🚀 ADFS Federation Setup & Claim Rules

**Complete federation setup for ADFS with Entra ID/Microsoft 365**. This includes both the federation connection and essential claim rules for common scenarios.

**⏰ When to use**: After completing your ADFS infrastructure setup (all 6 servers configured), use this to establish federation with Entra ID and configure claim rules.

---

## 📋 Step-by-Step Federation Process

### **Step 1: Basic Federation Setup** ⚡
**⏰ When**: Run this FIRST after your ADFS infrastructure is complete and working  
**📍 Where**: Run on your **ADFS1** server (primary ADFS server)  
**👤 Who**: **Domain Admin** account (for ADFS commands) + **Entra ID permissions** (Domain.ReadWrite.All scope or Global Admin for Graph API)

> **💡 Permission Options (Choose One):**
> - **Option A (Recommended)**: Use Domain Admin account, authenticate to Graph with delegated permissions when prompted
> - **Option B**: Use Domain Admin account that also has Global Admin role in Entra ID  
> - **Option C**: Use Domain Admin account + Service Principal (ClientId/Secret) with Domain.ReadWrite.All permissions  

```powershell
# Essential Federation Setup Function - Simplified but Complete
function Set-ADFSFederation {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [string]$ADFSHostname,
        
        [Parameter(Mandatory=$false)]
        [string]$ClientId,
        
        [Parameter(Mandatory=$false)]
        [string]$ClientSecret,
        
        [Parameter(Mandatory=$false)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$false)]
        [switch]$WhatIf
    )
    
    Write-Host "Setting up ADFS Federation for $DomainName..." -ForegroundColor Green
    
    # Install required modules
    $modules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.DirectoryManagement")
    foreach ($module in $modules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Install-Module $module -Force -Scope CurrentUser -AllowClobber
        }
        Import-Module $module -Force
    }
    
    # Get ADFS certificate
    $cert = Get-AdfsCertificate -CertificateType "Token-Signing" | Where-Object {$_.IsPrimary -eq $true}
    $certBase64 = [System.Convert]::ToBase64String($cert.Certificate.RawData)
    
    # Build federation configuration
    $federationConfig = @{
        DomainId                        = $DomainName
        DisplayName                     = "$DomainName ADFS Federation"
        IssuerUri                       = "http://$ADFSHostname/adfs/services/trust"
        ActiveSignInUri                 = "https://$ADFSHostname/adfs/services/trust/2005/usernamemixed"
        PassiveSignInUri                = "https://$ADFSHostname/adfs/ls/"
        SignOutUri                      = "https://$ADFSHostname/adfs/ls/?wa=wsignout1.0"
        MetadataExchangeUri             = "https://$ADFSHostname/adfs/services/trust/mex"
        SigningCertificate              = $certBase64
        PreferredAuthenticationProtocol = "wsFed"
        FederatedIdpMfaBehavior         = "acceptIfMfaDoneByFederatedIdp"
    }
        
    # Connect to Microsoft Graph
    if ($ClientId -and $ClientSecret -and $TenantId) {
        $SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $ClientCredential = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)
        Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientCredential -NoWelcome
    } else {
        Connect-MgGraph -Scopes @("Domain.ReadWrite.All") -NoWelcome
    }
    
    # Verify domain
    $domain = Get-MgDomain -DomainId $DomainName
    if (-not $domain.IsVerified) {
        Write-Error "Domain $DomainName must be verified in Entra ID first"
        return
    }
    
    if ($WhatIf) {
        Write-Host "WHATIF: Would create federation for $DomainName" -ForegroundColor Yellow
        return
    }
    
    # Create or update federation
    try {
        $existing = Get-MgDomainFederationConfiguration -DomainId $DomainName -ErrorAction SilentlyContinue
        if ($existing) {
            Update-MgDomainFederationConfiguration -DomainId $DomainName -InternalDomainFederationId $existing.Id -BodyParameter $federationConfig
            Write-Host "Updated existing federation configuration" -ForegroundColor Green
        } else {
            New-MgDomainFederationConfiguration @federationConfig
            Write-Host "Created new federation configuration" -ForegroundColor Green
        }
    } catch {
        Write-Error "Federation setup failed: $($_.Exception.Message)"
        return
    }
    
    # Create ADFS Relying Party Trust for Microsoft 365 if it doesn't exist
    try {
        $existingRP = Get-AdfsRelyingPartyTrust -Name "Microsoft Office 365 Identity Platform" -ErrorAction SilentlyContinue
        if (-not $existingRP) {
            Write-Host "Creating Microsoft 365 Relying Party Trust..." -ForegroundColor Green
            
            # Basic Relying Party Trust for Microsoft 365 (without specific claim rules - those come in Step 2)
            $rpTrustSplat = @{
                Name                   = "Microsoft Office 365 Identity Platform"
                MetadataUrl            = "https://nexus.microsoftonline-p.com/federationmetadata/2007-06/federationmetadata.xml"
                MonitoringEnabled      = $true
                AutoUpdateEnabled      = $true
                IssuanceTransformRules = @'
@RuleTemplate = "PassThroughClaims"
@RuleName = "Pass Through UPN"
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]
=> issue(claim = c);
'@
            }
            Add-AdfsRelyingPartyTrust @rpTrustSplat
            Write-Host "Created Microsoft 365 Relying Party Trust with basic claim rules" -ForegroundColor Green
            Write-Host "You can now apply additional claim rules from Step 2 below" -ForegroundColor Cyan
        } else {
            Write-Host "Microsoft 365 Relying Party Trust already exists" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Could not create Relying Party Trust: $($_.Exception.Message)"
        Write-Host "You may need to create it manually or apply claim rules from Step 2" -ForegroundColor Yellow
    }
    
    Disconnect-MgGraph
    Write-Host "Federation setup completed successfully!" -ForegroundColor Green
    Write-Host "Next: Apply specific claim rules from Step 2 based on your AD configuration" -ForegroundColor Cyan
}
```

**💡 Usage Examples for Step 1:**

**First**: Copy the entire `Set-ADFSFederation` function code block above and paste it into PowerShell on your **ADFS1** server.

**Then run one of these commands:**
```powershell
# Basic usage (DomainName and ADFSHostname are required) - Uses delegated permissions
Set-ADFSFederation -DomainName "domain.cc" -ADFSHostname "adfs.domain.cc"

# Preview what would happen (recommended first run)
Set-ADFSFederation -DomainName "domain.cc" -ADFSHostname "adfs.domain.cc" -WhatIf

# Advanced: With service principal authentication (if you have ClientId/Secret setup)
Set-ADFSFederation -DomainName "domain.cc" -ADFSHostname "adfs.domain.cc" -ClientId "your-client-id" -ClientSecret "your-client-secret" -TenantId "your-tenant-id"
```

---

### **Step 2: Choose Your Claim Rule Scenario** 🎯
**⏰ When**: Run this AFTER Step 1 completes successfully  
**📍 Where**: Run on your **ADFS1** server (same as Step 1)  
**👤 Who**: **Domain Admin** account (only local ADFS commands, no Entra ID access needed)  

> **🔍 First, check your AD attributes to choose the right scenario:**
> ```powershell
> Get-ADUser -Identity "testuser" -Properties objectGUID, mS-DS-ConsistencyGuid
> ```

> **📋 Need to populate mS-DS-ConsistencyGuid for Scenario B?**
> 
> **Microsoft Entra Connect Sync Setup**: If your users don't have mS-DS-ConsistencyGuid populated, you'll need to set up Entra Connect Sync first.
> 
> **Official Guide**: [Plan for Azure AD Connect - Design concepts](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/plan-connect-design-concepts)
> 
> **Quick Steps**:
> 1. Deploy Entra Connect on a domain-joined server (use the optional EntraConnect VM from this guide)
> 2. Run the Entra Connect wizard and choose "Customize synchronization options"
> 3. Select "mS-DS-ConsistencyGuid" as the source anchor during setup
> 4. Complete initial sync (this populates mS-DS-ConsistencyGuid for all users)
> 5. Return here and use Scenario B for federation
> 
> **⚠️ Important: Manual ADFS Management**
> 
> **This guide manages ADFS independently from Entra Connect**. When you use Entra Connect to manage ADFS, it automatically updates claim rules to match the sourceAnchor. However, since we're configuring ADFS separately, you must manually configure the claim rules below to ensure the ImmutableID claim is consistent with your Entra Connect sourceAnchor setting.
> 
> **Impact**: If you later deploy Entra Connect with ADFS management enabled, it may overwrite these manual claim rules. Choose your claim rules (Scenarios A, B, or C below) to match your intended Entra Connect sourceAnchor configuration.


**Choose ONE of these scenarios based on your AD configuration:**

#### **Scenario A: objectGUID Federation** (Legacy/Basic) 
**⏰ When to use**: Your AD users have objectGUID populated (default for all AD users)  
**✅ Best for**: Testing scenarios, quick proof-of-concept setups, environments without Entra Connect Sync  
**💡 Consider using Scenario B instead**: Microsoft recommends mS-DS-ConsistencyGuid (Scenario B) as the modern approach. Use objectGUID for testing/lab environments.  

```powershell
# Basic objectGUID claim rule for Entra ID/Microsoft 365 federation - works with most AD environments
# Use when: Your AD users have objectGUID populated (default for all AD users)

# Add this claim rule to your Relying Party Trust
$ClaimRuleSetObjectGUID = @'
@RuleTemplate = "LdapClaims"
@RuleName = "ObjectGUID to ImmutableID"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
=> issue(store = "Active Directory", types = ("http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID"), query = ";objectGUID;{0}", param = c.Value);
'@

# Apply the rule (updates existing Relying Party Trust)
Set-AdfsRelyingPartyTrust -TargetName "Microsoft Office 365 Identity Platform" -IssuanceTransformRules $ClaimRuleSetObjectGUID
```

#### **Scenario B: mS-DS-ConsistencyGuid Federation** (Recommended) 
**⏰ When to use**: Your AD users have mS-DS-ConsistencyGuid populated (requires AD Connect or manual population)  
**✅ Best for**: New setups, Microsoft's recommended approach, better for hybrid environments  

```powershell
# Modern mS-DS-ConsistencyGuid claim rule for Entra ID/Microsoft 365 - Microsoft's recommended approach
# Use when: Your AD users have mS-DS-ConsistencyGuid populated (requires AD Connect or manual population)

# Add this claim rule to your Relying Party Trust
$ClaimRuleSetConsistencyGuid = @'
@RuleTemplate = "LdapClaims"
@RuleName = "ConsistencyGuid to ImmutableID"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
=> issue(store = "Active Directory", types = ("http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID"), query = ";mS-DS-ConsistencyGuid;{0}", param = c.Value);
'@

# Apply the rule (updates existing Relying Party Trust)
Set-AdfsRelyingPartyTrust -TargetName "Microsoft Office 365 Identity Platform" -IssuanceTransformRules $ClaimRuleSetConsistencyGuid
```

#### **Scenario C: objectGUID to mS-DS-ConsistencyGuid Conversion**
**⏰ When to use**: **ONLY when modifying/migrating** existing federation from objectGUID to mS-DS-ConsistencyGuid  
**✅ Best for**: Migration scenarios, transitioning between existing attribute types, **NOT for new setups**  

```powershell
# Convert objectGUID to mS-DS-ConsistencyGuid format during claim issuance
# Use when: Migrating from objectGUID to mS-DS-ConsistencyGuid without AD changes

# Add this claim rule to your Relying Party Trust
$ClaimRuleSetConversion = @'
@RuleTemplate = "LdapClaims"
@RuleName = "ObjectGUID to ConsistencyGuid Format"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
=> issue(store = "Active Directory", types = ("http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID"), query = ";objectGUID;{0}", param = c.Value);

@RuleTemplate = "PassThroughClaims"
@RuleName = "Pass Through UPN"
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"]
=> issue(claim = c);
'@

# Apply the rule (updates existing Relying Party Trust)
Set-AdfsRelyingPartyTrust -TargetName "Microsoft Office 365 Identity Platform" -IssuanceTransformRules $ClaimRuleSetConversion
```

---

### **Step 3: Test Federation** ✅
**⏰ When**: Run this AFTER Step 2 completes successfully  
**📍 Where**: From any computer with internet access  
**👤 Who**: **Test user account** in your domain (regular user, not admin)  

```powershell
# 1. Verify ADFS configuration
Get-AdfsRelyingPartyTrust -Name "Microsoft Office 365 Identity Platform"

# 2. Test federation endpoint accessibility
Test-NetConnection -ComputerName "adfs.domain.cc" -Port 443

# 3. Test user authentication (replace with your domain)
# Open browser and navigate to:
# https://login.microsoftonline.com/domain.cc
```

---

## 🚀 Complete Setup Summary

### **Quick Reference - Do This In Order:**

1. **✅ Infrastructure Complete**: All 6 servers deployed and configured
2. **⚡ Step 1**: Run `Set-ADFSFederation` on ADFS1 server 
3. **🎯 Step 2**: Choose and apply ONE claim rule scenario (A, B, or C)
4. **✅ Step 3**: Test federation with browser authentication
5. **📊 Optional**: Run ADFS Report (see below) for health verification

### **Troubleshooting Commands:**
```powershell
# Check ADFS service status
Get-Service -Name "adfssrv"

# View federation configuration
Get-MgDomainFederationConfiguration -DomainId "domain.cc"

# Check claim rules
Get-AdfsRelyingPartyTrust -Name "Microsoft Office 365 Identity Platform" | Select-Object IssuanceTransformRules

# Remove federation if needed
Update-MgDomain -DomainId "domain.cc" -AuthenticationType "Managed"
```
---

### 🚀 **ADFS Report**

### 📋 **What Gets Analyzed:**

Service health, certificates, endpoints, trust relationships, security settings, modern auth, performance, and configuration.

> **📤 EXPORTS**: All Relying Party Trusts with complete configuration including claim rules, endpoints, and security settings.

### 📈 **Report Outputs:**

Creates **3 files** in Documents folder: JSON (technical analysis), CSV (Excel-ready data), Executive Summary (management report).

### 🎯 **Usage Methods:**

**Method 1: Direct from GitHub (Recommended)**
```powershell
iex (irm 'https://raw.githubusercontent.com/kevinblumenfeld/adfs-6vms-private/main/Get-ADFSReport.ps1')
#
```
1. Login as Domain Admin account
2. Open PowerShell as Administrator
3. Copy-paste the above code block, the report will be generated automatically in your Documents folder.

**Method 2: Copy-Paste**
1. Login as Domain Admin account
2. Copy the entire script content from [Get-ADFSReport.ps1](./Get-ADFSReport.ps1)
3. Open PowerShell as Administrator
4. Paste script and run: `Get-ADFSReport`

**Method 3: Save and Run**
1. Login as Domain Admin account
2. Download and save as `Get-ADFSReport.ps1`
3. Open PowerShell as Administrator
4. Run: `.\Get-ADFSReport.ps1`

---
**Credit**: Based on Paulo Marques templates
