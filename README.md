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

**Credit**: Based on Paulo Marques templates
