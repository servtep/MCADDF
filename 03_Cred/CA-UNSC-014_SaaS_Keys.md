# CA-UNSC-014: SaaS API Key Exposure

**MITRE ATT&CK Technique:** T1552.001 (Unsecured Credentials: Credentials in Files)  
**CVE:** N/A (Multi-vector logical vulnerability)  
**Platforms:** M365, Entra ID, Cloud SaaS Applications, GitHub/Development Repositories  
**Severity:** CRITICAL  
**Viability:** ACTIVE  
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

SaaS API key exposure is a critical multi-attack-vector credential access threat that compromises authentication credentials and authorization tokens across cloud applications, development platforms, and enterprise integrations. Threat actors who obtain exposed API keys, OAuth tokens, or service account credentials can access SaaS platforms, bypass multi-factor authentication, manipulate cloud infrastructure, and establish persistent backdoors across M365 and Entra ID environments. The Okta breach (October 2023) and subsequent Cloudflare compromise (November 2023) demonstrated that inadequately rotated credentials enable attackers to exfiltrate data months after initial incident detection. This module covers multi-vector detection strategies, forensic analysis, and mitigation approaches for protecting credentials across development pipelines, third-party SaaS integrations, and cloud authentication flows.

---

## 2. ATTACK NARRATIVE

### Attack Chain Overview

**Stage 1: Credential Discovery**
- Scan public GitHub repositories for hardcoded API keys and OAuth tokens using automated tools
- Monitor GitHub commits for exposed patterns (AWS AKIA*, Azure client secrets, OpenAI keys)
- Exploit misconfigured SaaS integration accounts with overprivileged permissions
- Access unencrypted configuration files in cloud storage buckets
- Extract service account credentials from CI/CD pipeline logs
- Intercept tokens in transit via adversary-in-the-middle (AiTM) phishing of SaaS login flows

**Stage 2: Credential Validation & Enumeration**
- Test exposed API keys against service APIs to verify validity
- Enumerate permissions associated with compromised credentials
- Identify secondary service accounts and integration chains
- Map API usage patterns to understand data access scope
- Correlate credentials across multiple SaaS platforms

**Stage 3: Lateral Movement & Data Exfiltration**
- Use valid credentials to access SaaS application APIs (Graph API, Okta APIs, Atlassian APIs)
- Bypass MFA and Conditional Access by leveraging service account credentials
- Register unauthorized devices or applications in cloud directories
- Access sensitive data repositories (emails, files, code, databases)
- Establish persistent backdoors via application credentials
- Chain compromises across integrated SaaS platforms

**Stage 4: Persistence & Obfuscation**
- Create rogue service principals or application registrations
- Establish OAuth consent grants with minimal monitoring
- Register fake devices for token-granting token (PRT) issuance
- Maintain access through undetected credential usage
- Exfiltrate data in small batches to evade DLP controls

### Real-World Example 1: Okta Breach (October 2023)

**Timeline:**
- **October 2, 2023:** Okta's customer support system compromised via MFA bypass (attacker details withheld by Okta)
- **October 18, 2023:** Customer evidence triggers incident notification (Okta delayed disclosure)
- **Exposure Scope:** 134+ Okta customers' support files accessed, containing:
  - Session tokens and cookies in HTTP Archive (HAR) files
  - Customer API keys and service account credentials
  - Single sign-on (SSO) credentials
  - Internal documentation

**Failure Modes:**
- Okta advised customers to "sanitize" HAR files but did not proactively remove credentials
- Many organizations missed the notification or failed to audit credential usage
- Leaked credentials remained valid for weeks after incident discovery

---

### Real-World Example 2: Cloudflare Follow-On Breach (November 2023)

**Timeline:**
- **October 2023:** Initial Okta breach; Cloudflare rotated 5,000 credentials within 72 hours
- **November 14, 2023:** Cloudflare detects reconnaissance activity on internal Atlassian systems
- **November 20-21, 2023:** Attacker gains access to source code repositories
- **Root Cause:** Two credentials were NOT rotated in initial response:
  - 1 Atlassian access token
  - 1 ScriptRunner service account credential
  - 1-2 additional service accounts identified post-breach

**Attack Sequence:**
1. Okta credential leak → Cloudflare internal files accessed
2. Attacker gains Okta session token from HAR file
3. Attacker accesses Atlassian suite (Jira, Confluence, Bitbucket)
4. Attacker establishes persistence via ScriptRunner automation
5. Attacker downloads source code from Bitbucket repositories
6. Scope: Multiple source code projects, infrastructure scripts, documentation

**Detection Failure:**
- Cloudflare's existing credential discovery solutions **failed to identify unrotated credentials**
- 72 hours of credential rotation was insufficient
- API credentials require centralized governance and automated discovery

---

### Real-World Example 3: GitHub Public Repository Exposure (Ongoing)

**Statistics:**
- **Scope:** 3+ billion commits scanned on GitHub public repositories (since 2018)
- **Pattern:** API keys exposed in plaintext: environment files, config.json, .env, docker-compose.yml
- **Common Targets:** AWS keys (AKIA prefix), Azure secrets, OpenAI tokens (sk-* pattern), GitHub PATs (ghp_* pattern)
- **Attacker Response Time:** Bots scan GitHub within minutes; credential usage detected within hours

**Example Scenario:**
```
Developer commits .env file to public repo containing:
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxx
AZURE_TENANT_ID=tenant-id
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

Within 5 minutes: Automated bots discover commit
Within 30 minutes: API key usage against OpenAI endpoints (crypto mining)
Within 2 hours: $200+ in unauthorized API charges accumulated
Outcome: GitHub auto-rotates key; damage already occurred
```

**GitHub's Response:**
- **GitHub Secret Scanning Partner Program:** 100+ service providers notified when secrets exposed
- **Auto-Revocation:** Major providers (OpenAI, AWS, GitHub, Google, Okta) auto-revoke exposed credentials
- **Rate:** GitHub processes ~100K secret detection alerts monthly across enterprise customers

---

## 3. TECHNICAL DETAILS

### SaaS Credential Types & Exposure Points

| Credential Type | Format | Exposure Location | Malicious Use |
|-----------------|--------|-------------------|---------------|
| **AWS Access Key** | AKIA + 16 chars | .env, config.json, GitHub, CloudTrail logs | EC2 launch, S3 access, credential enumeration |
| **Azure Client Secret** | Random string + special chars | appsettings.json, KeyVault backups, Terraform | Graph API access, resource group modification |
| **OpenAI API Key** | sk-proj- + 48 chars | Jupyter notebooks, Python scripts, GitHub | Model API calls, fine-tuning abuse (crypto mining) |
| **GitHub PAT** | ghp_* + 36 chars | .env, CI/CD logs, Docker images | Repository access, code exfiltration, malware insertion |
| **Okta API Token** | 0oa*/00T*/00u* pattern | Config files, Confluence docs, support tickets | User enumeration, session hijacking, MFA bypass |
| **OAuth Refresh Token** | Long JWT/opaque string | Browser storage, application logs, HAR files | Persistent access without MFA, device registration |
| **Service Account Key (JSON)** | {type: "service_account", ...} | GCS backups, GitHub Actions logs, local files | Workload identity abuse, data exfiltration |

### Attack Vector 1: Public Repository Credential Exposure

**Detection Pattern:**
```
// Environment files exposed in public repositories
.env, .env.example, .env.production, docker-compose.yml, 
package-lock.json (with embedded secrets), terraform.tfstate,
Dockerfile (ARG with secrets), helm values.yaml
```

**Scanning Tools:**
```bash
# GitHub Secret Scanning (native)
$ curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/repos/OWNER/REPO/secret-scanning/alerts

# GitGuardian API (pattern + validation)
$ python3 ggcli --all-your-secrets scan ./

# TruffleHog (entropy-based + regex)
$ truffleHog filesystem . --json | grep -i "api\|key\|secret"
```

**Remediation Automation:**
```powershell
# Rotate GitHub secret after exposure
git log --all --source --remotes --oneline | \
  git filter-repo --replace-text RULES.txt

# Invalidate exposed API keys
aws accessanalyzer validate-policy \
  --policy-document file://policy.json \
  --policy-type IDENTITY_POLICY
```

---

### Attack Vector 2: OAuth Token Phishing & Theft (Microsoft Entra ID)

**Scenario 1: VSCode Client Impersonation**
```
Attacker crafts OAuth URL:
https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?
  client_id=aebc6443-996d-45c2-90f0-388ff96faa56 (VSCode)
  scope=https://graph.microsoft.com/.default
  redirect_uri=insiders.vscode.dev/redirect
  login_hint=victim@company.com

Victim clicks link → Authenticates → Authorization code extracted
Attacker exchanges code for access token → Accesses /me/messages endpoint
Result: Email exfiltration without refresh token or long-lived session
```

**Scenario 2: Device Registration via Auth Broker (ROADtools)**
```
Phase 1 - OAuth Phishing:
  client_id = 29d9ed98-a469-4536-ade2-f981bc1d605e (Auth Broker)
  resource = 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9 (DRS)
  scope = adrs_access

Phase 2 - ROADtools Exploitation:
  $ python3 roadtx refreshtoken --input .roadtool_auth
  → Exchange RT for DRS-scoped token
  
  $ python3 roadtx device --input .roadtool_auth
  → Register fake Windows device (OS: 10.0.19041.928)
  → Receive device_id, certificate, private_key
  
  $ python3 roadtx prt --input .roadtool_auth
  → Mint Primary Refresh Token (PRT)
  → PRT acts as token-granting token
  
Phase 3 - Persistence:
  $ python3 roadtx prtenrich --prt <token>
  → Enrich PRT with user/device context
  
  $ python3 roadtx prtauth --prt <token> \
    --client-id teams --resource graph
  → Obtain access token for Teams/Graph
  
  → Access Exchange Online, SharePoint with device trust
  → Bypass MFA and Conditional Access policies

Result: Persistent cloud access bypassing conventional security controls
```

---

### Attack Vector 3: Third-Party SaaS Integration Abuse

**Okta → Atlassian Chain Attack (Cloudflare Incident):**
```
1. Okta Support System Breached
   ├─ Customer files accessed via compromised admin account
   ├─ HAR files downloaded (contain session tokens)
   └─ Session tokens valid for service integrations

2. Attacker Pivots to Cloudflare
   ├─ Uses Okta session token to access Cloudflare Atlassian
   ├─ Discovers 2 unrotated credentials:
   │  ├─ ScriptRunner automation account
   │  └─ Atlassian API token
   └─ Establishes persistence via ScriptRunner

3. Data Exfiltration
   ├─ Accesses Jira instance (source code references)
   ├─ Downloads Confluence documentation
   ├─ Exfiltrates Bitbucket repositories
   └─ Total data: Multiple source code projects + infrastructure docs

4. Post-Incident Analysis
   ├─ Root cause: Incomplete credential rotation
   ├─ Gap identified: Automated credential discovery tools didn't catch all instances
   ├─ Duration: ~37 days from initial Okta breach to Cloudflare detection
   └─ Impact: Significant IP theft, zero customer impact (per Cloudflare)
```

---

## 4. MITRE ATT&CK MAPPING

**Technique:** T1552.001 - Unsecured Credentials: Credentials in Files  
**Tactics Executed:**
- **Credential Access (TA0006):** Extract API keys from public repositories, config files, logs
- **Defense Evasion (TA0005):** Bypass MFA via service account credentials; establish persistence undetected
- **Lateral Movement (TA0008):** Chain SaaS compromises across integrated platforms
- **Persistence (TA0003):** Register rogue applications; maintain OAuth consent grants
- **Exfiltration (TA0010):** Use stolen credentials for bulk data export

**Sub-techniques & Related:**
- T1552.005 - Cloud Instance Metadata API (exploit overprivileged service accounts)
- T1078 - Valid Accounts (use stolen credentials as legitimate users)
- T1528 - Steal Application Access Token
- T1539 - Steal Web Session Cookie (extract from browser via AiTM)
- T1586 - Compromise Account (take over SaaS service accounts)
- T1556 - Modify Authentication Process (manipulate OAuth consent)

---

## 5. TOOLS & TECHNIQUES

### Attacker Tools

| Tool | Purpose | Viability | URL |
|------|---------|-----------|-----|
| **GitHub Secret Scanning** | Automated detection of exposed credentials | ACTIVE | https://docs.github.com/code-security/secret-scanning |
| **GitGuardian** | Multi-source secret detection + validation | ACTIVE | https://gitguardian.com |
| **TruffleHog** | Entropy + regex-based credential scanner | ACTIVE | https://github.com/trufflesecurity/trufflehog |
| **ROADtx** | OAuth token abuse + device registration | ACTIVE | https://github.com/dirkjanm/ROADtools |
| **Scattered Spider Toolkit** | AiTM phishing + RMM persistence | ACTIVE | Leaked 2025 |
| **LaZagne** | Credential extraction from SaaS applications | ACTIVE | https://github.com/AlessandroZ/LaZagne |
| **Pacu** | AWS credential enumeration + exploitation | ACTIVE | https://github.com/RhinoSecurityLabs/pacu |
| **STITCH** | Azure credential harvesting | ACTIVE | Internal tool set |

### Atomic Red Team Tests (T1552.001)

| Test Name | Command | Executor | Detection Trigger |
|-----------|---------|----------|------------------|
| **Find credentials in files** | `find / -name "*credentials*" -o -name "*.pem"` | bash | File enumeration process |
| **Grep for passwords** | `grep -r "password\|api_key\|secret" ./` | bash | Recursive search pattern |
| **Environment variable extraction** | `env \| grep -i "key\|secret\|token"` | bash | Environment access |
| **Azure credential enumeration** | `Get-AzAccessToken; Get-AzKeyVaultSecret` | PowerShell | Azure SDK cmdlet usage |
| **GitHub PAT extraction** | `git config --local user.token \| grep ghp_` | bash | Git credential access |
| **Browser credential dumping** | `LaZagne.exe browsers` | cmd.exe | Child process creation |
| **SaaS API key discovery** | `grep -r "sk-\|AKIA\|ghp_" ./` | bash | Pattern matching files |
| **Application configuration access** | `cat ~/.aws/credentials ~/.azure/tokens.json` | bash | Hidden file access |

---

## 6. FORENSIC ARTIFACTS

### File System Artifacts

| Artifact Path | Artifact Type | Significance | Attacker Indicator |
|---------------|---------------|--------------|-------------------|
| `.env, .env.production, .env.local` | Text file | Application secrets | Credentials extracted from version control history |
| `~/.aws/credentials` | Text file (plaintext) | AWS access keys | Modified recently with additional profiles |
| `~/.azure/config, ~/.azure/accessTokens.json` | JSON files | Azure CLI tokens | Unusual service account entries |
| `.git/config, .gitignore` | Git metadata | Repository access | Missing filters for secret files |
| `docker-compose.yml, Dockerfile` | Container config | Container secrets | ARG/ENV with hardcoded credentials |
| `package-lock.json, yarn.lock` | Lock files | Dependency credentials | Package registry authentication tokens |
| `terraform.tfstate, terraform.tfvars` | Terraform files | Infrastructure secrets | Unencrypted state files with credentials |
| `/home/*/.ssh/id_rsa*` | Private keys | SSH authentication | Extracted and used for lateral movement |
| `/var/log/auth.log, ~/.bash_history` | Log files | Command history | API key usage patterns, curl requests with tokens |
| `HAR files, .burp_projects` | Web proxy files | Session tokens | Exported from tools during troubleshooting |

### GitHub Repository Artifacts

| Artifact | Detection Pattern | Significance |
|----------|-------------------|--------------|
| **Commit history** | `git log --all --source --oneline \| grep -i "secret"` | Secrets pushed then deleted still recoverable via git filter-repo |
| **File diff** | `git diff <commit>^ <commit>` | Credentials added in specific commits |
| **Branch history** | Deleted branches with secrets | May contain sensitive data not visible in main branch |
| **Pull request comments** | Comments containing tokens/keys | Code review artifacts left behind |
| **CI/CD logs** | Actions/workflow logs | Environment variable exposure in build logs |

### Windows Event Log Indicators

| Event ID | Log Source | Significance | Detection Condition |
|----------|-----------|--------------|-------------------|
| **4688** | Security | Process creation | Child process: powershell.exe, cmd.exe spawning API enumeration tools |
| **4663** | Security | Object access | Access to config files, credential stores, environment variable paths |
| **4657** | Security | Registry modified | HKLM\Software\Microsoft\Windows\CurrentVersion environment variables changed |
| **3033** | PowerShell | Module logging | Execution of LaZagne, Get-AzAccessToken, credential dumping cmdlets |
| **4104** | PowerShell | Script block logging | PowerShell scripts containing API keys or credential extraction logic |

---

## 7. SPLUNK DETECTION

### Splunk Prerequisites
- **Data Sources:** GitHub audit logs, Azure audit logs, M365 audit logs, application logs, endpoint logs
- **Required Add-on:** Splunk Add-on for Microsoft Cloud Services v4.0+, GitHub Add-on
- **Source Types:** `github:audit`, `azure:activity`, `azure:signinlogs`, `wineventlog:security`, `powershell:operations`

### Detection 1: Exposed API Key in GitHub Repositories

**Detection Type:** Real-time Secret Pattern Matching  
**Alert Severity:** CRITICAL  
**Frequency:** Real-time on commit  
**Applies To:** All organizations using GitHub

**Splunk Query:**
```spl
index=github source=github:audit action=created 
  (commit.message LIKE "*.env" OR filename LIKE "*.env*" OR 
   filename LIKE "*credentials*" OR filename LIKE "*.key")
| regex payload="(AKIA[0-9A-Z]{16}|sk-proj-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36})" 
| eval RiskScore=case(
    payload LIKE "AKIA*", 100,
    payload LIKE "sk-*", 95,
    payload LIKE "ghp_*", 90,
    1=1, 50
  )
| stats count, values(actor), values(repository), max(RiskScore) as MaxRisk by payload
| where MaxRisk >= 80
```

**What This Detects:**
- Commits containing AWS keys (AKIA prefix)
- OpenAI API keys (sk-proj- prefix)
- GitHub Personal Access Tokens (ghp_ prefix)
- Azure storage connection strings
- Generic credential patterns in version control

**Alert Action:** Immediate rotation of exposed credentials; notification to affected teams

---

### Detection 2: Suspicious OAuth Token Request for SaaS Integration

**Detection Type:** Behavioral Anomaly  
**Alert Severity:** HIGH  
**Frequency:** Every 30 minutes  
**Applies To:** Organizations with M365 and third-party SaaS integrations

**Splunk Query:**
```spl
index=azure source=azure:signinlogs 
  (app_id="aebc6443-996d-45c2-90f0-388ff96faa56" OR 
   app_display_name="Visual Studio Code" OR
   app_id="29d9ed98-a469-4536-ade2-f981bc1d605e" OR
   app_display_name="Microsoft Authentication Broker")
  result="success" 
| where isnotnull(resource_display_name) AND 
        (resource_display_name="Microsoft Graph" OR 
         resource_display_name="Device Registration Service")
| stats count, values(client_ip) as IPs, values(device_id) as Devices, 
        values(user_agent) as Agents by user_principal_name, app_id, _time
| where count > 3 OR if(mvcount(IPs) > 1, 1, 0)
| eval AnomalyScore=case(
    mvcount(IPs) > 2, 85,
    mvcount(Devices) > 1, 75,
    count > 5, 80,
    1=1, 50
  )
| where AnomalyScore > 70
```

**False Positive Analysis:**
- Legitimate VSCode authentications for Azure development
- Tuning: Whitelist known developer IPs and time windows

---

### Detection 3: Service Account API Usage Anomalies

**Detection Type:** Baseline Deviation  
**Alert Severity:** HIGH  
**Frequency:** Every hour

**Splunk Query:**
```spl
index=azure source=azure:activity 
  (Operation="List Access Keys" OR Operation="Create or Update Identity Credential" OR 
   Operation="Add service principal credentials")
  result="success"
| where initiator_object_id LIKE "svc_%"
| stats count by initiator_principal_name, Operation, Resource, _time
| eventstats avg(count) as baseline_count, 
            stdev(count) as baseline_stdev by initiator_principal_name
| eval lower_threshold=baseline_count-2*baseline_stdev, 
       upper_threshold=baseline_count+2*baseline_stdev
| where count > upper_threshold
| eval RiskIndicator=if(Operation LIKE "*credential*", "High", "Medium")
```

---

## 8. MICROSOFT SENTINEL DETECTION

### Sentinel Prerequisites
- **Required Tables:** SigninLogs, AuditLogs, AzureActivity, CloudAppEvents, IdentityInfo
- **Required Fields:** AppId, UserId, OperationName, ClientIP, ResourceDisplayName
- **Data Connectors:** Azure AD, Azure Activity, Office 365, GitHub Audit

### Query 1: Detect OAuth Phishing as First-Party SaaS Client

**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Alert Severity:** Critical
- **Frequency:** Every 30 minutes
- **Lookback:** 1 hour
- **Applies To:** All M365 subscriptions with hybrid identity

**KQL Query:**
```kusto
SigninLogs
| where AppId in ("aebc6443-996d-45c2-90f0-388ff96faa56", "29d9ed98-a469-4536-ade2-f981bc1d605e")
    and ResultType == 0  // Successful
    and UserType == "Member"
| extend OAuth_Scope = extract(@"scope=([^&]+)", 1, tostring(AuthenticationProcessingDetails))
| extend ClientType = iff(AppId == "aebc6443-996d-45c2-90f0-388ff96faa56", "VSCode", 
                          iff(AppId == "29d9ed98-a469-4536-ade2-f981bc1d605e", "AuthBroker", "Other"))
| join kind=inner (
    AuditLogs
    | where OperationName in ("Authorize application", "Approve consent request")
    | where ResultDescription == "success"
) on UserId
| summarize 
    SigninCount = count(),
    UniqueIPs = dcount(ClientIP),
    FirstSignin = min(TimeGenerated),
    LastSignin = max(TimeGenerated),
    ResourceList = make_set(ResourceDisplayName)
    by UserId, ClientType, AppId, OAuth_Scope
| where SigninCount > 3 or UniqueIPs > 2
| extend RiskScore = case(
    ClientType == "AuthBroker" and OAuth_Scope contains "adrs_access", 95,
    ClientType == "VSCode" and OAuth_Scope contains "graph.microsoft.com", 85,
    UniqueIPs > 2, 75,
    1=1, 60
  )
| where RiskScore >= 75
| project UserId, ClientType, SigninCount, UniqueIPs, RiskScore, OAuth_Scope
```

**What This Detects:**
- Visual Studio Code client accessing Graph API with .default scope
- Microsoft Auth Broker targeting Device Registration Service
- Multiple IPs using same session token
- Rapid token exchanges within short timeframe
- Suspicious OAuth scope combinations

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Detect OAuth Phishing as First-Party SaaS Client`
   - Severity: `Critical`
5. **Set rule logic Tab:**
   - Paste KQL query above
   - Run every: `30 minutes`
   - Lookup data from last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
   - Grouping: By UserId
7. Click **Review + create**

**PowerShell Configuration:**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup `
  -WorkspaceName $WorkspaceName `
  -DisplayName "Detect OAuth Phishing as First-Party SaaS Client" `
  -Severity "Critical" `
  -Frequency (New-TimeSpan -Minutes 30) `
  -Period (New-TimeSpan -Hours 1)
```

---

### Query 2: Detect GitHub API Key Exposure & Usage

**Rule Configuration:**
- **Required Table:** CloudAppEvents (GitHub audit logs)
- **Alert Severity:** High
- **Applies To:** Organizations with GitHub Advanced Security

**KQL Query:**
```kusto
let SuspiciousAPIPatterns = dynamic([
    "AKIA.*",  // AWS Access Key
    "sk-proj-.*",  // OpenAI API
    "ghp_.*",  // GitHub PAT
    ".*Bearer [A-Za-z0-9_-]{32,}.*"  // Generic JWT
]);
CloudAppEvents
| where ActionType == "PublishCommit" 
    and RawEventData contains "secrets" or 
        RawEventData matches regex @"(AKIA|sk-proj-|ghp_|npm_)[A-Za-z0-9]{10,}"
| extend 
    ExposedCredentialType = case(
        RawEventData matches regex "AKIA[0-9A-Z]{16}", "AWS_Key",
        RawEventData matches regex "sk-proj-[A-Za-z0-9]{20,}", "OpenAI_Key",
        RawEventData matches regex "ghp_[A-Za-z0-9]{36}", "GitHub_PAT",
        1=1, "Unknown"
    ),
    RepositoryName = extract(@"repo[\"']?\s*[:=]\s*[\"']?([^\"']+)", 1, RawEventData)
| summarize 
    CredentialCount = count(),
    FirstExposure = min(Timestamp),
    LastExposure = max(Timestamp),
    Repositories = make_set(RepositoryName)
    by AccountDisplayName, ExposedCredentialType
| where CredentialCount >= 1
| project Timestamp = FirstExposure, AccountDisplayName, 
          ExposedCredentialType, CredentialCount, Repositories
```

---

## 9. WINDOWS EVENT LOG MONITORING

### Event ID: 4688 (Process Creation)

**Log Source:** Security  
**Trigger:** Execution of credential harvesting or API enumeration tools  
**Applies To Versions:** Server 2016+, Windows 10+

**Detection Pattern:**
```
Process: powershell.exe, cmd.exe, python.exe
CommandLine Contains: "LaZagne", "Get-AzAccessToken", "Get-AzSecret", "aws s3 ls", "trufflehog"
Parent Process: explorer.exe, svchost.exe (indicates manual or service execution)
```

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Expand **Process Tracking**
4. Enable: **Audit Process Creation**
5. Set to: **Success and Failure**
6. Run `gpupdate /force`

**Forensic Query (PowerShell):**
```powershell
$StartTime = (Get-Date).AddHours(-24)
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4688
    StartTime = $StartTime
} | Where-Object {
    $_.Properties[8].Value -match "LaZagne|trufflehog|Get-Az|aws s3"
} | Select-Object TimeCreated, 
    @{N="Process";E={$_.Properties[5].Value}},
    @{N="CommandLine";E={$_.Properties[8].Value}}
```

---

### Event ID: 4663 (Attempt to Access Object)

**Log Source:** Security  
**Trigger:** Access to credential storage locations or configuration files  
**Detection Condition:** Read access to .env, .aws/credentials, Azure config files

---

## 10. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+  
**Supported Platforms:** Windows 10, Windows Server 2016+

**Sysmon XML Configuration:**
```xml
<Sysmon schemaversion="4.22">
  <HashAlgorithms>md5,sha256</HashAlgorithms>
  
  <!-- Detect credential harvesting tools -->
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains">LaZagne</CommandLine>
    <CommandLine condition="contains">trufflehog</CommandLine>
    <CommandLine condition="contains">Get-AzAccessToken</CommandLine>
    <CommandLine condition="contains">Get-AzSecret</CommandLine>
    <CommandLine condition="contains">Get-StorageAccount</CommandLine>
  </ProcessCreate>
  
  <!-- Detect file access to credential locations -->
  <FileCreate onmatch="include">
    <TargetFilename condition="contains">\.env</TargetFilename>
    <TargetFilename condition="contains">\.aws\credentials</TargetFilename>
    <TargetFilename condition="contains">\.azure\config</TargetFilename>
    <TargetFilename condition="contains">appsettings.json</TargetFilename>
  </FileCreate>
  
  <!-- Detect environment variable enumeration -->
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains">env</CommandLine>
    <CommandLine condition="contains">$ENV</CommandLine>
    <CommandLine condition="contains">GetEnvironment</CommandLine>
  </ProcessCreate>
</Sysmon>
```

**Manual Configuration Steps:**
1. Download Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Create config file `sysmon-saas-config.xml` with XML above
3. Install Sysmon:
   ```cmd
   sysmon64.exe -accepteula -i sysmon-saas-config.xml
   ```
4. Verify installation:
   ```powershell
   Get-Service Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

---

## 11. MICROSOFT DEFENDER FOR CLOUD

### MDC Alert: "Suspicious API Activity Detected"

**Alert Name:** SuspiciousAPIUsage  
**Severity:** High  
**Description:** Microsoft Defender for Cloud detects unusual API call patterns from service accounts or applications, indicating potential credential compromise or token theft  
**Applies To:** All subscriptions with Defender for Cloud enabled

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for App Service**: ON
5. Go to **Security alerts** → **Filter** by "API" or "Application"
6. Configure automated response playbooks for credential rotation

---

## 12. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

### Query: Suspicious SaaS Integration Activity

**Operations:** Authorize application, Add service principal, Create API key  
**Workload:** Azure Activity, Azure Active Directory

**PowerShell Query:**
```powershell
Search-UnifiedAuditLog `
  -Operations "Authorize application", "Add service principal credentials", "Update application" `
  -StartDate (Get-Date).AddDays(-30) `
  -EndDate (Get-Date) `
  -FreeText "secret|token|key" `
  -ResultSize 10000 | 
  Select-Object CreationDate, UserIds, Operations, AuditData | 
  Export-Csv -Path "C:\SaaS-Integration-Audit.csv"
```

**Manual Configuration Steps (Enable Audit Log):**
1. Navigate to **Microsoft Purview Compliance Portal** (https://compliance.microsoft.com)
2. Go to **Audit** (left navigation)
3. If not enabled, click **Turn on auditing**
4. Wait 24-48 hours for logs to activate

---

## 13. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1.1 Implement Automated Credential Scanning in CI/CD Pipelines**

**Rationale:** Prevent credentials from being committed to repositories in the first place

**Applies To:** All development teams and code repositories

**Manual Steps (GitHub):**
1. Go to **Repository** → **Settings** → **Security & analysis**
2. Enable: **Secret scanning**
3. Click **Enable Dependabot alerts**
4. Configure branch protection rules

**Manual Steps (GitGuardian Integration):**
```bash
# Install GitGuardian CLI
pip install gitguardian-cli

# Scan before commit
pre-commit install -c .pre-commit-config.yaml

# In .pre-commit-config.yaml:
repos:
  - repo: https://github.com/gitguardian/ggshield
    rev: v1.x.x
    hooks:
      - id: ggshield
        stages: [commit]
```

**Manual Steps (TruffleHog Pre-Commit Hook):**
```bash
# .git/hooks/pre-commit
#!/bin/bash
trufflehog filesystem . --json | grep -q '"Verified":true'
if [ $? -eq 0 ]; then
    echo "ALERT: Verified secrets detected!"
    exit 1
fi
```

---

**1.2 Rotate All Exposed API Keys Within 1 Hour of Detection**

**Rationale:** Minimize exposure window; most automated credential abuse occurs within minutes

**Applies To:** AWS, Azure, GitHub, OpenAI, Okta, all SaaS integrations

**Manual Steps (AWS):**
```bash
# Identify exposed keys
aws iam list-access-keys --user-name service-account

# Deactivate exposed key
aws iam update-access-key-status --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Inactive --user-name service-account

# Create replacement key
aws iam create-access-key --user-name service-account

# Update all applications to use new key
# Test application connectivity
# Delete old key after 24-hour validation window
aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE \
  --user-name service-account
```

**Manual Steps (Azure):**
```powershell
# Get service principal
$sp = Get-AzADServicePrincipal -DisplayName "integration-app"

# List current credentials
Get-AzADAppCredential -ApplicationId $sp.AppId

# Delete compromised credential
Remove-AzADAppCredential -ApplicationId $sp.AppId -KeyId "compromised-key-id"

# Create new credential
$newCred = New-AzADAppCredential -ApplicationId $sp.AppId -EndDate (Get-Date).AddYears(1)

# Output new client secret
$newCred.SecretText | Set-Clipboard
```

---

**1.3 Enforce OAuth Token Binding & Conditional Access**

**Rationale:** Prevent stolen tokens from being replayed on different devices/locations

**Applies To:** All M365 tenants with Entra ID P1+

**Manual Steps (Token Protection Policy):**
1. Go to **Azure Portal** → **Entra ID** → **Conditional Access**
2. Click **+ New policy**
3. Name: `Require Token Protection for Office Apps`
4. **Assignments:**
   - Users: **All users**
   - Cloud apps: Select:
     - Office 365 Exchange Online
     - Office 365 SharePoint Online
     - Microsoft Teams Services
5. **Conditions:**
   - Client apps: **Mobile apps and desktop clients** (uncheck Browser)
   - Device platforms: **Windows** or **macOS**
6. **Access controls:**
   - Session: **Require token protection for sign-in sessions**
7. Enable policy: **On**

---

### Priority 2: HIGH

**2.1 Implement Service Account Credential Management (Zero Trust)**

**Rationale:** Service accounts are high-value targets; centralized management reduces exposure

**Manual Steps (Azure Managed Identity):**
```powershell
# Create managed identity for application
$identity = New-AzUserAssignedIdentity -ResourceGroupName "rg-prod" `
  -Name "app-integration-identity"

# Assign RBAC role (least privilege)
New-AzRoleAssignment -ObjectId $identity.PrincipalId `
  -RoleDefinitionName "Reader" `
  -Scope "/subscriptions/subscription-id"

# Application automatically receives token; no secret stored
```

**Manual Steps (GitHub Organization Secrets):**
```bash
# Store secrets in GitHub Actions encrypted storage
# Go to Organization → Settings → Secrets and variables → Actions
# Add secret: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID

# In workflow:
- name: Authenticate to Azure
  uses: azure/login@v1
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

---

**2.2 Enable Continuous Access Evaluation (CAE) for Microsoft 365**

**Rationale:** Enables real-time token revocation when risk is detected

**Manual Steps (PowerShell):**
```powershell
# Enable CAE for Exchange Online
Update-ExchangeOnline -CAEEnabled $true

# Enable CAE for SharePoint Online
Set-SPOTenant -CAEToken $true

# Verify CAE status
Get-ExoMailbox | Select-Object DisplayName, CAEToken
```

---

**2.3 Audit Third-Party SaaS Integration Permissions Quarterly**

**Rationale:** Prevent privilege creep and overprivileged integrations

**Manual Steps (Graph API Audit):**
```powershell
# Get all OAuth applications with permissions
Get-MgServicePrincipal | Where-Object {$_.AppId -ne $null} | 
  Select-Object DisplayName, AppId, CreatedDateTime | 
  Export-Csv "C:\SaaS-Apps-Inventory.csv"

# Remove unused applications
Remove-MgServicePrincipal -ServicePrincipalId "app-id" -Confirm:$false

# Audit permission scopes
Get-MgOauth2PermissionGrant | 
  Where-Object {$_.ConsentType -eq "AllPrincipals"} |
  Select-Object ClientId, Scope
```

---

### Compliance Mapping

| Compliance Framework | Control ID | Requirement | Mitigation |
|---|---|---|---|
| **NIST 800-53** | SC-28 | Protection of Information at Rest | Encrypt API keys in configuration management systems |
| **NIST 800-53** | IA-2 | Authentication | Enforce MFA for SaaS integrations; implement OAuth device flow |
| **CIS Microsoft 365** | 5.4 | Legacy authentication | Block basic authentication for all SaaS clients |
| **DISA STIG** | SV-253156 | Credential Storage | No plaintext secrets in repositories or logs |
| **ISO 27001:2022** | A.9.2.1 | Access provisioning | Automated credential lifecycle management |
| **GDPR Article 32** | Confidentiality | Encryption of transmitted data | Use HTTPS + token binding for SaaS APIs |
| **DORA (EU)** | Article 17 | ICT Security | Require FIPS 140-3 validation for key generation |
| **NIS2 Directive** | 4.2.1 | Technical security | Monitor API usage; implement anomaly detection |

---

## 14. INCIDENT RESPONSE PLAYBOOK

### Scenario: API Key Exposed on GitHub

**Assume Breach Timeline:**
1. **T+0m:** Developer commits .env file to public repo
2. **T+2m:** Automated bots discover API key via pattern scanning
3. **T+5m:** Attacker begins API usage testing
4. **T+15m:** Service provider (GitHub, OpenAI, AWS) auto-revokes credential
5. **T+30m:** Organization discovers exposure via alert

**Containment Actions (First 30 Minutes):**
```powershell
# Step 1: Revoke exposed credentials immediately
aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --user-name service-account

# Step 2: Make repository private
git remote set-url origin git@github.com:org/private-repo.git
git push origin main

# Step 3: Remove secrets from git history
git filter-repo --replace-text RULES.txt
git push -f origin main

# Step 4: Rotate credentials in application
$newSecret = New-AzADAppCredential -ApplicationId $appId -EndDate (Get-Date).AddYears(1)
Update-AppConfiguration -NewSecret $newSecret.SecretText
```

**Investigation (1-4 Hours):**
```powershell
# Step 1: Determine exposure window
$commit = git log --all --source --format="%H %ai" | grep -i ".env"
# Exposure time = commit date to detection date

# Step 2: Check API usage patterns during exposure
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAIOSFODNN7EXAMPLE

# Step 3: Identify all systems using the exposed credential
grep -r "AKIAIOSFODNN7EXAMPLE" /etc/ /var/www/ ~/.ssh/ ~/.aws/

# Step 4: Review CloudTrail for unauthorized operations
aws cloudtrail get-event-selectors --trail-name production-trail
```

**Recovery (4-24 Hours):**
1. Complete credential rotation across all systems
2. Remove secrets from git history using `git filter-repo`
3. Audit third-party integrations that used the exposed credential
4. Implement pre-commit hooks to prevent future exposure
5. Enable GitHub secret scanning on all repositories

---

## APPENDIX: DETECTION RULE SOURCES

- **Web ID 170**: Scattered Spider OAuth Phishing Detection (Seraphic Security)
- **Web ID 171**: Microsoft Entra ID OAuth Phishing & Detection (Elastic Security Labs)
- **Web ID 172**: Common Threat Actor Tactics (Mitiga)
- **Web ID 173**: Configuration Drift at Scale (Lares Security)
- **Web ID 174**: Token Protection in Entra ID (LinkedIn/Microsoft MVP)
- **Web ID 175**: Common SaaS Security Risks (BetterCloud)
- **Web ID 176**: SessionReaper CVE-2025-54236 (Flare)
- **Web ID 178**: Microsoft Entra ID Token Protection Concept
- **Web ID 179**: Token Theft Prevention (Cyberhoot)
- **Web ID 180**: SaaS Identity-Based Attacks (Wing Security)
- **Web ID 181**: Token Protection in Conditional Access (Microsoft Learn)
- **Web ID 183**: Understanding Tokens in Entra ID (Microsoft Learn)
- **Web ID 187**: GitHub Secret Scanning (GitHub Docs)
- **Web ID 188**: Cloudflare Okta Breach Analysis (Astrix Security)
- **Web ID 190**: Secret Scanning Documentation (GitHub)
- **Web ID 191**: Cloudflare Okta Follow-On Breach (Cybersecurity Dive)
- **Web ID 192**: Phishing Detection & Response (Sentinel Blog)
- **Web ID 193**: Secrets Detection Solutions (GitGuardian)
- **Web ID 194**: Cloudflare Okta Compromise Details (Cloudflare Blog)
- **Web ID 195**: OAuth App Abuse Investigation (Practical365)
- **Web ID 199**: Client API Key Exposure (Reddit r/developersIndia)
- **Web ID 200**: Okta Auth Tokens & Cloudflare Breach (GitGuardian Blog)

---
