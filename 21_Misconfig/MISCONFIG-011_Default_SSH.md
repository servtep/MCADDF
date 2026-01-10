# [MISCONFIG-011]: Default SSH Keys in Use

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-011 |
| **MITRE ATT&CK v18.1** | [T1098.004 – Account Manipulation: SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/) (related), [T1530 – Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/) (for stolen keys) |
| **Tactic** | Persistence / Initial Access |
| **Platforms** | Entra ID / Azure (Linux VMs, appliances, containers, IoT) |
| **Severity** | High / Critical (depending on exposure) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure Linux VMs, virtual appliances, and images using shared or default SSH host or authorized keys |
| **Patched In** | N/A – depends on image and configuration; mitigated via unique key provisioning and Entra-based SSH |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** Default or shared SSH keys are static key pairs shipped with images or reused across multiple hosts or tenants. If a private key is compromised once, any system trusting the matching public key is at risk. Examples include virtual appliances distributed with embedded vendor support keys, golden images cloned without regenerating host keys, or shared authorized_keys entries used by multiple teams. In Azure this misconfiguration commonly appears on Linux VMs built from custom images, marketplace appliances, or automation pipelines that reuse the same key pair.
- **Attack Surface:** Azure Linux VMs, network and security appliances, IoT edge devices, Kubernetes worker nodes, and bastion hosts using SSH for administration.
- **Business Impact:** **Silent backdoor and large blast radius.** A single leaked private key can provide persistent root-level access across many systems, bypassing password policies and MFA. Attackers can move laterally, implant additional backdoors, and exfiltrate secrets. Because key authentication often bypasses user directories, identity-based monitoring may not see distinct accounts.
- **Technical Context:** Modern guidance recommends per-user, per-host keys or Entra ID/OpenSSH certificate-based authentication. Default keys directly contradict this. Threat actors have historically abused default SSH keys in virtual appliances (for example, Cisco virtual security appliances with shared default keys) to gain remote root access.

### Operational Risk
- **Execution Risk:** Medium – rotating keys at scale can be disruptive without proper automation, but leaving defaults is unacceptable.
- **Stealth:** High – SSH key use is often not differentiated from legitimate admin activity in logs.
- **Reversibility:** High for configuration (keys can be rotated), but any compromise that occurred while defaults were in use is non-recoverable.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | Azure Foundations controls on SSH, network access | Unique credentials; no shared or default keys. |
| **DISA STIG** | RHEL/Unix STIG – default accounts/keys | Disallow vendor-supplied default auth material. |
| **CISA SCuBA** | Identity and access hardening | Unique strong credentials and key hygiene. |
| **NIST 800-53** | IA-2, IA-5, AC-2 | Identification and authentication; management of authenticators. |
| **GDPR** | Art. 32 | Appropriate security including access control to personal data. |
| **DORA** | Art. 9 | Access control and authentication for critical financial infrastructure. |
| **NIS2** | Art. 21 | Secure authentication and privileged access controls. |
| **ISO 27001** | A.5.17, A.8.2 | Management of authentication information and access rights. |
| **ISO 27005** | Risk Scenario | Shared credentials enabling undetected compromise of many assets.

## 3. TECHNICAL PREREQUISITES
- **Required Privileges:**
  - VM-level root or sudo to inspect and rotate host and authorized keys.
  - Azure VM access (Bastion, SSH, serial console) or Azure Run Command rights.
- **Required Access:**
  - Access to Azure subscription with VM read permissions.
  - Optionally, access to image build pipelines (for golden images).

**Supported Versions:**
- Azure Linux images (Ubuntu, RHEL, CentOS Stream, Debian, SUSE, Azure Linux, etc.).

## 4. ENVIRONMENTAL RECONNAISSANCE

### On-VM Key Fingerprint Recon

```bash
# List SSH host key fingerprints
sudo ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub
sudo ssh-keygen -l -f /etc/ssh/ssh_host_ecdsa_key.pub 2>/dev/null || true
sudo ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null || true

# List authorized keys for privileged users
sudo find /root /home -maxdepth 3 -name "authorized_keys" -print -exec cat {} \;
```

**What to Look For:**
- Identical host key fingerprints across many VMs.
- Vendor or support keys added to root or admin accounts.
- Keys not tied to named individuals or just-in-time workflows.

### Azure-Side Recon (Policy and VM Creation)

Check whether:
- VMs are created with `--generate-ssh-keys` for each deployment rather than reusing stored keys.
- Azure Policy is enforcing SSH key-only login and preventing password-based or default credentials.

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Exploiting Shared or Default Authorized Keys

**Supported Versions:** All Linux VMs.

#### Step 1: Reuse a Known Private Key
**Objective:** Connect to multiple VMs that share the same public key.

**Command:**
```bash
ssh -i id_rsa_default azureuser@vm1.contoso.cloud
ssh -i id_rsa_default admin@vm2.contoso.cloud
```

**Expected Output:**
- Direct shell access without password, potentially as root or sudo-capable user.

**What This Means:**
- Any compromise of that private key (for example via leaked repo, stolen laptop, or appliance advisory) gives access to all affected systems.

**OpSec & Evasion:**
- Log entries show regular SSH logins; no brute-force attempts.
- If the same key is used legitimately by admins, distinguishing attacker from admin is difficult.

### METHOD 2 – Vendor Default Keys in Virtual Appliances

**Supported Versions:** Marketplace or third-party virtual appliances.

#### Step 1: Identify Appliance Families with Known Issues
- Review vendor security advisories for default SSH key vulnerabilities (for example, Cisco virtual security appliances with default authorized and host keys).

#### Step 2: Connect Using Published Private Keys
- Threat actors may download or brute-force vendor-supplied default keys, then connect to exposed management interfaces.

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

Use Atomic Red Team for T1098.004 (Account Manipulation – SSH Authorized Keys) to simulate adding and abusing SSH keys in `authorized_keys`. While this does not specifically test default keys, it demonstrates the persistence vector.

## 7. TOOLS & COMMANDS REFERENCE

- `ssh-keygen` – generate and inspect key fingerprints.
- `ssh` – test key-based access.
- Azure CLI `az ssh vm` and Entra ID-based SSH for passwordless, keyless ephemeral certs.

## 8. SPLUNK DETECTION RULES

### Rule 1: Unusual SSH Key-Based Logins

- Collect Linux auth logs into Splunk.
- Detect logins from rarely-seen public keys or from keys associated with decommissioned users.

## 9. MICROSOFT SENTINEL DETECTION

- Ingest Linux Syslog (auth.log, secure) into Sentinel.
- Create KQL analytics for:
  - New public key additions to `authorized_keys`.
  - Logins from keys associated with service accounts or generic identities.

## 10. WINDOWS EVENT LOG MONITORING

Not directly applicable (Linux-focused) but Windows-based SSH servers can also use default keys; monitor for new authorized_keys and OpenSSH server configuration on Windows if used.

## 11. SYSMON DETECTION PATTERNS

For Windows OpenSSH servers:
- Use Sysmon to monitor writes to `%PROGRAMDATA%\ssh\administrators_authorized_keys` and `%USERPROFILE%\.ssh\authorized_keys`.

## 12. MICROSOFT DEFENDER FOR CLOUD

- Use recommendations such as "Authentication to Linux machines should require SSH keys" and Azure Policy to ensure VMs are deployed with proper SSH configuration.
- Use Defender for Servers to monitor for suspicious SSH activity.

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

Not directly applicable to SSH itself, but use Purview to monitor admin actions that deploy VMs, modify access policies, or add privileged identities that can use SSH.

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL
- Ban default and shared SSH keys in policy.
- Rotate host keys and authorized_keys for all affected systems; regenerate keys per VM and per user.
- Replace static keys with Entra ID-based SSH certificates where possible.

### Priority 2: HIGH
- Implement inventory of all SSH keys (public and private) and map to owners.
- Use Azure Policy to block deployments that do not meet SSH hardening requirements.

### Validation Command (Verify Fix)
```bash
# On each VM
sudo ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub

# Compare fingerprints across VMs – they must be unique per host.
```

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)
- Logins from unknown IPs using public keys with generic names or vendor identifiers.
- Use of the same key fingerprint across multiple production hosts.

### Forensic Artifacts
- SSH auth logs, Azure Bastion session logs.
- Configuration management repos storing private keys.

### Response Procedures
1. Urgently rotate all default or shared keys, starting with externally exposed hosts.
2. Invalidate and remove any vendor support keys unless contractually required and tightly controlled.
3. Conduct compromise assessment focusing on SSH sessions while default keys were in use.

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| 1 | Initial Access | Exposed SSH endpoint | Internet-accessible SSH on Azure VM or appliance. |
| 2 | Credential Access | Theft or discovery of default key | Attacker obtains private key (for example, from vendor advisory or leaked image). |
| 3 | Current Step | **MISCONFIG-011 – Default SSH Keys in Use** | Shared keys allow broad access across many systems. |
| 4 | Persistence | Add own keys | Attacker drops additional authorized_keys for long term access. |
| 5 | Lateral Movement & Impact | Pivot and data theft | Use SSH to pivot, exfiltrate, and deploy malware. |

## 17. REAL-WORLD EXAMPLES

### Example 1: Cisco Virtual Appliances Default SSH Keys (CVE-2015-4216/4217)
- Virtual appliances shipped with shared default SSH authorized and host keys across all customers; compromise of one deployment exposed others.

### Example 2: Cloud Images with Cloned Host Keys
- Organizations cloning golden images with pre-generated host keys, leading to reused fingerprints across dozens of VMs, enabling impersonation and man-in-the-middle attacks.

---