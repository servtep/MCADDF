# [MISCONFIG-012]: SQL Database Firewall Disabled

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | MISCONFIG-012 |
| **MITRE ATT&CK v18.1** | [T1526 – Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/) (misconfig enabling discovery and access); [T1530 – Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/) (data theft) |
| **Tactic** | Initial Access / Collection |
| **Platforms** | Entra ID / Azure (Azure SQL Database, SQL Managed Instance) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure SQL logical servers and managed instances with public endpoint and permissive firewall (0.0.0.0/0 or Allow Azure services) |
| **Patched In** | N/A – configuration-based; mitigated via proper firewall, private endpoints, and network isolation |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure SQL firewalls control which IP ranges or virtual networks may connect to a SQL server or managed instance. When misconfigured to allow `0.0.0.0/0` or the broad "Allow Azure services and resources to access this server" rule, the database becomes reachable from a vast number of sources, including other tenants (for legacy behavior) and attacker-controlled hosts. Combined with weak credentials, token theft, or SQL injection in upstream applications, this misconfiguration dramatically increases both the probability and impact of compromise.
- **Attack Surface:** Public endpoint of Azure SQL logical servers and managed instances, firewall rules (server-level and database-level), VNet rules, and connection policies.
- **Business Impact:** **High-risk exposure of core data assets.** Open or broadly exposed SQL endpoints can be brute-forced, targeted by credential stuffing, or abused via compromised workloads elsewhere in Azure. A successful compromise exposes structured business data, credentials, and keys, often with direct financial and regulatory consequences.
- **Technical Context:** By default, a new SQL server often includes a firewall rule that allows Azure services (StartIp 0.0.0.0, EndIp 0.0.0.0). Administrators frequently add wide IP ranges (for example, `0.0.0.0` to `255.255.255.255`) for troubleshooting and never remove them. Cloud security posture tools and CIS benchmarks explicitly flag these rules as critical misconfigurations.

### Operational Risk
- **Execution Risk:** Medium – tightening firewall rules may break legacy apps until connection paths are fixed, but leaving them open risks full data breach.
- **Stealth:** Medium – brute-force and exploitation attempts may be visible in SQL audit logs, but volume is high and often poorly monitored.
- **Reversibility:** High for configuration; low for any compromise that occurred while firewall was open.

### Compliance Mappings
| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | Azure Foundations controls for SQL firewall | Require restricted IP ranges and disallow 0.0.0.0/0 and AllowAllWindowsAzureIps. |
| **DISA STIG** | Database SRG network controls | Limit remote connections and enforce network access control lists. |
| **CISA SCuBA** | Database and PaaS access restrictions | Limit exposure of cloud databases to the internet. |
| **NIST 800-53** | AC-4, SC-7 | Boundary protection and system interconnections. |
| **GDPR** | Art. 32 | Data protection by design including network-level controls. |
| **DORA** | Art. 9 | ICT risk management including network and access segmentation. |
| **NIS2** | Art. 21 | Network and information system security, including access controls. |
| **ISO 27001** | A.8.20, A.8.21 | Network security and segregation. |
| **ISO 27005** | Risk Scenario | Database exposed to the internet leading to bulk data breach.

## 3. TECHNICAL PREREQUISITES
- **Required Privileges:**
  - Azure role with permission to manage SQL servers (for example, Owner, Contributor, SQL Server Contributor).
- **Required Access:**
  - Azure Portal, Azure CLI, or PowerShell access to subscription.

**Supported Versions:**
- Azure SQL Database and SQL Managed Instance in all public and sovereign clouds.

## 4. ENVIRONMENTAL RECONNAISSANCE

### Azure CLI Recon

```bash
# List all SQL servers in a subscription
az sql server list -o table

# List firewall rules for each server
az sql server firewall-rule list \
  --resource-group <rg> \
  --server <server-name> -o table
```

**What to Look For:**
- Rules with Start IP `0.0.0.0` and End IP `0.0.0.0` (Allow Azure services).
- Rules with Start/End IP that cover very broad ranges, such as `0.0.0.0` to `255.255.255.255`.

### PowerShell Recon

```powershell
Get-AzSqlServer | ForEach-Object {
  Get-AzSqlServerFirewallRule -ResourceGroupName $_.ResourceGroupName -ServerName $_.ServerName |
    Select-Object ServerName=@{n='Server';e={$_.ServerName}}, FirewallRuleName, StartIpAddress, EndIpAddress
}
```

**What to Look For:**
- Firewall rules named `AllowAllWindowsAzureIps` or similar.
- Any rules allowing 0.0.0.0/0 style access.

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Exploiting Open SQL Firewall from the Internet

**Supported Versions:** Azure SQL Database with public endpoint and `0.0.0.0/0` or broad rules.

#### Step 1: Discover Open SQL Endpoints
**Objective:** Use internet scanning or OSINT to identify Azure SQL servers with open firewall.

- Attackers can scan for `*.database.windows.net` endpoints and attempt connections on TCP 1433.

#### Step 2: Brute-Force or Spray Credentials
**Objective:** Attempt login using known or guessed SQL logins.

**Command (example using `sqlcmd`):**
```bash
sqlcmd -S tcp:<server>.database.windows.net,1433 -U <login> -P <password> -d master -Q "SELECT @@version;"
```

**Expected Output:**
- SQL Server version banner if login succeeds.

**OpSec & Evasion:**
- Failed logins and connection attempts are logged but may not be centrally monitored.

### METHOD 2 – Lateral Abuse via "Allow Azure Services" Rule

**Supported Versions:** Any Azure SQL server with `Allow Azure services and resources to access this server` enabled.

#### Step 1: Compromise Another Azure Resource
- Attacker compromises a VM, Function, or App Service in Azure (possibly even from another tenant under legacy behavior) and uses that foothold to attack the SQL server.

#### Step 2: Connect from Compromised Resource
- From that VM or app, connect to the SQL server using stolen connection strings, MSI/managed identity, or misconfigured credentials.

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

No dedicated Atomic test exists solely for Azure SQL firewall misconfiguration; use credential stuffing or SQL data exfiltration tests against a test database reachable via open firewall to validate detection and logging.

## 7. TOOLS & COMMANDS REFERENCE

- Azure CLI `az sql server firewall-rule` for rule management.
- PowerShell `Get-AzSqlServerFirewallRule`, `Set-AzSqlServerFirewallRule`, `Remove-AzSqlServerFirewallRule`.
- `sqlcmd` / Azure Data Studio / application connection strings to validate connectivity.

## 8. SPLUNK DETECTION RULES

### Rule 1: SQL Database Allows Ingress from Any IP

- Ingest Azure configuration inventory or CSPM export into Splunk.
- Build correlation search for firewall rules where StartIpAddress is `0.0.0.0` or where the range spans the full IPv4 space.

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: Azure SQL Servers with Open Firewall Rules (Azure Resource Graph)

```kusto
resources
| where type == "microsoft.sql/servers/firewallrules"
| extend startIp = tostring(properties.startIpAddress), endIp = tostring(properties.endIpAddress)
| where startIp == "0.0.0.0" or endIp == "255.255.255.255"
```

### Query 2: Brute-Force Activity Against Azure SQL

Use `AzureDiagnostics` or `SQLSecurityAuditEvents` to detect repeated failed logins from varied IPs towards a single server.

## 10. WINDOWS EVENT LOG MONITORING

Not directly applicable (PaaS service), but on self-hosted SQL Servers in IaaS VMs, use Windows Firewall and Event Log monitoring similar to endpoint guidance.

## 11. SYSMON DETECTION PATTERNS

For IaaS SQL Servers:
- Monitor process creation for unexpected `sqlcmd` usage from non-admin accounts.
- Monitor network connections to SQL ports from untrusted IP ranges.

## 12. MICROSOFT DEFENDER FOR CLOUD

Key built-in recommendations:
- "SQL servers should have firewall rules that restrict access".
- "SQL databases should not allow ingress from 0.0.0.0/0".

Use these recommendations to identify and remediate misconfigured servers.

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

For M365-integrated apps using Azure SQL as backend, ensure that privileged access and app credential usage is audited and correlated with SQL access patterns.

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL
- Disable `Allow Azure services and resources to access this server` and remove any firewall rules allowing 0.0.0.0/0.
- Require private endpoints or VNet integration for all production Azure SQL workloads; block public network access where possible.

### Priority 2: HIGH
- Restrict SQL logins; prefer Entra ID authentication and managed identities.
- Enforce strong passwords and lockout policies for SQL authentication.

### Validation Command (Verify Fix)
```bash
az sql server firewall-rule list --resource-group <rg> --server <server> -o table

# Ensure no rules with 0.0.0.0 or 255.255.255.255
```

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)
- High volume of failed SQL login attempts from random internet IPs.
- Successful logins from unexpected regions or networks.

### Forensic Artifacts
- SQL audit logs (failed and successful logins, role changes, data exports).
- Azure Activity Logs for firewall rule changes.

### Response Procedures
1. Immediately tighten firewall rules to only known IP ranges or private endpoints.
2. Rotate credentials and revoke compromised connection strings.
3. Review SQL audit logs for data exfiltration and privilege escalation.
4. Notify regulators and affected parties if sensitive data exposure is confirmed.

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| 1 | Initial Access | Exposure of SQL endpoint | Public SQL endpoint with weak firewall. |
| 2 | Credential Access | Password spray / token theft | Attacker obtains SQL credentials. |
| 3 | Current Step | **MISCONFIG-012 – SQL Database Firewall Disabled** | Firewall allows attacker to connect from untrusted networks. |
| 4 | Collection | SQL data export | SELECT and bulk export of sensitive tables. |
| 5 | Exfiltration & Impact | Data breach and extortion | Data exfiltration and regulatory impact. |

## 17. REAL-WORLD EXAMPLES

### Example 1: Cloud Database Breaches via Open Firewalls
- Multiple public reports describe Azure and other cloud-hosted databases left open to the internet with weak or no authentication, resulting in large-scale data breaches and ransom demands.

### Example 2: CSPM Findings Across Enterprises
- Cloud security posture tools routinely flag SQL servers configured with 0.0.0.0/0 or AllowAllWindowsAzureIps, demonstrating how common and dangerous this misconfiguration remains.

---