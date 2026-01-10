# [IMPACT-DENIAL-001]: Denial of Service via Azure DDoS

## 1. METADATA HEADER

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | IMPACT-DENIAL-001 |
| **Technique Name** | Denial of Service via Azure DDoS |
| **MITRE ATT&CK v18.1** | Network Denial of Service (T1498) – https://attack.mitre.org/techniques/T1498/ |
| **Tactic** | Impact |
| **Platforms** | Internet-facing services hosted on Azure public IPs (VMs, Load Balancers, App Gateways, AKS, Web Apps) |
| **Environment** | Entra ID / Azure (IaaS & PaaS) |
| **Severity** | Critical for externally facing production services |
| **CVE** | N/A (volumetric and protocol abuse; may be combined with other vulnerabilities) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | All Azure regions and public IP–based services (with or without Azure DDoS Protection) |
| **Patched In** | N/A – Azure DDoS Protection provides mitigation but cannot prevent all forms of DoS; configuration and architecture determine resilience.[3][10][16] |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:** Adversaries may perform network denial-of-service (DoS) or distributed denial-of-service (DDoS) attacks against Azure-hosted endpoints to exhaust bandwidth or service capacity and render applications inaccessible.[3][9] These attacks often leverage botnets and reflection/amplification techniques (T1498.001/T1498.002) to direct massive amounts of traffic to Azure public IPs that front web apps, APIs, VPN gateways, or other critical services.
- **Attack Surface:** Public IP addresses on Azure VMs, Azure Load Balancer, Application Gateway/WAF, Azure Front Door, AKS ingress controllers, and VPN/ExpressRoute gateways. Attackers target DNS hostnames that resolve to these IPs.
- **Business Impact:** **Temporary or prolonged unavailability of public-facing services, SLAs breaches, and potential financial and reputational damage.** For critical services (e.g., financial portals, citizen services), sustained DDoS can have regulatory and contractual implications.[3][15]
- **Technical Context:** Azure provides native DDoS Protection (Basic – platform-wide and Standard – customer-configurable) that can automatically detect and mitigate volumetric attacks.[4][10][16] Telemetry is surfaced via Azure Monitor, metrics, and logs, and can be consumed by Microsoft Sentinel and third-party SIEMs. However, customers remain responsible for enabling DDoS plans, architecting services behind load balancers/WAFs, and tuning alerts and automations.[4][7][13][14]

### Operational Risk

- **Execution Risk:** Low for attacker – DDoS can be launched from botnets with minimal cost or exposure.  
- **Stealth:** Low – high-volume attacks are obvious at the network layer but attribution to a specific threat actor may be difficult.  
- **Reversibility:** High – DoS generally does not corrupt data, but prolonged outages can still cause severe business impact.

### Compliance Mappings

| Framework | Control / ID | Description (Failure Mode) |
|---|---|---|
| **CIS Azure Foundations** | CIS AZURE 7.x | Missing DDoS protection and inadequate monitoring of public endpoints. |
| **DISA STIG** | Network & boundary STIGs | Lack of boundary protection and traffic filtering for mission systems. |
| **CISA SCuBA** | Network & Logging | Insufficient telemetry from cloud edge services (WAF, gateways, DDoS). |
| **NIST SP 800‑53 Rev.5** | SC-5, SC-7, CP-10, CA-7 | Inadequate denial-of-service protection, boundary defense, and continuity planning.[9] |
| **GDPR** | Art. 32 | Failure to ensure availability and resilience of systems processing personal data. |
| **DORA** | Art. 11 | Insufficient ICT resilience for critical financial services exposed to the internet. |
| **NIS2** | Art. 21 | Missing technical measures to prevent and respond to large‑scale network incidents. |
| **ISO 27001:2022** | A.8.16, A.5.29 | Poor capacity management and lack of monitoring of network security. |
| **ISO 27005** | Risk Scenario: "Public digital service unavailable due to DDoS" | High‑impact operational risk for online channels.

---

## 3. TECHNICAL PREREQUISITES

- **Attacker:**
  - Access to a botnet or DDoS‑as‑a‑Service platform capable of generating significant traffic volumes targeting Azure public IPs.
  - Knowledge of victim DNS names / IPs.
- **Defender:**
  - Azure DDoS Protection Standard enabled for virtual networks hosting critical public IPs.[4][10][16]
  - Telemetry export to Azure Monitor Logs / Sentinel.

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### Identify Public IPs and DDoS Protection Status

```bash
az network public-ip list -o table
```

```bash
az network vnet list -o table
# Check which VNets have DDoS Protection plans associated
```

**What to Look For:**
- Critical services with public IPs not protected by DDoS Protection Standard.

### Baseline Normal Traffic & Metrics

Use Azure Monitor metrics (e.g., `IngressBytes`, `SNATConnectionCount`) and Application Gateway/Front Door metrics to understand normal load.[10][16]

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

This section focuses on impact and detection rather than providing attacker runbooks (which would largely be external to Azure). The key is understanding how DDoS manifests in Azure telemetry.

### METHOD 1 – Volumetric Flood Against Azure Public IP

**Scenario:** Botnet sends high-volume TCP/UDP/SYN traffic to a public IP of an Azure Load Balancer fronting a web app.

**Observable Effects (Defender view):**
- Elevated metrics in Azure Monitor for the public IP and associated resources (e.g., `UnderDDoSAttack`, `AttackTraffic`, `DroppedPackets`).[4][7][10][16]
- Potential autoscale or throttling events in upstream services.

### METHOD 2 – Application-Layer Flood via Azure Application Gateway / WAF

**Scenario:** Large numbers of HTTP(S) requests per second from one or many IPs to an App Gateway or Front Door endpoint.

**Observable Effects:**
- Spikes in `TotalRequests`, `FailedRequests`, and `WAFBlockedRequests` metrics.  
- AzureDiagnostics entries from Application Gateway with repeated requests from suspicious IPs.[17][8]

---

## 6. ATTACK SIMULATION & VERIFICATION (Atomic Red Team)

Atomic Red Team does not currently provide full-scale cloud DDoS simulations due to ethical and legal constraints. However, T1498 is covered conceptually, and small‑scale traffic generation against lab environments can be used to validate detection logic.

Reference: MITRE ATT&CK T1498 – https://attack.mitre.org/techniques/T1498/

---

## 7. TOOLS & COMMANDS REFERENCE

- Azure DDoS Protection telemetry and metrics – https://learn.microsoft.com/azure/ddos-protection/monitor-ddos-protection
- Azure CLI and PowerShell to configure DDoS plans and alerts.

---

## 8. SPLUNK DETECTION RULES

### Rule 1: High Request Volume per IP (Application Logs)

Adaptation of typical Sentinel KQL into SPL for web/application logs:[5][8]

```spl
index=azure sourcetype="azure:diagnostics" 
| stats count as RequestCount by ClientIP_s, bin(_time, 1m)
| where RequestCount > 1000
| sort - RequestCount
```

**What This Detects:**
- IPs generating unusually high request rates indicative of DoS attempts.

---

## 9. MICROSOFT SENTINEL DETECTION

### Query 1: DDoS Protection Metrics – Under Attack

When DDoS Protection Standard is enabled, metrics are available via Azure Monitor and can be ingested into Sentinel.[7][10][13][16]

```kusto
AzureDiagnostics
| where Category == "DDoSProtectionNotifications"
| where OperationName == "DDoSAttackStarted"
```

### Query 2: Application Gateway / WAF Surge from Single IP

```kusto
AzureDiagnostics
| where ResourceType == "APPLICATIONGATEWAYS" and OperationName == "ApplicationGatewayAccessLog"
| summarize RequestCount = count() by ClientIP_s, bin(TimeGenerated, 1m)
| where RequestCount > 1000
| order by RequestCount desc
```

---

## 10. WINDOWS EVENT LOG MONITORING

_Not primary for this cloud-centric technique; most evidence is in Azure edge and network telemetry rather than guest OS logs._

---

## 11. SYSMON DETECTION PATTERNS

_Not applicable – DDoS impact is on service availability at the network edge rather than process-level behavior on endpoints._

---

## 12. MICROSOFT DEFENDER FOR CLOUD

Defender for Cloud integrates with Azure DDoS Protection and surface security recommendations and alerts about network protections, but DDoS Protection itself is the main engine for detection/mitigation.[4][16]

Ensure that:
- DDoS Protection Standard is enabled on VNets hosting critical public IPs.  
- DDoS metrics and notifications are exported to Log Analytics / Sentinel.[10][13]

---

## 13. MICROSOFT PURVIEW (UNIFIED AUDIT LOG)

Not directly applicable for network-layer DoS. However, if the DoS is used as a diversion for account takeover in M365, Purview logs should be correlated for suspicious logins and changes during attack windows.

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- Enable Azure DDoS Protection Standard for all critical internet-facing workloads.[4][10][16]
- Front services with Azure Application Gateway/WAF or Azure Front Door to gain additional L7 protection and logging.[14][17]

### Priority 2: HIGH

- Implement autoscaling and graceful degradation to handle volumetric spikes.  
- Design with multi-region or multi-provider failover where appropriate.

### Access Control & Architecture

- Restrict public IP exposure; use private endpoints where possible.  
- Rate-limit and throttle at the application layer; enforce WAF rules to block known abusive patterns.[17]

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Attack

- Rapid spike in inbound traffic volume or connection counts to one or more public IPs.[3][7][10][16]
- Azure DDoS Protection notifications (`DDoSAttackStarted`, `DDoSAttackMitigated`).[10][13]
- Increased WAF blocks and HTTP 429/503 rate limiting in application logs.[8][17]

### Response Procedures

1. Confirm DDoS via Azure Portal (DDoS Protection blade, metrics) and Sentinel dashboards.  
2. Engage Microsoft support and, if required, upstream ISPs/CDN providers.  
3. Activate incident communication plans and status pages to inform users.  
4. If attack appears targeted (e.g., specific source countries, protocols), update WAF rules and firewall ACLs accordingly.

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | Initial Access | N/A (external attack) | Adversary identifies public endpoints and capacity. |
| **2** | Current Step | **[IMPACT-DENIAL-001] Denial of Service via Azure DDoS** | Botnet or reflection attacks overwhelm Azure-hosted services. |
| **3** | Follow-on | T1190, T1078 | DoS used as distraction while exploiting other weaknesses or compromising accounts. |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: DDoS Campaigns Against Cloud-Hosted Services

MITRE and multiple vendors highlight T1498 as a common technique where adversaries use botnets and reflection amplification to disrupt online services, including those hosted in major clouds.[3][6][9][15] Azure DDoS Protection documentation notes support for mitigating volumetric attacks (TCP SYN, UDP floods, amplification) against Azure public IPs.[4][10][16]

### Example 2: Killnet and Politically Motivated DDoS

Recent analyses of Killnet campaigns show large-scale DDoS attacks against government and financial services hosted in public clouds. Detection and mitigation guidance for Azure environments emphasize the use of DDoS Protection, Application Gateway WAF, and Sentinel analytics to detect spikes and geo-anomalies in traffic.[17][14]

---