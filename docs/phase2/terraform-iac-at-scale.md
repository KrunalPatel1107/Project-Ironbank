# Month 5 — Special: Infrastructure as Code at Scale (Terraform Advanced)

!!! abstract "💰 Cost: $0-20/month — Terraform Cloud free tier, OPA free, optional self-hosted runners"

!!! danger "Why IaC at Scale Matters"
    Phase 2 terraform-modules-scanning teaches Terraform modules for reuse. This expansion teaches **enterprise-grade IaC**: managing 100+ environments, preventing drift, testing changes safely, enforcing policy, and recovering from state file disasters. Every "DevSecOps Engineer" job posting demands this. At scale, IaC mistakes ($100K+ AWS bills, security breaches, outages) are caught by policy, tested before deployment, and prevented from reaching production.

!!! info "Background Context"
    If you know Azure: Azure Blueprints → Terraform modules + Terraform Cloud. Azure Policy → OPA/Sentinel. This expansion teaches the **production-grade IaC** that powers companies like Netflix (Terraform at scale), Uber (multi-cloud Terraform), and AWS itself (Open Source Terraform AWS provider).

---

## Part 1: Monorepo vs. Polyrepo Strategies

**Monorepo:** All infrastructure code in one Git repo  
**Polyrepo:** Separate repos per environment/team/service

### Monorepo Approach

```
iron-bank-terraform/                    ← Single repo
├── environments/
│   ├── dev/
│   │   ├── main.tf                    ← Dev environment
│   │   ├── terraform.tfvars           ← Dev variables
│   │   └── backend.tf                 ← Dev state backend
│   ├── staging/
│   │   ├── main.tf                    ← Staging environment
│   │   ├── terraform.tfvars
│   │   └── backend.tf
│   └── prod/
│       ├── main.tf                    ← Production environment
│       ├── terraform.tfvars
│       └── backend.tf
├── modules/
│   ├── vpc/
│   ├── eks/
│   ├── rds/
│   ├── iam/
│   └── security/
├── global/                             ← Shared resources (Route53, IAM policies)
│   ├── domain.tf
│   └── shared-policies.tf
├── .github/workflows/
│   ├── terraform-plan-dev.yml
│   ├── terraform-plan-staging.yml
│   └── terraform-plan-prod.yml
├── .pre-commit-config.yaml             ← Run tfmt, tfsec, checkov locally
└── README.md

Advantages:
✅ Single source of truth (versioning, history)
✅ Atomic changes across environments
✅ Easier code reuse (all modules in one place)
✅ Simpler CI/CD (single pipeline)

Disadvantages:
❌ Large repo (can slow down git operations)
❌ Accidental cross-environment changes
❌ Everyone has read access to prod code
```

### Polyrepo Approach

```
Separate repos per environment:

iron-bank-terraform-dev/
├── main.tf
├── variables.tf
└── modules/ (or external source)

iron-bank-terraform-staging/
├── main.tf
├── variables.tf
└── modules/ (or external source)

iron-bank-terraform-prod/
├── main.tf
├── variables.tf
└── modules/ (or external source - separate Terraform module registry)

Advantages:
✅ Smaller repos (faster git operations)
✅ Separate access control per environment (prod team ≠ dev team)
✅ Independent pipelines (dev deploys won't affect prod)
✅ Different module versions per environment

Disadvantages:
❌ Code duplication across repos
❌ Harder to keep modules in sync
❌ Multiple CI/CD pipelines to maintain
❌ Risk of inconsistency between environments
```

### Hybrid Approach (Recommended)

```
Monorepo for modules + polyrepo for environments:

terraform-modules/                      ← Published to Terraform Registry
├── modules/
│   ├── vpc/
│   ├── eks/
│   ├── rds/
│   └── iam/
├── tests/                              ← Module tests (terratest)
└── README.md

iron-bank-terraform-dev/
├── main.tf (sources modules from registry)
├── terraform.tfvars
└── .github/workflows/

iron-bank-terraform-prod/
├── main.tf (sources modules from registry)
├── terraform.tfvars
└── .github/workflows/

Advantages:
✅ Modules versioned independently (terraform registry versions)
✅ Separate environment repos (independent access control)
✅ Code reuse without duplication
✅ Scalable CI/CD
```

### Terraform Cloud for Remote State & Runs

```bash
# Monorepo example with Terraform Cloud

# Step 1: Create workspaces for each environment
terraform cloud workspace create -name dev
terraform cloud workspace create -name staging
terraform cloud workspace create -name prod

# Step 2: Configure cloud backend
cat > backend.tf << 'EOF'
terraform {
  cloud {
    organization = "mycompany"
    
    workspaces {
      # Different workspace per environment
      name = "${var.environment}-workspace"
    }
  }
}
EOF

# Step 3: Deploy
terraform init       # Connects to Terraform Cloud
terraform workspace select dev
terraform plan       # Runs on Terraform Cloud (shows in UI)
terraform apply

# Terraform Cloud Benefits:
# ✅ Remote state (no local state files)
# ✅ State locking (prevents concurrent applies)
# ✅ Terraform runs in cloud (consistent environment)
# ✅ Cost estimation (before apply)
# ✅ Team access control
```

---

## Part 2: Terraform Testing with Terratest

**Terratest** is a Go testing library for validating Terraform modules in real AWS environments.

### Lab: Test a VPC Module with Terratest

```bash
# Install Go and terratest
go get -u github.com/gruntwork-io/terratest/modules/terraform
go get -u github.com/gruntwork-io/terratest/modules/aws
go get -u github.com/stretchr/testify/assert

# Create test directory
mkdir -p modules/vpc/test

# Create test file: modules/vpc/test/vpc_test.go
cat > modules/vpc/test/vpc_test.go << 'EOF'
package test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestVPCModule(t *testing.T) {
	// Step 1: Set Terraform options
	terraformOptions := &terraform.Options{
		TerraformDir: "../",  // Path to module
		Vars: map[string]interface{}{
			"project_name": "test-vpc",
			"vpc_cidr": "10.0.0.0/16",
			"public_subnet_cidrs": []string{"10.0.1.0/24", "10.0.2.0/24"},
			"private_subnet_cidrs": []string{"10.0.10.0/24", "10.0.11.0/24"},
			"availability_zones": []string{"us-east-1a", "us-east-1b"},
		},
	}

	// Step 2: Cleanup after test
	defer terraform.Destroy(t, terraformOptions)

	// Step 3: Run Terraform init + plan + apply
	terraform.InitAndApply(t, terraformOptions)

	// Step 4: Get VPC ID from terraform output
	vpcId := terraform.Output(t, terraformOptions, "vpc_id")

	// Step 5: Validate VPC was created
	vpc := aws.GetVpcById(t, vpcId, "us-east-1")
	assert.NotNil(t, vpc)
	assert.Equal(t, "10.0.0.0/16", *vpc.CidrBlock)

	// Step 6: Validate subnets were created
	subnets := aws.GetSubnetsForVpc(t, vpcId, "us-east-1")
	assert.Equal(t, 4, len(subnets))  // 2 public + 2 private

	// Step 7: Validate security group exists
	sgId := terraform.Output(t, terraformOptions, "security_group_id")
	sg := aws.GetSecurityGroupById(t, sgId, "us-east-1")
	assert.NotNil(t, sg)
}

func TestVPCModuleTags(t *testing.T) {
	// Ensure all resources have correct tags
	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"project_name": "test-vpc",
			// ... other vars
		},
	}

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	vpcId := terraform.Output(t, terraformOptions, "vpc_id")
	vpc := aws.GetVpcById(t, vpcId, "us-east-1")

	// Validate tags
	assert.Equal(t, "test-vpc-vpc", *vpc.Tags[0].Value)
	assert.Equal(t, "test-vpc", *vpc.Tags[1].Value)
}
EOF

# Run tests
cd modules/vpc/test
go test -v -timeout 15m vpc_test.go
# Output:
# --- PASS: TestVPCModule (45.2s)
# --- PASS: TestVPCModuleTags (30.1s)
# ok    github.com/mycompany/terraform/modules/vpc   75.3s
```

### Automated Testing in CI/CD

```yaml
# .github/workflows/terraform-test.yml
name: Terraform Test

on:
  push:
    paths:
      - 'modules/**'
  pull_request:
    paths:
      - 'modules/**'

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write

    steps:
      - uses: actions/checkout@v3

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: arn:aws:iam::ACCOUNT:role/github-actions
          aws-region: us-east-1

      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: 1.21

      - name: Run Terratest
        run: |
          cd modules/vpc/test
          go test -v -timeout 15m vpc_test.go
```

---

## Part 3: Policy as Code (OPA, Sentinel)

**Policy as Code** enforces organizational rules on Terraform configurations BEFORE they're applied.

### OPA (Open Policy Agent) Example

OPA policies are written in **Rego** language. This policy denies resources without required tags:

```bash
# Install OPA
wget https://openpolicyagent.org/downloads/latest/opa_linux_x86_64
chmod +x opa_linux_x86_64

# Create policy: policies/require_tags.rego
cat > policies/require_tags.rego << 'EOF'
# Deny AWS resources without required tags

package main

deny[msg] {
    # Get all AWS resources from the terraform plan
    resource := input.resource_changes[_]
    resource.type == "aws_ec2_instance"
    
    # Check if the "Environment" tag is missing
    tags := resource.change.after.tags
    not tags.Environment
    
    msg := sprintf(
        "EC2 instance '%s' must have 'Environment' tag",
        [resource.address]
    )
}

deny[msg] {
    # Similarly for S3 buckets
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    tags := resource.change.after.tags
    not tags.CostCenter
    
    msg := sprintf(
        "S3 bucket '%s' must have 'CostCenter' tag",
        [resource.address]
    )
}

# Also check for encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_rds_instance"
    storage_encrypted := resource.change.after.storage_encrypted
    storage_encrypted == false
    
    msg := sprintf(
        "RDS instance '%s' must have encryption enabled",
        [resource.address]
    )
}
EOF

# Generate terraform plan in JSON format
terraform plan -json > tfplan.json

# Convert to OPA input format
terraform show -json tfplan.json > tfplan-opa.json

# Run OPA policy check
./opa_linux_x86_64 eval -d policies/ -i tfplan-opa.json 'data.main.deny'

# Output (if violations found):
# {
#   "result": [
#     {
#       "expressions": [
#         {
#           "value": [
#             "EC2 instance 'aws_instance.example' must have 'Environment' tag",
#             "S3 bucket 'aws_s3_bucket.logs' must have 'CostCenter' tag"
#           ]
#         }
#       ]
#     }
#   ]
# }

# Fail the pipeline if policies violated
./opa_linux_x86_64 eval -d policies/ -i tfplan-opa.json 'data.main.deny' | grep -q "deny" && exit 1 || exit 0
```

### Terraform Sentinel (HashiCorp)

Sentinel is Terraform Cloud's policy language (more integrated than OPA):

```hcl
# policies/require_encryption.sentinel
import "tfplan/v2" as tfplan

# Deny unencrypted databases
deny_unencrypted_db = rule {
  all tfplan.resource_changes.aws_rds_instance as address, rc {
    rc.change.after.storage_encrypted is true
  }
}

# Deny unrestricted security groups
deny_unrestricted_sg = rule {
  all tfplan.resource_changes.aws_security_group as address, sg {
    all sg.change.after.ingress as ing {
      ing.cidr_blocks not contains "0.0.0.0/0"
    }
  }
}

# Enforce maximum instance type
deny_expensive_instances = rule {
  all tfplan.resource_changes.aws_instance as address, inst {
    inst.change.after.instance_type in ["t3.micro", "t3.small", "t3.medium"]
  }
}

# Combine all policies
main = rule {
  (deny_unencrypted_db and deny_unrestricted_sg and deny_expensive_instances) else false
}
```

---

## Part 4: Drift Detection & Remediation

**Drift** = difference between IaC definition and actual AWS resources.

Example: Someone manually adds a security group rule in the console. Now your Terraform doesn't match reality.

### Detect Drift with Terraform Refresh

```bash
# Refresh state from actual AWS
terraform refresh

# Shows differences (drift)
terraform plan

# Example output (if someone manually added an ingress rule):
# aws_security_group.app: Updating...
# ~ resource "aws_security_group" "app" {
#   + ingress {
#     from_port = 3000
#     to_port = 3000
#     protocol = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]  ← This was added manually, not in code
#   }
# }
```

### Automated Drift Detection

```bash
# Lambda function that runs daily and checks for drift
cat > lambda/drift-detection.py << 'EOF'
import boto3
import json
from datetime import datetime

cloudformation = boto3.client('cloudformation')
sns = boto3.client('sns')

def lambda_handler(event, context):
    """Detect CloudFormation/Terraform drift daily"""
    
    # For CloudFormation stacks
    response = cloudformation.detect_stack_drift(
        StackName='iron-bank-prod'
    )
    
    stack_drift_id = response['StackDriftDetectionId']
    
    # Get drift results
    drift_status = cloudformation.describe_stack_drift_detection_status(
        StackDriftDetectionId=stack_drift_id
    )
    
    if drift_status['StackDriftStatus'] == 'DRIFTED':
        # Send alert
        message = f"""
DRIFT DETECTED in production stack!

Stack: iron-bank-prod
Drift Status: DRIFTED
Detected at: {datetime.now()}

Resources with drift:
{json.dumps(drift_status, indent=2)}

Action: Review and reconcile drift immediately
Link: https://console.aws.amazon.com/cloudformation
"""
        sns.publish(
            TopicArn='arn:aws:sns:us-east-1:ACCOUNT:drift-alerts',
            Subject='ALERT: Production Stack Drift Detected',
            Message=message
        )
        return {'statusCode': 400, 'body': 'Drift detected'}
    
    return {'statusCode': 200, 'body': 'No drift'}

EOF

# Alternative: Use Terraform Enterprise for drift detection
# terraform_enterprise drift detection automatically runs on schedule
```

---

## Part 5: Multi-Cloud Infrastructure as Code

Managing infrastructure across AWS, GCP, Azure with single Terraform codebase:

```hcl
# main.tf - Multi-cloud example

# AWS Provider
provider "aws" {
  region = "us-east-1"
}

# GCP Provider
provider "google" {
  project = var.gcp_project_id
  region  = "us-central1"
}

# Azure Provider
provider "azurerm" {
  features {}
}

# Deploy VPC to AWS
module "aws_vpc" {
  source = "./modules/vpc/aws"
  
  cidr_block = "10.0.0.0/16"
  region     = "us-east-1"
}

# Deploy VPC to GCP
module "gcp_vpc" {
  source = "./modules/vpc/gcp"
  
  network_name = "iron-bank-gcp"
  ip_range     = "10.1.0.0/16"
}

# Deploy VNet to Azure
module "azure_vnet" {
  source = "./modules/vpc/azure"
  
  resource_group_name = "iron-bank-rg"
  address_space       = "10.2.0.0/16"
}

# Variables to switch clouds
variable "primary_cloud" {
  type    = string
  default = "aws"  # or "gcp", "azure"
}

# Conditional: deploy to primary cloud only
module "database" {
  count  = var.primary_cloud == "aws" ? 1 : 0
  source = "./modules/rds"
  # AWS RDS configuration
}

module "database_gcp" {
  count  = var.primary_cloud == "gcp" ? 1 : 0
  source = "./modules/cloudsql"
  # GCP Cloud SQL configuration
}
```

**Why multi-cloud?**
- Disaster recovery (if AWS goes down, failover to GCP)
- Vendor negotiation leverage
- Compliance (some data must be in specific regions)
- Cost optimization (use cheapest cloud for each workload)

---

## Part 6: Environment Management & Workspace Isolation

```bash
# Use Terraform Workspaces for environment separation

# Create workspaces
terraform workspace new dev
terraform workspace new staging
terraform workspace new prod

# Switch workspace
terraform workspace select dev

# Each workspace has isolated state file
# .terraform/
# ├── terraform.tfstate       ← Default workspace
# ├── env/
# │   ├── dev/
# │   │   └── terraform.tfstate
# │   ├── staging/
# │   │   └── terraform.tfstate
# │   └── prod/
# │       └── terraform.tfstate

# Variables per environment
cat > environments.tfvars << 'EOF'
# dev
dev_instance_count = 1
dev_instance_type  = "t3.micro"

# staging
staging_instance_count = 2
staging_instance_type  = "t3.small"

# prod
prod_instance_count = 10
prod_instance_type  = "t3.medium"
EOF

# Apply with environment-specific variables
terraform apply -var-file=environments/dev.tfvars
terraform apply -var-file=environments/staging.tfvars
terraform apply -var-file=environments/prod.tfvars
```

---

## Part 7: State File Disaster Recovery

**State files are CRITICAL** — if lost, Terraform can't manage resources (they become orphaned).

### Backup Strategy

```bash
# 1. Remote state with versioning (Terraform Cloud)
terraform {
  cloud {
    organization = "mycompany"
    workspaces { name = "prod" }
  }
}

# Terraform Cloud automatically:
# ✅ Backs up state
# ✅ Versions state (can rollback)
# ✅ Encrypts state
# ✅ Replicates across regions

# 2. S3 backend with versioning
terraform {
  backend "s3" {
    bucket         = "iron-bank-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true  # Enable encryption
    dynamodb_table = "terraform-lock"  # State locking
  }
}

# Setup S3 backend with versioning
aws s3api create-bucket \
  --bucket iron-bank-terraform-state \
  --region us-east-1

# Enable versioning (so you can recover old states)
aws s3api put-bucket-versioning \
  --bucket iron-bank-terraform-state \
  --versioning-configuration Status=Enabled

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket iron-bank-terraform-state \
  --server-side-encryption-configuration '{
    "Rules": [
      {
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "AES256"
        }
      }
    ]
  }'

# Create DynamoDB table for locking
aws dynamodb create-table \
  --table-name terraform-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

### Recover from State File Loss

```bash
# If terraform.tfstate is corrupted/deleted:

# Option 1: Restore from S3 versioning
aws s3api get-object \
  --bucket iron-bank-terraform-state \
  --key prod/terraform.tfstate \
  --version-id <VERSION_ID_FROM_S3> \
  terraform.tfstate

# Option 2: Rebuild state from AWS resources (last resort)
terraform import aws_instance.example i-0123456789abcdef0

# Option 3: Use Terraform state rm + import to rebuild
terraform state rm 'module.vpc.aws_vpc.this'
terraform import 'module.vpc.aws_vpc.this' vpc-abc123

# Verify state is correct
terraform plan  # Should show no changes if state matches reality
```

---

## Part 8: Write an IaC Security Finding

```bash
cat > ~/iac-finding.md << 'EOF'
# Finding: Terraform State Files Not Encrypted or Versioned

**Severity:** Critical  
**Component:** Infrastructure as Code (State Management)  

## Description
Terraform state files contain sensitive data (RDS passwords, API keys, database connection strings). Current setup stores state locally and on S3 WITHOUT encryption or versioning.

## Risk
- Unencrypted state files exposed if S3 bucket is compromised
- No version history: accidentally deleted state cannot be recovered
- Local state files stored in git (commit history contains secrets)
- State file corruption undetectable (no checksums)

## Remediation
1. **Enable S3 encryption:** Put-bucket-encryption with SSE-S3 or SSE-KMS
2. **Enable versioning:** Put-bucket-versioning with Status=Enabled
3. **Enable MFA Delete:** Require MFA to delete state versions
4. **Use Terraform Cloud:** Managed state with automatic backups and versioning
5. **Add state locking:** DynamoDB table prevents concurrent applies

## Effort
- Initial: 2 hours (migrate to S3 backend, enable encryption/versioning)
- Ongoing: 0 hours (automatic)

## Compliance
- PCI-DSS: Encryption at rest required
- HIPAA: State must be encrypted and versioned
- SOC2: Backup and recovery required
EOF

cat ~/iac-finding.md
```

---

## 🧹 Cleanup

```bash
rm -f ~/iac-finding.md
rm -f -r modules/vpc/test/

echo "✅ Infrastructure as Code at Scale lab cleaned up"
```

---

## Checklist

**Terraform Architecture at Scale**
- [ ] Understand monorepo vs. polyrepo vs. hybrid strategies
- [ ] Know when to use each pattern (team size, organization maturity)
- [ ] Can design a multi-environment Terraform structure
- [ ] Understand Terraform Cloud workspaces and benefits

**Terraform Testing**
- [ ] Know what Terratest is (Go testing for Terraform)
- [ ] Can write basic Terratest for a module
- [ ] Understand how to integrate Terratest into CI/CD
- [ ] Know limitations (Terratest creates real AWS resources)

**Policy as Code**
- [ ] Can write OPA/Rego policies for Terraform
- [ ] Know Terraform Sentinel (built into Terraform Cloud)
- [ ] Can integrate policies into CI/CD pipeline
- [ ] Understand difference between audit and enforcement

**Drift Detection**
- [ ] Understand what drift is (manual changes outside Terraform)
- [ ] Know how to detect drift (terraform refresh, terraform plan)
- [ ] Can setup automated drift detection (Lambda, CloudFormation)
- [ ] Know how to remediate drift (reapply or remove manual changes)

**Multi-Cloud IaC**
- [ ] Can write Terraform for AWS, GCP, Azure
- [ ] Understand module organization for multi-cloud
- [ ] Know conditional logic for cloud-specific resources
- [ ] Understand trade-offs (complexity, cost, portability)

**State File Management**
- [ ] Know why state files are critical
- [ ] Can setup S3 backend with encryption/versioning
- [ ] Understand DynamoDB state locking
- [ ] Can recover from state file loss

**Production Readiness**
- [ ] All state encrypted at rest and in transit
- [ ] Version control on all Terraform code
- [ ] Peer review required for prod changes
- [ ] Automated testing (Terratest) before merge
- [ ] Policy enforcement (OPA/Sentinel) blocks violations
- [ ] Drift detection alerting configured
- [ ] Disaster recovery plan for state files tested

---

## Integration with Phase 2 & Phase 4

This IaC at Scale expansion strengthens:
- **Phase 2 m5:** Base Terraform knowledge + advanced patterns
- **Phase 4 m10-week2:** IaC scanning gates now meaningful (what policies protect against)
- **Phase 4 m11-week1:** Config Rules as complement (detect drift at AWS level)
- **Phase 4 m11-week2:** Governance SCPs + IaC policies = defense in depth

---

## Production Deployment Checklist

Before using Terraform at scale in production:

1. **State Management:**
   - [ ] Terraform Cloud or S3 remote backend configured
   - [ ] Encryption enabled (SSE-KMS for sensitive data)
   - [ ] Versioning enabled (can rollback states)
   - [ ] State locking enabled (DynamoDB or Terraform Cloud)
   - [ ] MFA delete enabled (prevent accidental deletion)
   - [ ] Backup tested (restore from old version works)

2. **Code Quality:**
   - [ ] Terraform modules extracted (DRY principle)
   - [ ] Code review process documented
   - [ ] Formatting standard (terraform fmt applied)
   - [ ] Linting passes (tflint, checkov)
   - [ ] Policy checks pass (OPA, Sentinel)

3. **Testing:**
   - [ ] Unit tests written (Terratest)
   - [ ] Tests pass in CI/CD
   - [ ] Tests run in staging before prod
   - [ ] Manual testing in staging completed

4. **Operations:**
   - [ ] Runbook for rollback documented
   - [ ] Disaster recovery for state tested
   - [ ] Team training on Terraform completed
   - [ ] Monitoring/alerting for failed applies configured
   - [ ] Drift detection monitoring active

You now have **enterprise-grade Infrastructure as Code** practices. 🎓
