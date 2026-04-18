# Month 5 — Week 3: Terraform Modules & Security Scanning

!!! abstract "💰 Cost: $0"
    This week is focused on code structure and security scanning. No AWS resources are permanently deployed — you'll `terraform destroy` after each test.

!!! info "Background Context"
    Terraform modules = reusable Azure Bicep templates or ARM template linked deployments. Checkov = Azure Policy "what-if" scanning but for IaC files before deployment. This week's skills directly map to "DevSecOps engineer" job descriptions you'll apply for.

---

## What Are Terraform Modules?

A **module** is a folder of `.tf` files that can be called like a function — you pass in variables, it creates resources, it returns outputs. The Week 2 code you wrote can become a module that you (or a teammate) call in 3 lines.

```
Without modules:          With modules:
main.tf (500 lines)  →   main.tf (30 lines)
                          modules/
                            vpc/       ← reusable network code
                            sg/        ← reusable security group code
```

Benefits: reuse the same VPC design across dev/staging/prod environments by passing different variable values. The module code stays identical; only the inputs change.

---

## Part 1: Create a VPC Module

```bash
cd ~/projects/iron-bank-tf

# Create the module directory structure
mkdir -p modules/vpc
touch modules/vpc/main.tf modules/vpc/variables.tf modules/vpc/outputs.tf
```

**`modules/vpc/variables.tf`** — inputs the module accepts:

```hcl
variable "project_name" {
  description = "Prefix for resource names"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "List of CIDR blocks for public subnets"
  type        = list(string)
}

variable "private_subnet_cidrs" {
  description = "List of CIDR blocks for private subnets"
  type        = list(string)
}

variable "availability_zones" {
  description = "List of AZs to deploy into"
  type        = list(string)
}
```

**`modules/vpc/main.tf`** — the actual resources (move your vpc.tf content here):

```hcl
# VPC
resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project_name}-vpc", Project = var.project_name }
}

# Internet Gateway
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.project_name}-igw", Project = var.project_name }
}

# Public Subnets
resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name    = "${var.project_name}-public-${var.availability_zones[count.index]}"
    Project = var.project_name
    Tier    = "public"
  }
}

# Private Subnets
resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name    = "${var.project_name}-private-${var.availability_zones[count.index]}"
    Project = var.project_name
    Tier    = "private"
  }
}

# Public Route Table + associations
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = { Name = "${var.project_name}-public-rt", Project = var.project_name }
}

resource "aws_route_table_association" "public" {
  count          = length(var.public_subnet_cidrs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private Route Table + associations
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.project_name}-private-rt", Project = var.project_name }
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}
```

**`modules/vpc/outputs.tf`** — what the module exposes to the caller:

```hcl
output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.this.id
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "igw_id" {
  description = "Internet Gateway ID"
  value       = aws_internet_gateway.this.id
}
```

---

## Part 2: Call the Module From Root

Now update your root `main.tf` to use the module instead of inline resources:

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.6"
}

provider "aws" {
  region  = var.aws_region
  profile = "iron-bank"
}

# ─── Call the VPC module ──────────────────────────────────────────────────────
# This is like calling a function: module "label" { source = "path"; inputs... }
module "vpc" {
  source = "./modules/vpc"    # Path to the module folder

  # Pass in variables — the module uses these instead of hard-coded values
  project_name         = var.project_name
  vpc_cidr             = var.vpc_cidr
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
  availability_zones   = var.availability_zones
}
```

Update root `outputs.tf` to reference the module's outputs:

```hcl
# When a resource is inside a module, reference it as module.<name>.<output>
output "vpc_id" {
  value = module.vpc.vpc_id
}

output "public_subnet_ids" {
  value = module.vpc.public_subnet_ids
}

output "private_subnet_ids" {
  value = module.vpc.private_subnet_ids
}
```

```bash
# Re-initialize — Terraform needs to discover the new module
terraform init

# Plan — should still show the same resources, just organized differently
terraform plan

# Deploy to verify the module works
terraform apply
# Type: yes

terraform output
# Same output as before — but now the code is modular and reusable
```

??? note "Module source paths: local vs registry"
    `source = "./modules/vpc"` uses a local folder — great for your own modules.
    `source = "terraform-aws-modules/vpc/aws"` pulls from the public Terraform Registry — pre-built community modules. In production you'd use registry modules for well-tested code, and local modules for your organisation's custom patterns.

---

## Part 3: Checkov Deep Dive — Fix Real Findings

Now run a thorough security scan and work through the findings:

```bash
# Run Checkov against your entire project
checkov -d . --output cli

# For a specific file only:
checkov -f modules/vpc/main.tf

# Save results as JSON for later analysis
checkov -d . --output json > checkov-results.json

# Count how many checks passed/failed
cat checkov-results.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
summary = data['summary']
print(f\"Passed:  {summary['passed']}\")
print(f\"Failed:  {summary['failed']}\")
print(f\"Skipped: {summary['skipped']}\")
"
```

### Common Findings and Fixes

**Finding: CKV_AWS_130 — VPC should not enable public IPs by default**

This flags `map_public_ip_on_launch = true` on public subnets. For a Bastion host pattern, this is intentional — suppress it with a comment:

```hcl
resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true   #checkov:skip=CKV_AWS_130: Bastion host requires public IP
  # ↑ This tells Checkov: "I know about this, it's intentional"
  ...
}
```

**Finding: CKV2_AWS_12 — VPC should have Flow Logs enabled**

Fix this by adding flow logs to the module (you built these in Month 4 Week 4):

```hcl
# Add to modules/vpc/main.tf
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/${var.project_name}-flow-logs"
  retention_in_days = 7    # 7 days is enough for labs; production needs 90+

  tags = { Project = var.project_name }
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.this.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn

  tags = { Project = var.project_name }
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.project_name}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup", "logs:CreateLogStream",
        "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}
```

```bash
# Re-run Checkov after fixes
checkov -d .
# You should see the CKV2_AWS_12 finding disappear

# Re-deploy with the fixes
terraform apply
terraform output
```

---

## Part 4: tfsec — A Second Scanner Opinion

Using two scanners catches different things. `tfsec` is fast and gives a different rule set to Checkov:

```bash
# Install tfsec
curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash
# Or on macOS: brew install tfsec

# Run against your project
tfsec .

# Compare the findings with Checkov — note any differences
# A mature security posture uses multiple tools
```

!!! tip "Scanner philosophy"
    Don't aim for zero findings on Day 1. The goal is **understanding each finding** — is it a real risk, a false positive, or an intentional trade-off? Document your suppressions with `#checkov:skip=...` comments so future reviewers know *why*, not just *what*.

---

## 🧹 Cleanup

!!! abstract "🧹 Cleanup"

```bash
terraform destroy
# Type: yes

# Verify nothing remains
aws ec2 describe-vpcs \
  --filters "Name=tag:Project,Values=iron-bank" \
  --profile iron-bank \
  --query 'Vpcs[*].VpcId' --output text
# Should return nothing

echo "✅ All Week 3 resources destroyed"
```

---

## Checklist

- [ ] Created `modules/vpc/` with `main.tf`, `variables.tf`, `outputs.tf`
- [ ] Root `main.tf` calls the module — not inline resources
- [ ] `terraform init` re-run after adding module
- [ ] `terraform apply` succeeds using the module
- [ ] `checkov -d .` results saved to `checkov-results.json`
- [ ] At least 2 Checkov findings reviewed and either fixed or suppressed with a comment
- [ ] Flow Logs added to the VPC module (fixes CKV2_AWS_12)
- [ ] `tfsec` installed and run — findings compared to Checkov
- [ ] Can explain why you'd use `#checkov:skip=` rather than just ignoring a finding
- [ ] `terraform destroy` — everything clean
- [ ] **Bill verified $0**
