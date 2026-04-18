# Month 5 — Week 2: Iron Bank Architecture in Terraform

!!! danger "💰 Cost Warning"
    This week you build real infrastructure in code. Keep costs at **$0** by running `terraform destroy` at the end of every session.

    - VPC, Subnets, Route Tables, IGW, Security Groups = **FREE**
    - If you accidentally leave an EC2 instance running: ~$0.01/hour (t2.micro)
    - **Never** create a NAT Gateway ($32/mo) this week — it's not in the plan yet

!!! info "Background Context"
    You manually built this VPC in Month 4 using ~40 CLI commands. This week you encode the same architecture in Terraform HCL — about 80 lines that are version-controlled, repeatable, and auditable. This is what "Infrastructure as Code" means on a DevSecOps resume.

---

## The Goal: Translate Month 4 Into Code

In Month 4 you ran CLI commands one by one. This week you write Terraform that builds the **same architecture** — but now it lives in Git, can be reviewed in a PR, and reproduced in 60 seconds by any teammate.

Here's what you'll build:

```
Iron Bank VPC (10.0.0.0/16)
├── Public Subnet 1a  (10.0.1.0/24) ──→ Internet Gateway ──→ Internet
├── Public Subnet 1b  (10.0.2.0/24) ──→ Internet Gateway ──→ Internet
├── Private Subnet 1a (10.0.3.0/24)    (no internet route)
└── Private Subnet 1b (10.0.4.0/24)    (no internet route)
```

---

## Part 1: Project Structure

Good Terraform projects split code across multiple files — each file has one responsibility. Terraform automatically reads **all** `.tf` files in the directory.

```bash
cd ~/projects/iron-bank-tf
# Create the file structure
touch variables.tf outputs.tf vpc.tf security_groups.tf
ls -la
# You should see: main.tf  variables.tf  outputs.tf  vpc.tf  security_groups.tf
```

??? note "Why multiple files instead of one big main.tf?"
    Think of it like organizing Python code into modules. A 500-line `main.tf` is hard to navigate. Splitting by concern (`vpc.tf` for networking, `security_groups.tf` for firewalls) makes code easier to read and review. Terraform doesn't care — it reads all `.tf` files together.

---

## Part 2: Variables — Making Code Reusable

Variables let you change values without editing the core code. Think of them like function parameters.

**`variables.tf`** — declare all inputs here:

```hcl
# The AWS region to deploy into
# Type constraint "string" ensures nobody passes a number by mistake
variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"   # Used if no value is provided
}

# The VPC CIDR block — the full IP range for our network
variable "vpc_cidr" {
  description = "CIDR block for the Iron Bank VPC"
  type        = string
  default     = "10.0.0.0/16"
}

# A list of CIDRs for public subnets (one per AZ)
variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)    # list(string) means a list of text values
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

# A list of CIDRs for private subnets
variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.3.0/24", "10.0.4.0/24"]
}

# The availability zones to spread subnets across
variable "availability_zones" {
  description = "AZs to deploy subnets into"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

# A prefix for naming all resources (makes billing and console filtering easy)
variable "project_name" {
  description = "Prefix for all resource names"
  type        = string
  default     = "iron-bank"
}

# Your IP for the Bastion Security Group rule
variable "admin_ip" {
  description = "Your public IP in CIDR format (e.g. 1.2.3.4/32)"
  type        = string
  # No default — you MUST provide this value (sensitive, shouldn't be committed)
}
```

Now create **`terraform.tfvars`** — this is where you provide your actual values:

```hcl
# terraform.tfvars — your personal variable values
# Add this file to .gitignore if it contains sensitive values like admin_ip

admin_ip = "YOUR_IP_HERE/32"   # Replace with: curl checkip.amazonaws.com
```

```bash
# Get your IP and update the file
MY_IP=$(curl -s https://checkip.amazonaws.com)
echo "admin_ip = \"${MY_IP}/32\"" > terraform.tfvars
cat terraform.tfvars  # Verify it looks right

# Add to .gitignore so your IP is never committed
echo "terraform.tfvars" >> .gitignore
echo ".terraform/" >> .gitignore
echo "*.tfstate" >> .gitignore
echo "*.tfstate.backup" >> .gitignore
```

!!! warning "Never commit terraform.tfvars or *.tfstate to Git"
    `terraform.tfvars` may contain your IP, account IDs, or secrets. `terraform.tfstate` contains resource IDs and sometimes sensitive values in plaintext. Both belong in `.gitignore`.

---

## Part 3: The VPC Configuration

**`vpc.tf`** — all networking resources:

```hcl
# ─── VPC ──────────────────────────────────────────────────────────────────────
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr         # References our variable
  enable_dns_support   = true                 # Needed for EC2 hostname resolution
  enable_dns_hostnames = true                 # Gives instances DNS names

  tags = {
    Name    = "${var.project_name}-vpc"       # "${}" = string interpolation (like f-strings in Python)
    Project = var.project_name
  }
}

# ─── Internet Gateway ─────────────────────────────────────────────────────────
# The door between your VPC and the internet — one per VPC
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id   # Reference another resource's attribute

  tags = {
    Name    = "${var.project_name}-igw"
    Project = var.project_name
  }
}

# ─── Public Subnets ───────────────────────────────────────────────────────────
# count = 2 creates TWO copies of this resource (one per AZ)
resource "aws_subnet" "public" {
  count             = length(var.public_subnet_cidrs)   # length([...]) = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.public_subnet_cidrs[count.index]    # [0] first time, [1] second time
  availability_zone = var.availability_zones[count.index]

  # Instances launched here automatically get a public IP
  map_public_ip_on_launch = true

  tags = {
    Name    = "${var.project_name}-public-${var.availability_zones[count.index]}"
    Project = var.project_name
    Tier    = "public"
  }
}

# ─── Private Subnets ──────────────────────────────────────────────────────────
resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  # No public IP — private subnets are internal only
  map_public_ip_on_launch = false

  tags = {
    Name    = "${var.project_name}-private-${var.availability_zones[count.index]}"
    Project = var.project_name
    Tier    = "private"
  }
}

# ─── Public Route Table ───────────────────────────────────────────────────────
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  # Inline route: all internet traffic goes via IGW
  route {
    cidr_block = "0.0.0.0/0"                    # All destinations
    gateway_id = aws_internet_gateway.main.id    # → go through the IGW
  }

  tags = {
    Name    = "${var.project_name}-public-rt"
    Project = var.project_name
  }
}

# ─── Associate Public Subnets → Public Route Table ────────────────────────────
# count = 2 creates one association per public subnet
resource "aws_route_table_association" "public" {
  count          = length(var.public_subnet_cidrs)
  subnet_id      = aws_subnet.public[count.index].id    # Match by index
  route_table_id = aws_route_table.public.id
}

# ─── Private Route Table ──────────────────────────────────────────────────────
# No route to 0.0.0.0/0 — private subnets can't reach the internet
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name    = "${var.project_name}-private-rt"
    Project = var.project_name
  }
}

# ─── Associate Private Subnets → Private Route Table ─────────────────────────
resource "aws_route_table_association" "private" {
  count          = length(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}
```

??? note "What does aws_subnet.public[count.index].id mean?"
    When you use `count`, Terraform creates a *list* of resources. `aws_subnet.public` becomes a list of 2 subnet objects. `[count.index]` means "use the same index as the current iteration" — so the first `aws_route_table_association` gets the first subnet, the second gets the second. This is the standard Terraform pattern for creating multiple similar resources.

---

## Part 4: Security Groups

**`security_groups.tf`**:

```hcl
# ─── Bastion Security Group ───────────────────────────────────────────────────
resource "aws_security_group" "bastion" {
  name        = "${var.project_name}-bastion-sg"
  description = "SSH access from admin IP only"
  vpc_id      = aws_vpc.main.id

  # Inbound: SSH only from your IP
  ingress {
    description = "SSH from admin"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]    # Uses your variable — never hard-coded
  }

  # Outbound: allow all (standard — instances need to reach AWS APIs, package repos, etc.)
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"            # -1 means all protocols
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-bastion-sg"
    Project = var.project_name
  }
}

# ─── Private Instance Security Group ─────────────────────────────────────────
resource "aws_security_group" "private" {
  name        = "${var.project_name}-private-sg"
  description = "Allow SSH from Bastion SG only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "SSH from Bastion only"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    # Reference the Bastion SG — not an IP — so this works even after reboots
    security_groups = [aws_security_group.bastion.id]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-private-sg"
    Project = var.project_name
  }
}
```

---

## Part 5: Outputs — Capture Resource IDs

**`outputs.tf`** — print important values after `terraform apply`:

```hcl
# Outputs are printed at the end of terraform apply
# You can also retrieve them later with: terraform output

output "vpc_id" {
  description = "The ID of the Iron Bank VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id    # [*] = all items in the list
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "bastion_sg_id" {
  description = "Bastion Security Group ID"
  value       = aws_security_group.bastion.id
}

output "private_sg_id" {
  description = "Private Security Group ID"
  value       = aws_security_group.private.id
}
```

---

## Part 6: Deploy and Verify

```bash
# ─── Update provider in main.tf ───────────────────────────────────────────────
# Replace the contents of main.tf with just the provider block
# (all resources now live in vpc.tf and security_groups.tf)
cat > main.tf << 'EOF'
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"   # Use any 5.x version — pin to avoid surprise upgrades
    }
  }
  required_version = ">= 1.6"
}

provider "aws" {
  region  = var.aws_region
  profile = "iron-bank"
}
EOF

# ─── Security scan first — always before apply ────────────────────────────────
checkov -d .
# Expected: some warnings about missing flow logs, KMS encryption — note them
# The goal is awareness, not zero findings (yet — that's Week 3)

# ─── Plan and review ──────────────────────────────────────────────────────────
terraform init    # Re-run after adding new files
terraform plan    # Should show ~12 resources to create
# Read through each resource — confirm what you expect

# ─── Deploy ───────────────────────────────────────────────────────────────────
terraform apply
# Type: yes

# ─── Check outputs ────────────────────────────────────────────────────────────
terraform output
# Shows VPC ID, subnet IDs, SG IDs

# ─── Verify in AWS ────────────────────────────────────────────────────────────
VPC_ID=$(terraform output -raw vpc_id)
aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --profile iron-bank \
  --query 'Subnets[*].{Name:Tags[?Key==`Name`]|[0].Value,AZ:AvailabilityZone,CIDR:CidrBlock}' \
  --output table
# You should see all 4 subnets across both AZs
```

Expected `terraform output` result:
```
bastion_sg_id = "sg-0abc12345"
private_sg_id = "sg-0def67890"
private_subnet_ids = [
  "subnet-0abc11111",
  "subnet-0abc22222",
]
public_subnet_ids = [
  "subnet-0abc33333",
  "subnet-0abc44444",
]
vpc_id = "vpc-0abc55555"
```

---

## 🧹 Cleanup

!!! abstract "🧹 Cleanup — One command destroys everything"

```bash
terraform destroy
# Type: yes
# Terraform reads terraform.tfstate and deletes all resources in the correct order

# Verify in AWS
aws ec2 describe-vpcs \
  --filters "Name=tag:Project,Values=iron-bank" \
  --profile iron-bank \
  --query 'Vpcs[*].VpcId' --output text
# Should return nothing

echo "✅ All Month 5 Week 2 resources destroyed"
```

---

## Checklist

- [ ] Project structure: `main.tf`, `variables.tf`, `outputs.tf`, `vpc.tf`, `security_groups.tf`
- [ ] `terraform.tfvars` created with your IP — added to `.gitignore`
- [ ] `checkov -d .` run and findings reviewed (don't need to be zero yet)
- [ ] `terraform plan` shows ~12 resources to create
- [ ] `terraform apply` succeeds — all outputs displayed
- [ ] AWS Console confirms VPC, 4 subnets, 2 route tables, 2 SGs exist
- [ ] Can explain what `count` and `count.index` do
- [ ] `terraform destroy` succeeds — AWS Console is clean
- [ ] **Bill verified $0**
