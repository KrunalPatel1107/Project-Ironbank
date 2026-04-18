# Month 6 — Week 4: Terraform Exam & Phase 2 Wrap-Up

!!! abstract "💰 Cost: $0 this week"
    Week 4 is exam prep and project polish — no new AWS resources are created.
    Budget **$70.50** for the Terraform Associate 004 exam voucher if you haven't booked yet.

!!! info "Exam Details — Terraform Associate 004"
    | | |
    |---|---|
    | **Exam code** | TA-003 / 004 |
    | **Duration** | 60 minutes |
    | **Questions** | ~57 (multiple choice + multi-select) |
    | **Passing score** | ~70% (~40/57) |
    | **Cost** | $70.50 USD |
    | **Free retake** | Yes — within 1 year of purchase |
    | **Booking** | [hashicorp.com/certification](https://www.hashicorp.com/certification) |
    | **Format** | Online proctored (PSI) — webcam + quiet room required |

---

## Part 1: Exam Domains at a Glance

Review the topics you haven't touched yet. Everything from Month 5 Week 4 covered the core workflow — this week fills the remaining gaps.

### Terraform Cloud & Enterprise (know the concepts, not the UI)

```
Terraform Cloud features you need to know:
├── Remote state storage (replaces S3 + DynamoDB backend)
├── Remote plan + apply (runs in Terraform Cloud, not your laptop)
├── Sentinel policy-as-code (like Checkov, but built into the platform)
├── Cost estimation (shows predicted AWS cost before apply)
├── VCS integration (GitHub PR triggers a plan automatically)
└── Teams & RBAC (control who can approve applies)
```

**Exam tip:** You don't need to use Terraform Cloud — just know what differentiates it from the open-source CLI and when you'd choose one over the other.

### Terraform Provisioners (know what they are, and why to avoid them)

```hcl
# Provisioners run scripts AFTER a resource is created
# Avoid them when possible — they break Terraform's idempotency guarantees
resource "aws_instance" "bastion" {
  ami           = "ami-abc123"
  instance_type = "t2.micro"

  # local-exec: runs a script on YOUR machine (not the instance)
  provisioner "local-exec" {
    command = "echo ${self.public_ip} >> known_hosts.txt"
  }

  # remote-exec: SSHs into the instance and runs a script there
  provisioner "remote-exec" {
    inline = ["sudo yum install -y httpd"]
    connection {
      type        = "ssh"
      user        = "ec2-user"
      private_key = file("~/.ssh/iron-bank-key.pem")
      host        = self.public_ip
    }
  }
}
```

??? note "Why avoid provisioners?"
    Terraform's strength is declarative state management — it knows the desired state and enforces it. Provisioners run imperative scripts that Terraform can't track or re-run safely. If a provisioner fails partway, the resource is in an unknown state. Prefer **user_data** for instance bootstrapping and **AWS Systems Manager** for ongoing configuration management.

### Lifecycle Meta-Arguments

```hcl
resource "aws_security_group" "web" {
  name = "web-sg"

  lifecycle {
    # Create the replacement BEFORE destroying the old one
    # Prevents downtime when changing a resource that can't be updated in-place
    create_before_destroy = true

    # Never destroy this resource — even on terraform destroy
    # Use for production databases you never want accidentally deleted
    prevent_destroy = true

    # Tell Terraform to ignore changes to these attributes made outside Terraform
    # e.g. if someone manually changes the description in the console
    ignore_changes = [description, tags["LastModified"]]
  }
}
```

### Data Sources — Reading Existing Resources

```hcl
# Data sources READ existing resources — they don't create anything
# Use when you need info about something Terraform doesn't manage

# Get the latest Amazon Linux 2023 AMI without hard-coding an AMI ID
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023*-x86_64"]
  }
}

# Now reference it in a resource
resource "aws_instance" "bastion" {
  ami           = data.aws_ami.amazon_linux.id    # data.<type>.<name>.<attribute>
  instance_type = "t2.micro"
}

# Other common data sources:
data "aws_caller_identity" "current" {}     # Get your account ID
data "aws_region" "current" {}              # Get current region
data "aws_vpc" "main" {                     # Look up an existing VPC
  tags = { Name = "Iron-Bank-VPC" }
}
```

### Terraform Functions — The Most Tested Ones

```hcl
# length() — count items in a list or string
length(["a", "b", "c"])   # → 3

# toset() — convert list to set (removes duplicates, loses order)
toset(["us-east-1a", "us-east-1b"])

# lookup() — get a value from a map, with a default if missing
lookup(var.region_map, "us-east-1", "unknown")

# join() — combine a list into a string
join(", ", ["10.0.1.0/24", "10.0.2.0/24"])   # → "10.0.1.0/24, 10.0.2.0/24"

# flatten() — collapse nested lists into a single list
flatten([["a", "b"], ["c"]])   # → ["a", "b", "c"]

# merge() — combine two maps (second map wins on conflict)
merge({env="dev"}, {region="us-east-1"})   # → {env="dev", region="us-east-1"}

# file() — read a local file as a string
user_data = base64encode(file("${path.module}/scripts/bootstrap.sh"))

# jsonencode() — convert HCL object to JSON string (used for IAM policies)
policy = jsonencode({
  Version = "2012-10-17"
  Statement = [...]
})
```

---

## Part 2: Exam Practice — Final 10 Questions

Cover each answer, think through it, then reveal:

??? note "Q1: What is the purpose of `terraform init -upgrade`?"
    It upgrades provider plugins to the latest version that satisfies your version constraints. Run this after updating the `version` constraint in your `required_providers` block, or when HashiCorp releases a patch you want.

??? note "Q2: You have two workspaces: dev and prod. Both use the same main.tf. How do you make the instance type `t2.micro` in dev and `m5.large` in prod?"
    ```hcl
    variable "instance_types" {
      default = {
        dev  = "t2.micro"
        prod = "m5.large"
      }
    }

    resource "aws_instance" "app" {
      instance_type = var.instance_types[terraform.workspace]
    }
    ```
    `terraform.workspace` returns the current workspace name as a string.

??? note "Q3: What happens if you delete terraform.tfstate and run terraform apply?"
    Terraform has no record of existing resources, so it tries to create everything from scratch. This will fail for resources that already exist (e.g. duplicate S3 bucket name) or create duplicate resources if names are generated. **Never delete tfstate.** Restore it from the S3 backend or version history.

??? note "Q4: What is the difference between `for_each` and `count`?"
    `count` creates N identical resources indexed by integer (0, 1, 2...). If you remove item[0], all higher-indexed resources are re-indexed and Terraform destroys/recreates them.

    `for_each` creates resources keyed by a string or set. Removing one key only affects that specific resource — others are untouched. **Prefer `for_each` over `count` for anything more than a simple repeat.**

    ```hcl
    # count — fragile if list order changes
    resource "aws_subnet" "public" {
      count      = length(var.subnet_cidrs)
      cidr_block = var.subnet_cidrs[count.index]
    }

    # for_each — stable, keyed by CIDR
    resource "aws_subnet" "public" {
      for_each   = toset(var.subnet_cidrs)
      cidr_block = each.value
    }
    ```

??? note "Q5: A colleague ran `terraform apply` and added a tag to an EC2 instance. What happens when you run `terraform apply` next?"
    Terraform compares real infrastructure to your state file. If the tag change was made outside Terraform, it'll appear as a drift. Terraform will remove the manually-added tag on next `apply` to restore the declared state — unless you add `ignore_changes = [tags]` in the lifecycle block.

??? note "Q6: What command checks your configuration for syntax errors without connecting to AWS?"
    **`terraform validate`** — checks HCL syntax and internal references. It doesn't need AWS credentials. `terraform plan` also validates, but requires credentials because it reads real state.

??? note "Q7: You want to replace a resource without destroying it first (to avoid downtime). What lifecycle setting enables this?"
    **`create_before_destroy = true`** in the lifecycle block. Terraform creates the replacement, updates all references, then destroys the original.

??? note "Q8: Where does Terraform look for variable values? List in priority order (highest first)."
    1. `-var` flag on the CLI (e.g. `terraform apply -var="region=us-west-2"`)
    2. `-var-file` flag (e.g. `terraform apply -var-file="prod.tfvars"`)
    3. `*.auto.tfvars` files (loaded automatically, alphabetically)
    4. `terraform.tfvars` (loaded automatically)
    5. Environment variables (`TF_VAR_region`)
    6. Default value in `variable` block
    7. Interactive prompt (if no value found and no default)

??? note "Q9: What is a Terraform provider and what does `terraform init` do with it?"
    A provider is a plugin that lets Terraform talk to a specific platform (AWS, Azure, GCP, GitHub, etc.). `terraform init` reads your `required_providers` block, downloads the specified provider version from the Terraform Registry (or a custom registry), and stores it in `.terraform/providers/`. Without init, Terraform has no provider plugin and can't make API calls.

??? note "Q10: When would you use `terraform taint` (or its modern replacement)?"
    `terraform taint` is **deprecated** since Terraform 0.15.2. The replacement is **`terraform apply -replace=<resource_address>`** (e.g. `terraform apply -replace=aws_instance.bastion`). This forces Terraform to destroy and recreate a specific resource, even if no configuration change exists. Use it when a resource is in a broken state (e.g. an EC2 instance that passed OS checks but is unhealthy at the app level).

---

## Part 3: Final Phase 2 Project Polish

Before Phase 3, make sure your GitHub portfolio is presentable. Recruiters and hiring managers will look at this.

```bash
cd ~/projects/iron-bank-tf

# ─── Ensure all files are formatted ───────────────────────────────────────────
terraform fmt -recursive
git diff    # Review formatting changes

# ─── Final Checkov scan ───────────────────────────────────────────────────────
checkov -d . --output cli
# Document any remaining findings and your reasoning for each suppression

# ─── Update the root README with Phase 2 completion ──────────────────────────
cat >> README.md << 'EOF'

## Phase 2 Progress

| Month | Focus | Status |
|---|---|---|
| Month 4 | VPC Networking (CLI) | ✅ Complete |
| Month 5 | Terraform IaC | ✅ Complete |
| Month 6 | AWS Detection (GuardDuty, Config, Security Hub, SCPs) | ✅ Complete |

## Scripts

| Script | Description |
|---|---|
| `scripts/flow_analyzer.py` | VPC Flow Log security analyzer (Month 4) |
| `scripts/security_posture.py` | Security Hub + Config compliance dashboard (Month 6) |
EOF

# ─── Commit everything ────────────────────────────────────────────────────────
git add -A
git status    # Always review before committing
git commit -m "feat: Phase 2 complete — VPC, Terraform modules, detection stack"
git push

echo "✅ Phase 2 portfolio committed to GitHub"
```

---

## Phase 2 Complete — What You've Built

| Month | Built | Skills Demonstrated |
|---|---|---|
| **4** | Multi-AZ VPC, Bastion, Flow Log Analyzer | AWS networking, Python automation, network security monitoring |
| **5** | Terraform VPC module, Checkov scanning, remote state | IaC, modular design, security scanning in code |
| **6** | GuardDuty + SNS alerting, Config + Security Hub dashboard, SCPs, VPC Endpoints | Threat detection, compliance automation, Zero Trust design |

---

## Study Resources for Exam Day

| Resource | Use |
|---|---|
| [HashiCorp Study Guide](https://developer.hashicorp.com/terraform/tutorials/certification-003/associate-study) | Official — read this front to back |
| [Bryan Krausen Practice Exam (Udemy)](https://www.udemy.com/course/terraform-associate-practice-exam/) | Best practice questions (~$15) |
| [Spacelift Cheatsheet](https://spacelift.io/blog/terraform-associate-certification) | Quick day-before review |
| `terraform --help` | Know the subcommands cold |

!!! tip "Day-before checklist"
    - [ ] `terraform init` is always first after cloning
    - [ ] State file: never delete, store remotely in teams, lock with DynamoDB
    - [ ] `for_each` > `count` for stable resource addressing
    - [ ] `create_before_destroy` for zero-downtime replacements
    - [ ] `prevent_destroy` for databases and state buckets
    - [ ] Data sources read, resources create
    - [ ] Modules: local `./modules/name`, registry `namespace/module/provider`
    - [ ] `terraform apply -replace=` replaces `terraform taint`

---

## Phase 2 Final Checklist

- [ ] **Month 4:** Flow log analyzer pushed to GitHub
- [ ] **Month 5:** Terraform VPC module with Checkov annotations in repo
- [ ] **Month 5:** Remote S3 backend configured and used
- [ ] **Month 6:** GuardDuty → SNS → EventBridge pipeline tested end-to-end
- [ ] **Month 6:** Security posture dashboard script in `scripts/`
- [ ] **Month 6:** At least 3 SCP patterns read and understood
- [ ] **Month 6:** S3 Gateway Endpoint created and verified
- [ ] All 10 exam practice questions answered without looking
- [ ] GitHub repo `iron-bank-terraform` has a clean README
- [ ] **Terraform Associate exam booked**
- [ ] **All AWS resources cleaned up — bill verified $0**

---

!!! tip "What's next: Application Security"
    Month 7 begins OWASP Top 10 — you'll install Docker, spin up OWASP Juice Shop (a deliberately vulnerable web app), and start exploiting SQL injection and XSS in a safe lab environment. Your Microsoft security background gives you a head start on understanding what the vulnerabilities mean — now you'll see exactly how they're exploited.
