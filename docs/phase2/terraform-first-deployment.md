# Month 5 — Week 1: First Terraform Deployment

!!! abstract "💰 Cost: $0 — S3 bucket only (5GB free)"

## Your First `.tf` File

```bash
mkdir -p ~/projects/iron-bank-tf && cd ~/projects/iron-bank-tf
```

Create `main.tf`:

```hcl
# Tell Terraform we're using AWS
provider "aws" {
  region  = "us-east-1"
  profile = "iron-bank"
}

# Create an S3 bucket with encryption
resource "aws_s3_bucket" "vault" {
  bucket_prefix = "iron-bank-tf-"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "enc" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## The Terraform Workflow

```bash
# STEP 1: Initialize (downloads the AWS plugin for Terraform)
terraform init
# Creates a .terraform/ folder with the plugin files Terraform needs.
# Think of it like: "set up the tools before building anything"

# STEP 2: Security scan BEFORE deploying
checkov -d .
# Checks your .tf files for misconfigurations

# STEP 3: Preview (shows what WILL be created, creates NOTHING)
terraform plan

# STEP 4: Deploy (actually creates resources)
terraform apply
# Type "yes" when prompted
# Creates terraform.tfstate — NEVER delete this file!
```

??? note "What is terraform.tfstate?"
    The state file maps your code to real AWS resources. It says "aws_s3_bucket.vault = s3://iron-bank-tf-abc123". If you delete it, Terraform can't manage or destroy those resources. Treat it like a database.

## 🧹 Cleanup (The Beauty of Terraform!)

```bash
# One command destroys everything Terraform created:
terraform destroy
# Type "yes" — Terraform reads state and deletes in reverse order

# Verify
aws s3 ls --profile iron-bank    # Bucket should be gone
```

!!! tip "This is why Terraform beats CLI commands"
    With CLI, you have to remember every resource you created and delete them in the right order. With Terraform, `terraform destroy` handles everything automatically. You'll never forget to clean up a resource.

## Checklist

- [ ] Created `main.tf` with provider and S3 resource
- [ ] Ran `terraform init` successfully
- [ ] Ran `checkov -d .` — all checks pass
- [ ] Ran `terraform plan` — shows 3 resources to create
- [ ] Ran `terraform apply` — bucket created in AWS
- [ ] Understand `terraform.tfstate` (what it is, why never delete)
- [ ] Ran `terraform destroy` — bucket deleted
- [ ] Verified cleanup in AWS Console
