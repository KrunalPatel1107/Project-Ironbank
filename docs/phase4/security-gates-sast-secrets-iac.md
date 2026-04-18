# Month 10 — Week 2: Security Gates 1–3 (SAST, Secrets, IaC)

!!! abstract "💰 Cost: $0 — GitHub Actions runs on GitHub's servers"

!!! info "Background Context"
    If you've worked in Microsoft environments: Defender for DevOps scans repos in Azure DevOps — this week you build the GitHub equivalent. Automated security gates that block a pull request from merging if it introduces vulnerable code, a hardcoded secret, or a misconfigured Terraform resource. This is the most in-demand DevSecOps skill in job postings right now.

---

## The Security Gate Concept

A **security gate** is a GitHub Actions job that runs a scan and fails (exit code ≠ 0) if issues are found. When a job fails, GitHub blocks the pull request from merging.

```
Developer pushes code → GitHub Actions runs → Gate fails → PR blocked → Fix required
                                                 ↓
                                           Gate passes → PR can merge
```

This week you add three gates:

| Gate | Tool | What it catches |
|---|---|---|
| Gate 1 | Semgrep | Insecure code patterns (SQL injection, eval(), hardcoded passwords) |
| Gate 2 | Gitleaks | Secrets committed to git (API keys, tokens, passwords) |
| Gate 3 | Checkov | Terraform misconfigurations (public S3, unencrypted EBS, missing logs) |

---

## Setup: Repository to Scan

You need a repo that has both application code and Terraform. Use your `iron-bank-security-toolkit` from Month 8, or create a fresh one:

!!! info "About the JavaScript file below"
    The `src/app.js` file you create here is a **deliberately broken test target** — a minimal JavaScript file with a known vulnerability, used only to prove that Semgrep's scanner works. You are not learning to write JavaScript, and you don't need to understand every line. The important part is the one comment-marked line (`eval(query)`) which is the bug Semgrep will catch. Think of it like putting a fake credit card number in a security test — it's just bait for the scanner.

```bash
mkdir -p ~/projects/iron-bank-pipeline/.github/workflows
cd ~/projects/iron-bank-pipeline
git init

# Create a minimal Terraform file to scan
mkdir -p terraform
cat > terraform/main.tf << 'EOF'
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Intentionally insecure S3 bucket — Checkov will catch this
resource "aws_s3_bucket" "example" {
  bucket = "iron-bank-pipeline-test"
}
# Missing: encryption, versioning, public access block, logging
EOF

# Create a minimal JavaScript file for Semgrep to scan.
# This is a TEST TARGET — it contains a known vulnerability on purpose.
# You don't need to understand JavaScript to use this file.
# The only line that matters is: eval(query)  ← this is the bug Semgrep finds.
mkdir -p src
cat > src/app.js << 'EOF'
// This is a deliberately vulnerable test file.
// Its only purpose is to give Semgrep something to find.
// You do NOT need to write or understand JavaScript — this file is just bait.

const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  const query = req.query.q;
  eval(query);   // CWE-95: INTENTIONAL VULNERABILITY — eval of user input
                 // Semgrep's "p/javascript" ruleset will catch this line
  res.send('ok');
});

app.listen(3000);
EOF

git add -A
git commit -m "Initial commit with intentional vulnerabilities"
```

Push this to a new GitHub repo called `iron-bank-pipeline`. You can create the repo on github.com first, then:

```bash
git remote add origin https://github.com/<your-username>/iron-bank-pipeline.git
git push -u origin main
```

---

## Gate 1: Semgrep SAST

Create the workflow file:

```bash
cat > .github/workflows/gate1-sast.yml << 'EOF'
# ─────────────────────────────────────────────────────────────────────────────
# Gate 1: Static Application Security Testing (SAST) with Semgrep
# Triggers: on every pull request to main
# Blocks merge: if Semgrep finds any HIGH or CRITICAL severity findings
# ─────────────────────────────────────────────────────────────────────────────
name: Gate 1 — SAST (Semgrep)

on:
  pull_request:            # Run on every PR targeting main
    branches: [main]
  push:
    branches: [main]       # Also run on direct pushes to main

jobs:
  semgrep:
    name: Semgrep SAST Scan
    runs-on: ubuntu-latest

    # Semgrep needs to check out your code
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      # actions/checkout@v4 = a pre-built action that downloads your repo
      # This is like git clone, but optimised for CI

    - name: Run Semgrep
      uses: returntocorp/semgrep-action@v1
      # This is Semgrep's official GitHub Action
      # It installs Semgrep, runs it, and fails if findings are found
      with:
        config: >-
          p/owasp-top-ten
          p/javascript
          p/python
        # p/ = "ruleset" — these are pre-built rule packs maintained by Semgrep
        # owasp-top-ten = rules covering OWASP Top 10 vulnerabilities
        # javascript + python = language-specific insecure pattern rules

    - name: Upload Semgrep results to GitHub Security tab
      if: always()    # Run this step even if Semgrep found issues (always = don't skip on failure)
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: semgrep.sarif
        category: semgrep
      # SARIF = Static Analysis Results Interchange Format
      # This uploads findings to GitHub's "Security → Code scanning alerts" tab
      # Makes findings visible in the PR review UI — much easier to triage
      continue-on-error: true   # Don't fail if SARIF upload fails (SARIF may not be generated)
EOF
```

Push and test by creating a PR that modifies `src/app.js`:

```bash
git checkout -b test/semgrep-gate
echo "// test change" >> src/app.js
git add -A
git commit -m "test: trigger semgrep gate"
git push -u origin test/semgrep-gate
# Then open a PR on GitHub → watch the Actions tab
```

**Expected result:** The PR shows a failing check called "Semgrep SAST Scan". The `eval(query)` in app.js should trigger at minimum one finding. Check Security → Code scanning alerts to see the finding in context.

---

## Gate 2: Gitleaks Secret Detection

```bash
cat > .github/workflows/gate2-secrets.yml << 'EOF'
# ─────────────────────────────────────────────────────────────────────────────
# Gate 2: Secret Detection with Gitleaks
# Triggers: on every push (not just PRs — catches secrets added to any branch)
# Blocks merge: if any secrets are found in the commit history
# ─────────────────────────────────────────────────────────────────────────────
name: Gate 2 — Secret Detection (Gitleaks)

on:
  push:             # Every push, every branch
  pull_request:
    branches: [main]

jobs:
  gitleaks:
    name: Gitleaks Secret Scan
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0    # CRITICAL: fetch the FULL git history
        # By default, actions/checkout only fetches the latest commit (depth=1)
        # Gitleaks scans the entire commit history — it needs all commits
        # fetch-depth: 0 = fetch everything (0 = unlimited)

    - name: Run Gitleaks
      uses: gitleaks/gitleaks-action@v2
      # Official Gitleaks GitHub Action
      # Scans the full commit history for secrets
      # Fails (exit 1) if any secrets are found
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        # GITHUB_TOKEN is automatically provided by GitHub for every workflow
        # Gitleaks uses it to post PR comments with findings
        # You don't need to create this secret — GitHub creates it automatically

    - name: Upload Gitleaks report
      if: failure()    # Only run this if Gitleaks found something (failure = previous step failed)
      uses: actions/upload-artifact@v4
      with:
        name: gitleaks-report
        path: results.sarif
        retention-days: 7    # Keep the report for 7 days, then GitHub deletes it
EOF
```

Test by intentionally adding a fake secret (then immediately removing it — this tests the detection):

```bash
git checkout -b test/secrets-gate
# Add a fake AWS key (Gitleaks recognises the AKIA prefix format)
echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" >> .env
git add .env
git commit -m "oops: accidentally added env file"
git push -u origin test/secrets-gate
# Gitleaks will scan the history and find the key in the commit
```

**Expected result:** Gate 2 fails. Gitleaks finds `AKIAIOSFODNN7EXAMPLE` as a potential AWS access key. The PR is blocked. To fix: remove the secret from history with `git rebase` (but for the lab, just close the PR and delete the branch).

!!! warning "Real secrets need real remediation"
    If you ever commit a real secret — rotate it immediately. Deleting the commit is not enough because GitHub caches history. Use `git filter-repo` to scrub history, but rotation is always the priority.

---

## Gate 3: Checkov IaC Scanning

```bash
cat > .github/workflows/gate3-iac.yml << 'EOF'
# ─────────────────────────────────────────────────────────────────────────────
# Gate 3: Infrastructure-as-Code Security with Checkov
# Triggers: on PRs that change Terraform files
# Blocks merge: if Checkov finds HIGH severity misconfigurations
# ─────────────────────────────────────────────────────────────────────────────
name: Gate 3 — IaC Security (Checkov)

on:
  pull_request:
    branches: [main]
    paths:
      - 'terraform/**'    # Only run this gate when Terraform files change
      - '**.tf'           # Catch any .tf file anywhere in the repo

jobs:
  checkov:
    name: Checkov IaC Scan
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Run Checkov
      uses: bridgecrewio/checkov-action@master
      # Official Checkov GitHub Action from Bridgecrew (acquired by Prisma Cloud)
      with:
        directory: terraform/          # Scan the terraform/ folder
        framework: terraform           # Tell Checkov we're scanning Terraform (not CloudFormation/K8s)
        output_format: sarif           # Output in SARIF format for GitHub integration
        output_file_path: reports/     # Save reports to this folder
        soft_fail: false               # false = fail the gate if findings found
                                       # true = report findings but don't block the PR (use for initial rollout)
        skip_check: CKV_AWS_144        # Example: skip S3 cross-region replication check (not needed in labs)
        # To skip multiple: skip_check: CKV_AWS_144,CKV_AWS_145

    - name: Upload Checkov SARIF to GitHub Security
      if: always()
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: reports/results_sarif.sarif
        category: checkov
      continue-on-error: true
EOF
```

Test with the insecure S3 bucket already in `terraform/main.tf`:

```bash
git checkout -b test/checkov-gate
echo "# test change" >> terraform/main.tf
git add -A
git commit -m "test: trigger checkov gate"
git push -u origin test/checkov-gate
# Open a PR — Checkov will scan terraform/main.tf
```

**Expected Checkov failures on `terraform/main.tf`:**

```
Check: CKV_AWS_18   — Ensure the S3 bucket has access logging enabled       → FAILED
Check: CKV_AWS_19   — Ensure the S3 bucket has server-side encryption enabled → FAILED
Check: CKV_AWS_20   — Ensure the S3 bucket does not allow PUBLIC READ access  → FAILED
Check: CKV_AWS_21   — Ensure the S3 bucket has versioning enabled             → FAILED
Check: CKV2_AWS_62  — Ensure S3 buckets use event notifications               → FAILED
```

Fix the Terraform to make Checkov pass:

```hcl
# terraform/main.tf — secure version

resource "aws_s3_bucket" "example" {
  bucket = "iron-bank-pipeline-test"
}

# Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Versioning
resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration { status = "Enabled" }
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = aws_s3_bucket.example.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Logging (needs a separate log bucket)
resource "aws_s3_bucket_logging" "example" {
  bucket        = aws_s3_bucket.example.id
  target_bucket = aws_s3_bucket.example.id   # Log to self (for lab — use a separate bucket in prod)
  target_prefix = "access-logs/"
}
```

---

## Gate 4: Database Security (SQL Injection Patterns)

SQL injection is one of the most common web vulnerabilities. While Semgrep catches some patterns, a dedicated database security gate catches more nuanced issues.

```bash
cat > .github/workflows/gate4-database.yml << 'EOF'
# ─────────────────────────────────────────────────────────────────────────────
# Gate 4: Database Security Scanning
# Detects: SQL injection patterns, unsafe queries, credential exposure
# Tools: Semgrep with database-specific rulesets
# ─────────────────────────────────────────────────────────────────────────────
name: Gate 4 — Database Security

on:
  pull_request:
    branches: [main]
    paths:
      - '**.py'           # Python files (DB queries)
      - '**.js'           # JavaScript files (DB queries)
      - 'terraform/**'    # Terraform RDS/DB resources

jobs:
  database-security:
    name: Database Security Scan
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Run database security checks
      uses: returntocorp/semgrep-action@v1
      with:
        config: >-
          p/owasp-top-ten
          p/sql-injection
          p/aws-rds
        # p/sql-injection = rules detecting SQL injection vulnerabilities
        # p/aws-rds = rules for RDS-specific security issues

    - name: Upload database findings
      if: always()
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: semgrep.sarif
        category: database-security
      continue-on-error: true

# Example vulnerable code that this gate catches:
#   ❌ BAD:  query = f"SELECT * FROM users WHERE id = {user_id}"
#           (user_id could be malicious SQL)
#
#   ✓ GOOD: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
#           (parameterized query — SQL and data separated)
EOF

git add .github/workflows/gate4-database.yml
git commit -m "Add: Gate 4 — database security scanning"
```

---

## Gate 5: API Security (OWASP API Top 10)

APIs are a common attack surface. This gate checks for OWASP API vulnerabilities.

```bash
cat > .github/workflows/gate5-api-security.yml << 'EOF'
# ─────────────────────────────────────────────────────────────────────────────
# Gate 5: API Security Scanning
# Detects: Broken authentication, object-level authorization flaws, data exposure
# Tools: Semgrep API rulesets + custom checks
# ─────────────────────────────────────────────────────────────────────────────
name: Gate 5 — API Security

on:
  pull_request:
    branches: [main]
    paths:
      - '**.py'          # Python APIs (Flask, FastAPI)
      - '**.js'          # JavaScript APIs (Express, etc.)
      - 'src/**'         # Application source

jobs:
  api-security:
    name: OWASP API Top 10 Scan
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: API security scan
      uses: returntocorp/semgrep-action@v1
      with:
        config: >-
          p/owasp-api
          p/security-audit
          p/authentication
        # p/owasp-api = OWASP API Top 10 vulnerabilities
        # p/authentication = auth bypass patterns

    - name: Report API findings
      if: always()
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: semgrep.sarif
        category: api-security
      continue-on-error: true

# Examples this gate catches:
#   ❌ API without authentication:
#      @app.get("/admin")
#      def admin():  # No login check!
#
#   ❌ Weak password validation:
#      if len(password) < 4:  # Too weak
#
#   ✓ Proper auth:
#      @app.get("/admin")
#      def admin(user = Depends(get_current_user)):  # Requires login
#        if user.role != "admin":
#          raise HTTPException(403)
EOF

git add .github/workflows/gate5-api-security.yml
git commit -m "Add: Gate 5 — API security scanning"
```

---

## Gate 6: Infrastructure & Container Scanning (Trivy)

This gate scans for vulnerabilities in container images and infrastructure configurations.

```bash
cat > .github/workflows/gate6-infrastructure.yml << 'EOF'
# ─────────────────────────────────────────────────────────────────────────────
# Gate 6: Infrastructure & Container Scanning
# Detects: Vulnerable dependencies, insecure Docker configs, image CVEs
# Tools: Trivy (comprehensive vulnerability scanner)
# ─────────────────────────────────────────────────────────────────────────────
name: Gate 6 — Infrastructure & Container Scan

on:
  pull_request:
    branches: [main]
    paths:
      - 'Dockerfile'
      - 'docker-compose.yml'
      - 'requirements.txt'
      - 'package.json'
      - 'terraform/**'

jobs:
  trivy-scan:
    name: Trivy Vulnerability Scan
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Build Docker image (if Dockerfile exists)
      if: hashFiles('Dockerfile') != ''
      run: docker build -t iron-bank:scan . || echo "Build failed, Trivy will scan Dockerfile anyway"

    - name: Run Trivy scan
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'           # fs = filesystem scan (repo files)
        scan-ref: '.'             # Scan current directory
        format: 'sarif'           # Output format for GitHub integration
        output: 'trivy-results.sarif'
        severity: 'CRITICAL,HIGH' # Only report critical and high findings

    - name: Run Trivy on Dockerfile
      if: hashFiles('Dockerfile') != ''
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'config'       # config = configuration scan (Dockerfile, K8s YAML, Terraform)
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-config.sarif'

    - name: Upload Trivy results to GitHub
      if: always()
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: trivy-results.sarif
        category: trivy-filesystem
      continue-on-error: true

    - name: Upload Trivy config scan results
      if: always() && hashFiles('trivy-config.sarif') != ''
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: trivy-config.sarif
        category: trivy-config
      continue-on-error: true

# Trivy catches:
#   ❌ OLD package versions (dependencies with known CVEs)
#      Django==2.1  (very old, many vulnerabilities)
#   ✓ CURRENT versions:
#      Django==4.2  (current stable)
#
#   ❌ Insecure Dockerfile:
#      FROM ubuntu:18.04  (old base, not patched)
#      RUN apt-get install app  (doesn't clean cache, bloats image)
#
#   ✓ Secure Dockerfile:
#      FROM ubuntu:22.04
#      RUN apt-get update && apt-get install app && apt-get clean
#
#   ❌ Insecure Terraform:
#      aws_db_instance.db {
#        publicly_accessible = true  # Exposes DB to internet!
#      }
#
#   ✓ Secure:
#      aws_db_instance.db {
#        publicly_accessible = false
#        storage_encrypted = true
#      }
EOF

git add .github/workflows/gate6-infrastructure.yml
git commit -m "Add: Gate 6 — infrastructure and container scanning"
```

Test Gate 6 by creating a test dependency file with a vulnerable package:

```bash
git checkout -b test/trivy-gate

# Create a requirements.txt with an old vulnerable package
cat > requirements.txt << 'EOF'
Django==2.1.0         # Very old, many CVEs
requests==2.6.0       # Very old, vulnerable to many attacks
Flask==0.12.0         # Old and vulnerable
EOF

git add requirements.txt
git commit -m "test: vulnerable dependencies for Trivy"
git push -u origin test/trivy-gate
# Open PR — Trivy will find many vulnerabilities
```

**Expected:** Trivy reports 50+ medium/high severity vulnerabilities in those old packages. Fix by updating:

```bash
cat > requirements.txt << 'EOF'
Django==4.2
requests==2.31.0
Flask==3.0
EOF

git add requirements.txt
git commit -m "chore: update dependencies to secure versions"
git push
# PR now passes Gate 6
```

---

## Requiring Gates to Pass Before Merge

1. Go to your repo on GitHub → **Settings** → **Branches**
2. Click **Add branch protection rule**
3. Branch name pattern: `main`
4. Check: **Require status checks to pass before merging**
5. Add each gate:
   - `Semgrep SAST Scan` (Gate 1 — code vulnerabilities)
   - `Gitleaks Secret Scan` (Gate 2 — hardcoded secrets)
   - `Checkov IaC Scan` (Gate 3 — Terraform misconfigurations)
   - `Database Security Scan` (Gate 4 — SQL injection, RDS issues)
   - `OWASP API Top 10 Scan` (Gate 5 — API vulnerabilities)
   - `Trivy Vulnerability Scan` (Gate 6 — dependencies, container, infrastructure)
6. Check: **Require branches to be up to date before merging**
7. Check: **Dismiss stale pull request approvals when new commits are pushed**
8. Save changes

Now no PR can merge to main unless **all 6 security gates pass**.

---

## 🧹 Cleanup

```bash
# No AWS resources were created this week
# If you created test branches, delete them:
git branch -d test/semgrep-gate test/secrets-gate test/checkov-gate 2>/dev/null
git push origin --delete test/semgrep-gate test/secrets-gate test/checkov-gate 2>/dev/null

echo "✅ Week 2 complete — no AWS resources, no cost"
```

---

## Checklist

### Repository Setup
- [ ] `iron-bank-pipeline` repo created on GitHub
- [ ] Source files: `src/app.js` (with `eval()` vulnerability), `requirements.txt`, `package.json`
- [ ] Terraform files: `terraform/main.tf` (insecure S3 bucket)

### Gates 1–3 (SAST, Secrets, IaC)
- [ ] Gate 1 YAML created — Semgrep runs on PRs
- [ ] Gate 2 YAML created — Gitleaks scans full git history on every push
- [ ] Gate 3 YAML created — Checkov runs only when `.tf` files change
- [ ] Test PR created for Gate 1 — Semgrep found `eval()` vulnerability
- [ ] Test PR created for Gate 2 — Gitleaks detected fake AWS key
- [ ] Test PR created for Gate 3 — Checkov listed S3 failures
- [ ] Terraform fixed to pass Checkov

### Gates 4–6 (Database, API, Infrastructure)
- [ ] Gate 4 YAML created — Database security scanning
- [ ] Gate 5 YAML created — API security scanning
- [ ] Gate 6 YAML created — Trivy infrastructure/container scanning
- [ ] Test PR created for Gate 4 — Database patterns checked
- [ ] Test PR created for Gate 5 — API security patterns checked
- [ ] Test PR created for Gate 6 — Vulnerable dependencies detected

### Branch Protection
- [ ] Branch protection enabled on `main`
- [ ] **All 6 security gates** required to pass before merge
- [ ] Status: All PRs now blocked until all gates pass ✅

### Understanding
- [ ] Understand difference between `soft_fail: true` (report only) and `false` (block)
- [ ] Know what each gate catches and why it matters
- [ ] Can explain to interviewer: "We require SAST, secrets, IaC, database, API, and infrastructure scanning on every PR"

