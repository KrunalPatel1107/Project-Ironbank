# Month 10 — Week 1: Secrets Management + GitHub Actions Basics

!!! abstract "💰 Cost: $0 — GitHub Actions: 2,000 free min/month (private repos), unlimited (public repos)"

!!! danger "CRITICAL: Secrets in CI/CD"
    This is the **most common DevSecOps vulnerability**: developers hardcoding credentials in GitHub. By the end of this week, you'll know three ways to handle secrets safely:
    1. GitHub Secrets (simple, repo-level)
    2. AWS Secrets Manager (production-grade, rotatable)
    3. OIDC token exchange (best practice, no long-lived keys)

!!! info "Background Context"
    If you've worked in Microsoft environments: Azure Key Vault + Azure DevOps Pipeline "Secrets" / "Service connections" is the equivalent of what you build here. More importantly, this week covers OIDC token exchange — the modern approach that AWS, Azure, and GCP all now recommend over long-lived credentials.

---

# PART 1: Secrets Management in CI/CD

## The Problem: Why Not Just Hardcode Credentials?

Hardcoding credentials (API keys, AWS access keys, passwords) is the quickest way to be hacked. Here's what happens:

```
1. Developer: "I'll just hardcode my AWS_ACCESS_KEY in the workflow YAML"
2. File goes to GitHub (public or private)
3. Attacker scans GitHub for secrets (tools: TruffleHog, Gitleaks)
4. Attacker finds the key, uses it to access your AWS account
5. Attacker mines cryptocurrency on your EC2 instances
6. You get a $10,000 AWS bill the next month
```

This happens **constantly**. Major companies have leaked secrets on GitHub. The solution is: **never commit credentials**. Instead, use one of three approaches below.

---

## Approach 1: GitHub Secrets (Simple, Repo-Level)

**Best for:** Personal projects, development

**How it works:**
- You store the secret in GitHub repository settings (encrypted)
- GitHub passes it as an environment variable to the workflow
- The secret never appears in logs or job output
- Each repository has its own secrets (can't share across repos)

### Step 1: Create a GitHub Secret

Go to your GitHub repository:
1. Settings → Secrets and variables → Actions → New repository secret
2. Name: `AWS_ACCESS_KEY_ID`
3. Value: `AKIA...` (your access key, if testing — **don't use real credentials!**)
4. Click "Add secret"

Repeat for any other secrets:
- `AWS_SECRET_ACCESS_KEY`
- `API_TOKEN`
- `DATABASE_PASSWORD`
- etc.

### Step 2: Use the Secret in a Workflow

```yaml
# .github/workflows/deploy.yml

name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    # Use the secret as an environment variable
    - name: Deploy with credentials
      env:
        AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
        AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
      run: |
        # AWS CLI automatically uses AWS_* env vars
        aws ec2 describe-instances --region us-east-1
```

### Why GitHub Secrets Are Okay For Now

✅ **Secrets are encrypted** at rest in GitHub  
✅ **Never logged** (if you print `$AWS_ACCESS_KEY_ID`, GitHub masks it with `***`)  
✅ **Easy to rotate** (change in settings, old one invalid)  
❌ **Limited to one repo** (can't share across multiple repos)  
❌ **Long-lived credentials** (same key forever until manually rotated)  
❌ **Not production-grade** (doesn't meet compliance requirements)

---

## Approach 2: AWS Secrets Manager (Production-Grade)

**Best for:** Production systems, compliance-required (PCI-DSS, HIPAA), credential rotation

**How it works:**
- Credentials are stored encrypted in AWS Secrets Manager (not in GitHub)
- Your CI/CD pipeline gets temporary credentials to read the secret
- Secrets can be automatically rotated (Lambda-based)
- Audit trail in CloudTrail (who accessed the secret, when)

### Step 1: Store a Secret in AWS Secrets Manager

```bash
# Create a secret in AWS
aws secretsmanager create-secret \
  --name iron-bank/github-deploy-token \
  --secret-string "$(aws sts get-session-token --duration-seconds 3600 | jq -r '.Credentials')" \
  --profile iron-bank

# Returns:
# {
#   "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:iron-bank/github-deploy-token-AbCdEf",
#   "Name": "iron-bank/github-deploy-token",
#   "VersionId": "12345678-1234-1234-1234-123456789012"
# }
```

### Step 2: Grant GitHub Access to Read the Secret

Create an IAM policy that allows reading ONLY this secret:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:iron-bank/github-deploy-token-*"
    }
  ]
}
```

### Step 3: Use in Workflow

```yaml
- name: Retrieve secret from AWS
  env:
    AWS_REGION: us-east-1
    SECRET_ARN: arn:aws:secretsmanager:us-east-1:123456789012:secret:iron-bank/github-deploy-token-AbCdEf
  run: |
    SECRET=$(aws secretsmanager get-secret-value --secret-id $SECRET_ARN --query SecretString --output text)
    echo "::add-mask::$SECRET"
    echo "DEPLOY_TOKEN=$SECRET" >> $GITHUB_ENV
```

---

## Approach 3: OIDC Token Exchange (BEST PRACTICE) ⭐

**Best for:** Everything (AWS recommends this officially)

**How it works:**
- GitHub provides a short-lived OIDC token (valid for 1 hour, specific to this workflow run)
- GitHub token is exchanged for AWS temporary credentials (STS token)
- AWS credentials expire automatically (no long-lived keys in GitHub)
- CloudTrail logs which GitHub repo, branch, commit, and workflow ran
- BEST PRACTICE for zero long-lived secrets

### Why OIDC Is Better

| Approach | Long-Lived Key | Manual Rotation | CloudTrail Link to GitHub | Cost |
|---|---|---|---|---|
| GitHub Secrets | ❌ Yes | ❌ Manual | ❌ No | Free |
| Secrets Manager | ❌ Yes | ✅ Auto | ✅ Yes | $0.40/month |
| OIDC | ✅ No (1-hour tokens) | ✅ Auto | ✅ Yes | Free |

### Step 1: Set Up OIDC Provider in AWS

Run this ONCE (creates the trust relationship):

```bash
#!/bin/bash
# Create OIDC provider (allows GitHub to request AWS credentials)
# This is a one-time setup per AWS account

aws iam create-open-id-connect-provider \
  --url "https://token.actions.githubusercontent.com" \
  --client-id-list "sts.amazonaws.com" \
  --thumbprint-list "6938fd4d98bab03faadb97b34396831e3780aea1" \
  --profile iron-bank \
  2>/dev/null || echo "OIDC provider already exists"

echo "✓ OIDC provider created/exists"
```

### Step 2: Create IAM Role for GitHub

```bash
#!/bin/bash
# Script: Create IAM role that GitHub workflows can assume

GITHUB_ORG="YOUR_GITHUB_USERNAME"  # e.g., "your-github-username"
GITHUB_REPO="iron-bank-pipeline"    # Your repository name

# Create the role with trust policy
cat > /tmp/github-trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::\$(aws sts get-caller-identity --query Account --output text):oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:$GITHUB_ORG/$GITHUB_REPO:*"
        }
      }
    }
  ]
}
EOF

# Create the role
aws iam create-role \
  --role-name github-iron-bank-deploy \
  --assume-role-policy-document file:///tmp/github-trust-policy.json \
  --profile iron-bank

# Attach a policy that allows the role to deploy
aws iam attach-role-policy \
  --role-name github-iron-bank-deploy \
  --policy-arn arn:aws:iam::aws:policy/EC2FullAccess \
  --profile iron-bank

echo "✓ IAM role created: github-iron-bank-deploy"
echo "✓ Role ARN: arn:aws:iam::\$(aws sts get-caller-identity --query Account --output text):role/github-iron-bank-deploy"
```

### Step 3: Use OIDC in Your Workflow

Create `.github/workflows/deploy-with-oidc.yml`:

```yaml
name: Deploy with OIDC (No Long-Lived Keys)

on:
  push:
    branches: [main]

permissions:
  id-token: write  # ← CRITICAL: allows GitHub to provide OIDC token
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    # Step 1: Request OIDC token from GitHub (valid 1 hour)
    - name: Request OIDC token
      id: oidc
      uses: aws-actions/configure-aws-credentials@v2
      with:
        role-to-assume: arn:aws:iam::123456789012:role/github-iron-bank-deploy
        aws-region: us-east-1
    
    # Step 2: Use temporary AWS credentials (auto-provided by Step 1)
    - name: Deploy infrastructure
      run: |
        # AWS credentials are automatically available in the environment
        # (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
        # They expire automatically in 1 hour
        
        aws ec2 describe-instances --region us-east-1
        aws sts get-caller-identity  # Verify credentials work
```

### Why This Is Better

- ✅ **No long-lived keys**: GitHub doesn't have your AWS access key forever
- ✅ **Automatic expiration**: Token valid only for 1 hour (the job duration)
- ✅ **Audit trail**: CloudTrail shows which GitHub repo/branch/commit accessed AWS
- ✅ **Zero manual rotation**: New token generated on every job run
- ✅ **Compliance**: Meets PCI-DSS, HIPAA, SOC 2 requirements for temporary credentials

---

## Lab: Set Up OIDC (Step-by-Step)

### Step 1: Create the OIDC Provider

Save and run `scripts/setup-github-oidc.sh`:

```bash
chmod +x scripts/setup-github-oidc.sh
./scripts/setup-github-oidc.sh YOUR_GITHUB_USERNAME iron-bank-pipeline us-east-1
```

### Step 2: Create the IAM Role

The script above creates the role automatically. Verify:

```bash
aws iam get-role --role-name github-iron-bank-deploy --profile iron-bank
```

### Step 3: Add the Workflow File

Create `.github/workflows/oidc-test.yml` in your GitHub repository:

```yaml
name: Test OIDC

on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    - name: Configure AWS credentials via OIDC
      uses: aws-actions/configure-aws-credentials@v2
      with:
        role-to-assume: arn:aws:iam::123456789012:role/github-iron-bank-deploy
        aws-region: us-east-1
    
    - name: Verify OIDC worked
      run: |
        aws sts get-caller-identity
        aws ec2 describe-instances --max-results 1 || echo "No instances"
```

### Step 4: Push and Watch

```bash
git add .github/workflows/oidc-test.yml
git commit -m "Add OIDC test workflow"
git push
```

Then on GitHub → Actions tab → You'll see the workflow run and succeed (or fail with a clear error).

---

## Secrets Best Practices Checklist

- [ ] No credentials hardcoded in .yml, .tf, .py, or config files
- [ ] Each credential stored in ONE place (GitHub Secrets, Secrets Manager, or OIDC)
- [ ] Credentials rotated at least every 90 days (or auto-rotated by Secrets Manager)
- [ ] Credentials are minimal scope (e.g., EC2-only, not AdministratorAccess)
- [ ] CloudTrail logging enabled (audit trail of who accessed what)
- [ ] Using OIDC for AWS credentials (not long-lived access keys)
- [ ] Gitleaks enabled in your pipeline (detects accidental secret commits)

---

# PART 2: GitHub Actions Basics

Now that you understand secrets management, let's build your first workflow.

---

## What is GitHub Actions?

GitHub Actions is a workflow automation platform built directly into GitHub. Every time something happens in your repository (a push, a pull request, a schedule), GitHub spins up a fresh Ubuntu virtual machine, runs the commands you define in a YAML file, and reports pass/fail back to the PR.

```
You push code
    ↓
GitHub detects the trigger (push, PR, schedule...)
    ↓
GitHub spins up a free Ubuntu VM ("runner")
    ↓
Runner executes your YAML steps top-to-bottom
    ↓
Green checkmark ✅ (all steps exit 0) OR Red X ❌ (any step exits non-zero)
    ↓
Result appears on your PR / commit page
```

**Why this matters for security:** In weeks 2–4 you'll add security scanners as steps. If a scanner finds a vulnerability, the step exits with code 1 → the whole workflow fails → GitHub blocks the PR from merging. This is "shift-left security" — catching problems before code reaches production.

??? note "Microsoft equivalent: Azure DevOps Pipelines"
    Azure DevOps Pipelines (`azure-pipelines.yml`) is almost identical in concept:

    | Azure DevOps | GitHub Actions |
    |---|---|
    | Pipeline | Workflow |
    | Stage | Job |
    | Task | Step |
    | Agent pool | `runs-on` |
    | Service connection | Secret |
    | Pipeline trigger | `on:` |

    If you've read an `azure-pipelines.yml`, you can read a GitHub Actions YAML immediately.

---

## Anatomy of a Workflow File

All workflow files live in `.github/workflows/` in your repository. The filename doesn't matter — the `name:` field inside is what shows up in the Actions tab.

```yaml
# .github/workflows/hello.yml

name: My First Workflow           # What you see in the GitHub Actions UI

on:                               # TRIGGER: when does this run?
  push:                           #   on every push...
    branches: [main]              #   ...but only to the main branch

jobs:                             # JOBS: groups of steps that run on a VM
  greet:                          #   job name (you choose this)
    runs-on: ubuntu-latest        #   which VM to use (GitHub provides it free)

    steps:                        # STEPS: commands that run in sequence
    - name: Say hello             #   step name (shown in the UI)
      run: echo "Hello, world!"   #   the shell command to run

    - name: Show system info
      run: |                      #   the | means "multi-line command"
        echo "OS: $(uname -a)"
        echo "User: $(whoami)"
        echo "Python: $(python3 --version)"
        echo "Node: $(node --version)"
```

??? note "YAML indentation rules — read this if YAML is new to you"
    YAML is very sensitive to indentation. Rules:

    - Always use **spaces**, never tabs
    - Each level of nesting = **2 spaces** deeper
    - If a line is indented wrong, the whole workflow fails to parse

    ```yaml
    jobs:          # level 0
      greet:       # level 1 (2 spaces)
        runs-on:   # level 2 (4 spaces)
        steps:     # level 2 (4 spaces)
        - name:    # level 2 list item (4 spaces + dash)
          run:     # level 3 (6 spaces)
    ```

    If your workflow never shows up in the Actions tab, the most common cause is a YAML parse error. Check the red X on your commit on GitHub — it will show the exact line number.

---

## Your First Workflow

### Step 1: Create the workflow file

```bash
# In any GitHub repository on your machine:
mkdir -p .github/workflows

cat > .github/workflows/hello.yml << 'EOF'
name: My First Workflow

on:
  push:
    branches: [main]

jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
    - name: Say hello
      run: echo "Hello from GitHub Actions!"

    - name: Show system info
      run: |
        echo "OS: $(uname -a)"
        echo "User: $(whoami)"
        echo "Python: $(python3 --version)"
        echo "Node: $(node --version)"
        echo "Working directory: $(pwd)"
        echo "Disk space: $(df -h / | tail -1)"
EOF
```

### Step 2: Push and watch it run

```bash
git add .github/workflows/hello.yml
git commit -m "Add first GitHub Actions workflow"
git push
```

Then on GitHub:

1. Go to your repository → click the **Actions** tab
2. You'll see "My First Workflow" running (orange spinner)
3. Click on the run → click on the job name → expand each step
4. You can see every line of output in real time

---

## Triggers (`on:`) — The Most Important Concept

The `on:` block controls *when* your workflow fires. You'll use all of these in weeks 2–4.

```yaml
on:
  push:                       # Every push to any branch
    branches: [main]          #   (narrow it to main only)

  pull_request:               # When a PR is opened or updated
    branches: [main]          #   targeting main

  schedule:                   # Run on a timer (cron syntax)
    - cron: '0 9 * * 1'      #   Every Monday at 9:00 AM UTC

  workflow_dispatch:          # Manual trigger — adds a "Run workflow" button in the UI
```

??? note "Cron syntax quick reference"
    ```
    ┌── minute (0–59)
    │  ┌── hour (0–23, UTC)
    │  │  ┌── day of month (1–31)
    │  │  │  ┌── month (1–12)
    │  │  │  │  ┌── day of week (0=Sun, 1=Mon ... 6=Sat)
    │  │  │  │  │
    0  9  *  *  1    →  Every Monday at 9:00 AM UTC
    0  0  *  *  *    →  Every day at midnight UTC
    */15 * * * *     →  Every 15 minutes
    0  8  *  *  1-5  →  Weekdays at 8:00 AM UTC
    ```

    **The catch:** GitHub Actions cron uses UTC. If you're in Eastern Time (UTC-4 in summer), 9:00 AM UTC = 5:00 AM your time. Adjust accordingly.

**Which trigger to use for security gates?**

```yaml
on:
  pull_request:         # ← use this for security gates
    branches: [main]    #   runs when someone opens a PR targeting main
                        #   if the gate fails, GitHub blocks the merge
```

Pull request triggers are used for gates (not `push`) because:

- Gates run *before* the code merges — that's the whole point
- If you use `push` instead, bad code is already on main by the time the gate runs

---

## Jobs and Steps in Depth

### Multiple jobs

Jobs run **in parallel by default**. This is useful for running independent checks simultaneously:

```yaml
jobs:
  lint:                         # job 1: runs at the same time as job 2
    runs-on: ubuntu-latest
    steps:
    - run: echo "Linting..."

  test:                         # job 2: runs at the same time as job 1
    runs-on: ubuntu-latest
    steps:
    - run: echo "Testing..."
```

### Making jobs run in sequence (`needs:`)

If job B requires job A to succeed first, use `needs:`:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - run: echo "Building the Docker image..."

  scan:
    runs-on: ubuntu-latest
    needs: build               # ← scan only runs if build succeeds
    steps:
    - run: echo "Scanning the image..."

  deploy:
    runs-on: ubuntu-latest
    needs: scan                # ← deploy only runs if scan succeeds
    steps:
    - run: echo "Deploying..."
```

This is exactly how the Month 10 pipeline is structured: Build → Scan → Deploy.

### Checking out your code

By default, the Ubuntu VM has no files on it — it's a blank machine. You need to explicitly check out your repository using a pre-built "action":

```yaml
steps:
- name: Check out repository
  uses: actions/checkout@v4    # ← this is a pre-built action from GitHub
                               #   v4 = version 4 (always pin a version)
```

`uses:` runs a pre-packaged action instead of a raw shell command. `actions/checkout` is maintained by GitHub itself and clones your repo onto the runner VM.

---

## Environment Variables and Secrets

### Plain environment variables

Pass values into your steps using `env:`:

```yaml
jobs:
  example:
    runs-on: ubuntu-latest
    env:
      APP_ENV: production         # available to ALL steps in this job
    steps:
    - name: Use the variable
      run: echo "Running in $APP_ENV"

    - name: Step-level env var
      env:
        STEP_ONLY: hello          # only available in THIS step
      run: echo "$STEP_ONLY"
```

### Secrets (for API keys, tokens, passwords)

Never hardcode secrets in YAML files — they'd be visible in your git history. Store them in GitHub and reference them as `${{ secrets.NAME }}`:

```bash
# On GitHub: Settings → Secrets and variables → Actions → New repository secret
# Name: AWS_ACCESS_KEY_ID
# Value: AKIAIOSFODNN7EXAMPLE
```

```yaml
steps:
- name: Configure AWS credentials
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}         # pulled from GitHub Secrets
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }} # never visible in logs
    AWS_DEFAULT_REGION: us-east-1
  run: aws sts get-caller-identity --profile iron-bank
```

!!! warning "Secrets are masked in logs"
    If a step accidentally tries to print a secret value, GitHub replaces it with `***` in the log output. This is a safety feature — but it's not a reason to be careless. Never intentionally echo a secret.

---

## A Practical Workflow: Lint + Test

This is a realistic workflow that checks out code, sets up a language, and runs checks. You'll extend this pattern in weeks 2–4 by adding security tools.

```yaml
# .github/workflows/ci.yml
name: CI

on:
  pull_request:
    branches: [main]

jobs:
  quality:
    runs-on: ubuntu-latest

    steps:
    # Step 1: Get your code onto the VM
    - name: Check out code
      uses: actions/checkout@v4

    # Step 2: Install Python (the runner has Python pre-installed,
    #         but this pins a specific version so it's reproducible)
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: "3.11"

    # Step 3: Install your project's dependencies
    - name: Install dependencies
      run: |
        pip install --upgrade pip
        pip install flake8 pytest     # linter + test runner

    # Step 4: Run the linter — if any style error exists, this exits non-zero
    #         and the workflow fails, blocking the PR
    - name: Lint with flake8
      run: flake8 . --max-line-length=120

    # Step 5: Run tests — same concept
    - name: Run tests
      run: pytest tests/ -v
```

Push this to a PR and watch the Actions tab — you'll see each step tick green or red in real time.

---

## Reading Workflow Results

After a workflow runs, you can read the result in three places:

**1. The Actions tab (full logs)**

Repository → Actions → click a run → click a job → expand any step to see its full terminal output.

**2. On the PR page (status checks)**

When you open a PR, you'll see status checks at the bottom:

```
✅ CI / quality (pull_request)   — All checks have passed
❌ CI / quality (pull_request)   — 1 check failed
```

If a required check fails, GitHub shows "Merging is blocked" and greys out the merge button.

**3. On the commit itself**

Every commit has a small dot next to it (green ✅, red ❌, orange 🟡) showing its workflow status. Click it to jump straight to the run.

---

## Common Errors and Fixes

| Error | What it means | Fix |
|---|---|---|
| `YAML parse error at line N` | Indentation is wrong | Count your spaces — must be multiples of 2 |
| `Process completed with exit code 1` | A `run:` command failed | Click the step to see the actual error message |
| `Error: Unable to locate executable file` | Tool not installed on runner | Add an install step before using the tool |
| Workflow doesn't appear in Actions tab | YAML syntax error prevents parsing | Go to the commit → click the red X → see parse error |
| `Context access might be invalid: secrets.NAME` | Secret name typo | Check Settings → Secrets — names are case-sensitive |
| Workflow runs on push but not on PR | Wrong trigger configured | Change `on: push` to `on: pull_request` |

---

## Matrix Builds (Optional — Read Now, Use Later)

A **matrix** runs the same job multiple times with different inputs — useful for testing against multiple Python or Node versions:

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.9", "3.10", "3.11"]  # runs the job 3 times in parallel

    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
      with:
        python-version: ${{ matrix.python-version }}  # uses the current matrix value
    - run: python --version
```

You won't need matrix builds for the security pipeline, but knowing it exists is useful for future interviews.

---

## The `iron-bank-pipeline` Repository

Starting this week, all Month 10 work lives in a dedicated repository. Create it now:

```bash
mkdir -p ~/projects/iron-bank-pipeline/.github/workflows
cd ~/projects/iron-bank-pipeline
git init

# Create a placeholder workflow
cat > .github/workflows/ci.yml << 'EOF'
name: Iron Bank CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  hello:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Confirm checkout
      run: |
        echo "Repository: $GITHUB_REPOSITORY"
        echo "Branch: $GITHUB_REF_NAME"
        echo "Commit: $GITHUB_SHA"
        echo "Files checked out:"
        ls -la
EOF

# Create a minimal README
cat > README.md << 'EOF'
# Iron Bank Pipeline

DevSecOps CI/CD pipeline with 5 automated security gates.

| Gate | Tool | Catches |
|---|---|---|
| 1 | Semgrep | Insecure code patterns |
| 2 | Gitleaks | Committed secrets |
| 3 | Checkov | IaC misconfigurations |
| 4 | Trivy | Container CVEs |
| 5 | OWASP ZAP | Runtime web vulnerabilities |
EOF

git add -A
git commit -m "Initial iron-bank-pipeline setup"
```

Then create a new repository on GitHub named `iron-bank-pipeline` and push:

```bash
git remote add origin https://github.com/<your-username>/iron-bank-pipeline.git
git branch -M main
git push -u origin main
```

Go to the **Actions** tab — you should see `Iron Bank CI` running. Click in and verify it shows your files in the `ls -la` output.

---

## 🧹 Cleanup

Nothing to clean up — GitHub Actions runs on GitHub's servers, not yours. No AWS resources were created this week.

---

## Week 1 Summary

| Concept | What you learned |
|---|---|
| Workflow file | `.github/workflows/*.yml` — YAML defining triggers + jobs + steps |
| `on:` | What triggers the workflow: `push`, `pull_request`, `schedule`, `workflow_dispatch` |
| `jobs:` | Groups of steps that run on a fresh Ubuntu VM |
| `runs-on:` | Which VM type (always `ubuntu-latest` for security tools) |
| `steps:` | Individual commands — run top-to-bottom, stop on first failure |
| `uses:` | Pre-built actions (e.g. `actions/checkout@v4`) |
| `run:` | Raw shell commands |
| `env:` | Environment variables passed into steps |
| `secrets.*` | Sensitive values stored in GitHub, never visible in logs |
| `needs:` | Makes jobs run in sequence instead of parallel |

---

## Checklist

- [ ] Created `.github/workflows/hello.yml` — watched it run in the Actions tab
- [ ] Can explain: `on:`, `jobs:`, `runs-on:`, `steps:`, `uses:`, `run:`
- [ ] Know the difference between `push` and `pull_request` triggers — and which one to use for security gates
- [ ] `iron-bank-pipeline` repo created on GitHub, initial workflow running green
- [ ] Can find workflow results in: Actions tab, PR status checks, commit dot
- [ ] Know how to store a secret in GitHub Settings and reference it as `${{ secrets.NAME }}`
- [ ] Understand `needs:` for sequential jobs
- [ ] Ready for Week 2: adding Semgrep, Gitleaks, and Checkov as security gates
