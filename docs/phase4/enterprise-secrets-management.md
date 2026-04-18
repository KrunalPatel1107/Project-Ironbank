# Month 10 — Special: Enterprise Secrets Management (Advanced)

!!! abstract "💰 Cost: $0-10/month — HashiCorp Vault free tier, AWS Secrets Manager (pay per secret)"

!!! danger "Why Enterprise Secrets Management Matters"
    Phase 4 m10-week1 covered GitHub Secrets and AWS Secrets Manager basics. But as your infrastructure scales (10+ services, 100+ developers, multi-cloud), managing secrets becomes complex: **rotation policies, audit trails, secret discovery, least privilege access**. A leaked database password costs $200K+ to remediate. Enterprise secret management automates rotation, enforces access policies, and detects compromised credentials in real time.

!!! info "Background Context"
    You've learned to avoid hardcoding secrets (Phase 3 SDLC), use Secrets Manager in CI/CD (Phase 4 m10), and implement Zero Trust (Phase 4 m11). This extension deepens your understanding: HashiCorp Vault for complex scenarios, automated rotation, detection of leaked secrets, and compliance (SOC2, PCI-DSS require secret rotation every 90 days).

---

## Part 1: HashiCorp Vault (Self-Hosted Secret Management)

**Vault** is a professional-grade secret management system used by Fortune 500 companies.

### Vault Concepts

```
Vault Architecture:
┌─────────────────────────────────────────┐
│         Unseal Key 1 / 2 / 3            │  Stored offline, offline backup
├─────────────────────────────────────────┤
│       Vault Sealed Database              │  Encrypted at rest
│  (root tokens, secrets, policies)        │  Requires threshold of keys to unlock
├─────────────────────────────────────────┤
│     Mount Points (Auth Methods)          │
│  - Kubernetes (pod identity)             │  K8s ServiceAccount → JWT
│  - AWS (EC2 instance role)               │  IAM role → Vault credentials
│  - OIDC (GitHub Actions, SAML)           │  GitHub OIDC token → Vault creds
├─────────────────────────────────────────┤
│     Secret Engines                       │
│  - kv (key-value storage)                │
│  - database (rotate DB passwords)        │
│  - pki (issue certs)                     │
│  - transit (data encryption)             │
└─────────────────────────────────────────┘

Key Principle: UNSEAL KEY SEPARATION
- Key 1, 2, 3 held by different people (split knowledge)
- Quorum of 2 keys needed to unseal Vault
- No single person can access all secrets
```

### Lab: Deploy Vault Locally (Docker)

```bash
# Run Vault in dev mode (for testing only — not production)
docker run --cap-add=IPC_LOCK \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' \
  -p 8200:8200 \
  vault:latest

# In another terminal, authenticate
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='myroot'

# Write a secret
vault kv put secret/database/prod \
  username=admin \
  password='SuperSecret123!'

# Read the secret
vault kv get secret/database/prod
# Output:
# ===== Secret Path =====
# secret/database/prod
#
# ======= Metadata =======
# Key                Value
# ---                -----
# created_time       2024-01-15T10:30:00Z
# deletion_time      n/a
# destroyed          false
# version            1
#
# ====== Data ======
# Key         Value
# ---         -----
# username    admin
# password    SuperSecret123!

# List all secrets
vault kv list secret/database/

# Rotate a secret (overwrite with new value)
vault kv put secret/database/prod \
  username=admin \
  password='NewPassword456!'
# Note: Old version still accessible (versioning enabled by default)

# View secret history
vault kv metadata get secret/database/prod
```

### Vault in Production: HA Setup

```bash
# Vault production typically deployed on Kubernetes with HA backend

# 1. Unseal keys are backed up in separate secure storage
# 2. Multiple Vault instances run (3-5 replicas)
# 3. Database backend for HA (PostgreSQL, etcd)
# 4. TLS for all communication (Vault to clients, Vault to Vault)

# Example: Vault on K8s with Helm
helm repo add hashicorp https://helm.releases.hashicorp.com
helm install vault hashicorp/vault \
  --set server.ha.enabled=true \
  --set server.ha.replicas=3 \
  --set server.dataStorage.size=10Gi \
  --set server.auditStorage.size=10Gi

# Unsealing (manual process, quarterly)
# Step 1: Get unseal keys (stored in offline vault/HSM)
# Step 2: SSH to Vault server, run:
vault operator unseal KEY1
vault operator unseal KEY2
vault operator unseal KEY3
# Vault now operational
```

---

## Part 2: Automated Secret Rotation

**Rotation** is the most important secret hygiene: every 90 days, change all database passwords, API keys, certificates.

### Database Password Rotation with Vault

```bash
# Vault can auto-rotate database passwords using Vault's Database Engine

# 1. Enable Database Engine
vault secrets enable database

# 2. Configure PostgreSQL connection
vault write database/config/postgresql \
  plugin_name=postgresql-database-plugin \
  allowed_roles="readonly" \
  connection_url="postgresql://vaultadmin:vaultpassword@postgres.example.com:5432/mydb" \
  username="vaultadmin" \
  password="vaultpassword"

# 3. Create a rotating role (rotates password every 30 days)
vault write database/roles/readonly \
  db_name=postgresql \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';" \
  default_ttl="24h" \
  max_ttl="720h" \
  rotation_statements="ALTER USER \"{{name}}\" WITH PASSWORD '{{password}}';"

# 4. Application reads credentials from Vault
# (Vault auto-rotates the password in the background)

vault read database/creds/readonly
# Output:
# Key                Value
# ---                -----
# lease_duration     24h
# lease_id           database/creds/readonly/hvs.CAESIIhp...
# password           <NEW_ROTATING_PASSWORD>
# username           v-readonly-<RANDOM>

# Every 30 days, Vault:
# 1. Generates a new password
# 2. Updates the database
# 3. Revokes the old password
# (Application's lease expires, must request new credentials)
```

### Certificate Rotation with Vault PKI

```bash
# Vault can issue and rotate TLS certificates

# 1. Enable PKI engine
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki

# 2. Generate root CA (self-signed)
vault write -field=certificate pki/root/generate/internal \
  common_name="mycompany.com" \
  ttl=87600h > root_ca.crt

# 3. Create a certificate role
vault write pki/roles/example-dot-com \
  allowed_domains="mycompany.com,*.mycompany.com" \
  allow_subdomains=true \
  max_ttl="720h"

# 4. Issue a certificate
vault write pki/issue/example-dot-com \
  common_name="api.mycompany.com" \
  ttl="24h"

# Output: certificate valid for 24 hours
# Your load balancer/nginx reads the cert from Vault
# When TTL expires, Vault automatically revokes it
# Application must request a new certificate
```

### Rotation Policy Enforcement

```bash
cat > ~/rotation-policy.md << 'EOF'
# Secret Rotation Policy

## Rotation Schedule

| Secret Type | Rotation Interval | Responsibility |
|---|---|---|
| Database password | 30 days | Vault auto-rotation |
| API key (external services) | 90 days | Manual + alerts |
| TLS certificate | 30 days (before expiry) | Vault + cert-manager |
| SSH key pair | 180 days | Manual, with audit |
| Slack/GitHub bot tokens | 180 days | Manual, with audit |
| Root AWS access key | Never (disable root) | Disable after creation |

## Rotation Process

1. **Before rotation:** Alert team, schedule maintenance window
2. **During rotation:** Generate new secret, test in staging
3. **Deploy:** Update all consumers of the secret simultaneously
4. **Verify:** Confirm app is using new secret (check logs)
5. **Revoke:** Disable old secret (don't delete, might need to recover)

## Audit Trail

Every rotation is logged:
```
2024-01-15T14:30:00Z: Database password rotated
  - Old: vaultadmin / (redacted)
  - New: v-readonly-abc123def456 / (new password in Vault)
  - Reason: Automatic (30-day TTL)
  - Action: revoked old role

2024-01-15T14:35:00Z: Application received new credentials
  - Source: application-name/production
  - Secret: database/creds/readonly
  - IP: 10.0.2.100
  - Status: success
```
EOF

cat ~/rotation-policy.md
```

---

## Part 3: Detecting Leaked Secrets in Code

**Secret scanning** catches credentials that developers accidentally commit to git.

### Tools for Detecting Leaked Secrets

| Tool | Coverage | Type | When to Use |
|---|---|---|---|
| **gitleaks** | Git history | CLI | Pre-commit, CI/CD |
| **GitHub Secret Scanning** | GitHub native | Cloud | GitHub Enterprise |
| **Snyk** | Supply chain | SaaS | Dependencies + secrets |
| **AWS IAM Access Analyzer** | AWS resources | Cloud | AWS accounts |
| **TruffleHog** | Git history + web | CLI/API | Comprehensive scanning |

### Lab: Scan for Leaked Secrets with gitleaks

```bash
# Install gitleaks
pip install gitleaks --break-system-packages

# Or use Docker
docker run zricethezav/gitleaks:latest

# Scan git history
gitleaks detect --source . --verbose

# Output:
# Finding:
#   Description: AWS Manager ID
#   File: src/config.py
#   Secret: AKIAIOSFODNN7EXAMPLE
#   Match: aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
#   Commit: abc123def456
#   Author: john@example.com
#   Date: 2024-01-15

# Scan a remote repo
gitleaks detect --source https://github.com/my-org/my-repo.git --verbose

# Generate report
gitleaks detect --source . --report-path gitleaks-report.json

# Setup pre-commit hook (prevent commits with secrets)
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
EOF

pre-commit install
# Now, gitleaks runs on every commit — blocks if secret found
```

### Secrets Scanning in GitHub Actions

```yaml
# GitHub Actions: Automated secret scanning

name: Secrets Scanning

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  secrets-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Scan entire history

      - name: Run gitleaks
        uses: gitleaks/gitleaks-action@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Check for secrets in code
        run: |
          # Scan source code (current files, not history)
          gitleaks detect --source . --verbose --no-git

      - name: Fail if secrets found
        if: failure()
        run: |
          echo "❌ Secrets detected! Do not commit credentials."
          exit 1
```

---

## Part 4: Secrets Scanning in Terraform

Terraform files often contain secrets (database passwords, API keys). Scan before deploying.

### Lab: Scan Terraform for Hardcoded Secrets

```bash
cat > ~/main.tf << 'EOF'
# BAD: Hardcoded database password
resource "aws_db_instance" "prod" {
  allocated_storage    = 20
  engine               = "postgres"
  engine_version       = "14.0"
  instance_class       = "db.t3.micro"
  db_name              = "mydb"
  username             = "admin"
  password             = "SuperSecret123!"  # ❌ LEAKED!
  publicly_accessible  = false
  skip_final_snapshot  = false
}

# BAD: Hardcoded API key
resource "aws_lambda_function" "api_caller" {
  filename      = "lambda.zip"
  function_name = "api-caller"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  environment {
    variables = {
      API_KEY = "sk_live_abc123def456"  # ❌ LEAKED!
    }
  }
}
EOF

# Scan with tfsec
pip install tfsec --break-system-packages

tfsec . --format sarif > tfsec-report.json

# Output:
# resource.aws_db_instance.prod:
#   Password is hardcoded
#   Recommendation: Use Secrets Manager or Vault, reference via data block

# Fix: Use Secrets Manager instead
cat > ~/main-fixed.tf << 'EOF'
# GOOD: Password from Secrets Manager
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
}

resource "aws_db_instance" "prod" {
  allocated_storage    = 20
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  username             = "admin"
  password             = data.aws_secretsmanager_secret_version.db_password.secret_string
  publicly_accessible  = false
  skip_final_snapshot  = false
}
EOF

# Verify fix
tfsec . --format sarif
# ✅ No hardcoded secrets found
```

---

## Part 5: Credential Vending (Just-In-Time Access)

**Credential vending** = issuing temporary credentials on-demand, with automatic expiration.

### Example: AWS STS AssumeRole (Credential Vending)

```bash
# Instead of storing long-lived AWS keys, use temporary credentials

# Application needs access to S3
# Old way: Store AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY in config (LEAKED!)
# New way: Use STS AssumeRole to get temporary credentials (15 min expiry)

# Step 1: Application (in EC2/Lambda/Container) has IAM role attached
# Step 2: Application calls AWS STS AssumeRole
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT:role/app-role \
  --role-session-name app-session

# Output:
# {
#   "Credentials": {
#     "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
#     "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
#     "SessionToken": "AQoDYXdzEJr...",
#     "Expiration": "2024-01-15T14:45:00Z"  ← 15 min from now
#   }
# }

# Step 3: App uses temporary credentials (auto-refresh when expired)
# SDK (boto3, AWS SDK JS) handles refresh automatically
```

### Example: Vault Credential Vending (Kubernetes)

```bash
# In Kubernetes, Vault can issue temporary credentials per pod

# 1. Pod starts, has ServiceAccount attached
# 2. Vault Kubernetes auth method verifies pod identity
# 3. Vault issues temporary token + secret credentials
# 4. Pod stores credentials in memory (NEVER on disk)
# 5. Credentials auto-revoke when pod terminates

# Config example
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp
  namespace: default
---
apiVersion: v1
kind: Pod
metadata:
  name: myapp-pod
spec:
  serviceAccountName: myapp
  containers:
  - name: myapp
    image: myapp:latest
    env:
    - name: VAULT_ADDR
      value: "http://vault.vault.svc:8200"
    - name: VAULT_ROLE
      value: "myapp"
    volumeMounts:
    - name: vault-token
      mountPath: /var/run/secrets/vault
  volumes:
  - name: vault-token
    projected:
      sources:
      - serviceAccountToken:
          audience: vault
          expirationSeconds: 3600
          path: token

# Pod can now read JWT token from /var/run/secrets/vault/token
# Use token to authenticate to Vault, get temporary credentials
```

---

## Part 6: Write a Secrets Management Finding

```bash
cat > ~/secrets-finding.md << 'EOF'
# Finding: Long-Lived Secrets (API Keys) Without Rotation — Compromise Risk

**Severity:** Critical  
**Component:** Infrastructure (Secrets Management)  

## Description
API keys for external services (Slack, GitHub, Stripe) are stored in AWS Secrets Manager, but rotation is manual and infrequent (if ever). A compromised key could grant attackers access to sensitive integrations for months before detection.

## Evidence
- Last rotation: GitHub API key rotated 18 months ago
- No automated rotation: Secrets are marked "do not rotate"
- No audit trail: Cannot determine when key was accessed
- No monitoring: No alerts if key is used from unauthorized location

## Risk Scenario
1. Attacker finds GitHub API key in git history (or phishes dev)
2. Attacker uses key to push malicious code to production
3. Malicious code runs in production for 2+ weeks (undetected)
4. Data breach discovered during security audit
5. Compliance penalty ($1M+ for PCI-DSS violation)

## Remediation
1. **Automate rotation:** Set rotation interval (90 days max for API keys)
2. **Implement monitoring:** Alert if key is used from unexpected IP/location
3. **Revoke compromised keys:** Disable old key, regenerate new one
4. **Audit access:** Log every use of the key (Slack token accessed from X IP at Y time)
5. **Enforce least privilege:** Key grants minimum necessary permissions (read-only if possible)

## Effort
- Initial: 8 hours (setup Vault, configure rotation, test)
- Ongoing: 2 hours/month (monitor, respond to alerts)
EOF

cat ~/secrets-finding.md
```

---

## 🧹 Cleanup

```bash
rm -f ~/rotation-policy.md ~/main.tf ~/main-fixed.tf ~/secrets-finding.md

echo "✅ Secrets management lab cleaned up"
```

---

## Checklist

**HashiCorp Vault Fundamentals**
- [ ] Can explain Vault architecture (unseal keys, sealed database, auth methods, secret engines)
- [ ] Understand key separation principle (quorum of unseal keys)
- [ ] Know when to use Vault vs. AWS Secrets Manager (self-hosted vs. cloud)
- [ ] Can deploy Vault locally or on Kubernetes
- [ ] Understand Vault HA setup (3-5 replicas, database backend)

**Automated Secret Rotation**
- [ ] Can define rotation intervals (30 days for DB passwords, 90 days for API keys)
- [ ] Know how Vault auto-rotates database passwords
- [ ] Understand TTL (time-to-live) for credentials
- [ ] Can configure certificate rotation with Vault PKI
- [ ] Know audit trail requirements (who/what/when/where)

**Secret Leak Detection**
- [ ] Can use gitleaks to scan git history
- [ ] Know how to setup pre-commit hook (prevent commits with secrets)
- [ ] Can configure GitHub secret scanning in Actions
- [ ] Understand TruffleHog for comprehensive scanning
- [ ] Know how to respond to leaked secrets (rotate immediately, check logs, assess impact)

**Terraform Secret Scanning**
- [ ] Can use tfsec to scan Terraform for hardcoded secrets
- [ ] Know how to fix: use data sources (Secrets Manager, Vault) instead of hardcoding
- [ ] Can integrate secret scanning into CI/CD
- [ ] Understand blocking PRs with hardcoded secrets

**Credential Vending**
- [ ] Can explain just-in-time (JIT) credentials (temporary, auto-expiring)
- [ ] Know AWS STS AssumeRole for temporary credentials
- [ ] Understand Vault credential vending in Kubernetes
- [ ] Know benefits: no long-lived keys, automatic revocation, audit trail

**Real-World Scenarios**
- [ ] Can explain: why long-lived keys are risky (compromise, slow rotation, no audit)
- [ ] Can explain: how credential vending prevents compromise (temp creds, auto-revoke)
- [ ] Can explain: why Vault > Secrets Manager for multi-cloud/complex scenarios
- [ ] Understand: secrets management as foundation for Zero Trust

---

## Integration with Phase 4

This secrets management extension deepens Phase 4 m10:

- **m10-week1 (Base):** GitHub Secrets, AWS Secrets Manager, OIDC
- **enterprise-secrets-management (Deep):** Vault, rotation policies, detection, credential vending ← **This Week**
- **m10-week2:** Security gates (SAST, secrets scanning, etc.)
- **m11-week2:** Zero Trust enforcement with SCPs

Secrets management is the **foundation for Zero Trust**: no standing credentials, everything audited, every access justified.
