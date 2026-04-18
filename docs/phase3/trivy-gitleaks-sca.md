# Month 8 — Week 3: Trivy & Gitleaks (SCA)

!!! abstract "💰 Cost: $0 — All local tools"

!!! info "Background Context"
    SCA (Software Composition Analysis) is about the code you *didn't write* — third-party libraries and Docker base images. Log4Shell (the 2021 critical CVE) was an SCA failure — organisations didn't know they were running the vulnerable library until attackers exploited it. Gitleaks finds secrets already committed to repos — a critical first step when joining any security team.

---

## What Is SCA?

SCA scans your **dependencies and container images** for known vulnerabilities (CVEs) and misconfigurations. Your code might be perfect — but if you're using a library with a critical CVE, you're still at risk.

| Tool | What It Scans | Finds |
|---|---|---|
| **Trivy** | Container images, filesystems, Git repos, IaC | CVEs in OS packages + library deps, misconfigs, secrets |
| **Gitleaks** | Git history | Hardcoded secrets, API keys, tokens committed at any point in history |

---

## Part 1: Install Trivy

```bash
# Ubuntu/WSL
sudo apt install wget apt-transport-https gnupg -y
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | \
  sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | \
  sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt update && sudo apt install trivy -y

# macOS
# brew install trivy

# Verify
trivy --version

# Or run via Docker (no install needed)
docker run --rm aquasec/trivy --version
```

---

## Part 2: Scan a Container Image

```bash
# ─── Scan the Juice Shop image for vulnerabilities ────────────────────────────
trivy image bkimminich/juice-shop

# Expected: hundreds of findings — Juice Shop is intentionally vulnerable
# Output columns: Library, Vulnerability ID, Severity, Installed Version, Fixed Version

# ─── Filter to only CRITICAL and HIGH findings ────────────────────────────────
trivy image --severity CRITICAL,HIGH bkimminich/juice-shop

# ─── Save as JSON for programmatic processing ─────────────────────────────────
trivy image --format json --output ~/projects/trivy-juice-shop.json bkimminich/juice-shop

# Count findings by severity
python3 << 'EOF'
import json
from collections import Counter

with open('/root/projects/trivy-juice-shop.json') as f:
    data = json.load(f)

counts = Counter()
for result in data.get('Results', []):
    for vuln in result.get('Vulnerabilities', []):
        counts[vuln.get('Severity', 'UNKNOWN')] += 1

total = sum(counts.values())
print(f"Total CVEs found: {total}")
for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
    print(f"  {sev}: {counts.get(sev, 0)}")
EOF

# ─── Scan a specific CVE to understand it ────────────────────────────────────
# Find a CRITICAL CVE in the output and look it up:
trivy image --severity CRITICAL bkimminich/juice-shop 2>/dev/null | head -30
# Pick a CVE ID (e.g. CVE-2021-44228) and read about it:
# https://nvd.nist.gov/vuln/detail/CVE-2021-44228
```

??? note "What is a CVE?"
    CVE (Common Vulnerabilities and Exposures) is a standardised ID for a known security vulnerability. Format: `CVE-YEAR-NUMBER`. CVSS score (0–10) indicates severity:

    | Score | Severity | Meaning |
    |---|---|---|
    | 9.0–10.0 | CRITICAL | Remotely exploitable, no auth, full impact |
    | 7.0–8.9 | HIGH | Serious risk, patch immediately |
    | 4.0–6.9 | MEDIUM | Moderate risk, patch within a sprint |
    | 0.1–3.9 | LOW | Minimal risk, patch in routine maintenance |

---

## Part 3: Scan a Filesystem and IaC

```bash
# ─── Scan your Terraform code for misconfigurations ───────────────────────────
trivy config ~/projects/iron-bank-tf/
# Checks for: S3 buckets without encryption, SGs open to 0.0.0.0/0,
#             missing flow logs, public EC2 instances, etc.

# ─── Scan the Juice Shop source code for CVEs in node_modules ────────────────
git clone https://github.com/juice-shop/juice-shop.git /tmp/juice-shop-src 2>/dev/null || true
trivy fs --scanners vuln /tmp/juice-shop-src/
# Reads package.json and package-lock.json to find vulnerable npm packages

# ─── Scan a Git repository (including history) ────────────────────────────────
trivy repo https://github.com/juice-shop/juice-shop
# Clones and scans — checks for CVEs in dependencies AND secrets in code
```

---

## Part 4: Install and Run Gitleaks

Gitleaks scans Git history for secrets — it finds credentials committed at any point, even if they were later deleted. Deletion doesn't remove them from `git log`.

```bash
# Install Gitleaks
# Ubuntu/WSL:
wget -q https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_$(uname -m)_linux.tar.gz \
  -O /tmp/gitleaks.tar.gz
tar -xzf /tmp/gitleaks.tar.gz -C /tmp/
sudo mv /tmp/gitleaks /usr/local/bin/
# macOS: brew install gitleaks

gitleaks version

# ─── Scan a local repository ──────────────────────────────────────────────────
git clone https://github.com/juice-shop/juice-shop.git /tmp/juice-shop-scan 2>/dev/null || true
gitleaks detect --source /tmp/juice-shop-scan --report-path ~/projects/gitleaks-report.json

# ─── Read the findings ────────────────────────────────────────────────────────
cat ~/projects/gitleaks-report.json | python3 -c "
import json, sys
findings = json.load(sys.stdin)
print(f'Secrets found: {len(findings)}')
for f in findings[:5]:
    print(f\"  Rule: {f.get('RuleID')}\")
    print(f\"  File: {f.get('File')}:{f.get('StartLine')}\")
    print(f\"  Match: {f.get('Secret', '')[:30]}...\")
    print()
"

# ─── Scan YOUR own iron-bank repos for any accidental commits ─────────────────
# Always run this before making a repo public
gitleaks detect --source ~/projects/iron-bank-tf --report-path ~/projects/gitleaks-myrepo.json
cat ~/projects/gitleaks-myrepo.json   # Should be empty — if not, rotate those credentials NOW
```

!!! danger "If Gitleaks finds secrets in your repo"
    1. **Rotate the credential immediately** — assume it's already compromised
    2. Remove it using `git filter-repo` or BFG Repo Cleaner
    3. Force-push to overwrite history
    4. Audit your AWS CloudTrail for any usage of the leaked key

---

## Part 5: Add Gitleaks as a Pre-commit Hook

```bash
cd ~/projects/iron-bank-semgrep   # Add to your existing pre-commit setup

# Add Gitleaks to .pre-commit-config.yaml
cat >> .pre-commit-config.yaml << 'EOF'

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
EOF

pre-commit install
pre-commit run --all-files
# Gitleaks will now run on every commit, blocking any accidental secret inclusion
```

---

## Part 6: Understand the Fix Workflow

Finding a CVE is only half the job — you need to know what to do with it.

```bash
# ─── For a library CVE (e.g. in package.json) ────────────────────────────────
# 1. Identify the vulnerable version and the fixed version (Trivy shows both)
# 2. Update the dependency:
#    npm update vulnerable-package
#    npm audit fix
# 3. Re-scan to confirm the CVE is gone:
#    trivy fs .

# ─── For a base image CVE ────────────────────────────────────────────────────
# 1. Identify which base image layer introduced the CVE
# 2. Update FROM in your Dockerfile:
#    FROM node:18-alpine  →  FROM node:20-alpine
# 3. Rebuild and re-scan:
#    docker build -t myapp:fixed .
#    trivy image myapp:fixed

# ─── For IaC misconfigurations ────────────────────────────────────────────────
# Trivy tells you exactly which line to fix:
# aws-s3-no-public-access   s3.tf:12   CRITICAL
# Fix: add aws_s3_bucket_public_access_block resource (you already did this in Month 5)
```

---

## 🧹 Cleanup

```bash
docker image rm bkimminich/juice-shop 2>/dev/null
rm -rf /tmp/juice-shop-src /tmp/juice-shop-scan

# Commit reports and pre-commit config
mkdir -p ~/projects/security-toolkit/sca-reports
cp ~/projects/trivy-*.json ~/projects/security-toolkit/sca-reports/ 2>/dev/null
cp ~/projects/gitleaks-*.json ~/projects/security-toolkit/sca-reports/ 2>/dev/null

cd ~/projects/iron-bank-semgrep
git add -A
git commit -m "feat: add Gitleaks pre-commit hook — Month 8 Week 3"
git push

echo "✅ Week 3 complete — no cloud resources used"
```

---

## Checklist

- [ ] Trivy installed — `trivy --version` works
- [ ] Juice Shop image scanned — CRITICAL/HIGH count noted
- [ ] Understand CVE format and CVSS scoring
- [ ] Trivy config scan run against `~/projects/iron-bank-tf/`
- [ ] Trivy filesystem scan run against Juice Shop source (npm deps)
- [ ] Gitleaks installed — `gitleaks version` works
- [ ] Juice Shop repository scanned with Gitleaks — findings reviewed
- [ ] Your own `iron-bank-tf` repo scanned — confirmed no secrets leaked
- [ ] Gitleaks added as pre-commit hook alongside Semgrep
- [ ] Know the fix workflow for: library CVEs, base image CVEs, IaC misconfigs
- [ ] Reports saved to `security-toolkit/sca-reports/`

