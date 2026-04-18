# Project: Security Testing Toolkit

!!! abstract "💰 Cost: $0 — All local tools"

!!! info "Month 8 Deliverable"
    This week you assemble three weeks of tools (Semgrep, ZAP, Trivy, Gitleaks) into a single GitHub repository — the **Iron Bank Security Testing Toolkit**. This is your most demonstrable AppSec portfolio piece. Interviewers can run it and see it work.

---

## What You're Building

A unified security testing toolkit that a developer can clone and run with a single command to get:

```
iron-bank-security-toolkit/
├── scan.sh                  ← Master script: runs all tools in sequence
├── Makefile                 ← make sast / make dast / make sca / make all
├── rules/
│   └── semgrep/             ← Your custom Semgrep rules from Week 1
├── reports/                 ← Generated HTML/JSON reports (gitignored)
├── .pre-commit-config.yaml  ← Semgrep + Gitleaks on every commit
└── README.md                ← How to use it
```

---

## Part 1: Create the Project Structure

```bash
mkdir -p ~/projects/iron-bank-security-toolkit/{rules/semgrep,reports,.zap}
cd ~/projects/iron-bank-security-toolkit
git init

# Copy your custom Semgrep rules from Week 1
cp ~/projects/iron-bank-semgrep/rules/*.yml rules/semgrep/ 2>/dev/null || echo "Add rules manually"
cp ~/projects/iron-bank-semgrep/.pre-commit-config.yaml . 2>/dev/null || true
```

---

## Part 2: The Master Scan Script

```bash
cat > scan.sh << 'SCRIPT'
#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Iron Bank Security Testing Toolkit — scan.sh
# Usage: ./scan.sh <target-dir-or-url> [--sast] [--dast] [--sca] [--secrets]
#        ./scan.sh ~/projects/myapp --sast --sca
#        ./scan.sh http://localhost:3000 --dast
#        ./scan.sh . --all
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail    # Exit on error, treat unset vars as errors, fail on pipe errors

TARGET="${1:-}"      # First argument = the target (directory or URL)
REPORTS_DIR="$(dirname "$0")/reports"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
PASS=0               # Number of tools that found no issues
FAIL=0               # Number of tools that found issues

mkdir -p "$REPORTS_DIR"

# ─── Colour helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[FAIL]${NC}  $*"; }

# ─── Check tool availability ──────────────────────────────────────────────────
check_tool() {
  if ! command -v "$1" &>/dev/null; then
    warn "$1 not found — skipping. Install with: $2"
    return 1
  fi
  return 0
}

# ─── SAST: Semgrep ────────────────────────────────────────────────────────────
run_sast() {
  info "Running SAST (Semgrep) against: $TARGET"
  if ! check_tool semgrep "pip install semgrep"; then return; fi

  REPORT="$REPORTS_DIR/semgrep-${TIMESTAMP}.json"
  if semgrep \
    --config "p/owasp-top-ten" \
    --config "$(dirname "$0")/rules/semgrep/" \
    --json \
    --output "$REPORT" \
    "$TARGET" 2>/dev/null; then
    FINDING_COUNT=$(python3 -c "import json; d=json.load(open('$REPORT')); print(len(d.get('results',[])))" 2>/dev/null || echo "0")
    if [ "$FINDING_COUNT" -eq 0 ]; then
      info "SAST: ✅ No findings"
      PASS=$((PASS + 1))
    else
      error "SAST: ❌ $FINDING_COUNT findings — see $REPORT"
      FAIL=$((FAIL + 1))
    fi
  else
    warn "SAST: scan completed with findings"
    FAIL=$((FAIL + 1))
  fi
}

# ─── DAST: OWASP ZAP ─────────────────────────────────────────────────────────
run_dast() {
  info "Running DAST (ZAP Baseline) against: $TARGET"
  if ! check_tool docker "Install Docker Desktop or docker.io"; then return; fi

  REPORT="$REPORTS_DIR/zap-baseline-${TIMESTAMP}.html"
  if docker run --rm --network host \
    -v "$REPORTS_DIR:/zap/wrk" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py \
    -t "$TARGET" \
    -r "zap-baseline-${TIMESTAMP}.html" \
    -l WARN 2>&1 | tail -5; then
    info "DAST: ✅ Baseline scan complete — see $REPORT"
    PASS=$((PASS + 1))
  else
    error "DAST: ❌ Findings detected — see $REPORT"
    FAIL=$((FAIL + 1))
  fi
}

# ─── SCA: Trivy ───────────────────────────────────────────────────────────────
run_sca() {
  info "Running SCA (Trivy) against: $TARGET"
  if ! check_tool trivy "sudo apt install trivy"; then return; fi

  REPORT="$REPORTS_DIR/trivy-${TIMESTAMP}.json"

  # Detect if target is a Docker image (contains /) or a filesystem path
  if [[ "$TARGET" == http* ]]; then
    warn "SCA: TARGET is a URL — scanning as filesystem path instead"
    SCAN_TARGET="."
  else
    SCAN_TARGET="$TARGET"
  fi

  trivy fs \
    --severity CRITICAL,HIGH \
    --format json \
    --output "$REPORT" \
    "$SCAN_TARGET" 2>/dev/null

  CRITICAL=$(python3 -c "
import json
d=json.load(open('$REPORT'))
n=sum(len([v for v in r.get('Vulnerabilities',[]) if v.get('Severity')=='CRITICAL']) for r in d.get('Results',[]))
print(n)" 2>/dev/null || echo "0")

  if [ "$CRITICAL" -eq 0 ]; then
    info "SCA: ✅ No CRITICAL CVEs"
    PASS=$((PASS + 1))
  else
    error "SCA: ❌ $CRITICAL CRITICAL CVEs — see $REPORT"
    FAIL=$((FAIL + 1))
  fi
}

# ─── Secrets: Gitleaks ────────────────────────────────────────────────────────
run_secrets() {
  info "Running secret scan (Gitleaks) against: $TARGET"
  if ! check_tool gitleaks "Download from github.com/gitleaks/gitleaks"; then return; fi

  REPORT="$REPORTS_DIR/gitleaks-${TIMESTAMP}.json"
  if gitleaks detect \
    --source "$TARGET" \
    --report-path "$REPORT" \
    --exit-code 0 2>/dev/null; then
    SECRET_COUNT=$(python3 -c "import json; print(len(json.load(open('$REPORT'))))" 2>/dev/null || echo "0")
    if [ "$SECRET_COUNT" -eq 0 ]; then
      info "Secrets: ✅ No secrets detected"
      PASS=$((PASS + 1))
    else
      error "Secrets: ❌ $SECRET_COUNT secrets found — ROTATE IMMEDIATELY — see $REPORT"
      FAIL=$((FAIL + 1))
    fi
  fi
}

# ─── Parse flags and run ──────────────────────────────────────────────────────
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target> [--sast] [--dast] [--sca] [--secrets] [--all]"
  exit 1
fi

shift   # Remove target from args, leaving only flags
RUN_ALL=false
[[ "$*" == *"--all"* ]] && RUN_ALL=true

[[ "$RUN_ALL" == true || "$*" == *"--sast"*    ]] && run_sast
[[ "$RUN_ALL" == true || "$*" == *"--dast"*    ]] && run_dast
[[ "$RUN_ALL" == true || "$*" == *"--sca"*     ]] && run_sca
[[ "$RUN_ALL" == true || "$*" == *"--secrets"* ]] && run_secrets

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
echo "  🏦 Iron Bank Security Toolkit — Summary"
echo "══════════════════════════════════════════"
echo "  ✅ Passed: $PASS"
echo "  ❌ Failed: $FAIL"
echo "  📁 Reports: $REPORTS_DIR"
echo "══════════════════════════════════════════"

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
SCRIPT

chmod +x scan.sh
```

---

## Part 3: The Makefile

```makefile
# Makefile — convenient shortcuts for common scan scenarios
# Usage: make sast TARGET=~/projects/myapp
#        make all  TARGET=http://localhost:3000

TARGET ?= .

.PHONY: sast dast sca secrets all clean help

help:
	@echo "Iron Bank Security Toolkit"
	@echo ""
	@echo "  make sast    TARGET=<path>  — Static analysis (Semgrep)"
	@echo "  make dast    TARGET=<url>   — Dynamic testing (ZAP)"
	@echo "  make sca     TARGET=<path>  — Dependency scan (Trivy)"
	@echo "  make secrets TARGET=<path>  — Secret scan (Gitleaks)"
	@echo "  make all     TARGET=<path>  — Run all tools"
	@echo "  make clean                  — Remove all reports"

sast:
	./scan.sh $(TARGET) --sast

dast:
	./scan.sh $(TARGET) --dast

sca:
	./scan.sh $(TARGET) --sca

secrets:
	./scan.sh $(TARGET) --secrets

all:
	./scan.sh $(TARGET) --all

clean:
	rm -rf reports/*.json reports/*.html
	@echo "Reports cleared"
```

```bash
cat > Makefile << 'EOF'
TARGET ?= .

.PHONY: sast dast sca secrets all clean help

help:
	@echo "Iron Bank Security Toolkit"
	@echo "  make sast    TARGET=<path>  Static analysis (Semgrep)"
	@echo "  make dast    TARGET=<url>   Dynamic testing (ZAP)"
	@echo "  make sca     TARGET=<path>  Dependency scan (Trivy)"
	@echo "  make secrets TARGET=<path>  Secret scan (Gitleaks)"
	@echo "  make all     TARGET=<path>  Run everything"
	@echo "  make clean                  Remove reports"

sast:    ; ./scan.sh $(TARGET) --sast
dast:    ; ./scan.sh $(TARGET) --dast
sca:     ; ./scan.sh $(TARGET) --sca
secrets: ; ./scan.sh $(TARGET) --secrets
all:     ; ./scan.sh $(TARGET) --all
clean:   ; rm -rf reports/*.json reports/*.html && echo "Reports cleared"
EOF
```

---

## Part 4: Test the Toolkit End-to-End

```bash
cd ~/projects/iron-bank-security-toolkit

# Start Juice Shop as the DAST target
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
sleep 10

# Run SAST against Juice Shop source (needs clone)
git clone https://github.com/juice-shop/juice-shop.git /tmp/js-src 2>/dev/null || true
make sast TARGET=/tmp/js-src

# Run DAST against live Juice Shop
make dast TARGET=http://localhost:3000

# Run SCA against Juice Shop source
make sca TARGET=/tmp/js-src

# Run secrets scan
make secrets TARGET=/tmp/js-src

# Run everything against your own iron-bank-tf project
make all TARGET=~/projects/iron-bank-tf

# List generated reports
ls -lh reports/
```

---

## Part 5: README and GitHub Push

```bash
cat > README.md << 'EOF'
# 🏦 Iron Bank Security Testing Toolkit

Automated security scanning toolkit combining SAST, DAST, SCA, and secret detection.
Built as part of the [Iron Bank 12-Month Cloud Security Training Plan](https://github.com/YOUR_USERNAME/iron-bank).

## Tools

| Tool | Category | What It Scans |
|---|---|---|
| [Semgrep](https://semgrep.dev) | SAST | Source code — finds injection, auth bugs, unsafe patterns |
| [OWASP ZAP](https://zaproxy.org) | DAST | Running apps — automated penetration testing |
| [Trivy](https://trivy.dev) | SCA | Container images, dependencies — CVE detection |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secrets | Git history — finds committed credentials |

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/iron-bank-security-toolkit.git
cd iron-bank-security-toolkit

# Scan a source directory
./scan.sh /path/to/app --sast --sca --secrets

# Scan a running application
./scan.sh http://localhost:3000 --dast

# Run everything
./scan.sh /path/to/app --all
```

## Custom Semgrep Rules

The `rules/semgrep/` directory contains custom rules targeting:
- `eval()` usage (CWE-95)
- Hardcoded credentials (CWE-798)
- SQL string concatenation (CWE-89)

## Pre-commit Integration

```bash
pip install pre-commit
pre-commit install
# Now Semgrep + Gitleaks run on every git commit
```

## Month 8 Portfolio Context

Written as part of Phase 3 (AppSec) — builds on manual Juice Shop exploitation
(Month 7) by automating the same tests with industry-standard tools.
EOF

# .gitignore
cat > .gitignore << 'EOF'
reports/
.semgrep/
__pycache__/
*.pyc
EOF

git add -A
git status   # Review before committing
git commit -m "feat: Iron Bank Security Testing Toolkit — Month 8 complete"
git remote add origin https://github.com/<your-username>/iron-bank-security-toolkit.git
git push -u origin main

echo "✅ Month 8 toolkit pushed to GitHub"
```

---

## 🧹 Cleanup

```bash
docker stop juice-shop 2>/dev/null && docker rm juice-shop 2>/dev/null
docker image rm bkimminich/juice-shop ghcr.io/zaproxy/zaproxy:stable 2>/dev/null
rm -rf /tmp/js-src
echo "✅ All containers removed — toolkit lives on GitHub"
```

---

## Month 8 Summary

| Week | Tool | Category | Portfolio |
|---|---|---|---|
| 1 | Semgrep | SAST | `iron-bank-semgrep` repo with 3 custom rules |
| 2 | OWASP ZAP | DAST | Baseline + active + API scan reports |
| 3 | Trivy + Gitleaks | SCA + Secrets | Pre-commit hooks, CVE triage skills |
| 4 | All combined | Full toolkit | `iron-bank-security-toolkit` on GitHub |

---

## Checklist

- [ ] `scan.sh` runs without errors
- [ ] `make sast TARGET=...` successfully scans Juice Shop source
- [ ] `make dast TARGET=http://localhost:3000` produces an HTML report
- [ ] `make sca TARGET=...` shows CRITICAL CVE count
- [ ] `make secrets TARGET=...` returns clean on your own repos
- [ ] `make all` runs all four tools in sequence with a summary
- [ ] README written — explains all four tools and how to use the toolkit
- [ ] Toolkit pushed to GitHub as `iron-bank-security-toolkit`
- [ ] Pre-commit hooks installed — Semgrep + Gitleaks block on every commit
- [ ] All Docker containers cleaned up — bill $0

