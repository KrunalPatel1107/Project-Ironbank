# Project: DevSecOps Pipeline

!!! abstract "💰 Cost: ~$0.10 — ECR image storage only. No compute this week."

!!! info "Month 10 Deliverable"
    This week you polish, document, and publish the complete 5-gate security pipeline as a GitHub repository called **iron-bank-pipeline**. This is your most important Phase 4 portfolio piece — a working CI/CD pipeline that automatically enforces security on every code change. Interviewers can fork it and run it.

---

## What You're Shipping

```
iron-bank-pipeline/
├── .github/
│   └── workflows/
│       ├── gate1-sast.yml          ← Semgrep on every PR
│       ├── gate2-secrets.yml       ← Gitleaks on every push
│       ├── gate3-iac.yml           ← Checkov when .tf files change
│       ├── gate4-container.yml     ← Trivy before ECR push
│       └── gate5-dast.yml          ← ZAP on app deployment
├── .zap/
│   └── rules.tsv                   ← ZAP alert thresholds
├── terraform/
│   └── main.tf                     ← Secure Terraform (passes Checkov)
├── src/
│   └── app.js                      ← Demo Node.js app
├── Dockerfile                      ← Hardened (non-root, alpine, multi-stage)
├── Makefile                        ← Developer shortcuts
└── README.md                       ← How to use the pipeline
```

---

## Part 1: Consolidate All Gates into One Status Workflow

Right now each gate is a separate workflow. Add a final summary workflow that shows overall pass/fail across all gates:

```bash
cat > .github/workflows/security-summary.yml << 'EOF'
# ─────────────────────────────────────────────────────────────────────────────
# Security Summary: runs after all gates and posts a PR comment with results
# This doesn't fail the build — it just aggregates results for visibility
# ─────────────────────────────────────────────────────────────────────────────
name: Security Summary

on:
  workflow_run:
    workflows:
      - "Gate 1 — SAST (Semgrep)"
      - "Gate 2 — Secret Detection (Gitleaks)"
      - "Gate 3 — IaC Security (Checkov)"
      - "Gate 4 — Container Scan (Trivy)"
    types: [completed]    # Run when any of these workflows finish

jobs:
  summary:
    name: Post Security Summary
    runs-on: ubuntu-latest
    if: github.event.workflow_run.event == 'pull_request'

    steps:
    - name: Get workflow run results
      uses: actions/github-script@v7
      # ─────────────────────────────────────────────────────────────────────────
      # NOTE: This step uses JavaScript (inside the "script:" block).
      # You do NOT need to understand or write this JavaScript yourself.
      # Copy and paste it as-is — it's a standard GitHub Actions pattern for
      # posting PR summary comments using the GitHub API.
      #
      # What it does in plain English:
      #   1. Gets a list of all the check runs (gate results) for the current commit
      #   2. Builds a Markdown table showing each gate's pass/fail result
      #   3. Posts that table as a summary in the GitHub Actions UI
      #
      # If you want to skip this step entirely, just delete this step — the gates
      # still work perfectly. This is cosmetic only (a nice summary table).
      # ─────────────────────────────────────────────────────────────────────────
      with:
        script: |
          // Get all check runs for this commit
          const checks = await github.rest.checks.listForRef({
            owner: context.repo.owner,
            repo: context.repo.repo,
            ref: context.payload.workflow_run.head_sha
          });

          // Build a summary table
          let summary = '## 🔒 Security Gate Results\n\n';
          summary += '| Gate | Status |\n|---|---|\n';

          const gateNames = [
            'Gate 1 — SAST (Semgrep)',
            'Gate 2 — Secret Detection (Gitleaks)',
            'Gate 3 — IaC Security (Checkov)',
            'Gate 4 — Container Scan (Trivy)',
          ];

          for (const name of gateNames) {
            const check = checks.data.check_runs.find(c => c.name.includes(name));
            if (check) {
              const icon = check.conclusion === 'success' ? '✅' : '❌';
              summary += `| ${name} | ${icon} ${check.conclusion} |\n`;
            } else {
              summary += `| ${name} | ⏳ pending |\n`;
            }
          }

          // Post the summary as a GitHub Actions job summary (visible in the workflow UI)
          await core.summary.addRaw(summary).write();
          console.log(summary);
EOF
```

---

## Part 2: Makefile for Local Development

Developers should be able to run all security checks locally before pushing:

```bash
cat > Makefile << 'EOF'
# ─────────────────────────────────────────────────────────────────────────────
# Iron Bank Pipeline — Makefile
# Run these locally before pushing to catch issues before the gate does
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: sast secrets iac container dast all clean help

help:
	@echo ""
	@echo "  🔒 Iron Bank Pipeline — Security Checks"
	@echo ""
	@echo "  make sast       Run Semgrep SAST on src/"
	@echo "  make secrets    Run Gitleaks on full git history"
	@echo "  make iac        Run Checkov on terraform/"
	@echo "  make container  Build image and run Trivy scan"
	@echo "  make dast       Start app in Docker and run ZAP baseline"
	@echo "  make all        Run all checks in sequence"
	@echo "  make clean      Remove generated reports"
	@echo ""

# ── Gate 1: SAST ─────────────────────────────────────────────────────────────
sast:
	@echo "🔍 Running Semgrep SAST..."
	semgrep --config p/owasp-top-ten --config p/javascript src/ || true

# ── Gate 2: Secrets ───────────────────────────────────────────────────────────
secrets:
	@echo "🔑 Running Gitleaks..."
	gitleaks detect --source . --verbose

# ── Gate 3: IaC ───────────────────────────────────────────────────────────────
iac:
	@echo "🏗️  Running Checkov on terraform/..."
	checkov -d terraform/ --framework terraform

# ── Gate 4: Container ─────────────────────────────────────────────────────────
container:
	@echo "🐳 Building image and running Trivy..."
	docker build -t iron-bank-app:local .
	trivy image --severity CRITICAL,HIGH iron-bank-app:local

# ── Gate 5: DAST ─────────────────────────────────────────────────────────────
dast:
	@echo "🌐 Starting app and running ZAP..."
	docker run -d --name dast-target -p 3000:3000 iron-bank-app:local 2>/dev/null || true
	sleep 5
	docker run --rm --network host \
	  -v $$(pwd)/reports:/zap/wrk \
	  ghcr.io/zaproxy/zaproxy:stable \
	  zap-baseline.py -t http://localhost:3000 -r zap-local.html -l WARN
	docker stop dast-target && docker rm dast-target

# ── Run everything ────────────────────────────────────────────────────────────
all: sast secrets iac container dast
	@echo ""
	@echo "✅ All local security checks complete — check output above"

# ── Clean up reports ──────────────────────────────────────────────────────────
clean:
	rm -rf reports/ *.sarif *.html
	docker image rm iron-bank-app:local 2>/dev/null || true
	@echo "Reports cleared"
EOF
```

---

## Part 3: README

```bash
cat > README.md << 'MARKDOWN'
# 🏦 Iron Bank — DevSecOps Pipeline

A production-grade GitHub Actions CI/CD pipeline with automated security gates.
Built as part of the [Iron Bank 12-Month Cloud Security Training Plan](https://github.com/YOUR_USERNAME/iron-bank).

## Security Gates

| Gate | Tool | Trigger | What It Checks |
|---|---|---|---|
| 1 | Semgrep | Every PR | Code — injection, auth bugs, unsafe patterns |
| 2 | Gitleaks | Every push | Git history — committed secrets |
| 3 | Checkov | `.tf` file changes | Terraform — misconfigurations |
| 4 | Trivy | Dockerfile changes | Container image — CVEs |
| 5 | ZAP | App deployment | Running app — web vulnerabilities |

## Local Development

```bash
# Run all checks before pushing
make all

# Or run individual gates
make sast       # Semgrep SAST
make secrets    # Gitleaks
make iac        # Checkov
make container  # Trivy
make dast       # ZAP (starts app, scans, stops app)
```

## Pipeline Architecture

```
PR opened → Gate 1 (Semgrep) + Gate 2 (Gitleaks) + Gate 3 (Checkov)
              ↓ all pass
PR merged → Gate 4 (Trivy) → only clean images pushed to ECR
              ↓ passes
Deploy    → Gate 5 (ZAP) → blocks promotion if HIGH web vuln found
```

## Requirements

- GitHub repository with Actions enabled
- AWS credentials stored as GitHub Secrets (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- ECR repository named `iron-bank-app` in `us-east-1`
- Docker installed locally for `make dast`

## Month 10 Portfolio Context

Written as Phase 4 of the Iron Bank curriculum. Builds on:
- Month 8: manual use of Semgrep, ZAP, Trivy, Gitleaks
- Month 9: Docker hardening, ECR, ECS Fargate
- Month 10: all tools automated in a CI/CD pipeline with blocking gates
MARKDOWN
```

---

## Part 4: Push and Verify the Complete Pipeline

```bash
# Ensure all files are staged
git add -A
git status

# Review what you're committing
git diff --cached --stat

# Commit
git commit -m "feat: complete 5-gate DevSecOps pipeline — Month 10 deliverable"

# Push
git push origin main

# Verify: go to GitHub repo → Actions tab
# You should see all workflows listed
# Make a test PR to see Gates 1-3 fire
```

Verify branch protection is configured (Settings → Branches → main):

```
Required status checks:
  ✅ Semgrep SAST Scan
  ✅ Gitleaks Secret Scan
  ✅ Checkov IaC Scan
  ✅ Build Image and Trivy Scan
```

---

## Part 5: Interview Talking Points

When asked about this project in interviews:

??? note "How to explain the pipeline in 2 minutes"
    **The problem:** Developers commit code that has security issues — hardcoded secrets, SQL injection, misconfigured cloud resources. These get caught in production (expensive) or not at all.

    **The solution:** Automated security gates in CI/CD. Every pull request triggers Semgrep (static analysis), Gitleaks (secret detection), and Checkov (IaC scanning). The PR cannot merge if any gate fails. On merge, Trivy scans the Docker image before it reaches the container registry. On deployment, ZAP tests the running application.

    **The result:** Security issues are caught at the cheapest possible moment — before the code is deployed, before the image is built, before the infrastructure exists.

??? note "Common interview question: SAST vs DAST"
    **SAST (Static Application Security Testing):** analyzes source code without running it. Finds issues at the code level — SQL injection patterns, use of `eval()`, hardcoded credentials. Fast, no infrastructure needed. Tool: Semgrep.

    **DAST (Dynamic Application Security Testing):** tests a running application by sending real HTTP requests. Finds runtime behaviour — missing security headers, injection via live inputs, insecure sessions. Requires a running app. Tool: OWASP ZAP.

    You need both: SAST catches issues before the app runs; DAST catches issues that only appear at runtime.

??? note "Common interview question: How do you prevent secrets from reaching git?"
    Three layers: (1) Gitleaks pre-commit hook runs on `git commit` — catches secrets before they leave the developer's machine. (2) Gitleaks CI gate on every `git push` — catches anything that slipped past the pre-commit hook. (3) GitHub Secret Scanning — GitHub's own built-in secret detection, always enabled on public repos.

??? note "Common interview question: What is shift left security?"
    Finding security issues earlier in the development lifecycle (shifting them to the left on the timeline). The earlier you find a bug, the cheaper it is to fix. A vulnerability found in code review costs hours to fix; the same vulnerability found in production costs days and may involve an incident response. CI/CD security gates are the primary mechanism for shift-left.

---

## 🧹 Cleanup

```bash
# Remove local Docker images created during testing
docker image rm iron-bank-app:local 2>/dev/null || true

# Remove local report files
rm -rf reports/ *.html *.sarif 2>/dev/null || true

# Optional: delete the ECR image if you pushed one (costs $0.01/month to store)
aws ecr batch-delete-image \
  --repository-name iron-bank-app \
  --image-ids imageTag=latest \
  --profile iron-bank \
  --region us-east-1 2>/dev/null || true

echo "✅ Month 10 complete — pipeline lives on GitHub"
```

---

## Month 10 Summary

| Week | Gates Added | Tools | Portfolio |
|---|---|---|---|
| 1 | Foundation | GitHub Actions basics | First workflow running |
| 2 | Gates 1–3 | Semgrep, Gitleaks, Checkov | PR gates blocking on code issues |
| 3 | Gates 4–5 | Trivy, ZAP | Container and runtime security gates |
| 4 | Full pipeline | All 5 gates | `iron-bank-pipeline` published on GitHub |

---

## Checklist

- [ ] All 5 gate workflows committed to `.github/workflows/`
- [ ] `security-summary.yml` added — summary visible in Actions tab
- [ ] `Makefile` created — `make all` runs all 5 checks locally
- [ ] `README.md` written — explains gates, architecture, and how to run locally
- [ ] Branch protection on `main` — Gates 1–4 required to pass before merge
- [ ] Test PR created — watched at least 3 gates fire and report
- [ ] Pipeline pushed to GitHub as `iron-bank-pipeline` (public repo)
- [ ] Can explain SAST vs DAST vs SCA in one sentence each
- [ ] Can explain "shift left security" in 30 seconds
- [ ] ECR image deleted if pushed — bill verified at $0

!!! tip "What's next: Phase 4 Month 11 — Compliance as Code"
    Month 11 takes the governance work from Phase 2 (Config rules, SCPs, Security Hub) and codes it programmatically — writing OPA policies, AWS Config conformance packs, and automating compliance reporting. You'll go from "I configured these manually" to "I deploy and enforce compliance through code."

