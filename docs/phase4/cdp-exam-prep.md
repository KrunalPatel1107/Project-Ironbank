# Month 11 — Week 3: CDP Exam Prep (Certified DevSecOps Professional)

!!! abstract "💰 Cost: $0 — Study week, no AWS resources"

!!! info "What is the CDP Exam?"
    The **Certified DevSecOps Professional (CDP)** is offered by the DevSecOps Institute. It validates that you can integrate security into DevOps pipelines — exactly what you've been building in Phase 4. The exam covers: threat modelling in CI/CD, security testing automation, supply chain security, shift-left practices, and governance-as-code. It complements your AWS Security Specialty (Month 9) by adding the DevOps integration angle.

---

## CDP Exam Overview

| | |
|---|---|
| **Provider** | DevSecOps Institute (https://www.devsecopsinstitute.com) |
| **Duration** | 120 minutes |
| **Questions** | 40 multiple choice |
| **Passing score** | 70% (28/40) |
| **Cost** | ~$499 USD |
| **Validity** | 2 years |
| **Prerequisite** | No formal prerequisites (but real DevSecOps experience strongly recommended) |

---

## Domain 1: Threat Modelling in CI/CD

The CDP exam expects you to apply STRIDE in a pipeline context — not just to applications.

```
Pipeline Threat Model (STRIDE applied to CI/CD):

Spoofing:
  - Attacker submits a PR as a trusted developer
  - Attacker replaces a GitHub Actions dependency with a malicious version
  Defence: branch protection, signed commits, pinned action versions (SHA not tag)

Tampering:
  - Attacker modifies pipeline YAML to bypass a security gate
  - Attacker alters an artifact between build and deploy steps
  Defence: CODEOWNERS file, signed artifacts, artifact verification in deploy step

Repudiation:
  - Developer denies making a code change that introduced a vulnerability
  Defence: CloudTrail, git commit signing, immutable audit logs

Information Disclosure:
  - Secret leaks via pipeline logs (console.log(password))
  - SARIF report exposes vulnerability details in a public repo
  Defence: secret masking in runners, private repo for security reports

Denial of Service:
  - Attacker triggers thousands of workflow runs to exhaust GitHub Actions minutes
  Defence: concurrency limits, workflow dispatch approval

Elevation of Privilege:
  - Pipeline job escapes its container and accesses runner host
  - GitHub Actions token has excessive permissions
  Defence: minimal GITHUB_TOKEN permissions, isolated runners
```

### Pin GitHub Actions to SHA (Supply Chain Security)

```yaml
# ❌ Vulnerable — tag can be moved to a different, malicious commit
- uses: actions/checkout@v4
- uses: returntocorp/semgrep-action@v1

# ✅ Secure — SHA hash cannot be changed (it's cryptographically bound to the exact code)
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
- uses: returntocorp/semgrep-action@fcd5ab7458e2d761c793af0fc3432e4e5e6e1f72  # v1.x

# To find the SHA for an action:
# 1. Go to the action's GitHub repo
# 2. Click on the release tag (e.g. v4.1.1)
# 3. The URL shows the commit SHA, or use:
#    git ls-remote https://github.com/actions/checkout refs/tags/v4
```

---

## Domain 2: Supply Chain Security (SLSA Framework)

SLSA (Supply chain Levels for Software Artifacts) is a Google-originated framework that defines levels of supply chain security. CDP exam commonly tests this.

```
SLSA Levels:
  Level 1: Build process documented, basic provenance generated
  Level 2: Build is automated (no manual steps), hosted build service
  Level 3: Build is fully isolated, signed provenance (can't be forged)
  Level 4: Hermetic builds (build environment cannot access the internet)
            Two-person review of all changes

Most companies target SLSA Level 2-3.

How GitHub Actions achieves SLSA Level 2:
  ✅ Automated build (no manual build steps)
  ✅ GitHub-hosted runner (hosted service)
  ✅ Build provenance via GitHub Attestations (new in 2024)
  ✅ Git tag + commit SHA traceability

Provenance: a signed statement that says "this artifact was built
from this source code, using this build process, at this time."
```

Generate provenance for your Docker images in GitHub Actions:

```yaml
# Add to gate4-container.yml after the docker build step
- name: Generate artifact attestation
  uses: actions/attest-build-provenance@v1
  with:
    subject-name: ${{ env.ECR_REGISTRY }}/${{ env.ECR_REPOSITORY }}
    subject-digest: ${{ steps.build.outputs.digest }}
    push-to-registry: true
# This creates a signed attestation linking the image to:
# - The exact commit SHA
# - The workflow run ID
# - The GitHub Actions runner environment
# Anyone can verify: gh attestation verify oci://<image> --owner <org>
```

---

## Domain 3: Security Testing Automation (Exam Quick Reference)

| Category | Tool | What it does | When it runs |
|---|---|---|---|
| SAST | Semgrep | Finds insecure code patterns in source | On PR (Gate 1) |
| Secrets | Gitleaks | Finds credentials in git history | On push (Gate 2) |
| IaC | Checkov | Finds Terraform misconfigurations | On TF file change (Gate 3) |
| SCA | Trivy | Finds CVEs in dependencies and images | On image build (Gate 4) |
| DAST | OWASP ZAP | Finds runtime web vulnerabilities | Post-deploy (Gate 5) |
| IAST | Contrast Security | Monitors app from inside during testing | Runtime agent (advanced) |

??? note "What is SCA vs SAST?"
    **SAST (Static Analysis):** reads source code — finds logic bugs, injection patterns, use of unsafe functions. Does not need the app to run. Misses runtime-only issues.

    **SCA (Software Composition Analysis):** reads dependency manifests (package.json, requirements.txt, go.mod) — finds known CVEs in third-party libraries. Does not analyze your own code logic.

    You need both: SAST catches your bugs, SCA catches bugs in libraries you use.

??? note "What is IAST?"
    **IAST (Interactive Application Security Testing):** an agent runs inside your application during functional testing. It monitors real code execution and identifies vulnerabilities from the inside — catching things SAST and DAST miss. More accurate than both but requires a running app and agent integration. Tools: Contrast Security, Seeker, HCL AppScan. Not tested as heavily as SAST/DAST on CDP but good to know.

---

## Domain 4: DevSecOps Metrics (Exam Favourite)

The CDP exam tests whether you know how to measure the effectiveness of a DevSecOps program.

```
Key DevSecOps Metrics:

Mean Time to Detect (MTTD):
  How long from a vulnerability existing to it being detected?
  Target: minutes (automated scanning) vs months (manual pen testing)

Mean Time to Remediate (MTTR):
  How long from detection to the fix being deployed?
  Target: < 24 hours for CRITICAL, < 7 days for HIGH

Escape Rate:
  % of vulnerabilities that reach production vs caught in pipeline
  Formula: (prod vulns / (pipeline vulns + prod vulns)) × 100
  Target: < 5% escape rate

False Positive Rate:
  % of pipeline alerts that are not real vulnerabilities
  High FPR → developers start ignoring gates → gates become useless
  Target: < 20% for SAST tools, < 10% for SCA

Security Gate Bypass Rate:
  % of PRs that skip or bypass security gates
  Any bypass should be logged, reviewed, and approved
  Target: 0% unreviewed bypasses

Security Debt:
  Total count of known vulnerabilities × severity weight
  Trends up or down each sprint — a DevSecOps team tracks this like tech debt
```

---

## Domain 5: Practice Questions (CDP Level)

??? note "Q1: A developer's PR fails Gate 1 (Semgrep) for a finding that is a false positive. What is the correct process?"
    1. Developer documents why the finding is a false positive (adds a code comment or Semgrep ignore annotation)
    2. A second reviewer confirms the annotation is legitimate
    3. Developer adds `# nosemgrep: rule-id` comment on the flagged line (or adds an entry to `.semgrepignore`)
    4. The finding is suppressed for that specific location only — not globally
    5. The suppression and its justification are recorded in a PR comment for audit trail

    **Never:** turn off the rule entirely, bypass the gate without documentation, or suppress the finding globally.

??? note "Q2: Your organization's security team wants proof that the Docker images in ECR were built from the approved pipeline and not uploaded manually. How?"
    Implement **SLSA provenance attestations** using `actions/attest-build-provenance`. Every image build generates a signed statement linking the image digest to the exact GitHub Actions run, workflow file, and commit SHA. Anyone can verify with `gh attestation verify`. Enable ECR's **image tag immutability** and **scan on push** to prevent overwriting a signed image.

??? note "Q3: A GitHub Actions workflow needs to push to ECR. What is the most secure way to provide AWS credentials?"
    Use **OIDC (OpenID Connect)** — not static AWS access keys. GitHub Actions can request a short-lived AWS token via OIDC without storing any secrets. The token is valid only for the duration of the workflow run. Configure with `aws-actions/configure-aws-credentials` and `role-to-assume`. The IAM role has a trust policy that validates the GitHub OIDC provider and constrains which repos/branches can assume it.

??? note "Q4: What is the difference between a security gate (blocking) and a security scan (advisory)?"
    A **gate** has `exit-code: 1` or `fail_action: true` — if findings exist, the pipeline stops and the PR cannot merge. A **scan** (advisory mode) always exits 0, uploads results for review, but doesn't block. Most teams start new gates in advisory mode to establish a baseline, then switch to blocking once the false positive rate is low enough to trust.

??? note "Q5: A team discovers that a secret was committed 60 commits ago and is present throughout the git history. What are the steps?"
    1. **Rotate immediately** — assume the secret is compromised regardless of who has access to the repo
    2. **Revoke and reissue** the credential (API key, cert, password)
    3. **Audit usage** — check CloudTrail/access logs for any calls using the leaked credential
    4. **Purge from history** using `git filter-repo` (or BFG Repo-Cleaner) to rewrite commits removing the secret
    5. **Force push** the cleaned history (after team coordination — this rewrites all SHAs)
    6. **Enable Gitleaks pre-commit hook** and GitHub Secret Scanning to prevent recurrence

??? note "Q6: How does Checkov integrate into a DevSecOps workflow versus running it manually?"
    Manually: a developer runs `checkov -d .` locally before committing. Depends on discipline — easy to forget or skip. No visibility to team.

    In CI/CD: Checkov runs automatically in Gate 3 on every PR that changes `.tf` files. Results are uploaded to GitHub's Security tab as SARIF, visible to all reviewers. The gate blocks merge if findings exist. No human needs to remember to run it. Results are stored, auditable, and consistent across developers.

---

## Study Resources

| Resource | Best For | Cost |
|---|---|---|
| [DevSecOps Institute CDP page](https://www.devsecopsinstitute.com/certifications/cdp/) | Official exam guide + syllabus | Free |
| [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/) | Framework reference | Free |
| [SLSA.dev](https://slsa.dev) | Supply chain security framework | Free |
| [GitHub Actions security hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions) | Official hardening guide | Free |
| Your own `iron-bank-pipeline` repo | Walk through each gate and explain it | Free |

---

## Checklist

- [ ] CDP exam domains listed from memory — can explain each in one sentence
- [ ] STRIDE applied to a CI/CD pipeline — 2 threats per STRIDE category identified
- [ ] Know why pinning actions to SHA is more secure than using a tag
- [ ] SLSA levels 1-4 explained — know which level GitHub Actions achieves
- [ ] SAST vs SCA vs DAST vs IAST — one-sentence distinction for each
- [ ] 5 DevSecOps metrics named — MTTD, MTTR, Escape Rate, FPR, Gate Bypass Rate
- [ ] All 6 practice questions answered without looking at the answers
- [ ] CDP exam booked (or date confirmed)
- [ ] No AWS resources running — bill $0

