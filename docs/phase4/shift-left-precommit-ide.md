# Month 10 — Special: Shift Left Further — Security in DevOps

!!! abstract "💰 Cost: Free (GitHub Actions, pre-commit hooks, IDE plugins all free)"

!!! danger "Why Shift Left Matters"
    Phase 4 m10 taught DevSecOps (security gates in CI/CD). This expansion teaches **ultra-left shift**: catching vulnerabilities BEFORE code reaches CI/CD. When a developer types code in VS Code, they get real-time security warnings. When they `git commit`, pre-commit hooks validate secrets, SAST, linting. When they plan sprints, threat modeling is built into acceptance criteria. Result: fewer vulnerabilities escape to production, faster feedback loops (seconds vs. minutes), and security becomes a developer responsibility, not a gate team bottleneck.

!!! info "Background Context"
    Phase 4 m10 taught security gates (shift-right: catch issues in CI/CD). This expansion teaches shift-left: prevent issues before code is written. Together: shift-left (prevent) + shift-right (detect) = defense in depth.

---

## Part 1: Pre-Commit Hooks for Security Validation

Pre-commit hooks run BEFORE `git commit` succeeds. No secrets, no unformatted code, no known CVEs allowed.

### Install Pre-Commit Framework

```bash
# Install pre-commit framework (language-agnostic)
pip install pre-commit --break-system-packages

# Create .pre-commit-config.yaml in repo root
cat > .pre-commit-config.yaml << 'EOF'
# Pre-commit hooks: security + code quality

repos:
  # 1. GitLeaks: Detect secrets (AWS keys, Stripe API keys, etc.)
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
        name: Detect secrets with Gitleaks
        entry: gitleaks protect --verbose --redact --staged
        language: system
        stages: [commit]
        pass_filenames: false

  # 2. YAML Lint: Validate YAML structure
  - repo: https://github.com/adrienverge/yamllint
    rev: v1.32.0
    hooks:
      - id: yamllint
        name: Lint YAML files
        args: [--strict]

  # 3. JSON validation
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: check-json
      - id: check-yaml
      - id: check-ast
      - id: detect-private-key
      - id: mixed-line-ending

  # 4. Semgrep (SAST): Detect code vulnerabilities
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        args: ['--config=p/security-audit', '--error']
        types: [python, javascript, typescript, go, java]

  # 5. Trivy: Check dependencies for known CVEs
  - repo: https://github.com/aquasecurity/trivy
    rev: v0.46.0
    hooks:
      - id: trivy
        name: Scan for CVEs with Trivy
        entry: trivy fs --exit-code 1 --no-progress
        language: system
        types: [file]

  # 6. TFSec: Terraform security scanning
  - repo: https://github.com/aquasecurity/tfsec
    rev: v1.28.0
    hooks:
      - id: tfsec
        name: Scan Terraform for security issues
        entry: tfsec
        language: system
        types: [terraform]

  # 7. Bandit: Python security linter
  - repo: https://github.com/PyCPA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ['-c', '.bandit']
        types: [python]

  # 8. Black: Code formatter (consistency prevents bugs)
  - repo: https://github.com/psf/black
    rev: 23.12.0
    hooks:
      - id: black
        language_version: python3.11

  # 9. Pylint: Python linter
  - repo: https://github.com/pylint-dev/pylint
    rev: pylint-3.0.0
    hooks:
      - id: pylint
        args: [--disable=all, --enable=E,F]  # Only errors + fatal
        types: [python]

# Global settings
default_language_version:
  python: python3.11

# Run only on staged files (fast feedback)
stages:
  - commit
  - push
EOF

# Install the hooks
pre-commit install

# (Optional) Run against all files (useful first-time setup)
pre-commit run --all-files
```

### Example Hook Run

```bash
# Developer tries to commit AWS key
$ git add -A
$ git commit -m "Add new feature"

Running hook: Detect secrets with Gitleaks...
❌ FAILURE: Secret detected!
   File: config.py
   Pattern: AWS_ACCESS_KEY = "AKIA2P..."
   Remediation: Remove the key, use environment variables instead

# Pre-commit BLOCKS the commit
error: commit failed due to pre-commit hook failure

# Developer fixes it
$ cat config.py
# Before:
# AWS_ACCESS_KEY = "AKIA2P..."
# After:
aws_key = os.environ['AWS_ACCESS_KEY']

$ git add config.py
$ git commit -m "Add new feature"

Running hook: Detect secrets with Gitleaks...
✅ PASS

Running hook: Lint YAML files...
✅ PASS

Running hook: Scan for CVEs with Trivy...
❌ FAILURE: Known vulnerability found!
   Dependency: requests==2.28.0
   CVE-2023-32681: Requests vulnerable to HTTP header injection
   Fix: requests>=2.31.0

# Developer updates requirements.txt
$ pip install requests==2.31.0
$ git add requirements.txt
$ git commit -m "Add new feature"

All hooks passed ✅
[main abc123def] Add new feature
 3 files changed, 25 insertions(+)

# Commit succeeds!
```

### Hook Configuration Files

Create `.bandit` for Python security:
```yaml
# .bandit — Bandit configuration

tests:
  - B101  # assert_used
  - B601  # paramiko_calls
  - B602  # shell_injection
  - B603  # subprocess_without_shell_equals_true
  - B607  # start_process_with_partial_path

exclude_dirs:
  - tests/
  - venv/
```

Create `semgrep.yml` for custom SAST rules:
```yaml
# semgrep.yml — Custom Semgrep rules

rules:
  - id: no-hardcoded-secrets
    pattern-either:
      - pattern: 'AWS_SECRET = "..."'
      - pattern: 'DATABASE_PASSWORD = "..."'
      - pattern: 'API_KEY = "..."'
    message: "Hardcoded secret detected"
    severity: ERROR

  - id: no-sql-injection
    pattern: 'db.query($USER_INPUT)'
    message: "Potential SQL injection: use parameterized queries"
    severity: ERROR

  - id: no-eval
    pattern: 'eval(...)'
    message: "eval() is dangerous. Use safer alternatives."
    severity: ERROR
```

---

## Part 2: IDE Plugins for Real-Time Security Warnings

As developers type, their IDE shows security warnings before code is saved.

### VS Code Setup

Install security extensions:

```bash
# Git in VS Code
code --install-extension eamodio.gitlens

# Security linting
code --install-extension GitHub.copilot-nightly  # AI code review
code --install-extension sonarsource.sonarlint-vscode  # SAST in-editor
code --install-extension ms-python.python  # Pylint integration
code --install-extension ms-vscode.makefile-tools  # Makefile support

# Cloud security
code --install-extension AmazonWebServices.aws-toolkit-vscode
code --install-extension HashiCorp.terraform
```

### .vscode/settings.json

Configure VS Code to highlight security issues inline:

```json
{
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": true,
  "python.linting.pylintArgs": ["--disable=all", "--enable=E,F"],
  "python.linting.banditEnabled": true,
  "python.linting.banditArgs": ["-r", "."],
  
  "sonarlint.rules": {
    "python:S101": "on",   // Duplicate code
    "python:S3776": "on",  // Cognitive complexity
    "python:S1143": "on",  // Return in finally
  },
  
  "[python]": {
    "editor.defaultFormatter": "ms-python.python",
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
      "source.fixAll.pylint": true,
      "source.fixAll.bandit": true
    }
  },
  
  "git.ignoreMissingGitWarning": false,
  "gitlens.hovers.currentLine.enabled": false
}
```

### Real-Time Warnings Example

Developer types vulnerable code:

```python
# In VS Code, developer types:
import sqlite3

def get_user(username):
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = {username}"  # ❌ SQL injection!
    cursor.execute(query)
    return cursor.fetchall()

# IDE warnings appear immediately:
❌ Line 5: SonarLint — Potential SQL injection detected
   Use parameterized queries: cursor.execute(?, ?) or f-string validation
   
❌ Line 3: Pylint — Unused import 'sqlite3'

✅ Suggestion: Replace with safe query
   cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

IDE can auto-fix with one click:

```python
# After IDE auto-fix:
def get_user(username):
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))  # ✅ Safe!
    return cursor.fetchall()
```

---

## Part 3: Threat Modeling in Sprint Planning

Every sprint includes security acceptance criteria based on threat models.

### Threat Modeling User Story

Incorporate threat modeling into JIRA/Azure DevOps stories:

```markdown
# Story: User Registration API

## Acceptance Criteria
[ ] Passwords encrypted with bcrypt (salt rounds >= 12)
[ ] Email verified (prevent spam registration)
[ ] Rate limiting: max 10 registrations/minute per IP
[ ] No PII in logs (error messages shouldn't expose email)

## Security Acceptance Criteria (from threat model)
Threat: Account takeover via password guessing
[ ] Implement max 5 failed login attempts → 15-min lockout
[ ] Log failed login attempts to CloudWatch
[ ] Alert on 10+ failed logins in 5 minutes

Threat: Credential stuffing (attacker tries known leaked passwords)
[ ] Check password against Have I Been Pwned database
[ ] Reject passwords on breached list
[ ] Notify user if their password appears in breach database

Threat: API abuse
[ ] Rate limit registration endpoint (10/min per IP)
[ ] CAPTCHA after 3 failed attempts
[ ] Log all registrations to audit table

## Definition of Done
- [ ] All acceptance criteria met
- [ ] All security acceptance criteria met
- [ ] Pre-commit hooks pass (no secrets, SAST clean)
- [ ] Unit tests cover threat scenarios
- [ ] Deployed to staging, tested by security team
- [ ] No new CVEs introduced (Trivy scan passes)
```

### Threat Modeling Template (STRIDE)

Every sprint, team reviews stories through STRIDE lens:

```yaml
# Sprint Planning: Threat Model for "Payment Processing"

Threat: Spoofing (attacker impersonates legitimate user)
  Existing Control: JWT tokens with RS256 signature
  Test Case: Can attacker forge a JWT? No (RSA signature required)
  New Control Needed? No

Threat: Tampering (attacker modifies transaction amount)
  Existing Control: HTTPS + signature verification
  Test Case: Attacker modifies transaction JSON → signature fails ✅
  New Control Needed? No

Threat: Repudiation (user denies making transaction)
  Existing Control: Audit log of all payments
  Test Case: Transaction logged with timestamp + user ID ✅
  New Control Needed? No

Threat: Information Disclosure (attacker reads transaction data)
  Existing Control: HTTPS encryption in transit
  Test Case: Database encryption at rest? Currently NO ❌
  New Control Needed? YES → Implement AWS KMS encryption for payment DB
           Story: "Encrypt payment database with KMS"
           Effort: 8 hours
           Sprint: Q2

Threat: Denial of Service (attacker floods payment API)
  Existing Control: Rate limiting (100 req/min per user)
  Test Case: Send 200 requests/min → error after 100 ✅
  New Control Needed? Consider DDoS mitigation (WAF, CloudFront)

Threat: Elevation of Privilege (attacker gains admin access)
  Existing Control: IAM roles (users can't call admin APIs)
  Test Case: Regular user calls CreateAdminUser → AccessDenied ✅
  New Control Needed? No
```

---

## Part 4: Security Training in Onboarding

New developers learn security practices on day 1.

### Developer Onboarding Checklist

```markdown
# Day 1: Security Onboarding

## Environment Setup
- [ ] Install pre-commit hooks (run: pre-commit install)
- [ ] Verify hook runs on git commit (try committing a test file)
- [ ] Install VS Code security extensions (SonarLint, GitLeaks)
- [ ] Configure .vscode/settings.json (copy from repo)

## Security Training (30 min)
- [ ] Read SECURITY.md (1 page overview of company security practices)
- [ ] Watch: "How Pre-Commit Hooks Catch Secrets" (2 min video)
- [ ] Watch: "OWASP Top 10 for Backend Developers" (10 min)

## First Commit
- [ ] Clone repo
- [ ] Create feature branch
- [ ] Make a test code change
- [ ] Commit: `git commit -m "test"`
- [ ] Verify: Pre-commit hooks run automatically
- [ ] Verify: IDE shows security warnings (try creating a hardcoded password)

## Resources
- [ ] Bookmarked: Internal security wiki (threat models, vulnerabilities, incident reports)
- [ ] Access: Vault for local development secrets (AWS keys, DB passwords, API keys)
- [ ] Contact: Security team on Slack #security-dev-help

## Compliance
- [ ] Acknowledged: Code of conduct (no sharing secrets)
- [ ] Signed: Security training agreement (understand consequences of sharing secrets)
```

### SECURITY.md Template

Every repo includes a SECURITY.md file:

```markdown
# Security Guidelines

## Secret Management
- ❌ DON'T: Hardcode AWS keys, DB passwords, API keys
- ✅ DO: Use environment variables or AWS Secrets Manager
- ✅ DO: Use `vault` for local development

```bash
# Wrong:
AWS_KEY = "AKIA2P..."

# Right:
AWS_KEY = os.environ['AWS_ACCESS_KEY_ID']
```

## Code Review Security Checklist
Every PR review includes security checks:
- [ ] No hardcoded secrets (checked by pre-commit)
- [ ] No SQL injection (checked by Semgrep)
- [ ] No unsafe deserialization (checked by Bandit)
- [ ] No weak cryptography (checked by Semgrep)
- [ ] Dependencies scanned for CVEs (checked by Trivy)
- [ ] New endpoints have rate limiting
- [ ] New database access uses parameterized queries

## Reporting Vulnerabilities
Found a vulnerability? Report it to security@company.com (not GitHub issues, not Slack).
We follow responsible disclosure: fix in private, then disclose.

## Compliance
- PCI-DSS: No credit card data in logs or errors
- HIPAA: No PHI in logs
- SOC2: No customer data in test databases

## Contact
Questions? Slack #security-dev-help or email security@company.com
```

---

## Part 5: Shift-Left Metrics

Track how many vulnerabilities are caught at each shift-left stage.

```yaml
# Vulnerability Detection by Stage

Stage 1: Pre-Commit Hooks (Developer's machine)
  Vulnerabilities caught: Secrets, basic SAST, CVEs in dependencies
  Example catch: "Hardcoded AWS key"
  Effort to fix: 1 minute (developer removes key locally)
  
Stage 2: IDE / Code Review (Pull request)
  Vulnerabilities caught: Design flaws, missing validation, auth issues
  Example catch: "SQL injection in new endpoint"
  Effort to fix: 5 minutes (developer revises code)
  
Stage 3: CI/CD Gates (Automated tests)
  Vulnerabilities caught: Integration issues, deployment errors, policy violations
  Example catch: "Container image has 3 critical CVEs"
  Effort to fix: 15 minutes (developer updates dependencies)
  
Stage 4: Staging / Security Testing (QA environment)
  Vulnerabilities caught: Business logic flaws, real-world attack scenarios
  Example catch: "CORS policy allows any origin"
  Effort to fix: 30 minutes (developer adjusts security policies)
  
Stage 5: Production / Monitoring (Live system)
  Vulnerabilities caught: Edge cases, real attacks, configuration errors
  Example catch: "Attacker sending malformed JSON → crash"
  Effort to fix: 1-4 hours (incident response required)

## Goal: Shift Left
- Target: 70% vulnerabilities caught at Stages 1-2 (pre-commit + code review)
- Current: 40% caught pre-commit, 30% caught in CI/CD, 20% caught in production
- Action: Better pre-commit rules, security code review training, threat modeling in stories

## Metrics Dashboard

Total vulnerabilities fixed this quarter: 45
├─ Pre-commit (secrets, basic SAST): 18 (40%)  ← Target 70%
├─ Code review (design flaws): 12 (27%)
├─ CI/CD gates (policy violations): 8 (18%)
├─ Staging testing (business logic): 5 (11%)
└─ Production (real attacks): 2 (4%)

Trend: 
  Q1: 10% pre-commit, 5% code review, 30% CI/CD, 25% staging, 30% production (REACTIVE)
  Q2: 20% pre-commit, 15% code review, 25% CI/CD, 20% staging, 20% production (IMPROVING)
  Q3: 40% pre-commit, 30% code review, 15% CI/CD, 10% staging, 5% production (SHIFT-LEFT!)
```

---

## Part 6: Common Shift-Left Mistakes

What NOT to do:

```bash
# ❌ WRONG: Pre-commit hooks too strict (developers bypass them)
[pre-commit rules that fail 80% of commits]
→ Result: Developers disable pre-commit (git commit --no-verify)
→ Security defeated

# ✅ RIGHT: Pre-commit hooks target high-risk items only
[Only: secrets, critical SAST, obvious CVEs]
→ Result: Developers respect hooks, don't bypass
→ Security maintained

---

# ❌ WRONG: Pre-commit hooks too slow (developers wait 5+ minutes)
[Running full test suite in pre-commit]
→ Result: Developers get annoyed, disable hooks
→ Security defeated

# ✅ RIGHT: Pre-commit hooks run fast (<10 seconds)
[Secrets check, quick SAST, dependency scan on changes only]
→ Result: Developers don't mind the wait
→ Security maintained

---

# ❌ WRONG: Security training once per year
[Annual compliance training on security]
→ Result: Developers forget by next sprint
→ Security debt accumulates

# ✅ RIGHT: Security training integrated into sprint
[Threat modeling in story planning, security in code review, incident learning in retro]
→ Result: Security becomes team culture
→ Security debt prevented

---

# ❌ WRONG: IDE plugins not configured
[SonarLint installed but not reporting errors]
→ Result: Developers don't see security warnings
→ Vulnerabilities ship

# ✅ RIGHT: IDE plugins configured with team rules
[SonarLint + .sonarlint config in repo, errors highlighted red]
→ Result: Developers fix issues immediately
→ Vulnerabilities prevented
```

---

## 🧹 Cleanup

```bash
# Pre-commit and IDE setup are permanent
# No cleanup needed (they're part of your development workflow)

echo "✅ Shift-Left security setup complete"
```

---

## Checklist

**Pre-Commit Hooks**
- [ ] Install pre-commit framework: `pip install pre-commit`
- [ ] Create .pre-commit-config.yaml with 9 hooks (GitLeaks, SAST, CVE scanning, TFSec, etc.)
- [ ] Run `pre-commit install` in repo
- [ ] Test: Try committing a test secret → hook blocks it ✅
- [ ] Document: Add to onboarding (new developers run pre-commit install)

**IDE Security Plugins**
- [ ] Install: SonarLint, Pylint, AWS Toolkit, Terraform extensions
- [ ] Configure .vscode/settings.json with security rules
- [ ] Test: Type vulnerable code → see warning in editor ✅
- [ ] Team training: Show new developers IDE warnings live

**Threat Modeling in Sprints**
- [ ] Add "Security Acceptance Criteria" field to story template (JIRA/Azure DevOps)
- [ ] Include threat model (STRIDE) in sprint planning (15-30 min per epic)
- [ ] Create new stories for security controls (e.g., "Encrypt DB with KMS")
- [ ] Security team reviews stories before sprint starts

**Developer Onboarding**
- [ ] Create SECURITY.md (1-page guidelines)
- [ ] Create onboarding checklist (includes pre-commit setup + security training)
- [ ] Record 2-3 min security training videos (secrets, OWASP, common vulns)
- [ ] New developers complete checklist on day 1 (manager verifies)

**Shift-Left Metrics**
- [ ] Dashboard: % vulnerabilities caught at each stage (pre-commit, code review, CI/CD, staging, production)
- [ ] Target: 70% caught pre-commit + code review
- [ ] Monthly review: Are metrics improving? Which stages need help?
- [ ] Team discussion: Celebrate shift-left wins (e.g., "We caught SQL injection before it reached production")

---

## Integration with Phase 4

This shift-left expansion strengthens:
- **Phase 4 m10-week1:** GitHub Actions → pre-commit hooks (local CI/CD)
- **Phase 4 m10-week2:** SAST in CI/CD → SAST in IDE (earlier detection)
- **Phase 4 m10-week3:** Container scanning → pre-commit CVE scanning (shift left)
- **Phase 4 policy-as-code-opa-sentinel:** Policy enforcement → IDE policy hints
- **Phase 4 m12-week3:** IR capstone → prevent incidents via shift-left practices

---

## Real-World Scenarios

**Scenario 1: Shift-Left Catches Credential Leak**
```
10:30 Developer writes code with hardcoded AWS key
10:31 Developer tries git commit
     ❌ Pre-commit hook: GitLeaks detects secret
     Hook blocks commit
10:32 Developer removes key, uses environment variable instead
10:33 git commit succeeds
     Code never reaches GitHub (secret never exposed)
Result: Credential leak prevented entirely (cost: 2 minutes dev time)
```

**Scenario 2: IDE Warns of SQL Injection**
```
14:00 Developer types vulnerable query in VS Code
14:00 IDE shows red warning: "SQL injection risk"
14:01 Developer clicks SonarLint suggestion: "Use parameterized query"
14:02 IDE auto-fixes code to safe version
14:03 Developer tests fix locally
14:05 git commit (pre-commit passes)
Result: Vulnerability fixed before code review (cost: 5 minutes)
       vs. finding in security test (cost: 1 hour + PR revision)
```

**Scenario 3: Threat Modeling in Sprint Prevents Design Flaw**
```
Sprint Planning meeting:
Team discusses: "New endpoint for resetting user password"

Security lead asks: "Did we threat model this?"
Team applies STRIDE:
  - Spoofing: How do we verify it's really the user?
    Solution: Send reset link to email, user clicks link + verifies
  - Tampering: Can attacker change password for other users?
    Solution: Token is unique per reset + contains user ID
  - Elevation of Privilege: Can user reset admin password?
    Solution: Check permissions before allowing reset

Team adds security stories:
  "Implement password reset flow with token-based verification"
  "Test: Attacker cannot reset other user's password"
  "Test: Admin users protected from reset if not authorized"

Result: Design flaws prevented before coding (cost: 30 min discussion)
       vs. finding in security review (cost: 4 hours redesign)
```

You now have **comprehensive shift-left security**. 🚀

