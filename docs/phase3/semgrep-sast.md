# Month 8 — Week 1: Semgrep (SAST)

!!! abstract "💰 Cost: $0 — Runs locally, no cloud resources"

!!! info "Background Context"
    SAST (Static Application Security Testing) is the "find the bug before it ships" discipline. You've been finding vulnerabilities manually in Juice Shop — Semgrep automates that same analysis across an entire codebase in seconds. This is what "shift-left security" means on a DevSecOps job description.

---

## What Is SAST?

SAST analyses source code **without running it** — it reads the code the same way a security reviewer would, but at machine speed across thousands of files.

| | SAST | DAST (Week 2) |
|---|---|---|
| **When** | Before deployment — on code | After deployment — on running app |
| **What it needs** | Source code | A running URL |
| **Finds** | Code-level bugs: SQLi patterns, hardcoded secrets, unsafe functions | Runtime bugs: actual exploitable vulnerabilities |
| **False positives** | Higher — can't see runtime context | Lower — it actually exploits the issue |
| **Speed** | Fast — runs in CI on every commit | Slower — needs to probe all endpoints |

**Semgrep** is the most popular open-source SAST tool. It uses pattern-matching rules to find security bugs across 30+ languages. It's what companies like Dropbox, Figma, and GitLab use internally.

---

## Part 1: Install Semgrep

```bash
# Install via pip
pip install semgrep --break-system-packages

# Verify
semgrep --version   # Should show 1.x

# Or run via Docker (no install needed)
docker run --rm -v "${PWD}:/src" returntocorp/semgrep semgrep --version
```

---

## Part 2: Download Juice Shop Source Code

```bash
# Clone Juice Shop so you have real source code to scan
git clone https://github.com/juice-shop/juice-shop.git ~/projects/juice-shop-src
cd ~/projects/juice-shop-src
ls
# You'll see: frontend/, lib/, routes/, models/, config/ etc.
```

---

## Part 3: Your First Scan — Auto-detect Rules

Semgrep has a free registry of thousands of community and official rules at [semgrep.dev/r](https://semgrep.dev/r).

```bash
cd ~/projects/juice-shop-src

# ─── Scan with the OWASP Top 10 rule pack ────────────────────────────────────
semgrep --config "p/owasp-top-ten" .
# Downloads rules, scans all JS/TS files, prints findings

# ─── Scan with the JavaScript security rule pack ──────────────────────────────
semgrep --config "p/javascript" .

# ─── Scan for secrets (hardcoded passwords, API keys) ────────────────────────
semgrep --config "p/secrets" .

# ─── Run all three together and save to a report ──────────────────────────────
semgrep \
  --config "p/owasp-top-ten" \
  --config "p/javascript" \
  --config "p/secrets" \
  --json \
  --output ~/projects/semgrep-report.json \
  .

# Count findings by severity
cat ~/projects/semgrep-report.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('results', [])
from collections import Counter
severities = Counter(r['extra']['severity'] for r in results)
print(f'Total findings: {len(results)}')
for sev, count in sorted(severities.items()):
    print(f'  {sev}: {count}')
"
```

---

## Part 4: Read a Finding

Semgrep output looks like this — learn to interpret it:

```
/home/user/projects/juice-shop-src/routes/login.js
  javascript.lang.security.audit.sqli.node-sequelize-injection.node-sequelize-injection
    User-controlled data flows into a Sequelize query without sanitization.
    This could result in SQL injection.

    31┆ models.User.findOne({where: {email: req.body.email}})

    Autofix: Use parameterized queries instead.
```

Breaking it down:
- **File + line:** `routes/login.js:31` — exactly where the bug is
- **Rule ID:** identifies which rule triggered and why
- **Description:** plain English explanation of the risk
- **Code snippet:** the actual vulnerable line
- **Autofix:** Semgrep sometimes suggests the fix

```bash
# Look at the actual vulnerable line in context
sed -n '25,40p' ~/projects/juice-shop-src/routes/login.js
# You'll recognise this — it's the same login route you exploited in Month 7!
```

---

## Part 5: Write Custom Rules

This is what separates a junior from a senior AppSec engineer — writing rules for your organisation's specific patterns.

!!! info "You are writing YAML, not JavaScript"
    Semgrep rules are written in **YAML** — the same format you've already used for GitHub Actions workflows and Terraform outputs. The rules *describe patterns to look for inside JavaScript or Python code*, but you're not writing JavaScript yourself. Think of it like writing a search query: you describe what a bad code pattern looks like, and Semgrep finds it in someone else's code.

    The `languages: [javascript, typescript]` line just tells Semgrep *which type of files* to scan. You're still writing YAML.

```bash
mkdir -p ~/projects/iron-bank-semgrep/rules
```

**Rule 1 — Detect `eval()` usage (code injection risk):**

```yaml
# ~/projects/iron-bank-semgrep/rules/no-eval.yml
# This YAML rule tells Semgrep: "scan JavaScript files and flag any use of eval()"
# eval() is a dangerous JavaScript function that executes arbitrary code from a string.
# When user input reaches eval(), it's a critical security vulnerability.
rules:
  - id: no-eval
    pattern: eval(...)    # The pattern to look for: any call to eval() with any arguments (...)
    message: |
      eval() executes arbitrary code from a string — never use with user input.
      Remediation: if parsing JSON data, use JSON.parse() instead of eval().
    languages: [javascript, typescript]   # Scan JavaScript and TypeScript files
    severity: ERROR
    metadata:
      category: security
      owasp: "A03:2021 - Injection"
      cwe: "CWE-95: Improper Neutralisation of Directives in Dynamically Evaluated Code"
```

**Rule 2 — Detect hardcoded passwords:**

```yaml
# ~/projects/iron-bank-semgrep/rules/no-hardcoded-password.yml
# This rule looks for JavaScript/Python variable assignments where the variable name
# contains "password", "secret", "api_key", etc. and the value is a hardcoded string.
# The $VAR is a metavariable — it matches ANY variable name (like a wildcard).
rules:
  - id: no-hardcoded-password
    patterns:
      - pattern-either:             # Match ANY of these patterns:
          - pattern: const $VAR = "..."    # const password = "abc123"  (JavaScript)
          - pattern: let $VAR = "..."      # let secret = "abc123"      (JavaScript)
          - pattern: var $VAR = "..."      # var api_key = "abc123"     (older JavaScript)
          - pattern: $VAR = "..."          # password = "abc123"        (Python)
      - pattern-regex: "(?i)(password|passwd|secret|api_key|token)\\s*=\\s*['\"][^'\"]{6,}"
      # pattern-regex = regular expression matching. (?i) = case-insensitive.
      # This regex looks for: variable names containing "password/secret/token" assigned to a string value
    message: |
      Hardcoded credential detected. Move to environment variables or AWS Secrets Manager.
      Never commit credentials to source control — even in test/dev code.
    languages: [javascript, typescript, python]
    severity: ERROR
    metadata:
      category: security
      owasp: "A02:2021 - Cryptographic Failures"
```

**Rule 3 — Flag SQL string concatenation:**

```yaml
# ~/projects/iron-bank-semgrep/rules/no-sql-concat.yml
# This rule finds SQL queries built by joining strings together — a classic SQLi pattern.
# The "..." in the pattern matches any string content.
# $USERINPUT matches any variable (a metavariable — starts with $).
rules:
  - id: no-sql-string-concat
    pattern: $QUERY = "SELECT ..." + $USERINPUT
    message: |
      SQL built with string concatenation is vulnerable to injection.
      Remediation: use parameterised queries (also called prepared statements).
      Example (Python): cursor.execute("SELECT * WHERE id = ?", [user_id])
    languages: [javascript, typescript, python]
    severity: ERROR
    metadata:
      category: security
      owasp: "A03:2021 - Injection"
```

```bash
# Test your custom rules against Juice Shop
semgrep --config ~/projects/iron-bank-semgrep/rules/ ~/projects/juice-shop-src/

# Validate rule syntax
semgrep --validate --config ~/projects/iron-bank-semgrep/rules/
```

---

## Part 6: Pre-commit Hook

A pre-commit hook runs Semgrep automatically on every `git commit` — blocking code with findings from entering the repo.

```bash
cd ~/projects/iron-bank-semgrep
pip install pre-commit --break-system-packages

cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        args:
          - --config=p/owasp-top-ten
          - --config=rules/
          - --error
          - --severity=ERROR
EOF

git init
pre-commit install

# Test it manually
pre-commit run --all-files
```

---

## 🧹 Cleanup

```bash
# No cloud resources — just commit your work to GitHub
cd ~/projects/iron-bank-semgrep
git add -A
git commit -m "feat: custom Semgrep rules — Month 8 Week 1"
git push

# Optional: remove Juice Shop source clone to save disk space
rm -rf ~/projects/juice-shop-src

echo "✅ Week 1 complete — no cloud resources used"
```

---

## Checklist

- [ ] Semgrep installed — `semgrep --version` works
- [ ] Juice Shop source cloned and scanned with `p/owasp-top-ten`
- [ ] Can read a finding and identify: file, line, rule, risk
- [ ] Found the SQLi finding in `routes/login.js` — matches what you exploited manually
- [ ] JSON report generated and finding counts parsed with Python
- [ ] At least **3 custom Semgrep rules** written, validated, and tested
- [ ] Pre-commit hook installed and tested
- [ ] Custom rules committed to GitHub as `iron-bank-semgrep`

