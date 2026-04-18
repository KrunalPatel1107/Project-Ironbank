# Month 8 — Week 2: OWASP ZAP (DAST)

!!! abstract "💰 Cost: $0 — ZAP runs in Docker locally"

!!! info "Background Context"
    DAST (Dynamic Application Security Testing) is automated penetration testing. In Week 2 of Month 7 you manually exploited Juice Shop — ZAP automates those same probes across every endpoint simultaneously. This is what AppSec teams run nightly against staging environments.

---

## What Is DAST?

DAST probes a **running application** from the outside — exactly like an attacker would. It sends crafted inputs to every endpoint, URL parameter, and form field, then checks responses for signs of vulnerability.

| | SAST (Week 1) | DAST |
|---|---|---|
| **Input** | Source code | Running app URL |
| **Finds** | Code-pattern bugs | Actually exploitable runtime issues |
| **False positives** | More common | Fewer — it proves exploitability |
| **Best run** | On every commit (CI) | On every deployment (CD staging) |
| **Blind spots** | Runtime context, logic flaws | Code not reachable via HTTP |

**OWASP ZAP** (Zed Attack Proxy) is the industry-standard open-source DAST tool, maintained by OWASP. It's free, extensible, and has both a GUI and a CLI/API for automation.

---

## Part 1: Start ZAP and Juice Shop via Docker

```bash
# ─── Start Juice Shop (the target) ───────────────────────────────────────────
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
# -d = detached (runs in background)
echo "Juice Shop starting at http://localhost:3000"

# ─── Start ZAP in daemon mode (headless — no GUI) ─────────────────────────────
docker run -d --name zap \
  --network host \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon \
  -port 8090 \
  -config api.disablekey=true \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true
# --network host = ZAP can reach localhost:3000
# api.disablekey=true = no API key needed for lab (never in production)

# Wait for ZAP to be ready (takes ~30 seconds)
sleep 30
echo "ZAP API ready at http://localhost:8090"

# Verify ZAP is running
curl -s http://localhost:8090/JSON/core/view/version/ | python3 -m json.tool
# Should show ZAP version
```

---

## Part 2: Baseline Scan (Passive — Read-Only)

A **baseline scan** is passive — ZAP spiders the application and looks for security issues in responses without sending any attack payloads. Safe to run against production.

```bash
# ─── Run a baseline scan via ZAP Docker (easiest method) ─────────────────────
docker run --rm --network host \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t http://localhost:3000 \
  -r /zap/wrk/baseline-report.html \
  -J /zap/wrk/baseline-report.json \
  -l WARN

# The report is inside the container — copy it out
docker cp zap:/zap/wrk/baseline-report.html ~/projects/zap-baseline-report.html
docker cp zap:/zap/wrk/baseline-report.json  ~/projects/zap-baseline-report.json

# Open the HTML report in your browser
# On WSL: explorer.exe ~/projects/zap-baseline-report.html
# On macOS: open ~/projects/zap-baseline-report.html

# Count alerts by risk level
cat ~/projects/zap-baseline-report.json | python3 -c "
import json, sys
from collections import Counter
data = json.load(sys.stdin)
risks = Counter(alert['risk'] for alert in data.get('site', [{}])[0].get('alerts', []))
for risk, count in sorted(risks.items()):
    print(f'{risk}: {count}')
"
```

---

## Part 3: Active Scan (Attacks Enabled)

An **active scan** sends actual attack payloads — SQLi strings, XSS payloads, path traversal sequences — to every parameter. Only run against targets you own.

!!! warning "Only scan systems you own or have written permission to test"
    Running an active scan against any system you don't own is illegal. Juice Shop on localhost is your lab — fair game.

```bash
# ─── Full active scan via CLI ──────────────────────────────────────────────────
docker run --rm --network host \
  -v ~/projects:/zap/wrk \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py \
  -t http://localhost:3000 \
  -r zap-active-report.html \
  -J zap-active-report.json \
  -l WARN \
  -m 5    # Spider for 5 minutes max

# This takes 10–20 minutes — ZAP is probing every endpoint
# You'll see it discover URLs, submit forms, and test parameters

echo "Active scan complete — check ~/projects/zap-active-report.html"
```

---

## Part 4: API Scan (OpenAPI/Swagger)

Juice Shop exposes a Swagger spec — ZAP can use it to find and test every API endpoint automatically without spidering.

```bash
# ─── Download the Juice Shop OpenAPI spec ─────────────────────────────────────
curl -s http://localhost:3000/api-docs -o ~/projects/juice-shop-openapi.json
# Verify it's a valid JSON spec
cat ~/projects/juice-shop-openapi.json | python3 -m json.tool | head -20

# ─── Run ZAP API scan against the OpenAPI spec ────────────────────────────────
docker run --rm --network host \
  -v ~/projects:/zap/wrk \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py \
  -t /zap/wrk/juice-shop-openapi.json \
  -f openapi \
  -r zap-api-report.html \
  -J zap-api-report.json

echo "API scan complete"
```

---

## Part 5: Read and Triage Findings

ZAP findings have four risk levels. Know what each means:

| Risk | Action | Example Finding |
|---|---|---|
| **High** | Fix immediately | SQL Injection, Remote Code Execution |
| **Medium** | Fix this sprint | Missing security headers, CSRF |
| **Low** | Fix next sprint | Verbose error messages, cookie flags |
| **Informational** | Review, not necessarily fix | Cookies without Secure flag on HTTP |

```bash
# Parse the active scan JSON report and print High + Medium findings
python3 << 'EOF'
import json

with open('/root/projects/zap-active-report.json') as f:
    data = json.load(f)

alerts = data.get('site', [{}])[0].get('alerts', [])
for alert in alerts:
    risk = alert.get('risk', '')
    if risk in ('High', 'Medium'):
        print(f"[{risk.upper()}] {alert['alert']}")
        print(f"  URL:         {alert.get('instances', [{}])[0].get('uri', 'N/A')}")
        print(f"  Description: {alert['desc'][:100]}...")
        print(f"  Solution:    {alert['solution'][:100]}...")
        print()
EOF
```

---

## Part 6: ZAP in Automation (GitHub Actions Preview)

In Month 10 you'll add ZAP to your CI/CD pipeline. Here's what that step looks like — understand the pattern now:

```yaml
# .github/workflows/dast.yml (preview — you'll build this in Month 10)
- name: ZAP Baseline Scan
  uses: zaproxy/action-baseline@v0.10.0
  with:
    target: 'https://staging.yourapp.com'
    rules_file_name: '.zap/rules.tsv'   # Suppress known false positives
    issue_title: 'ZAP Baseline Scan'
    fail_action: true    # Fail the pipeline if High findings exist
```

---

## 🧹 Cleanup

```bash
docker stop juice-shop zap 2>/dev/null
docker rm   juice-shop zap 2>/dev/null
docker image rm bkimminich/juice-shop ghcr.io/zaproxy/zaproxy:stable 2>/dev/null

# Keep reports — commit them
mkdir -p ~/projects/security-toolkit/zap-reports
cp ~/projects/zap-*.html ~/projects/security-toolkit/zap-reports/ 2>/dev/null
cp ~/projects/zap-*.json ~/projects/security-toolkit/zap-reports/ 2>/dev/null

echo "✅ Containers removed — reports saved to security-toolkit"
```

---

## Checklist

- [ ] ZAP and Juice Shop running via Docker simultaneously
- [ ] Baseline scan completed — HTML report opened and reviewed
- [ ] Active scan completed — understand the difference from baseline
- [ ] API scan run against the Juice Shop OpenAPI spec
- [ ] At least 3 High or Medium findings read and understood (risk + solution)
- [ ] Understand when to use baseline vs active vs API scan
- [ ] ZAP GitHub Actions step read — understand what Month 10 pipeline will look like
- [ ] Reports saved to `security-toolkit/zap-reports/`
- [ ] All Docker containers stopped and removed

