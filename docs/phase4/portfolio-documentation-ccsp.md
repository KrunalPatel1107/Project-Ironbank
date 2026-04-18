# Month 12 — Week 4: Documentation, Portfolio & CCSP Exam

!!! abstract "💰 Cost: $599 CCSP exam fee + $0 AWS (no resources this week)"

!!! info "You Made It"
    This is the final week of the 12-month Iron Bank curriculum. This week has three objectives: (1) document everything you built in a way that demonstrates your capabilities to hiring managers, (2) take the CCSP exam, and (3) plan what comes next.

---

## Part 1: Portfolio Documentation

Your GitHub portfolio should tell a clear story: "I went from [your background] to full-stack Cloud/DevSecOps engineer in 12 months — here is the evidence."

### Repository Structure (Final State)

```
GitHub Profile: github.com/<your-username>
│
├── iron-bank-pipeline          ← Month 10: DevSecOps CI/CD pipeline
│   Five security gates, Makefile, full README
│
├── iron-bank-security-toolkit  ← Month 8: SAST/DAST/SCA toolkit
│   scan.sh, Makefile, custom Semgrep rules
│
├── iron-bank-tf                ← Month 5: Terraform infrastructure modules
│   VPC, ECS, Security Groups — reusable modules
│
├── juice-shop-writeups         ← Month 7: AppSec exploitation writeups
│   OWASP Top 10 labs, STRIDE threat model
│
└── iron-bank-fortress          ← Month 12: Capstone project (PRIVATE — costs money to run)
    Full architecture, cleanup scripts, CIS compliance scripts
```

### Polishing Each Repository

For each public repo, ensure:

```bash
# Check your public repos
gh repo list --public --limit 20 --json name,description,url | \
  python3 -c "
import json, sys
repos = json.load(sys.stdin)
for r in repos:
    desc = r.get('description') or '⚠️  NO DESCRIPTION'
    print(f'{r[\"name\"]:<40} {desc[:60]}')
"
# Every repo needs a description — add via GitHub repo Settings

# Check README quality for key repos
for repo in iron-bank-pipeline iron-bank-security-toolkit juice-shop-writeups; do
    echo "=== $repo ==="
    gh repo view $repo --json description,readme | \
      python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'Description: {d.get(\"description\", \"MISSING\")}')
readme = d.get('readme', {}).get('text', '')
print(f'README length: {len(readme)} chars ({'OK' if len(readme) > 500 else \"TOO SHORT\"})')
"
done
```

### Write Your GitHub Profile README

Create a special `<username>/<username>` repository — GitHub displays its README on your profile page:

```bash
mkdir -p ~/projects/github-profile
cat > ~/projects/github-profile/README.md << 'PROFILE'
# Hi, I'm [YOUR NAME] 👋

**Cloud Security | DevSecOps | AppSec**

[YOUR CURRENT TITLE] transitioning to Cloud-native and DevSecOps engineering.
12-month self-directed curriculum building every layer of the cloud security
stack from scratch.

## Certifications
- 🏅 AWS Certified Security Specialty (SCS-C03)
- 🏅 AWS Certified Solutions Architect Associate (SAA-C03)
- 🏅 AWS Certified Cloud Practitioner (CLF-C02)
- 🏅 Certified DevSecOps Professional (CDP)
- 🏅 CCSP — ISC2 Certified Cloud Security Professional
- 📘 [ADD YOUR EXISTING CERTIFICATIONS HERE]

## Featured Projects

### 🔒 [iron-bank-pipeline](https://github.com/YOUR_USERNAME/iron-bank-pipeline)
5-gate DevSecOps CI/CD pipeline — Semgrep → Gitleaks → Checkov → Trivy → ZAP.
Every PR automatically scanned. No vulnerable code reaches production.

### 🛡️ [iron-bank-security-toolkit](https://github.com/YOUR_USERNAME/iron-bank-security-toolkit)
Unified security scanner: SAST + DAST + SCA + secret detection in a single `scan.sh`.
Used Semgrep, OWASP ZAP, Trivy, and Gitleaks against OWASP Juice Shop.

### 📝 [juice-shop-writeups](https://github.com/YOUR_USERNAME/juice-shop-writeups)
Professional exploit writeups for OWASP Juice Shop — STRIDE threat model,
OWASP Top 10 (2021), API Security Top 10 (2023). Interview-ready AppSec demonstrations.

## What I Build

```text
Cloud Security      AWS IAM, SCPs, KMS, Secrets Manager, VPC, GuardDuty
Infrastructure      Terraform (modules, remote state, Checkov IaC scanning)
AppSec              OWASP Top 10, Burp Suite, ZAP, Semgrep, threat modelling
Container Security  Docker hardening, ECR, ECS Fargate, K8s RBAC/NetworkPolicy
DevSecOps           GitHub Actions CI/CD, security gates, shift-left automation
Compliance          CIS AWS Foundations Benchmark, AWS Config, Security Hub
```

## Background
[YOUR CURRENT ROLE] @ [YOUR CURRENT EMPLOYER] | [ADD PREVIOUS ROLES AS DESIRED]
PROFILE

echo "GitHub profile README created at ~/projects/github-profile/README.md"
echo "Create a repo named exactly '<your-username>' on GitHub, then push this file"
```

---

## Part 2: LinkedIn Profile Update

Key sections to update:

```
Headline (choose one):
  "Cloud Security Engineer | DevSecOps | AWS Security Specialty | CCSP"
  "Security Advisor → DevSecOps | AWS | Containers | CI/CD Pipeline Security"

Summary additions:
  - Built a complete DevSecOps pipeline with 5 automated security gates
  - Implemented CIS AWS Foundations Benchmark compliance automation
  - Hands-on with: Terraform, Docker, K8s, Semgrep, ZAP, Trivy, Gitleaks
  - AWS: Security Specialty, SAA, CCP | CDP | CCSP

Featured projects (add links to):
  - iron-bank-pipeline repository
  - iron-bank-security-toolkit repository
  - juice-shop-writeups repository

Skills to add:
  DevSecOps, GitHub Actions, Terraform, Docker, Kubernetes, OWASP ZAP,
  Semgrep, Trivy, AWS Security Hub, AWS GuardDuty, AWS Config, KMS,
  AWS Organizations, SCPs, Shift-Left Security, Container Security
```

---

## Part 3: CCSP Exam Day

### Final Review (Day Before Exam)

```
Domain 1 — Cloud Concepts, Architecture, Design (17%):
  ✓ IaaS / PaaS / SaaS with examples
  ✓ Cloud deployment models: public, private, hybrid, community
  ✓ Shared responsibility model — where AWS responsibility ends, yours begins
  ✓ CSA CCM — Cloud Controls Matrix (know it exists, maps to standards)

Domain 2 — Cloud Data Security (20%):
  ✓ Data lifecycle: Create → Store → Use → Share → Archive → Destroy
  ✓ Data at rest, in transit, in use — different controls for each
  ✓ BYOK vs HYOK vs provider-managed keys
  ✓ Data classification (Public → Internal → Confidential → Restricted)

Domain 3 — Cloud Platform & Infrastructure Security (17%):
  ✓ Hypervisor types: Type 1 (bare metal, more secure) vs Type 2 (hosted)
  ✓ Network security: virtual firewalls = Security Groups, VPCs = network isolation
  ✓ Identity: federation, SSO, MFA, privileged access management
  ✓ Physical security (multi-tenant, colocation concerns)

Domain 4 — Cloud Application Security (17%):
  ✓ SSDLC — Secure Software Development Lifecycle
  ✓ OWASP Top 10 — know all 10 (you've exploited them in Juice Shop)
  ✓ SAST, DAST, IAST, SCA — definitions and tools
  ✓ API security, OAuth 2.0, JWT basics

Domain 5 — Cloud Security Operations (16%):
  ✓ Incident response: prepare → identify → contain → eradicate → recover → lessons
  ✓ Business continuity: RPO (how much data you can lose) vs RTO (how long to recover)
  ✓ Log management: CloudTrail = control plane, VPC Flow Logs = network, CloudWatch = app
  ✓ Vulnerability management lifecycle

Domain 6 — Legal, Risk & Compliance (13%):
  ✓ GDPR, HIPAA, PCI-DSS, SOX scope (one sentence each)
  ✓ eDiscovery, legal hold, chain of custody
  ✓ SLA, MSA, DPA — contract terms
  ✓ Audit types: internal, external, third-party, regulatory
```

### CCSP Exam Strategy

```
Format: 150 questions, 4 hours, CAT (Computer Adaptive Testing)
CAT means: if you answer correctly, the next question is harder
           if you answer incorrectly, the next question is easier
           You CANNOT go back to change answers
           The exam ends when the computer is confident in your result (could be < 150 questions)

Strategy:
  Read all 4 options before selecting (CCSP questions often have 2 close options)
  "MOST appropriate" = look for the most complete, vendor-neutral answer
  "FIRST" = think about sequence — detect before investigate, contain before remediate
  Data security questions: always consider all 3 states (at rest, in transit, in use)
  When in doubt: the most risk-averse, process-oriented answer is usually correct

Passing: 700 / 1000
  This is a scaled score — it does not mean "70% correct"
  It means you demonstrated competency at the 700-point threshold on ISC2's scale
```

---

## Part 4: The Complete 12-Month Curriculum Summary

### Skills Built

| Phase | Months | Skills |
|---|---|---|
| **Phase 1: Foundations** | 1–3 | Linux, Python/boto3, AWS IAM, S3, KMS, AWS CCP |
| **Phase 2: Cloud Security** | 4–6 | VPC, Terraform, GuardDuty, Config, SCPs, Terraform Associate |
| **Phase 3: AppSec** | 7–9 | OWASP, Burp Suite, Semgrep, ZAP, Docker, ECS, K8s, AWS Security Specialty |
| **Phase 4: DevSecOps** | 10–12 | GitHub Actions, 5-gate pipeline, Compliance as Code, CDP, CCSP |

### Certifications Earned

```
Month 3:  AWS Certified Cloud Practitioner (CLF-C02)
Month 7:  AWS Certified Solutions Architect Associate (SAA-C03)
Month 9:  AWS Certified Security Specialty (SCS-C03)  ← most prestigious
Month 11: Certified DevSecOps Professional (CDP)
Month 12: CCSP — ISC2 Certified Cloud Security Professional
```

### GitHub Portfolio

```
iron-bank-pipeline          5-gate DevSecOps CI/CD
iron-bank-security-toolkit  SAST+DAST+SCA+secrets scanner
juice-shop-writeups         AppSec exploit writeups
iron-bank-tf                Terraform infrastructure modules
```

---

## Part 5: What Comes Next

```
Immediate (next 3 months):
  1. Apply to DevSecOps / Cloud Security Engineer roles
     Target titles: DevSecOps Engineer, Cloud Security Engineer,
     Security Platform Engineer, AppSec Engineer
  2. Target industries: fintech, healthcare, regulated industries
     (any prior compliance or enterprise security experience is a differentiator)
  3. Start contributing to open source security tools (Semgrep rules, OPA policies)

6-month goals:
  1. CKAD (Certified Kubernetes Application Developer) or CKS (Certified Kubernetes Security Specialist)
     — if you want to go deeper into container platforms
  2. HashiCorp Terraform Associate (TA-003)
     — validates your Terraform skills with a vendor cert
  3. AWS DevOps Engineer Professional (DOP-C02)
     — if you want to go deeper into AWS automation

Long-term:
  CISSP (Certified Information Systems Security Professional) from ISC2
  — if you want to move into Security Architecture or CISO track
  — Your CCSP is a stepping stone; CISSP experience credit counts
```

---

## 🧹 Final Cleanup

```bash
# Verify no AWS resources are running
echo "=== Checking for running resources ==="

echo "EC2 Instances:"
aws ec2 describe-instances \
  --profile iron-bank \
  --query "Reservations[].Instances[?State.Name=='running'].[InstanceId,InstanceType]" \
  --output text

echo "ECS Services:"
aws ecs list-services --cluster iron-bank-fortress-cluster --profile iron-bank 2>/dev/null || echo "(no cluster)"

echo "NAT Gateways:"
aws ec2 describe-nat-gateways \
  --profile iron-bank \
  --query "NatGateways[?State=='available'].[NatGatewayId]" \
  --output text

echo "GuardDuty Detectors (monthly cost if active):"
aws guardduty list-detectors --profile iron-bank --query 'DetectorIds' --output text

echo ""
echo "=== AWS Cost Summary ==="
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '-7 days' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity DAILY \
  --metrics BlendedCost \
  --profile iron-bank \
  --query 'ResultsByTime[-1].Total.BlendedCost' 2>/dev/null || echo "(Cost Explorer not enabled)"

echo ""
echo "✅ Iron Bank 12-Month Curriculum — COMPLETE"
echo "   You did it."
```

---

## Final Checklist

- [ ] CCSP exam taken — score recorded
- [ ] If passed: ISC2 membership created, CPE plan established (90 CPEs / 3 years)
- [ ] If failed: review score report, identify weak domains, rebook within 60 days
- [ ] GitHub profile README published at github.com/<username>/<username>
- [ ] All public repos have descriptions and polished READMEs
- [ ] iron-bank-pipeline is public — walkthrough it as a portfolio demo
- [ ] LinkedIn updated — headline, summary, skills, featured projects
- [ ] No AWS resources running — final bill verified < $5 for the month
- [ ] Certification list updated with CDP and CCSP
- [ ] Job applications started or next cert path chosen
- [ ] 12-month progress.md updated — all months marked complete

!!! tip "Congratulations"
    You started this curriculum with your existing security experience and zero AWS hands-on. You finish it with 5 AWS/security certifications, a public DevSecOps pipeline that automatically enforces security gates on every code change, exploit writeups demonstrating AppSec knowledge, and Terraform infrastructure modules that would pass a code review at most companies. That is a career pivot, not a certificate collection.

