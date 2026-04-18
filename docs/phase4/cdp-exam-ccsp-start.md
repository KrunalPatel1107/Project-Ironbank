# Month 11 — Week 4: CDP Exam & CCSP Study Start

!!! abstract "💰 Cost: $499 CDP exam fee + $599 CCSP exam fee (future)"

!!! danger "💰 Exam Costs"
    **CDP exam:** ~$499 USD — book through the DevSecOps Institute website. Vouchers occasionally available through employer training budgets or Promo codes — check before paying full price.

    **CCSP (for Month 12):** ~$599 USD — book through ISC2. If you hold a current CISSP, the CCSP endorsement path exists instead of the full exam.

---

## Part 1: CDP Exam Day

### Exam Format

```
40 questions × multiple choice
120 minutes = 3 minutes per question on average
Passing: 70% = 28 correct

Question style:
  - Scenario-based ("A developer commits code that... what should the pipeline do?")
  - Tool selection ("Which tool would you use to detect secrets in git history?")
  - Process-based ("What is the correct order of steps for...?")
  - Metrics ("Which metric measures how long it takes to fix a vulnerability?")
```

### Exam Day Tips

```
Before exam:
  ✓ Review your iron-bank-pipeline repository — walk through each gate
  ✓ Review STRIDE threat model for CI/CD (from Week 3)
  ✓ Review SLSA levels 1-4
  ✓ Review DevSecOps metrics (MTTD, MTTR, Escape Rate)
  ✓ Know the difference: SAST / DAST / IAST / SCA
  ✓ Know tool associations: Semgrep=SAST, ZAP=DAST, Trivy=SCA, Gitleaks=secrets

During exam:
  ✓ Read all 4 options before selecting — CDP questions often have 2 "close" options
  ✓ "Most secure" = fewest permissions, most automation, no manual steps
  ✓ "First step" = always contains/mitigate/isolate before investigating
  ✓ Flag and return — don't spend >5 min on any single question

After exam:
  ✓ Screenshot your passing score (or note your score for retake planning)
  ✓ Update your LinkedIn with the credential
  ✓ Add to your GitHub profile README
```

### CDP Quick Reference Sheet

```
Pipeline Security Pattern:
  Prevent (SCPs, pre-commit hooks) → Detect (SAST, secrets scan) → Respond (auto-block) → Report (SARIF, dashboards)

Gate Order by When They Run:
  1. Pre-commit: Gitleaks hook, Semgrep hook
  2. PR: Gate 1 (Semgrep), Gate 2 (Gitleaks), Gate 3 (Checkov)
  3. Merge: Gate 4 (Trivy), build/push to registry
  4. Deploy: Gate 5 (ZAP)

Supply Chain Security Keywords:
  SLSA → Levels 1-4, provenance, attestation
  SBOM → Software Bill of Materials (list of all dependencies)
  Sigstore/Cosign → signing container images
  Dependabot → auto-PRs for dependency updates

Container Security in CI:
  - Scan image: Trivy (after build, before push)
  - Sign image: Cosign (after push)
  - Verify image: in deploy job (reject unsigned images)
  - Base image: pin to SHA, not :latest
```

---

## Part 2: Start CCSP Study (Month 12 Exam Target)

The **CCSP (Certified Cloud Security Professional)** from ISC2 is one of the most recognized cloud security certifications globally. It's vendor-neutral — it covers AWS, Azure, GCP, and on-prem cloud equally.

### CCSP Overview

| | |
|---|---|
| **Provider** | ISC2 (https://www.isc2.org) |
| **Duration** | 4 hours |
| **Questions** | 150 multiple choice (CAT format — adaptive) |
| **Passing score** | 700 / 1000 |
| **Cost** | $599 USD |
| **Validity** | 3 years (requires 90 CPEs) |
| **Prerequisite** | 5 years of IT experience, 1 year in cloud security (or CISSP waives the requirement) |

### CCSP Domains

| Domain | Weight |
|---|---|
| Cloud Concepts, Architecture and Design | 17% |
| Cloud Data Security | 20% |
| Cloud Platform & Infrastructure Security | 17% |
| Cloud Application Security | 17% |
| Cloud Security Operations | 16% |
| Legal, Risk & Compliance | 13% |

### CCSP vs Your AWS Background

The CCSP assumes NO knowledge of a specific cloud provider — it tests cloud security principles and frameworks. Here is how your work maps:

```
Your experience → CCSP Domain

IAM, SCPs, Permission Boundaries → Cloud Platform & Infrastructure Security
KMS, Secrets Manager, S3 encryption → Cloud Data Security
VPC, Security Groups, WAF → Cloud Platform & Infrastructure Security
GuardDuty, CloudTrail, Security Hub → Cloud Security Operations
OWASP Top 10, Semgrep, ZAP → Cloud Application Security
AWS Compliance (Config, FSBP) → Legal, Risk & Compliance
Containers, ECS, Kubernetes → Cloud Platform & Infrastructure Security
CI/CD Pipeline Security → Cloud Application Security
```

Most of your 11 months of work covers the exam — you need to learn the CCSP terminology and the vendor-neutral frameworks.

### Week 4 CCSP Study Plan (First 5 Days)

**Day 1 — Cloud Architecture Fundamentals:**

```
Key concepts to know cold:
  Cloud service models:
    IaaS: you manage OS and above (EC2)
    PaaS: you manage application and data (Elastic Beanstalk, RDS)
    SaaS: you manage nothing (Gmail, Salesforce, Workday)

  Cloud deployment models:
    Public cloud:  shared infrastructure, multi-tenant (AWS, Azure, GCP)
    Private cloud: dedicated infrastructure (on-prem VMware, OpenStack)
    Hybrid cloud:  public + private connected (Direct Connect + on-prem)
    Community cloud: shared by organizations with common requirements (gov, healthcare)

  Cloud shared responsibility model:
    AWS is responsible FOR the cloud (hardware, facilities, hypervisor)
    You are responsible IN the cloud (IAM config, data, patching guest OS)
    SaaS: provider responsible for nearly everything, you manage data and access

  CSA CCM (Cloud Controls Matrix):
    Industry standard control framework for cloud security
    197 control objectives across 17 domains
    Maps to ISO 27001, NIST, PCI-DSS, HIPAA
    CCSP exam references this heavily — know it exists and what it does
```

**Day 2 — Cloud Data Security:**

```
Data lifecycle phases (CCSP loves these):
  Create → Store → Use → Share → Archive → Destroy

Data classification:
  Public → Internal → Confidential → Restricted/Secret

Data security controls by phase:
  At rest:    encryption (KMS/AES-256), access control (IAM), DLP (Macie)
  In transit: TLS 1.2+, certificate validation, VPN/Direct Connect
  In use:     memory encryption (confidential computing), secure enclaves

Data residency vs data sovereignty:
  Residency: where data physically sits (AWS region)
  Sovereignty: which country's laws govern the data (can differ from residency)
  Example: Canadian data in us-east-1 → stored in US, governed by which law?

Key Management (CCSP angle — vendor neutral):
  BYOK (Bring Your Own Key): you generate the key, cloud provider encrypts with it
  HYOK (Hold Your Own Key): key never leaves your hardware (AWS CloudHSM)
  Provider-managed: AWS manages the key (AWS Managed Keys)
```

**Day 3 — Cloud Application Security:**

```
Secure Software Development Lifecycle (SSDLC) — CCSP core topic:
  1. Requirements:    include security requirements (threat modelling)
  2. Design:          threat model the architecture (STRIDE)
  3. Development:     secure coding standards, code review, SAST
  4. Testing:         DAST, penetration testing, SCA
  5. Deployment:      IaC scanning, hardened container images
  6. Operations:      runtime monitoring, DAST re-scan, patch management
  7. Decommission:    secure data deletion, key revocation

OWASP Cloud-10 (different from OWASP Top 10):
  A prominent CCSP topic — cloud-specific risks:
  1. Accountability and Data Ownership risks
  2. User Identity Federation issues
  3. Regulatory Compliance violations
  4. Business Continuity and Resiliency failures
  5. User Privacy and Secondary Usage violations
  6. Service and Data Integration risks
  7. Multi-tenancy and Physical Security issues
  8. Incidence Analysis and Forensic Support gaps
  9. Infrastructure Security issues
  10. Non-Production Environment Exposure
```

**Day 4 — Legal, Risk & Compliance:**

```
Key regulations CCSP tests (memorize acronyms and scope):
  GDPR:    EU data protection, applies to any org processing EU personal data
  HIPAA:   US healthcare data — PHI (Protected Health Information)
  PCI-DSS: Payment card data — applies to any org that processes card payments
  SOX:     US public companies — financial data integrity and audit trails
  FedRAMP: US federal cloud systems — ATO (Authority to Operate) required

eDiscovery in cloud:
  Legal hold: preserve data that may be relevant to litigation
  Chain of custody: documented trail of who had access to evidence
  Forensics challenge in cloud: multi-tenancy, shared infrastructure, jurisdictions

Risk management terms:
  Risk = Likelihood × Impact
  Residual risk = risk that remains after controls are applied
  Risk appetite: how much risk an org is willing to accept
  Risk transfer: buy insurance or use a cloud provider (they take some risk)

Cloud contract terms to know:
  SLA (Service Level Agreement): uptime guarantees (AWS SLA = 99.99% for EC2)
  MSA (Master Service Agreement): overall relationship terms
  DPA (Data Processing Agreement): required under GDPR, defines processor/controller
```

**Day 5 — Review and Practice Questions:**

```bash
# CCSP study resources
echo "Recommended resources:"
echo ""
echo "1. Official ISC2 CCSP Study Guide (Mike Chapple & David Seidl)"
echo "   → Best book, covers all 6 domains"
echo ""
echo "2. Official ISC2 CCSP Practice Tests"
echo "   → 1000+ questions, matches real exam difficulty"
echo ""
echo "3. ThorTeaches CCSP on Udemy"
echo "   → Video course, good for commute/gym"
echo ""
echo "4. Boson Practice Exams"
echo "   → Hardest practice exams, closest to real difficulty"
echo ""
echo "5. ISC2 Free CCSP Self-Study Guide"
echo "   → Free from ISC2 website — start here before buying anything"
```

---

## Phase 4 Progress Check

| Month | Milestone | Status |
|---|---|---|
| 10 | 5-gate DevSecOps pipeline | ✅ Complete |
| 11 | Compliance as Code + AWS Governance | ✅ Complete |
| 11 | CDP Exam | 🎯 This week |
| 12 | Capstone: Iron Bank Fortress | ⬜ Up next |
| 12 | CCSP Exam | 🔜 Month 12 target |

---

## Checklist

- [ ] CDP exam taken — score recorded
- [ ] If passed: LinkedIn updated, GitHub profile updated
- [ ] If failed: review incorrect questions, identify weak domain, rebook
- [ ] CCSP 6 domains listed from memory with weights
- [ ] Cloud service models explained: IaaS vs PaaS vs SaaS with AWS example for each
- [ ] Shared responsibility model explained without looking it up
- [ ] Cloud data lifecycle phases: Create → Store → Use → Share → Archive → Destroy
- [ ] GDPR, HIPAA, PCI-DSS scope explained in one sentence each
- [ ] CCSP study guide or Udemy course started — minimum 5 hours of study time this week
- [ ] CCSP exam booked for Month 12 target date

!!! tip "What's next: Month 12 — Capstone"
    Month 12 puts everything together. You deploy the full Iron Bank Fortress: VPC + ECS + WAF + GuardDuty + CloudTrail + Security Hub all connected, the 5-gate pipeline running against it, compliance checks automated, and a public portfolio writeup. Then you sit the CCSP exam. This is the capstone that everything in Months 1–11 has been building toward.

