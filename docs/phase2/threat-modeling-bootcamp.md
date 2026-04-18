# Lab: Threat Modeling Bootcamp

!!! abstract "💰 Cost: $0"
    This week is pure planning and diagramming — no AWS resources created yet.

!!! info "What You Know Already"
    You've done threat modeling in your **Microsoft security certifications** (SC-100 specifically). This week we translate that to AWS terminology and build the discipline of threat modeling **before** you design infrastructure, not after.

---

## Why Threat Model First?

Before you build a 3-tier VPC (Week 1), launch an RDS database (Month 5), or deploy containers (Month 9), ask: **What are we actually protecting? From whom? Why?**

Threat modeling answers these questions **before you write Terraform code**. Once you know the threats, you can:
- Choose the right AWS controls (Security Groups, NACLs, encryption, IAM policies)
- Design the network with threats in mind
- Justify every security decision in interviews ("Why did you put the database in a private subnet?" → "Because the threat model identified attackers trying to access the DB directly from the internet.")

---

## Part 1: STRIDE Methodology

You know **STRIDE** from SC-100. Let's apply it to AWS.

**STRIDE** = 6 threat categories:

| Threat | AWS Example | Defense |
|---|---|---|
| **S**poofing identity | Attacker assumes a valid IAM role (e.g., `AssumeRole` without conditions) | IAM Conditions, MFA, OIDC, assume role trust policies |
| **T**ampering with data | Attacker modifies data in S3 or RDS in transit | TLS/HTTPS, RDS encryption, S3 versioning, access logs |
| **R**epudiation | Attacker deletes CloudTrail logs to cover tracks | Immutable CloudTrail (S3 Object Lock), log validation, CloudWatch alarms |
| **I**nformation disclosure | Attacker reads secrets (API keys, passwords) from Systems Manager, Secrets Manager, or environment variables | Encrypt secrets at rest, rotate credentials, restrict access (IAM), don't log secrets |
| **D**enial of Service | Attacker floods your API Gateway or ALB, exhausting capacity | WAF rules, rate limiting, auto-scaling, DDoS protection (Shield) |
| **E**levation of privilege | Attacker assumes a highly privileged role (e.g., `AdministratorAccess`) | Least privilege IAM, permission boundaries, SCPs, MFA for sensitive operations |

---

## Part 2: Data Flow Diagram (DFD)

A **DFD** is a visual map of how data moves through your system. It identifies where data could be intercepted, modified, or stolen.

### Simple DFD Example (Iron Bank - Month 5)

```
┌─────────┐                    ┌─────────────┐
│  User   │ ──(HTTPS)────────→ │  ALB        │
└─────────┘ ←──────(HTTPS)──── │  (Public)   │
                                └─────────────┘
                                      ↓
                                (Private Subnet)
                                      ↓
                                ┌──────────┐
                                │   Web    │
                                │ Server   │
                                │  (EC2)   │
                                └──────────┘
                                      ↓
                               (IAM AssumeRole)
                                      ↓
                    ┌───────────────────────────────┐
                    │  RDS (Private Subnet)         │
                    │  - Encryption at rest         │
                    │  - IAM database auth          │
                    │  - No public IP               │
                    └───────────────────────────────┘
                                      ↓
                    ┌───────────────────────────────┐
                    │  S3 (Encrypted)               │
                    │  - Server-side encryption     │
                    │  - Access logs enabled        │
                    └───────────────────────────────┘
```

**Data flows to identify threats:**
1. **User → ALB** — Can an attacker intercept? (Defense: HTTPS, WAF)
2. **ALB → Web Server** — Unencrypted? (Defense: ALB → EC2 on private network)
3. **Web Server → RDS** — Who can connect? (Defense: Security Group restricted to EC2, IAM auth)
4. **Web Server → S3** — Who can read? (Defense: IAM role, S3 ACLs, encryption)

---

## Part 3: Building a Threat Model

### Step 1: Define Assets

What are you protecting?
- **Data**: Customer usernames, passwords, transaction history
- **Services**: Web application, API, backend workers
- **Infrastructure**: EC2, RDS, S3 buckets

### Step 2: Identify Threat Actors

Who might attack?
- **External attacker** — No initial access, internet-facing
- **Disgruntled employee** — Has AWS console access
- **Compromised EC2** — Can reach private subnets, RDS
- **AWS insider** — Theoretically could access your account (AWS manages this)

### Step 3: Identify Threats (Using STRIDE)

For each data flow, ask: "What can go wrong?"

**Example: User → ALB (HTTPS)**

| Threat | Description | Risk | Defense |
|---|---|---|---|
| **Spoofing** | Attacker spoof the ALB domain (DNS hijacking) | User visits fake site, enters credentials | DNSSEC, Route 53 monitoring, SSL certificates |
| **Tampering** | Attacker intercepts traffic, modifies response | Inject malware, deface response | HTTPS enforcement, ALB security groups |
| **Repudiation** | Attacker denies they made request | Liability, compliance (PCI-DSS requires audit logs) | ALB access logs, CloudTrail, WAF logs |
| **Information Disclosure** | Attacker reads HTTPS traffic (shouldn't be possible with proper certs) | Steal credentials, session tokens | TLS 1.2+, certificate pinning (mobile) |
| **Denial of Service** | Attacker floods ALB with traffic | Service unavailable, costs spike | WAF rate limiting, Shield Standard (free), Shield Advanced |
| **Elevation of Privilege** | Attacker gains access to ALB controls | Could redirect traffic to malicious server | ALB security groups, IAM policies restrict modification |

### Step 4: Risk Rating

Rate each threat:

**Risk = Likelihood × Impact**

| Likelihood | Impact | Risk Level | Action |
|---|---|---|---|
| Low | Low | Low | Document, deprioritize |
| Low | High | Medium | Mitigate with one control |
| High | Low | Medium | Monitor |
| High | High | **High** | **Implement multiple controls NOW** |

**Example:**
- **Spoofing ALB domain**: Likelihood = Very Low (DNSSEC + Route 53 management), Impact = High → **Low-Medium risk** → Monitor DNS settings
- **Denial of Service on ALB**: Likelihood = High (easy to flood), Impact = Medium (downtime costs $) → **High risk** → Implement WAF rate limiting + Shield Advanced

---

## Part 4: Hands-On Lab — Threat Model Iron Bank

This lab creates the threat model you'll use to justify architecture decisions in Weeks 2–4.

### Step 1: Sketch Your Architecture

Create a simple diagram (or describe in text):

```
┌─ VPC: 10.0.0.0/16 ─────────────────────────────────┐
│                                                      │
│  ┌─ Public Subnet (10.0.1.0/24) ────────┐          │
│  │                                        │          │
│  │  ┌─ ALB (Port 443) ────────────────┐  │          │
│  │  │ (Internet-facing)                │  │          │
│  │  └────────────────────────────────┘  │          │
│  │                                        │          │
│  └────────────────────────────────────┬──┘          │
│                                        │             │
│  ┌─ Private Subnet (10.0.2.0/24) ────┼──┐          │
│  │                                    │  │          │
│  │  ┌─ EC2 Web Servers ──────────────┼─┐│          │
│  │  │ (Port 80 from ALB only)        │││          │
│  │  └──────────────────────────────┘││          │
│  │         ↓                          ││          │
│  │  ┌─ RDS (Private, no public IP) ──┼─┐│        │
│  │  │ (Port 3306 from EC2 only)      │││        │
│  │  └──────────────────────────────┘││        │
│  │         ↓                          ││        │
│  │  ┌─ S3 Bucket ───────────────────┼─┐│      │
│  │  │ (Access via IAM role)         │││      │
│  │  └──────────────────────────────┘││      │
│  │                                    ││      │
│  └──────────────────────────────────┘┘      │
│                                              │
└──────────────────────────────────────────────┘
```

### Step 2: Identify 5 Key Data Flows

Write them down:
1. External user → ALB (HTTPS, port 443)
2. ALB → EC2 (HTTP, port 80, private network)
3. EC2 → RDS (TCP port 3306, private network, IAM auth)
4. EC2 → S3 (HTTPS, via IAM role)
5. Monitoring: CloudTrail, CloudWatch Logs (to S3 for archival)

### Step 3: Apply STRIDE to Each Flow

For each flow, ask: "What **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, or **E**levation of privilege threats exist?"

**Example: EC2 → RDS**

```
Flow: EC2 Web Server connects to RDS database

S (Spoofing):    Can attacker pretend to be the EC2 instance?
                 → Mitigate: Restrict RDS Security Group to EC2 Security Group only
                 → Further: Use IAM database authentication instead of password

T (Tampering):   Can attacker modify data in RDS in transit?
                 → Mitigate: Enable RDS encryption in-transit (Enforce SSL)

R (Repudiation): Can attacker delete evidence of queries?
                 → Mitigate: Enable RDS enhanced monitoring, audit logs

I (Disclosure):  Can attacker read data in RDS?
                 → Mitigate: RDS encryption at rest (AES-256), restrict to private subnet

D (DoS):         Can attacker exhaust RDS connection pool?
                 → Mitigate: Set max_connections limit, CloudWatch alarms on connection count

E (Elevation):   Can attacker escalate from EC2 to RDS admin?
                 → Mitigate: EC2 IAM role has db-connect only, not admin permissions
```

### Step 4: Risk Rating Matrix

Create a simple table:

```
Threat                          | Likelihood | Impact | Risk Level | Control(s)
─────────────────────────────────────────────────────────────────────────────────
ALB spoofing (DNS hijacking)    | Low        | High   | Medium     | DNSSEC, monitoring
ALB DoS attack                  | High       | Medium | High       | WAF rate limiting
EC2-RDS tampering (transit)     | Low        | High   | Medium     | TLS enforcement
RDS data theft (compromised EC2)| Medium     | High   | High       | Encryption at rest, IAM auth
EC2 privilege escalation to RDS | Low        | High   | Medium     | Least privilege IAM
S3 unauthorized access          | Medium     | High   | High       | Bucket policy, IAM role
CloudTrail tampering            | Low        | High   | Medium     | S3 Object Lock, validation
```

### Step 5: Document in Markdown

Create a file `threat-model-iron-bank.md` in your `scripts/` folder with:
- Architecture diagram (ASCII or link to Drawio)
- Data flows (list all)
- STRIDE analysis (table)
- Risk matrix (table)
- Top 3 high-risk threats and their controls

---

## Part 5: Using Your Threat Model Going Forward

**Week 1 (VPC)**: "I'm designing a VPC with public/private subnets because my threat model says internet-facing traffic should be separated from backend databases."

**Week 2 (Subnets & Routing)**: "I'm routing through a NAT Gateway in the public subnet to prevent EC2 instances from reaching the internet directly — threat model says EC2 shouldn't initiate outbound connections."

**Week 3 (Security Groups)**: "I'm restricting RDS Security Group to EC2 Security Group only — threat model identified tampering risk if RDS is accessible from other sources."

**Week 4 (Flow Logs)**: "I'm enabling Flow Logs to detect anomalous traffic — threat model says we need visibility into network traffic for repudiation and DoS detection."

---

## Deliverables (By End of Week)

- [ ] Understand STRIDE methodology and AWS threat types
- [ ] Draw architecture DFD (ASCII or tool of choice)
- [ ] Identify 5+ data flows in your VPC
- [ ] Apply STRIDE to 2 critical flows
- [ ] Create risk rating matrix (at least 7 threats)
- [ ] Document top 3 risks and their controls
- [ ] **Save to GitHub**: `scripts/threat-model-iron-bank.md`

!!! tip "Use a Diagramming Tool"
    - **Free online**: [draw.io](https://draw.io/) (or [diagrams.net](https://diagrams.net/))
    - **Export as image**: PNG or PDF for your portfolio
    - **Add to GitHub**: Commit the Drawio XML file so others can edit it

---

## Next: Week 1 — Build the VPC

Once you understand the threats, you're ready to build infrastructure that mitigates them. Week 1 creates the foundational VPC based on your threat model.

**↓ Next: [Week 1: VPC & CloudTrail](vpc-cloudtrail.md)**
