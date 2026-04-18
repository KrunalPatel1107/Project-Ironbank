# Month 7 — Week 4: AWS SAA Exam Prep & Threat Modelling

!!! danger "💰 Cost: $150 exam fee"
    No new AWS resources this week. Budget **$150 USD** for the AWS Solutions Architect Associate (SAA-C03) voucher when ready to book.

!!! info "Exam Details — AWS Solutions Architect Associate (SAA-C03)"
    | | |
    |---|---|
    | **Duration** | 130 minutes |
    | **Questions** | 65 (multiple choice + multi-response) |
    | **Passing score** | 720 / 1000 |
    | **Cost** | $150 USD |
    | **Validity** | 3 years |
    | **Booking** | [aws.amazon.com/certification](https://aws.amazon.com/certification) |
    | **Format** | Online proctored (Pearson VUE) or testing centre |

---

## Part 1: SAA-C03 Exam Domains

| Domain | Weight | What to Know |
|---|---|---|
| Design Secure Architectures | **30%** | IAM, SCP, VPC, encryption, least privilege |
| Design Resilient Architectures | 26% | Multi-AZ, Auto Scaling, RDS failover, S3 versioning |
| Design High-Performing Architectures | 24% | CloudFront, ElastiCache, read replicas, S3 Transfer Acceleration |
| Design Cost-Optimised Architectures | 20% | Reserved vs Spot instances, S3 tiers, Right Sizing |

**Good news:** Domain 1 (Secure Architectures) is your strongest area — it maps directly to everything you built in Phases 1 and 2.

---

## Part 2: Key SAA Concepts to Know Cold

### Domain 1 — Secure Architectures (your advantage)

```
VPC security model:
├── Security Groups     → stateful, instance-level, allow only
├── NACLs               → stateless, subnet-level, allow + deny
├── VPC Flow Logs       → network audit trail
├── VPC Endpoints       → private path to AWS services (Gateway: S3/DDB, Interface: everything else)
└── PrivateLink         → expose your own service privately to other VPCs

Identity:
├── IAM Roles           → attach to EC2/Lambda/services — no long-term credentials
├── IAM Policies        → identity-based (who) vs resource-based (what resource allows who)
├── SCP                 → org-level guardrail, overrides IAM
├── Permission Boundary → cap on what a role/user can ever be granted
└── IAM Identity Center → SSO for multi-account — replaces IAM users for humans

Encryption:
├── KMS CMK             → you control the key, AWS manages the HSM
├── S3-SSE-KMS          → server-side encryption using your CMK
├── EBS encryption      → enabled per volume, uses KMS
├── RDS encryption      → at rest via KMS, in transit via SSL/TLS
└── Secrets Manager     → stores secrets, rotates automatically, backed by KMS
```

### Domain 2 — Resilient Architectures

```
High Availability patterns:
├── Multi-AZ RDS        → synchronous standby in a second AZ, auto-failover
├── Read Replica        → async copy for read scaling (NOT for HA — replica can lag)
├── ALB + Auto Scaling  → distribute traffic, replace unhealthy instances automatically
├── S3 versioning       → protects against accidental deletion
├── Route 53 failover   → health checks + DNS failover to standby region
└── ElastiCache         → Redis/Memcached in-memory cache — reduces DB load

Key distinction for the exam:
  Multi-AZ = High Availability (automatic failover)
  Read Replica = Read Scalability (no automatic failover)
```

### Domain 3 — High-Performing Architectures

```
Performance accelerators:
├── CloudFront          → CDN — cache content at edge locations near users
├── S3 Transfer Acceleration → faster uploads via CloudFront edge
├── ElastiCache         → cache frequent DB queries in memory (ms vs ms)
├── RDS read replicas   → offload read traffic from primary DB
└── SQS                 → decouple producers from consumers (handle traffic spikes)

Storage types (know which to use when):
  S3          → object storage, unlimited scale, 11 nines durability
  EBS         → block storage for EC2 (like a hard drive), single AZ
  EFS         → shared file system, multiple EC2 instances, NFS protocol
  Instance Store → ephemeral, fastest (physically attached), lost on stop/terminate
```

### Domain 4 — Cost-Optimised Architectures

```
EC2 pricing models:
  On-Demand    → pay per hour/second, no commitment — dev/test
  Reserved     → 1-3 year commitment, up to 72% discount — steady production workloads
  Spot         → bid on spare capacity, up to 90% discount — interruptible batch jobs
  Savings Plans → flexible commitment ($/hour), covers EC2 + Lambda + Fargate

S3 storage classes (cheapest is furthest right):
  S3 Standard → S3 Intelligent-Tiering → S3 Standard-IA → S3 Glacier Instant → S3 Glacier Flexible → S3 Glacier Deep Archive
```

---

## Part 3: SAA Practice Questions

??? note "Q1: Your app needs to store session state shared across multiple EC2 instances in an Auto Scaling group. What do you use?"
    **ElastiCache (Redis)**. EC2 instance local memory is not shared across instances and is lost when an instance is replaced. ElastiCache provides a shared, low-latency in-memory store. DynamoDB is an alternative for persistent session state.

??? note "Q2: You need to grant an EC2 instance access to S3 without storing credentials on the instance. How?"
    Create an **IAM Role** with the required S3 policy, attach the role to the EC2 instance as an **instance profile**. The AWS SDK automatically retrieves temporary credentials from the Instance Metadata Service (IMDS). Never place access keys on EC2 instances.

??? note "Q3: Your RDS database is in a Multi-AZ deployment. The primary fails at 2am. What happens?"
    AWS **automatically** detects the failure, promotes the standby replica in the second AZ to primary, and updates the DNS endpoint. Your application reconnects after a brief outage (typically 60–120 seconds). No manual intervention required. The key exam point: the connection string (endpoint URL) doesn't change — DNS is updated automatically.

??? note "Q4: An S3 bucket must only be accessible from within your VPC. Users with admin IAM permissions must not be able to bypass this. How do you enforce it?"
    Combine a **VPC Gateway Endpoint** with an **S3 bucket policy** that denies access unless the request comes via the endpoint:
    ```json
    {"Condition": {"StringNotEquals": {"aws:sourceVpce": "vpce-xxxxx"}}}
    ```
    IAM permissions are necessary but not sufficient — the bucket policy adds an independent enforcement layer that even IAM admins can't bypass without modifying the bucket policy itself.

??? note "Q5: What is the difference between an S3 bucket policy and an IAM policy for S3 access?"
    **IAM policy** is identity-based — attached to a user, group, or role. It controls what that principal can do.
    **S3 bucket policy** is resource-based — attached to the bucket. It controls who can access the bucket, including cross-account access and anonymous public access.
    Both must allow an action for it to succeed (logical AND). Either can deny to block it.

??? note "Q6: Your Lambda function processes images uploaded to S3. What's the most cost-efficient and operationally simple way to trigger it?"
    **S3 Event Notification → Lambda**. Configure the S3 bucket to invoke the Lambda function on `s3:ObjectCreated:*` events. No polling, no queue needed for simple use cases. For high-volume or retry-required scenarios, add an **SQS queue** between S3 and Lambda for buffering.

??? note "Q7: Spot instances are running a batch job. How do you handle Spot interruptions gracefully?"
    Enable the **Spot Instance interruption notice** — AWS sends a two-minute warning via the Instance Metadata Service before terminating. Your application should checkpoint its work on this signal. Use **Spot Fleet** or **EC2 Auto Scaling with mixed instances policy** (combine On-Demand + Spot) so the job continues on On-Demand if all Spot capacity is reclaimed.

---

## Part 4: Threat Modelling — STRIDE

Threat modelling is a structured way to identify and prioritise security risks during the design phase — before a line of code is written. It's a core skill for AppSec and Cloud Security roles.

**STRIDE** is the most common framework. Each letter = a category of threat:

| Letter | Threat | What It Means | Example |
|---|---|---|---|
| **S** | Spoofing | Pretending to be someone else | Stolen JWT token used to impersonate a user |
| **T** | Tampering | Modifying data in transit or at rest | SQL injection changes database records |
| **R** | Repudiation | Denying you did something | No audit log means attacker can deny actions |
| **I** | Information Disclosure | Exposing sensitive data | API returns password hashes or internal IDs |
| **D** | Denial of Service | Making the service unavailable | No rate limiting allows 100k requests/minute |
| **E** | Elevation of Privilege | Gaining higher permissions | Regular user accesses admin panel (A01) |

---

## Part 5: Threat Model Juice Shop

Apply STRIDE to what you exploited in Weeks 2 and 3:

```bash
mkdir -p ~/projects/juice-shop-writeups
cat > ~/projects/juice-shop-writeups/threat-model-juice-shop.md << 'EOF'
# Threat Model — OWASP Juice Shop

**Date:** 2026-04
**Methodology:** STRIDE
**Scope:** Authentication, User Data, Product Catalog, Order Flow

## Architecture Overview

```
Browser → Juice Shop (Node.js + SQLite) → File System (/ftp)
              ↓
        Database (SQLite)
```

## STRIDE Analysis

### S — Spoofing
| Threat | Current Control | Risk | Mitigation |
|---|---|---|---|
| JWT token theft via XSS | None — stored in localStorage | HIGH | Use httpOnly cookies; implement CSP |
| Credential brute force | No lockout or rate limit | HIGH | Account lockout after 5 attempts; CAPTCHA |
| Forged JWT (alg:none) | Server may accept | CRITICAL | Pin algorithm server-side; reject alg:none |

### T — Tampering
| Threat | Current Control | Risk | Mitigation |
|---|---|---|---|
| SQL injection modifies records | None — no parameterisation | CRITICAL | Parameterised queries (prepared statements) |
| Price tampering in order API | Client-side validation only | HIGH | Validate and recalculate price server-side |
| File upload of malicious content | No type validation | HIGH | Whitelist file types; scan uploads |

### R — Repudiation
| Threat | Current Control | Risk | Mitigation |
|---|---|---|---|
| No audit log of admin actions | None | MEDIUM | Log all sensitive actions with timestamp + user |
| Feedback submission not attributed | Anonymous allowed | LOW | Require authentication for feedback |

### I — Information Disclosure
| Threat | Current Control | Risk | Mitigation |
|---|---|---|---|
| /ftp directory exposed | None | HIGH | Remove from production; restrict via web server config |
| Stack traces in error responses | None | MEDIUM | Generic error messages in production |
| Excessive API response fields | None | MEDIUM | API response shaping — return only needed fields |

### D — Denial of Service
| Threat | Current Control | Risk | Mitigation |
|---|---|---|---|
| No rate limiting on any endpoint | None | HIGH | Rate limit by IP + user (e.g. 60 req/min) |
| Large file uploads accepted | No size limit | MEDIUM | Enforce max upload size |

### E — Elevation of Privilege
| Threat | Current Control | Risk | Mitigation |
|---|---|---|---|
| Admin panel accessible via direct URL | UI-only access control | CRITICAL | Server-side role check on every admin route |
| BOLA — access any user's data | None | HIGH | Server-side ownership verification |
| Mass assignment — update role via API | None | HIGH | Whitelist allowed fields in update endpoints |

## Top 5 Prioritised Risks

1. CRITICAL: SQL Injection on login — full auth bypass
2. CRITICAL: Admin panel has no server-side access control
3. HIGH: No rate limiting anywhere — DoS and brute force exposure
4. HIGH: JWT algorithm not pinned — forgery possible
5. HIGH: /ftp directory exposed — sensitive files accessible

## Remediation Roadmap

**Immediate (this sprint):**
- Parameterised queries on all database calls
- Server-side role checks on all admin routes
- Rate limiting middleware (express-rate-limit)

**Short-term (next sprint):**
- httpOnly cookies replacing localStorage JWTs
- Content Security Policy header
- Remove /ftp from production build

**Long-term:**
- Static analysis (Semgrep) in CI pipeline — Month 8
- DAST scan (ZAP) on every PR — Month 8
EOF

git -C ~/projects/juice-shop-writeups add .
git -C ~/projects/juice-shop-writeups commit -m "feat: STRIDE threat model for Juice Shop — Month 7 deliverable"
git -C ~/projects/juice-shop-writeups push
```

---

## Part 6: SAA Study Resources

| Resource | What to Use It For | Cost |
|---|---|---|
| [Adrian Cantrill's SAA Course](https://learn.cantrill.io/p/aws-certified-solutions-architect-associate) | Best video course — deep and visual | ~$40 |
| [TutorialsDojo Practice Exams](https://tutorialsdojo.com/aws-certified-solutions-architect-associate/) | Best practice questions — closest to real exam | ~$15 |
| [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/) | Free official whitepaper — read the Security pillar | FREE |
| [AWS FAQ pages](https://aws.amazon.com/faqs/) | Read FAQs for: EC2, S3, RDS, VPC, IAM, CloudFront | FREE |
| `aws --help` + AWS Console | Hands-on is the best revision | FREE |

!!! tip "SAA exam strategy"
    - Read **all four answers** before choosing — AWS loves "all are partially correct, only one is best"
    - Cost and operational overhead are tiebreakers — managed services > self-managed, simpler > complex
    - "Most secure" questions: think least privilege + encryption at rest + encryption in transit + no public endpoints
    - You already built 80% of the SAA content in Phases 1 and 2 — trust your hands-on knowledge

---

## Month 7 Summary

| Week | Built / Learned | Portfolio Item |
|---|---|---|
| 1 | OWASP Top 10 theory, first SQLi exploit | Juice Shop running locally |
| 2 | XSS, IDOR, sensitive data, JWT analysis, 10 PortSwigger labs | 2+ exploit writeups on GitHub |
| 3 | API Security Top 10, BOLA, SSRF/IMDS, security headers, 10 more labs | 2+ API finding writeups |
| 4 | SAA exam prep, STRIDE threat model for Juice Shop | Threat model document on GitHub |

---

## Checklist

- [ ] All 7 SAA practice questions answered without looking
- [ ] Know the Multi-AZ vs Read Replica distinction cold
- [ ] Know Gateway vs Interface VPC Endpoint distinction
- [ ] STRIDE framework explained in your own words
- [ ] Threat model covering all 6 STRIDE categories committed to GitHub
- [ ] Top 5 risks ranked and remediation roadmap written
- [ ] At least **20 total PortSwigger labs** completed across Weeks 2–3
- [ ] All Juice Shop writeups pushed to GitHub (3+ documents)
- [ ] AWS SAA exam booked (or date set)
- [ ] **No AWS resources left running — bill $0**

!!! tip "What's next: Month 8 — SAST/DAST/SCA"
    You'll stop doing manual exploitation and start automating it. Semgrep finds the SQLi and XSS bugs in source code before they ship. OWASP ZAP runs the same attacks you did manually — but against every endpoint, automatically. Trivy and Gitleaks find secrets and vulnerable libraries. By end of Month 8, you'll have a security testing toolkit that runs in CI/CD.
