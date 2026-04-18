# Month 9 — Week 4: AWS Security Specialty Exam (SCS-C03)

!!! danger "💰 Cost: $300 exam fee"
    No new AWS resources this week. Budget **$300 USD** for the AWS Security Specialty (SCS-C03) voucher. This is the most prestigious AWS cert for security professionals — worth every dollar on your resume.

!!! info "Exam Details — AWS Security Specialty (SCS-C03)"
    | | |
    |---|---|
    | **Duration** | 170 minutes |
    | **Questions** | 65 (multiple choice + multi-response) |
    | **Passing score** | 750 / 1000 |
    | **Cost** | $300 USD |
    | **Validity** | 3 years |
    | **Booking** | [aws.amazon.com/certification](https://aws.amazon.com/certification) |
    | **Difficulty** | Specialty level — the hardest AWS cert you'll have taken |

---

## Exam Domains

| Domain | Weight | Your Preparation |
|---|---|---|
| Threat Detection & Incident Response | **14%** | GuardDuty, CloudTrail, Security Hub — Month 6 |
| Security Logging & Monitoring | **18%** | CloudTrail, Config, VPC Flow Logs, CloudWatch — Months 4 + 6 |
| Infrastructure Security | **20%** | VPC, SGs, NACLs, WAF, Shield — Months 4 + 5 |
| Identity & Access Management | **16%** | IAM, SCPs, Permission Boundaries, Identity Center — Months 3 + 6 |
| Data Protection | **18%** | KMS, Secrets Manager, Macie, S3 encryption — Month 3 |
| Management & Security Governance | **14%** | Config, Control Tower, Security Hub, Organizations — Month 6 |

**Good news:** You've hands-on built content for 5 of 6 domains across Phases 1–3.

---

## Part 1: Domain Deep Dives — Fill the Gaps

### KMS & Encryption (Data Protection — 18%)

This is the most technical domain. Know these cold:

```
KMS Key Types:
├── AWS Managed Key (aws/s3, aws/ebs)   → AWS controls rotation, you can't export
├── Customer Managed Key (CMK)          → You control policy, rotation, deletion
└── Customer Provided Key (SSE-C)       → You provide the key per-request (rare)

Envelope Encryption (how KMS actually works):
  1. KMS generates a Data Encryption Key (DEK)
  2. DEK encrypts your data
  3. KMS encrypts the DEK with your CMK (the DEK is now a "wrapped key")
  4. Wrapped DEK stored alongside encrypted data
  5. To decrypt: KMS decrypts the wrapped DEK → DEK decrypts your data
  → Your plaintext key material NEVER leaves KMS

Key Policies vs IAM Policies for KMS:
  Key Policy: resource-based — attached to the key. MUST explicitly grant access.
  IAM Policy: identity-based — allows principal to call KMS.
  BOTH must allow for access to succeed.
  Key difference from S3: with KMS, the key policy must ALSO grant access to the account root.

Rotation:
  AWS Managed Keys: rotated automatically every year (you can't change this)
  CMKs: enable automatic rotation (creates new backing key, old keys still decrypt old data)
```

```bash
# Practice: create a CMK and encrypt/decrypt a secret
CMK_ID=$(aws kms create-key \
  --description "Iron Bank test key" \
  --profile iron-bank \
  --query KeyMetadata.KeyId --output text)

# Encrypt
CIPHERTEXT=$(aws kms encrypt \
  --key-id $CMK_ID \
  --plaintext "my-secret-value" \
  --profile iron-bank \
  --query CiphertextBlob --output text)
echo "Encrypted: $CIPHERTEXT"

# Decrypt
aws kms decrypt \
  --ciphertext-blob $CIPHERTEXT \
  --profile iron-bank \
  --query Plaintext --output text | base64 -d
# → my-secret-value

# Delete the key (schedule deletion — 7 day minimum waiting period)
aws kms schedule-key-deletion \
  --key-id $CMK_ID \
  --pending-window-in-days 7 \
  --profile iron-bank
```

### WAF & Shield (Infrastructure Security — 20%)

```
AWS WAF:
  Protects: ALB, CloudFront, API Gateway, AppSync
  Rules:    Managed Rule Groups (OWASP Top 10, bot control, known bad IPs)
            Custom Rules (rate limiting, IP allow/block lists, geo-blocking)
  Action:   Allow / Block / Count (Count = test mode, doesn't block yet)

AWS Shield:
  Standard: FREE — protects all AWS resources against L3/L4 DDoS automatically
  Advanced: $3,000/month — L7 DDoS protection, 24/7 DRT (DDoS Response Team),
            cost protection (AWS pays for scaling costs during an attack),
            advanced attack visibility in CloudWatch

Key exam distinction:
  WAF = application-layer (L7) filtering — inspects HTTP content
  Shield = network-layer (L3/L4) volumetric DDoS mitigation
  For full protection: CloudFront + WAF + Shield Advanced
```

### AWS Macie (Data Protection — 18%)

```
Macie uses ML to discover and protect sensitive data in S3:
  - Finds: PII (names, addresses, SSNs, passport numbers)
  - Finds: Credentials (AWS keys, SSH keys, OAuth tokens)
  - Finds: Financial data (credit card numbers, bank accounts)
  - Generates findings for: unencrypted buckets, publicly accessible buckets

Exam pattern: "How do you automatically detect if PHI/PII is stored in S3?"
Answer: Enable Macie. It runs managed data discovery jobs.
```

### CloudTrail Deep Dive (Logging — 18%)

```
CloudTrail log types:
  Management Events:  API calls that CREATE/MODIFY/DELETE resources (default enabled)
  Data Events:        API calls on data within resources (S3 GetObject, Lambda Invoke)
                      → Must explicitly enable, high volume = higher cost
  Insights Events:    Detects unusual API call volume (anomaly detection)
                      → Must enable, costs extra

CloudTrail integrity:
  Log file validation: SHA-256 digest file proves logs haven't been tampered with
  Enable it: aws cloudtrail create-trail --enable-log-file-validation

CloudTrail → S3 + CloudWatch Logs:
  Best practice: send to both
  S3 = long-term archive (90 days → Glacier)
  CloudWatch Logs = real-time alerting (GuardDuty, metric filters)

Multi-region trail:
  One trail that covers ALL regions — required for compliance
  aws cloudtrail create-trail --is-multi-region-trail
```

---

## Part 2: Exam Practice Questions (SCS-C03 Level)

These are harder than SAA — closer to real exam difficulty:

??? note "Q1: A developer accidentally committed AWS access keys to a public GitHub repo 3 days ago. What is the correct incident response order?"
    1. **Deactivate the key immediately** via IAM Console or CLI (`aws iam update-access-key --status Inactive`)
    2. **Review CloudTrail** for the past 3 days — filter by the access key ID to see every API call it made
    3. **Check for new IAM users, roles, or policies created** — common attacker persistence mechanism
    4. **Check for new S3 buckets or data exfiltration** — `s3:ListBuckets`, `s3:GetObject` calls
    5. **Delete the key** once you've inventoried the damage
    6. **Rotate any secrets** the key had access to (RDS passwords, Secrets Manager secrets)
    7. **Enable GuardDuty** if not already on — it would have detected anomalous API calls from a new location

??? note "Q2: You need to ensure no S3 bucket in your AWS Organization can ever be made public, even by account administrators. How?"
    Apply an **SCP** at the Organization root that denies `s3:PutBucketPublicAccessBlock` with `Value=false` and `s3:PutBucketAcl` with public ACL values. This prevents even account admins from removing public access blocks. Combine with **AWS Config rule** `s3-bucket-public-access-prohibited` for detection and **CloudWatch alarm** for alerting when the rule is violated.

??? note "Q3: An EC2 instance is sending unusual outbound traffic to an IP address known to be a malware C2 server. What AWS service detects this automatically and what is your first response step?"
    **GuardDuty** detects this — specifically a `Trojan:EC2/BlackholeTraffic` or `CryptoCurrency:EC2/BitcoinTool.B` finding. GuardDuty correlates VPC Flow Logs with its threat intelligence feed of known malicious IPs.

    First response: **isolate the instance** — modify its Security Group to block all inbound and outbound traffic. This stops data exfiltration while you investigate. Do NOT terminate the instance yet — you need the memory, processes, and network connections for forensics. Take an EBS snapshot first.

??? note "Q4: How do you give a Lambda function access to a Secrets Manager secret without hardcoding credentials?"
    Attach an **IAM execution role** to the Lambda function with a policy that allows `secretsmanager:GetSecretValue` on the specific secret ARN. In the function code, call the Secrets Manager API at runtime — never store the secret in environment variables or code. Enable **automatic rotation** on the secret so the Lambda always gets a fresh value when it calls the API.

??? note "Q5: What is the difference between a KMS Key Policy and a KMS Grant?"
    **Key Policy:** JSON document attached to the key that defines who can use and administer it. Changes require `kms:PutKeyPolicy` permission. Persistent — survives until explicitly changed.

    **Grant:** Temporary, programmatic delegation. An application calls `kms:CreateGrant` to allow another principal to use the key for a specific purpose (e.g. `Decrypt` only). Grants can be retired programmatically without modifying the key policy. Used by AWS services internally (e.g. EBS, S3) to use your CMK on your behalf.

??? note "Q6: A security audit finds that an IAM role with admin permissions is attached to 47 EC2 instances. How do you fix this with minimum disruption?"
    1. **Audit actual usage** with AWS Access Analyzer and CloudTrail — determine which specific permissions each instance actually uses
    2. Create **least-privilege role(s)** based on observed usage — separate roles per application tier if needed
    3. **Test the new role** on one non-production instance first
    4. Use **EC2 Instance Profile replacement** (no instance restart required — `aws ec2 replace-iam-instance-profile-association`)
    5. Roll out across all 47 instances during a maintenance window
    6. Monitor CloudTrail for `AccessDenied` errors for one week — indicates missing permissions
    7. Delete or disable the admin role after confirmed safe

??? note "Q7: What is AWS Control Tower and when would you use it instead of manually configuring Organizations + SCPs?"
    **Control Tower** is a higher-level service that automates the setup of a multi-account AWS environment with security guardrails built in. It creates a landing zone with: a management account, log archive account, audit account, pre-configured SCPs (called guardrails), and AWS Config rules.

    **Use Control Tower when:** setting up a new multi-account environment from scratch, need pre-built compliance guardrails, want automatic account vending (Account Factory).

    **Use manual Organizations + SCPs when:** you have an existing org structure you don't want to disturb, need custom guardrails beyond what Control Tower provides, or your team has strong Terraform skills and prefers IaC control.

---

## Part 3: Study Resources

| Resource | Best For | Cost |
|---|---|---|
| [Adrian Cantrill SCS-C03 Course](https://learn.cantrill.io/p/aws-certified-security-specialty) | Best video — deep service coverage | ~$40 |
| [TutorialsDojo Practice Exams](https://tutorialsdojo.com/aws-certified-security-specialty-scs-c02/) | Best practice questions | ~$15 |
| [AWS Security Documentation](https://docs.aws.amazon.com/security/) | Primary source — read service security guides | FREE |
| [AWS re:Inforce sessions (YouTube)](https://www.youtube.com/results?search_query=aws+reinforce+security) | Deep-dive talks from AWS security engineers | FREE |
| [AWS Security Blog](https://aws.amazon.com/blogs/security/) | Real-world patterns and reference architectures | FREE |

!!! tip "Exam strategy for SCS-C03"
    - **Elimination works well** — two answers are usually obviously wrong, then pick the more security-focused of the remaining two
    - **"Most secure" = least privilege + encryption at rest + encryption in transit + no public access**
    - **Incident response questions** always follow the same pattern: detect → contain → investigate → remediate → recover
    - **KMS questions** are everywhere — understand envelope encryption, key policies vs IAM, and rotation cold
    - **You have 170 minutes for 65 questions** — ~2.6 minutes each. Flag difficult ones and return.

---

## Phase 3 Complete — Portfolio Summary

| Month | GitHub Deliverable | Skills Demonstrated |
|---|---|---|
| **7** | `juice-shop-writeups` — exploit writeups + STRIDE threat model | Manual AppSec, OWASP Top 10, API security |
| **8** | `iron-bank-security-toolkit` — Semgrep + ZAP + Trivy + Gitleaks | Automated security testing, CI/CD integration |
| **9** | Secure Dockerfile, ECR/ECS Terraform module, K8s security manifests | Container security, cloud-native deployment |

---

## Checklist

- [ ] All 7 exam practice questions answered without looking
- [ ] KMS envelope encryption explainable in plain English
- [ ] Difference between WAF and Shield stated clearly
- [ ] CloudTrail: know Management vs Data vs Insights events
- [ ] Macie's purpose in one sentence
- [ ] SCS-C03 exam booked (or date confirmed)
- [ ] Adrian Cantrill course started (minimum: IAM, KMS, GuardDuty, CloudTrail modules)
- [ ] TutorialsDojo practice exam score > 70%
- [ ] All Phase 3 GitHub repos have clean READMEs and are public
- [ ] **No AWS resources running — bill $0**

!!! tip "What's next: DevSecOps"
    Month 10 puts everything together in a **GitHub Actions CI/CD pipeline** with security gates: Semgrep on every PR, ZAP on every deployment, Trivy on every image build, Checkov on every Terraform change. You'll go from "I know these tools" to "I automated them" — the difference between a junior and a mid-level DevSecOps engineer.

