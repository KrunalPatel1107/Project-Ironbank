# Month 6 — Week 3: Zero Trust Principles + SCPs & Networking

!!! danger "💰 Cost Warning"
    - **AWS Organizations:** Free service — no cost.
    - **SCPs (Service Control Policies):** Free to create and attach.
    - **VPC Endpoints:** ~$0.01/hour each ($7.20/month per endpoint). **Delete after the lab.**
    - **PrivateLink / Interface Endpoints:** $0.01/hour + $0.01/GB data processed. Delete when done.

!!! info "If you know Azure governance"
    SCPs = Azure Management Group Policies (covered in SC-100). VPC Endpoints = Azure Private Endpoints / Private Link — used to keep traffic off the public internet. Zero Trust is the **architecture philosophy** — SCPs + VPC Endpoints are the **implementation tools** in AWS. This week you build it hands-on.

---

## This Week: Two Concepts

**1. Zero Trust Architecture** — The philosophy: "Never trust by default, always verify." Apply this to every layer (identity, network, data, applications).

**2. Service Control Policies (SCPs) + Zero Trust Networking** — The tools to enforce zero trust: deny-by-default policies, network isolation, encryption everywhere.

---

# PART 1: Zero Trust Principles in AWS

!!! abstract "What is Zero Trust?"
    **Zero Trust** = "Never trust, always verify"
    
    Traditional: "Trust inside the firewall, verify outside"  
    Zero Trust: "Verify everything, everywhere, always"
    
    In AWS terms:
    - Identity: Verify who is accessing (IAM + MFA)
    - Network: Verify traffic is encrypted, on private paths (VPC Endpoints, TLS)
    - Data: Verify data is encrypted at rest & in transit (KMS, S3-SSE, RDS encryption)
    - Applications: Verify API calls, log everything (CloudTrail, CloudWatch)

## Zero Trust Maturity Model

Zero Trust implementation has layers:

```
┌─ Level 0: No Zero Trust (Vulnerable) ────────────────────┐
│  - Users have broad IAM permissions ("*")                  │
│  - Traffic flows through public internet (no VPC Endpoints)│
│  - No MFA, no audit logging                                │
│  - Example: Developer with AdministratorAccess role        │
└──────────────────────────────────────────────────────────┘

┌─ Level 1: Basic Zero Trust (Traditional Security) ────────┐
│  - IAM principle of least privilege                        │
│  - MFA enforced for console access                         │
│  - CloudTrail logging enabled                              │
│  - Example: Developer can only modify S3 bucket they own   │
└──────────────────────────────────────────────────────────┘

┌─ Level 2: Advanced Zero Trust (Defense in Depth) ─────────┐
│  - Resource-based policies + IAM conditions                │
│  - Network isolation (private subnets, Security Groups)    │
│  - Encryption at rest + in transit                         │
│  - VPC Endpoints for AWS service access (no internet)      │
│  - Example: EC2 can only talk to RDS via PrivateLink      │
└──────────────────────────────────────────────────────────┘

┌─ Level 3: Maximum Zero Trust (Google BeyondCorp) ─────────┐
│  - Continuous verification (every request verified)        │
│  - Device posture checks (only trusted devices)            │
│  - Behavioral analytics (detect anomalies)                 │
│  - Fine-grained access decisions (per-request)             │
│  - Example: Access depends on device health, location, time│
└──────────────────────────────────────────────────────────┘
```

---

## Zero Trust Pillars in AWS

### Pillar 1: Identity (Who Am I?)

**Concept**: Verify identity before granting access. Never trust an IP address or network location.

| Traditional | Zero Trust |
|---|---|
| "User is inside the network, trust them" | "Verify IAM principal on every request" |
| Username + password | MFA + temporary credentials (STS tokens) |
| Long-lived access keys | Short-lived session tokens (1 hour) |

**AWS Implementation**:
```hcl
# ❌ BAD: Broad permissions (Level 0)
{
  "Effect": "Allow",
  "Principal": "*",                    # Anyone can assume
  "Action": "sts:AssumeRole"
}

# ✓ GOOD: Restricted to specific principal (Level 1)
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:role/EC2-App"
  },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "unique-id-here"  # Extra verification
    },
    "IpAddress": {
      "aws:SourceIp": ["10.0.0.0/8"]  # Only from VPC
    },
    "Bool": {
      "aws:MultiFactorAuthPresent": "true"  # MFA required
    }
  }
}
```

### Pillar 2: Network (Where Does Traffic Flow?)

**Concept**: Encrypt all traffic. Keep traffic off the public internet. Assume the network is compromised.

| Traditional | Zero Trust |
|---|---|
| "Firewall protects internal network" | "Encrypt all traffic, assume internet is hostile" |
| Unencrypted internal communication | TLS for all connections |
| Public IPs to reach AWS services | VPC Endpoints (private, AWS-managed paths) |

**AWS Implementation**:
```bash
# ❌ BAD: EC2 reaches S3 via public internet (Level 0)
EC2 → Internet Gateway → Public Internet → S3 API

# ✓ GOOD: EC2 reaches S3 via VPC Endpoint (Level 2)
EC2 → VPC Endpoint → AWS private backbone → S3

# Traffic never leaves AWS network (no internet exposure)
```

### Pillar 3: Data (Is Data Protected?)

**Concept**: Encrypt data at rest and in transit. Use encryption keys you control (KMS).

| Traditional | Zero Trust |
|---|---|
| Encrypted at rest "if you remember to enable it" | Encryption enabled by default (deny unencrypted) |
| AWS-managed keys | Customer-managed KMS keys (you control who can decrypt) |
| S3 server-side encryption optional | S3 enforced encryption (via bucket policy) |

**AWS Implementation**:
```json
{
  "Effect": "Deny",
  "Action": [
    "s3:PutObject"
  ],
  "Resource": "*",
  "Condition": {
    "StringNotEquals": {
      "s3:x-amz-server-side-encryption": "aws:kms"
    }
  }
}
// Forces all S3 uploads to use KMS encryption
```

### Pillar 4: Applications & Access (What Can They Do?)

**Concept**: Fine-grained access. An EC2 instance doesn't need admin access — only what it needs (IAM role with specific permissions).

| Traditional | Zero Trust |
|---|---|
| Admin role for troubleshooting | Specific role (dev-tier: S3 read, RDS connect only) |
| All developers in same group | Separate roles per team/application |
| Permission boundaries optional | Permission boundaries + Resource policies required |

**AWS Implementation**:
```hcl
# ❌ BAD: EC2 role with too much access
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ec2:*",  # Can do ANYTHING with EC2
      "Resource": "*"
    }
  ]
}

# ✓ GOOD: EC2 role with minimal access (principle of least privilege)
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "rds-db:connect",  # Can only connect to RDS
        "s3:GetObject"     # Can only read from S3
      ],
      "Resource": [
        "arn:aws:rds:*:*:db:ironbank-db/*",
        "arn:aws:s3:::ironbank-data/*"
      ]
    }
  ]
}
```

### Pillar 5: Visibility & Analytics (What Happened?)

**Concept**: Log everything. Detect anomalies. Continuous verification requires continuous monitoring.

| Traditional | Zero Trust |
|---|---|
| Logs are optional | Logging mandatory (CloudTrail, Flow Logs, VPC Flow) |
| Reactive investigation | Proactive detection (GuardDuty, Security Hub) |
| Manual access reviews | Automated anomaly detection |

**AWS Implementation**:
```bash
# Enable all logging sources
- CloudTrail (API calls)
- VPC Flow Logs (network traffic patterns)
- CloudWatch Logs (application logs)
- GuardDuty (threat detection, e.g., unusual access pattern)
- Security Hub (compliance status)

# Set CloudWatch alarm: Deny actions exceed threshold
- If 10+ "Denied" actions in 5 minutes → Security team alert
- Indicates compromised credential or malicious activity
```

---

## Zero Trust Audit Lab

Let's audit your Iron Bank VPC against zero trust maturity:

### Checklist: Zero Trust Implementation

Save this as `zero-trust-audit.md`:

```markdown
# Iron Bank Zero Trust Audit

## Pillar 1: Identity ✓/✗

- [ ] MFA enforced for console users
  Status: {{ }}
  
- [ ] IAM roles have resource-specific permissions (not "Principal": "*")
  Status: {{ }}
  
- [ ] Permission boundaries configured (even restricted roles can't escalate)
  Status: {{ }}
  
- [ ] External ID required for cross-account assume role
  Status: {{ }}
  
- [ ] Short-lived credentials (STS tokens, no long-lived access keys)
  Status: {{ }}
  
- [ ] Service roles (EC2, Lambda) don't have broad AWS access
  Status: {{ }}

## Pillar 2: Network ✓/✗

- [ ] EC2 instances in private subnets (no public IPs)
  Status: {{ }}
  
- [ ] Security Groups enforce least privilege (specific ports/IPs)
  Status: {{ }}
  
- [ ] VPC Endpoints configured for S3, DynamoDB, Secrets Manager
  Status: {{ }}
  
- [ ] No unencrypted traffic (all connections use TLS)
  Status: {{ }}
  
- [ ] VPC Flow Logs enabled (visibility into network traffic)
  Status: {{ }}

## Pillar 3: Data ✓/✗

- [ ] S3 bucket policy enforces encryption (aws:kms)
  Status: {{ }}
  
- [ ] RDS encryption at rest enabled (KMS-managed)
  Status: {{ }}
  
- [ ] RDS encryption in transit enforced (TLS)
  Status: {{ }}
  
- [ ] EBS volumes encrypted
  Status: {{ }}
  
- [ ] KMS keys have resource-based policies (explicit who can decrypt)
  Status: {{ }}

## Pillar 4: Applications & Access ✓/✗

- [ ] No users with AdministratorAccess (only privileged roles)
  Status: {{ }}
  
- [ ] EC2 role has only db-connect, not admin
  Status: {{ }}
  
- [ ] Lambda role has specific S3 read access (not "s3:*")
  Status: {{ }}
  
- [ ] SCPs restrict dangerous actions (DeleteTrail, ModifySecurityGroup)
  Status: {{ }}

## Pillar 5: Visibility ✓/✗

- [ ] CloudTrail enabled, logs to S3
  Status: {{ }}
  
- [ ] CloudWatch Logs for application logs
  Status: {{ }}
  
- [ ] VPC Flow Logs enabled
  Status: {{ }}
  
- [ ] GuardDuty enabled (threat detection)
  Status: {{ }}
  
- [ ] Security Hub enabled (compliance dashboard)
  Status: {{ }}
  
- [ ] CloudWatch alarms for suspicious actions
  Status: {{ }}

## Maturity Level

- Level 0 (< 5 checks): No Zero Trust
- Level 1 (5–10 checks): Basic (least privilege)
- Level 2 (11–20 checks): Advanced (defense in depth)
- Level 3 (21+ checks): Maximum (continuous verification)

Your Iron Bank maturity: **Level {{ }}**

## Top 3 Gaps to Fix

1. {{ gap 1 }}
2. {{ gap 2 }}
3. {{ gap 3 }}
```

---

## Checklist (Zero Trust Principles)

- [ ] Understand the 5 Zero Trust pillars (identity, network, data, apps, visibility)
- [ ] Know the difference between Level 0, 1, 2, 3 maturity
- [ ] Understand IAM conditions and why they matter
- [ ] Know VPC Endpoint concept (S3, DynamoDB, Secrets Manager)
- [ ] Understand encryption at rest vs. in transit
- [ ] Completed Zero Trust audit of your VPC
- [ ] Identified gaps in your architecture

---

# PART 2: Service Control Policies (SCPs) & Zero Trust Networking

!!! danger "💰 Cost Warning"
    - **AWS Organizations:** Free service — no cost.
    - **SCPs (Service Control Policies):** Free to create and attach.
    - **VPC Endpoints:** ~$0.01/hour each ($7.20/month per endpoint). **Delete after the lab.**

!!! info "SCPs = Deny Policies at Organization Level"
    SCPs enforce **organization-wide guardrails**. Even if someone gets high-privilege IAM access, SCPs restrict what they can actually do. This is the "deny-by-default" part of zero trust.

---

## Concept 1: Service Control Policies (SCPs)

SCPs work at the **AWS Organizations** level — above IAM. Think of IAM as "what this user is allowed to do in their account" and SCPs as "what any user in this entire organisational unit is ever permitted to do, no matter what their IAM policy says."

```
AWS Organization
└── Root
    ├── Management Account  (SCPs don't apply here — be careful)
    └── OU: Iron-Bank-Labs  ← SCP applied here
        └── Member Account  (your lab account)
```

!!! warning "SCPs apply a logical AND with IAM policies"
    If an SCP says `"Deny: s3:DeleteBucket"` and an IAM policy says `"Allow: s3:*"` — the result is **Deny**. The SCP wins. This is why SCPs are powerful for establishing non-negotiable guardrails.

### SCP Use Cases You'll See in Interviews

| SCP Pattern | What It Prevents |
|---|---|
| Deny leaving the organisation | Account cannot be removed from org by accident |
| Deny disabling GuardDuty | Security tools can't be turned off by a compromised admin |
| Deny creating resources outside approved regions | Data residency / sovereignty compliance |
| Deny creating IAM users (force SSO) | Enforces federated identity |
| Deny root account API access | Root can only be used for emergency console break-glass |

---

## Part 2 Content Continues Below...

(This section contains the existing SCP content from the original file)

---

## Part 1: Understanding SCPs

SCPs work at the **AWS Organizations** level — above IAM. Think of IAM as "what this user is allowed to do in their account" and SCPs as "what any user in this entire organisational unit is ever permitted to do, no matter what their IAM policy says."

```
AWS Organization
└── Root
    ├── Management Account  (SCPs don't apply here — be careful)
    └── OU: Iron-Bank-Labs  ← SCP applied here
        └── Member Account  (your lab account)
```

!!! warning "SCPs apply a logical AND with IAM policies"
    If an SCP says `"Deny: s3:DeleteBucket"` and an IAM policy says `"Allow: s3:*"` — the result is **Deny**. The SCP wins. This is why SCPs are powerful for establishing non-negotiable guardrails.

### SCP Use Cases You'll See in Interviews

| SCP Pattern | What It Prevents |
|---|---|
| Deny leaving the organisation | Account cannot be removed from org by accident |
| Deny disabling GuardDuty | Security tools can't be turned off by a compromised admin |
| Deny creating resources outside approved regions | Data residency / sovereignty compliance |
| Deny creating IAM users (force SSO) | Enforces federated identity |
| Deny root account API access | Root can only be used for emergency console break-glass |

---

## Part 2: Set Up an AWS Organization (if not already)

```bash
# ─── Check if you already have an Organisation ────────────────────────────────
aws organizations describe-organization --profile iron-bank 2>/dev/null || echo "No org yet"

# ─── Create an Organisation (if you don't have one) ──────────────────────────
# Note: This must be run from the management (root) account
aws organizations create-organization \
  --feature-set ALL \
  --profile iron-bank
# ALL = enables both Consolidated Billing AND Service Control Policies
# CONSOLIDATED_BILLING_ONLY = billing only, no SCPs

# ─── Enable SCP policy type ───────────────────────────────────────────────────
ROOT_ID=$(aws organizations list-roots \
  --profile iron-bank \
  --query 'Roots[0].Id' --output text)
echo "Root ID: $ROOT_ID"

aws organizations enable-policy-type \
  --root-id $ROOT_ID \
  --policy-type SERVICE_CONTROL_POLICY \
  --profile iron-bank

echo "✅ SCPs enabled at the root"
```

??? note "Do I need an Organisation for my lab?"
    Creating an Organisation is free but requires careful management — the management account has no SCP restrictions by default. For a solo lab account, you can study SCP **syntax and concepts** without applying them to avoid accidentally locking yourself out. Read through the examples below, understand them, and note that you'll apply SCPs for real in team/enterprise environments.

---

## Part 3: Write and Understand SCP Policies

SCPs are written in the same JSON syntax as IAM policies. Study these patterns — they appear on the Terraform Associate and AWS Security Specialty exams.

**SCP 1 — Deny all actions outside approved regions:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "organizations:*",
        "sts:*",
        "support:*",
        "cloudfront:*",
        "route53:*",
        "waf:*",
        "budgets:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["us-east-1", "us-west-2"]
        }
      }
    }
  ]
}
```

??? note "Why NotAction instead of Action?"
    `Action: Deny all except these` = you'd have to list every AWS action. That's thousands of actions.
    `NotAction: Deny everything except this short list` = much more maintainable. The services listed (IAM, Route53, CloudFront, etc.) are **global services** that don't have a region — they'd be incorrectly denied by a region restriction, so we exclude them.

**SCP 2 — Deny disabling GuardDuty:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyGuardDutyDisable",
      "Effect": "Deny",
      "Action": [
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:StopMonitoringMembers",
        "guardduty:UpdateDetector"
      ],
      "Resource": "*"
    }
  ]
}
```

**SCP 3 — Require MFA for sensitive actions (Zero Trust identity control):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyHighRiskActionsWithoutMFA",
      "Effect": "Deny",
      "Action": [
        "iam:DeletePolicy",
        "iam:DeleteRolePolicy",
        "ec2:TerminateInstances",
        "s3:DeleteBucket",
        "organizations:LeaveOrganization"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

```bash
# Save SCP 2 as a file and create it in AWS
cat > /tmp/deny-guardduty-disable.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyGuardDutyDisable",
    "Effect": "Deny",
    "Action": [
      "guardduty:DeleteDetector",
      "guardduty:DisassociateFromMasterAccount",
      "guardduty:StopMonitoringMembers",
      "guardduty:UpdateDetector"
    ],
    "Resource": "*"
  }]
}
EOF

SCP_ID=$(aws organizations create-policy \
  --name "DenyGuardDutyDisable" \
  --description "Prevents any principal from disabling GuardDuty" \
  --type SERVICE_CONTROL_POLICY \
  --content file:///tmp/deny-guardduty-disable.json \
  --profile iron-bank \
  --query 'Policy.PolicySummary.Id' --output text)

echo "SCP created: $SCP_ID"

# List all SCPs in the organisation
aws organizations list-policies \
  --filter SERVICE_CONTROL_POLICY \
  --profile iron-bank \
  --query 'Policies[*].{Name:Name,ID:Id,Description:Description}' \
  --output table
```

---

## Part 4: Zero Trust Networking — VPC Endpoints

Without VPC Endpoints, when your EC2 instance calls the S3 API, the traffic leaves your VPC, travels over the public internet to `s3.amazonaws.com`, and comes back. Even though S3 is an AWS service, the traffic takes a public route.

**VPC Endpoints** keep that traffic entirely within the AWS backbone — it never touches the public internet.

```
Without VPC Endpoint:   EC2 → public internet → S3
With VPC Endpoint:      EC2 → private AWS backbone → S3
```

There are two types:

| Type | Services | Mechanism |
|---|---|---|
| **Gateway Endpoint** | S3, DynamoDB only | Free — adds a route to your route table |
| **Interface Endpoint** | 100+ services (SSM, KMS, STS, etc.) | Costs $0.01/hour — creates an ENI in your subnet |

```bash
# ─── Re-use or recreate your Iron Bank VPC ────────────────────────────────────
VPC_ID=$(aws ec2 describe-vpcs \
  --filters "Name=tag:Name,Values=Iron-Bank-VPC" \
  --profile iron-bank \
  --query 'Vpcs[0].VpcId' --output text 2>/dev/null)

# If VPC doesn't exist, create a minimal one for this lab
if [ "$VPC_ID" = "None" ] || [ -z "$VPC_ID" ]; then
  VPC_ID=$(aws ec2 create-vpc \
    --cidr-block 10.0.0.0/16 \
    --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=Iron-Bank-VPC}]' \
    --profile iron-bank \
    --query Vpc.VpcId --output text)
  echo "Created VPC: $VPC_ID"
fi

# Get the private route table ID
PRIV_RT=$(aws ec2 describe-route-tables \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:Name,Values=*private*" \
  --profile iron-bank \
  --query 'RouteTables[0].RouteTableId' --output text)

# ─── Gateway Endpoint for S3 (FREE) ──────────────────────────────────────────
S3_ENDPOINT=$(aws ec2 create-vpc-endpoint \
  --vpc-id $VPC_ID \
  --service-name com.amazonaws.us-east-1.s3 \
  --route-table-ids $PRIV_RT \
  --vpc-endpoint-type Gateway \
  --tag-specifications 'ResourceType=vpc-endpoint,Tags=[{Key=Name,Value=iron-bank-s3-endpoint}]' \
  --profile iron-bank \
  --query 'VpcEndpoint.VpcEndpointId' --output text)

echo "S3 Gateway Endpoint: $S3_ENDPOINT"

# ─── Verify: the endpoint adds a route to your private route table ─────────────
aws ec2 describe-route-tables \
  --route-table-ids $PRIV_RT \
  --profile iron-bank \
  --query 'RouteTables[0].Routes[*].{Destination:DestinationPrefixListId,Target:GatewayId}' \
  --output table
# You should see a row with pl-xxxxxxxx (S3 prefix list) as the destination

# ─── Enforce S3 access ONLY via endpoint (Zero Trust bucket policy) ───────────
# Add this policy to any S3 bucket to block access from outside the VPC endpoint:
cat << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonVPCEndpointAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::YOUR-BUCKET-NAME",
        "arn:aws:s3:::YOUR-BUCKET-NAME/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:sourceVpce": "vpce-YOUR-ENDPOINT-ID"
        }
      }
    }
  ]
}
EOF
# Replace YOUR-BUCKET-NAME and vpce-YOUR-ENDPOINT-ID with real values
# This policy makes the bucket only accessible from inside your VPC
```

??? note "SSM Session Manager — the Bastion replacement"
    With an Interface Endpoint for SSM, you can connect to EC2 instances in private subnets **without a Bastion Host and without SSH open**. This is the modern Zero Trust approach:

    - No inbound port 22 anywhere
    - No SSH key management
    - Full audit trail in CloudTrail (every session logged)
    - IAM controls who can start sessions

    The endpoint creates a private channel: your laptop → SSM API (via endpoint) → EC2 agent. No public internet path exists.

---

## Part 5: Zero Trust Mental Model — Putting It Together

After Weeks 1–3 of Month 6, you've built the three layers of AWS Zero Trust:

```
Layer 1 — Identity Controls (SCPs + IAM)
  └── SCPs: guardrails even admins can't bypass
  └── IAM: least-privilege roles per workload

Layer 2 — Network Controls (VPC Endpoints + Security Groups)
  └── Gateway Endpoint: S3/DynamoDB traffic never leaves AWS backbone
  └── Interface Endpoint: SSM, KMS, STS — no public path
  └── Security Groups: only allow what's needed, from where it's needed

Layer 3 — Detective Controls (GuardDuty + Config + Security Hub)
  └── GuardDuty: runtime threat detection
  └── Config: continuous compliance monitoring
  └── Security Hub: consolidated score and findings
```

!!! tip "This is your Phase 2 narrative for interviews"
    "I designed and implemented a defence-in-depth AWS security posture: SCPs enforce non-negotiable guardrails at the org level, VPC Endpoints eliminate public routing for AWS service traffic, GuardDuty and Config provide continuous threat detection and compliance monitoring, all aggregated into Security Hub."

---

## 🧹 Cleanup

!!! abstract "🧹 Cleanup"

```bash
# Delete VPC Endpoint
aws ec2 delete-vpc-endpoints \
  --vpc-endpoint-ids $S3_ENDPOINT \
  --profile iron-bank

# Delete SCP (must detach from all targets first — if you attached it)
# aws organizations detach-policy --policy-id $SCP_ID --target-id $ROOT_ID --profile iron-bank
aws organizations delete-policy --policy-id $SCP_ID --profile iron-bank

# Clean up VPC if you created one fresh for this lab
aws ec2 delete-vpc --vpc-id $VPC_ID --profile iron-bank 2>/dev/null || echo "VPC has dependencies — clean subnets/SGs first"

echo "✅ Week 3 resources cleaned up"
```

---

## Checklist

- [ ] Can explain the difference between SCPs and IAM policies (both needed, SCP wins on Deny)
- [ ] Read and understood all 3 SCP examples — can explain what each one blocks and why
- [ ] SCP `DenyGuardDutyDisable` created in AWS Organizations
- [ ] Understand why `NotAction` is used in the region-restriction SCP
- [ ] S3 Gateway Endpoint created — confirmed route appears in private route table
- [ ] Can explain Gateway vs Interface endpoints (free vs paid, S3/DynamoDB vs all services)
- [ ] Can articulate the "no Bastion, use SSM" Zero Trust pattern
- [ ] Written the 3-layer Zero Trust narrative in your own words
- [ ] **VPC Endpoint deleted**
- [ ] **SCP deleted from Organizations**
- [ ] **Bill verified $0**
