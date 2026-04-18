# Month 11 — Week 2: AWS Governance at Scale

!!! danger "💰 Cost Warning"
    This week uses AWS Organizations features. If you have a multi-account org setup from Month 6, most of this is free (SCPs are free, Config aggregator is free). The **Config organizational rules** cost $0.001 per evaluation per rule. For a small lab account this is pennies — but always `disable` rules when done.

!!! info "Background Context"
    Microsoft has Azure Management Groups, Azure Policy, and Microsoft Defender for Cloud for cross-subscription governance. AWS has Organizations, SCPs, Config Aggregators, and Security Hub for the same purpose. If you're familiar with Azure governance, this week you build the AWS equivalent: a central governance view across all accounts with automated enforcement.

---

## The Governance Architecture

```
Management Account (root)
    ├── SCP: Deny non-approved regions
    ├── SCP: Deny disabling GuardDuty
    ├── SCP: Require MFA for IAM actions
    └── Config Aggregator → gathers findings from all member accounts
                            → Security Hub aggregator → central dashboard
Member Account A (dev)
    └── Config Rules → evaluated and reported to aggregator
Member Account B (prod)
    └── Config Rules → evaluated and reported to aggregator
```

!!! tip "Single-account lab alternative"
    If you only have one AWS account (the `iron-bank` account), you can still complete this week by deploying Config rules locally, enabling Security Hub, and reviewing the Security Hub dashboard. Skip the Organizations sections that require multiple accounts.

---

## Part 1: Review and Strengthen SCPs

You wrote SCPs in Month 6 Week 3. This week you add two production-grade SCPs that appear in most enterprise AWS environments.

### SCP: Require MFA for Sensitive Actions

```bash
# Create a file with the SCP JSON
cat > /tmp/scp-require-mfa.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyHighRiskActionsWithoutMFA",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:AttachUserPolicy",
        "iam:DetachUserPolicy",
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "organizations:*",
        "account:*"
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
EOF
# BoolIfExists: "false" = deny if MFA is not present
# BoolIfExists vs Bool:
#   Bool: applies only when the key exists in the request
#   BoolIfExists: applies even when the key is missing (i.e. assumed false)
# Use BoolIfExists so service roles that can't have MFA aren't blocked

# Create the SCP (requires Organizations management account access)
aws organizations create-policy \
  --name "iron-bank-require-mfa-for-iam" \
  --description "Require MFA for IAM user creation and key rotation" \
  --content file:///tmp/scp-require-mfa.json \
  --type SERVICE_CONTROL_POLICY \
  --profile iron-bank 2>/dev/null || echo "Note: Organizations API requires management account"
```

### SCP: Deny Disabling Security Services

```bash
cat > /tmp/scp-protect-security.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProtectSecurityServices",
      "Effect": "Deny",
      "Action": [
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:StopMonitoringMembers",
        "config:DeleteConfigRule",
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "config:StopConfigurationRecorder",
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "securityhub:DeleteHub",
        "securityhub:DisableSecurityHub"
      ],
      "Resource": "*"
    }
  ]
}
EOF
# This SCP prevents anyone — even account administrators — from
# disabling security monitoring. Common in regulated industries.
# The management account can always override an SCP (it's not subject to SCPs itself).

aws organizations create-policy \
  --name "iron-bank-protect-security-services" \
  --description "Prevent disabling GuardDuty, Config, CloudTrail, Security Hub" \
  --content file:///tmp/scp-protect-security.json \
  --type SERVICE_CONTROL_POLICY \
  --profile iron-bank 2>/dev/null || echo "Note: Organizations API requires management account"
```

---

## Part 2: Security Hub as the Central Dashboard

Security Hub aggregates findings from GuardDuty, Config, Macie, Inspector, and third-party tools into one place. Think of it as your AWS Defender for Cloud equivalent.

```bash
# ── Enable Security Hub with all default standards ────────────────────────────
aws securityhub enable-security-hub \
  --enable-default-standards \
  --profile iron-bank \
  --region us-east-1

# The default standards enabled:
#   AWS Foundational Security Best Practices (FSBP)
#   CIS AWS Foundations Benchmark 1.2
# Optional (enable separately):
#   PCI-DSS 3.2.1
#   NIST SP 800-53

# ── Check overall Security Hub score ─────────────────────────────────────────
aws securityhub get-finding-statistics \
  --profile iron-bank \
  --region us-east-1 \
  --query 'FindingCounts' 2>/dev/null

# Better: use the Console
# Security Hub → Summary → shows % of controls passing
```

### Query Security Hub Findings with Python

```bash
cat > ~/projects/config-rules/security_hub_report.py << 'EOF'
"""
security_hub_report.py — summarize Security Hub findings by severity and status.
Run: python3 security_hub_report.py --profile iron-bank
"""
import boto3
import argparse
from collections import Counter

def get_active_findings(client):
    """Fetch all ACTIVE findings (not archived or suppressed)."""
    findings = []
    paginator = client.get_paginator('get_findings')
    
    filters = {
        'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
        'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}]
        # NEW = not yet triaged. Also try NOTIFIED, RESOLVED, SUPPRESSED
    }
    
    for page in paginator.paginate(Filters=filters, MaxResults=100):
        findings.extend(page['Findings'])
    
    return findings

def report(findings):
    """Print a summary of findings by severity."""
    severity_counts = Counter(f['Severity']['Label'] for f in findings)
    
    print(f"\n{'='*55}")
    print(f"  Security Hub — Active Findings Summary")
    print(f"{'='*55}")
    print(f"\n  Total active findings: {len(findings)}\n")
    
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']:
        count = severity_counts.get(sev, 0)
        bar = '█' * min(count, 30)
        print(f"  {sev:<15} {count:>4}  {bar}")
    
    print()
    
    # Show top 10 non-compliant Config controls
    config_findings = [
        f for f in findings
        if f.get('ProductName', '') in ('Config', 'Security Hub')
        and f['Severity']['Label'] in ('CRITICAL', 'HIGH')
    ][:10]
    
    if config_findings:
        print("  Top HIGH/CRITICAL Config findings:")
        for f in config_findings:
            title = f.get('Title', 'Unknown')[:60]
            print(f"     ❌ {title}")
    
    print(f"\n{'='*55}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', default='iron-bank')
    args = parser.parse_args()
    
    session = boto3.Session(profile_name=args.profile, region_name='us-east-1')
    client = session.client('securityhub')
    
    findings = get_active_findings(client)
    report(findings)

if __name__ == '__main__':
    main()
EOF

python3 ~/projects/config-rules/security_hub_report.py --profile iron-bank
```

---

## Part 3: Automated Suppression of Known-Acceptable Findings

Not every finding is a real risk. In enterprise environments, some findings are "accepted risk" — documented, approved, and suppressed to reduce noise.

```bash
cat > ~/projects/config-rules/suppress_findings.py << 'EOF'
"""
suppress_findings.py — suppress known-acceptable Security Hub findings.
This is the programmatic equivalent of clicking "Suppress" in the console.

Usage: python3 suppress_findings.py --profile iron-bank --dry-run
       python3 suppress_findings.py --profile iron-bank  (actually suppresses)
"""
import boto3
import argparse

# Define which findings to suppress and why
# This list is your "accepted risk register" in code form
SUPPRESSION_RULES = [
    {
        'title_contains': 'S3 Block Public Access should be enabled at the bucket level',
        'resource_contains': 'iron-bank-logs',   # Only suppress for this specific bucket
        'reason': 'Log bucket intentionally has no public access block (it never had objects)'
    },
    {
        'title_contains': 'CloudTrail should be enabled and configured with at least one multi-Region trail',
        'resource_contains': '',    # Apply to all matching
        'reason': 'Single-region trail is intentional for cost reduction in lab environment'
    }
]

def find_matching_findings(client, rule):
    """Find Security Hub findings matching a suppression rule."""
    filters = {
        'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
        'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}],
        'Title': [{'Value': rule['title_contains'], 'Comparison': 'CONTAINS'}]
    }
    
    if rule['resource_contains']:
        filters['ResourceId'] = [{'Value': rule['resource_contains'], 'Comparison': 'CONTAINS'}]
    
    response = client.get_findings(Filters=filters, MaxResults=100)
    return response['Findings']

def suppress_finding(client, finding_id, product_arn, reason, dry_run):
    """Suppress a finding by setting its WorkflowStatus to SUPPRESSED."""
    if dry_run:
        print(f"  [DRY RUN] Would suppress: {finding_id[:40]}...")
        return
    
    client.batch_update_findings(
        FindingIdentifiers=[{'Id': finding_id, 'ProductArn': product_arn}],
        Workflow={'Status': 'SUPPRESSED'},
        Note={'Text': f'Accepted risk: {reason}', 'UpdatedBy': 'iron-bank-automation'}
    )
    print(f"  ✅ Suppressed: {finding_id[:40]}...")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', default='iron-bank')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be suppressed without doing it')
    args = parser.parse_args()
    
    session = boto3.Session(profile_name=args.profile, region_name='us-east-1')
    client = session.client('securityhub')
    
    total = 0
    for rule in SUPPRESSION_RULES:
        print(f"\nRule: {rule['title_contains'][:60]}...")
        findings = find_matching_findings(client, rule)
        print(f"  Found {len(findings)} matching findings")
        
        for f in findings:
            suppress_finding(client, f['Id'], f['ProductArn'], rule['reason'], args.dry_run)
            total += 1
    
    print(f"\nTotal suppressed: {total} findings ({'dry run' if args.dry_run else 'applied'})")

if __name__ == '__main__':
    main()
EOF

# Dry run first — see what would be suppressed
python3 ~/projects/config-rules/suppress_findings.py --profile iron-bank --dry-run
```

---

## Part 4: Zero Trust Architecture in AWS (Review & Enforcement)

From Month 6 Week 3, you learned Zero Trust's 5 pillars:

| Pillar | AWS Service | SCP Enforcement |
|--------|-------------|-----------------|
| **Identity** | IAM, Identity Center, MFA | Deny access without MFA (SCP) |
| **Network** | VPC, Security Groups, NACLs | Deny inter-VPC routing outside bastion (SCP) |
| **Data** | KMS, S3 SSE, TLS | Deny unencrypted S3 uploads (SCP) |
| **Applications** | WAF, API Gateway, ALB | Deny public ALBs without WAF (Config rules) |
| **Visibility** | CloudTrail, GuardDuty, Config | Deny disabling security services (SCP) |

This week you **enforce** Zero Trust principles using SCPs — turning policies into guardrails that prevent misconfiguration regardless of who holds the keys.

### Zero Trust Maturity Model

```
Level 0: No Trust Boundary
  → Console access = full AWS account access
  → No encryption by default
  → Anyone can create resources without approval
  
Level 1: Basic Identity (Minimum)
  → MFA required for console
  → Default deny for high-risk IAM actions
  → This is where most enterprises START
  
Level 2: Network Isolation
  → VPC isolation by environment (dev/staging/prod)
  → No direct internet access except through bastion/NAT
  → All inter-account communication via VPN or PrivateLink
  
Level 3: Data & Application Controls
  → All data encrypted by default (S3 SSE, RDS encryption, EBS encryption)
  → All APIs require authentication (API Gateway + IAM)
  → All findings auto-remediated (no manual config fixes)
  
Level 4: Continuous Verification
  → Risk-based auth (evaluate every request: who, when, from where, to what)
  → Automated breach simulation (chaos engineering)
  → Real-time anomaly detection (Falco, GuardDuty, Macie)
```

---

## Part 5: Implementing Zero Trust via SCPs (Deny-by-Default)

The **principle of least privilege** means: "Deny everything by default, allow only specific actions."

SCPs are the mechanism — they block actions at the account level, regardless of IAM policies.

### SCP: Enforce Encryption on All Storage

```bash
cat > /tmp/scp-enforce-encryption.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedS3Uploads",
      "Effect": "Deny",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
          # Only allow uploads that use KMS (customer-managed keys)
          # Rejects: unencrypted, AES256 (default), AWS-managed KMS
        }
      }
    },
    {
      "Sid": "DenyUnencryptedEBS",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:volume/*",
      "Condition": {
        "Bool": {
          "ec2:Encrypted": "false"
          # All EBS volumes must have encryption enabled
        }
      }
    },
    {
      "Sid": "DenyUnencryptedRDS",
      "Effect": "Deny",
      "Action": [
        "rds:CreateDBInstance",
        "rds:ModifyDBInstance"
      ],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "rds:StorageEncrypted": "false"
          # All RDS databases must have encryption enabled
        }
      }
    }
  ]
}
EOF

aws organizations create-policy \
  --name "iron-bank-enforce-encryption" \
  --description "Enforce encryption on S3, EBS, RDS" \
  --content file:///tmp/scp-enforce-encryption.json \
  --type SERVICE_CONTROL_POLICY \
  --profile iron-bank 2>/dev/null || echo "Note: Requires Organizations management account"
```

### SCP: Enforce Network Isolation (Deny Public Resources)

```bash
cat > /tmp/scp-enforce-network-isolation.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicS3Buckets",
      "Effect": "Deny",
      "Action": "s3:PutAccountPublicAccessBlock",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "s3:BlockPublicAcls": "false",
          "s3:BlockPublicPolicy": "false"
          # Must block all public access
        }
      }
    },
    {
      "Sid": "DenyPublicAMIs",
      "Effect": "Deny",
      "Action": "ec2:ModifyImageAttribute",
      "Resource": "arn:aws:ec2:*:*:image/*",
      "Condition": {
        "StringEquals": {
          "ec2:ImagePublic": "true"
          # Don't allow making AMIs public
        }
      }
    },
    {
      "Sid": "DenyPublicDatabase",
      "Effect": "Deny",
      "Action": "rds:ModifyDBInstance",
      "Resource": "arn:aws:rds:*:*:db/*",
      "Condition": {
        "Bool": {
          "rds:PubliclyAccessible": "true"
          # All RDS instances must be private (VPC only)
        }
      }
    },
    {
      "Sid": "DenyPublicElastiCache",
      "Effect": "Deny",
      "Action": "elasticache:ModifyCacheSubnetGroup",
      "Resource": "*"
      # ElastiCache must use subnet groups (no public access)
    }
  ]
}
EOF

aws organizations create-policy \
  --name "iron-bank-enforce-network-isolation" \
  --description "Deny public S3, AMIs, RDS, ElastiCache" \
  --content file:///tmp/scp-enforce-network-isolation.json \
  --type SERVICE_CONTROL_POLICY \
  --profile iron-bank 2>/dev/null || echo "Note: Requires Organizations management account"
```

### SCP: Enforce Regions (Multi-Region Attack Surface)

```bash
cat > /tmp/scp-enforce-regions.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnapprovedRegions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-east-1",
            "us-west-2"
            # Only allow resources in these 2 regions
            # Reduces blast radius if attacker gains console access
          ]
        }
      }
    }
  ]
}
EOF

aws organizations create-policy \
  --name "iron-bank-enforce-regions" \
  --description "Only allow us-east-1 and us-west-2" \
  --content file:///tmp/scp-enforce-regions.json \
  --type SERVICE_CONTROL_POLICY \
  --profile iron-bank 2>/dev/null || echo "Note: Requires Organizations management account"
```

---

## Part 6: Automated Compliance & Governance Reporting

With Config rules + Security Hub + SCPs, your governance is now **automated and auditable**.

### Generate a Governance Compliance Report

```bash
cat > ~/projects/config-rules/governance_report.py << 'EOF'
#!/usr/bin/env python3
"""
governance_report.py — unified compliance report across:
  1. SCP enforcement (what actions are denied)
  2. Config rules (what's non-compliant)
  3. Security Hub findings (what's high-severity)
  4. GuardDuty threats (what's actively being attacked)

Usage: python3 governance_report.py --profile iron-bank
"""
import boto3
from datetime import datetime, timedelta

def get_config_compliance(client):
    """Get Config compliance score."""
    try:
        response = client.get_compliance_summary_by_config_rule()
        compliant = response['ComplianceSummary']['CompliantResourceCount']['CappedCount']
        non_compliant = response['ComplianceSummary']['NonCompliantResourceCount']['CappedCount']
        total = compliant + non_compliant
        score = (compliant / total * 100) if total > 0 else 0
        return score, compliant, non_compliant
    except:
        return 0, 0, 0

def get_security_hub_findings(client):
    """Get Security Hub finding counts by severity."""
    try:
        response = client.get_finding_statistics(
            Filters={'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]},
            GroupByAttribute='SEVERITY'
        )
        counts = {}
        for item in response['GroupByAttribute']['ItemCounts']:
            counts[item['Key']] = item['Value']
        return counts
    except:
        return {}

def get_guardduty_findings(client):
    """Get GuardDuty findings from past 24 hours."""
    try:
        since = (datetime.utcnow() - timedelta(days=1)).isoformat()
        response = client.list_findings(
            FindingCriteria={
                'Criterion': {
                    'updatedAt': {'Gte': int(datetime.fromisoformat(since).timestamp() * 1000)}
                }
            }
        )
        return len(response['FindingIds'])
    except:
        return 0

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', default='iron-bank')
    args = parser.parse_args()
    
    session = boto3.Session(profile_name=args.profile, region_name='us-east-1')
    
    print(f"\n{'='*65}")
    print(f"  Iron Bank — Unified Governance & Compliance Report")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*65}\n")
    
    # Config Compliance
    config_score, compliant, non_compliant = get_config_compliance(session.client('config'))
    print(f"  Config Compliance Score: {config_score:.1f}%")
    print(f"    ✅ Compliant Rules: {compliant}")
    print(f"    ❌ Non-Compliant Rules: {non_compliant}\n")
    
    # Security Hub
    findings = get_security_hub_findings(session.client('securityhub'))
    print(f"  Security Hub — Active Findings:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']:
        count = findings.get(severity, 0)
        print(f"    {severity:<15} {count:>4}")
    print()
    
    # GuardDuty
    gd_findings = get_guardduty_findings(session.client('guardduty'))
    print(f"  GuardDuty Findings (last 24h): {gd_findings}\n")
    
    # Overall posture
    issues = non_compliant + findings.get('CRITICAL', 0) + findings.get('HIGH', 0)
    status = "🟢 HEALTHY" if issues < 5 else "🟡 CAUTION" if issues < 20 else "🔴 AT RISK"
    print(f"  Overall Posture: {status}")
    print(f"  Critical Issues: {issues}")
    print(f"\n{'='*65}\n")

if __name__ == '__main__':
    main()
EOF

chmod +x ~/projects/config-rules/governance_report.py
python3 ~/projects/config-rules/governance_report.py --profile iron-bank
```

### Understanding SCP Impact

To verify an SCP is working, use the **IAM Policy Simulator**:

```bash
# Test if a user can perform an action (blocked by SCP or IAM?)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT_ID:user/test-user \
  --action-names s3:PutObject rds:ModifyDBInstance \
  --resource-arns "*" \
  --profile iron-bank \
  --query 'EvaluationResults[*].[ActionName,EvalDecision]' \
  --output table

# If EvalDecision = "implicitDeny", the SCP is blocking the action
# If EvalDecision = "allowed", the IAM policy allows it (but SCP might still block)
```

### SCP vs Config Rules

| Feature | SCP | Config Rule |
|---------|-----|-------------|
| **When it runs** | Before the action (preventive) | After deployment (detective) |
| **Effect** | Blocks action — action fails | Detects and reports non-compliance |
| **Use case** | Prevent misconfigs from being created | Catch and fix misconfigs post-deployment |
| **Overhead** | Zero — SCP is inherited from Organization | Config charges $0.001 per rule evaluation |
| **Auto-remediation** | No — SCP only blocks | Yes — Config can trigger Lambda to fix |

---

## Part 7: Governance Audit Trail

All SCP changes are logged in CloudTrail. You can audit who changed governance policies:

```bash
# Find SCP modifications in CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreatePolicy \
  --profile iron-bank \
  --query 'Events[*].[EventTime,Username,EventName]' \
  --output table

# Who disabled a security service?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteConfigRule \
  --profile iron-bank \
  --query 'Events[*].[EventTime,Username,EventName]' \
  --output table
```

This is **compliance evidence** for auditors:
- "Here's who created SCPs and when"
- "Here's who attempted (and failed) to disable CloudTrail"
- "Here's the drift detection history"

---

## 🧹 Cleanup

```bash
# Disable Security Hub (stops billing for non-default standards if any were enabled)
aws securityhub disable-security-hub \
  --profile iron-bank \
  --region us-east-1 2>/dev/null || echo "Security Hub was not enabled or already disabled"

# Delete SCPs (only if you created them with Organizations)
# First detach from any OUs/accounts, then delete:
# aws organizations delete-policy --policy-id <policy-id> --profile iron-bank

# Remove local Python files
rm -f /tmp/scp-require-mfa.json /tmp/scp-protect-security.json

echo "✅ Week 2 governance resources cleaned up"
```

---

## Checklist

**Core Governance (SCPs & Security Hub)**
- [ ] SCP for MFA-required IAM actions written and understood — know why `BoolIfExists` is used
- [ ] SCP for protecting security services written — list 5 actions it blocks from memory
- [ ] Security Hub enabled with default standards
- [ ] `security_hub_report.py` run — findings summary visible with severity breakdown
- [ ] `suppress_findings.py` run in dry-run mode — understand accepted risk suppression workflow
- [ ] Can explain: SCP vs Config rule (SCP prevents actions; Config rules detect and report after the fact)
- [ ] Can explain: Security Hub vs GuardDuty (Hub = aggregator; GuardDuty = threat detector)

**Zero Trust Architecture Review**
- [ ] Can map Zero Trust 5 pillars to AWS services (Identity → IAM, Network → VPC, Data → KMS, etc.)
- [ ] Understand Zero Trust maturity levels 0–4
- [ ] Know why Level 1 (MFA + basic deny) is minimum for production

**Zero Trust SCP Enforcement**
- [ ] SCP for encryption enforcement written (S3, EBS, RDS)
- [ ] SCP for network isolation written (deny public buckets, AMIs, RDS)
- [ ] SCP for region restriction written
- [ ] Can explain: Encryption enforcement is "preventive" — blocks unencrypted uploads before they happen
- [ ] Can explain: why region restriction reduces blast radius if credentials leak

**Compliance & Governance Automation**
- [ ] `governance_report.py` run — Config score + Security Hub findings + GuardDuty visible
- [ ] Used IAM Policy Simulator to test SCP blocking behavior
- [ ] Understand: SCP runs BEFORE action (preventive), Config runs AFTER (detective)
- [ ] Reviewed CloudTrail for policy modifications — understand audit trail
- [ ] Can defend: "Why we use SCPs even though IAM policies exist" (SCPs apply to ALL, prevent mistakes)

**Cleanup & Cost**
- [ ] Security Hub disabled if you won't use it — check Billing to confirm no ongoing cost
- [ ] SCPs not deleted (they're free, and enforcement benefit is worth keeping)
- [ ] CloudTrail still enabled (free tier covers most usage)

