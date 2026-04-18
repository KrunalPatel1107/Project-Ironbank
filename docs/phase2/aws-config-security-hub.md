# Month 6 — Week 2: AWS Config & Security Hub

!!! danger "💰 Cost Warning"
    - **AWS Config:** ~$0.003 per configuration item recorded. A lab account generates ~100–300 items. Expect **< $1** for the week. **Disable the recorder after the lab.**
    - **Security Hub:** First 30 days free trial. After that ~$0.0010 per check per resource per month. **Disable after the lab.**
    - **Config Rules:** $1.00 per active rule per region per month (after 1 free rule). You'll create ~4 rules — **~$3 for the week if left running.** Delete them when done.

!!! info "If you know the Microsoft security stack"
    AWS Config = Azure Policy (continuous compliance). Security Hub = Microsoft Defender for Cloud's "Secure Score" dashboard. If you've presented Secure Score metrics to leadership before, Security Hub gives you the AWS equivalent — a consolidated compliance percentage and finding list you can screenshot for your portfolio.

---

## What Is AWS Config?

AWS Config is a **continuous compliance recorder**. It tracks every configuration change to your AWS resources and evaluates those configurations against rules you define.

| Feature | What It Does |
|---|---|
| **Configuration Recorder** | Snapshots resource configs (VPC, SG, IAM, S3…) every time they change |
| **Config Rules** | Evaluates resources against security standards — marks them COMPLIANT or NON_COMPLIANT |
| **Configuration History** | Answers "what did this resource look like 3 weeks ago?" |
| **Remediation** | Can automatically fix non-compliant resources via SSM Automation |

## What Is Security Hub?

Security Hub is the **centralised security findings aggregator**. It pulls findings from GuardDuty, Config, Inspector, Macie, and third-party tools into a single dashboard with a compliance score against standards like CIS AWS Foundations Benchmark and AWS Foundational Security Best Practices.

Think of it as the pane-of-glass on top of all your individual security services.

---

## Part 1: Enable AWS Config

```bash
# ─── Step 1: Create an S3 bucket for Config to deliver snapshots ──────────────
ACCOUNT_ID=$(aws sts get-caller-identity --profile iron-bank --query Account --output text)
CONFIG_BUCKET="iron-bank-config-${ACCOUNT_ID}"

aws s3api create-bucket \
  --bucket $CONFIG_BUCKET \
  --region us-east-1 \
  --profile iron-bank

# Block all public access on the Config bucket
aws s3api put-public-access-block \
  --bucket $CONFIG_BUCKET \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --profile iron-bank

# Attach a bucket policy that allows Config to write to it
aws s3api put-bucket-policy \
  --bucket $CONFIG_BUCKET \
  --policy "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [
      {
        \"Sid\": \"AWSConfigBucketPermissionsCheck\",
        \"Effect\": \"Allow\",
        \"Principal\": {\"Service\": \"config.amazonaws.com\"},
        \"Action\": \"s3:GetBucketAcl\",
        \"Resource\": \"arn:aws:s3:::${CONFIG_BUCKET}\"
      },
      {
        \"Sid\": \"AWSConfigBucketDelivery\",
        \"Effect\": \"Allow\",
        \"Principal\": {\"Service\": \"config.amazonaws.com\"},
        \"Action\": \"s3:PutObject\",
        \"Resource\": \"arn:aws:s3:::${CONFIG_BUCKET}/AWSLogs/${ACCOUNT_ID}/Config/*\",
        \"Condition\": {
          \"StringEquals\": {\"s3:x-amz-acl\": \"bucket-owner-full-control\"}
        }
      }
    ]
  }" \
  --profile iron-bank

echo "Config S3 bucket created: $CONFIG_BUCKET"

# ─── Step 2: Create an IAM role for Config ────────────────────────────────────
# Config needs permission to read your resource configurations
aws iam create-role \
  --role-name AWSConfigRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "config.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }' \
  --profile iron-bank

# Attach the AWS-managed Config policy (covers all the read permissions Config needs)
aws iam attach-role-policy \
  --role-name AWSConfigRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWS_ConfigRole \
  --profile iron-bank

CONFIG_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/AWSConfigRole"
echo "Config IAM Role: $CONFIG_ROLE_ARN"

# ─── Step 3: Create the Configuration Recorder ───────────────────────────────
# The recorder is what actually watches your resources for changes
aws configservice put-configuration-recorder \
  --configuration-recorder "{
    \"name\": \"iron-bank-recorder\",
    \"roleARN\": \"${CONFIG_ROLE_ARN}\",
    \"recordingGroup\": {
      \"allSupported\": true,
      \"includeGlobalResourceTypes\": true
    }
  }" \
  --profile iron-bank

# ─── Step 4: Create the Delivery Channel (where Config sends its data) ────────
aws configservice put-delivery-channel \
  --delivery-channel "{
    \"name\": \"iron-bank-channel\",
    \"s3BucketName\": \"${CONFIG_BUCKET}\",
    \"configSnapshotDeliveryProperties\": {
      \"deliveryFrequency\": \"TwentyFour_Hours\"
    }
  }" \
  --profile iron-bank

# ─── Step 5: Start the recorder ───────────────────────────────────────────────
aws configservice start-configuration-recorder \
  --configuration-recorder-name iron-bank-recorder \
  --profile iron-bank

echo "✅ AWS Config is now recording all resource changes"
```

---

## Part 2: Add Config Rules

Config Rules evaluate your resources against security best practices. AWS provides hundreds of **managed rules** — you just enable them.

```bash
# ─── Rule 1: S3 buckets must block public access ─────────────────────────────
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "s3-bucket-public-access-prohibited",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
    }
  }' \
  --profile iron-bank

# ─── Rule 2: Root account must have MFA enabled ──────────────────────────────
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "root-account-mfa-enabled",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "ROOT_ACCOUNT_MFA_ENABLED"
    }
  }' \
  --profile iron-bank

# ─── Rule 3: IAM password policy must meet minimum standards ─────────────────
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "iam-password-policy",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "IAM_PASSWORD_POLICY"
    },
    "InputParameters": "{\"RequireUppercaseCharacters\":\"true\",\"RequireLowercaseCharacters\":\"true\",\"RequireSymbols\":\"true\",\"RequireNumbers\":\"true\",\"MinimumPasswordLength\":\"14\",\"MaxPasswordAge\":\"90\"}"
  }' \
  --profile iron-bank

# ─── Rule 4: VPC Flow Logs must be enabled ────────────────────────────────────
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "vpc-flow-logs-enabled",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "VPC_FLOW_LOGS_ENABLED"
    }
  }' \
  --profile iron-bank

echo "✅ 4 Config Rules created. Evaluation begins in ~5 minutes."

# ─── Check compliance status after ~5 minutes ─────────────────────────────────
sleep 300
aws configservice describe-compliance-by-config-rule \
  --profile iron-bank \
  --query 'ComplianceByConfigRules[*].{Rule:ConfigRuleName,Status:Compliance.ComplianceType}' \
  --output table
```

??? note "COMPLIANT vs NON_COMPLIANT vs NOT_APPLICABLE"
    - **COMPLIANT** — all evaluated resources pass this rule
    - **NON_COMPLIANT** — at least one resource violates the rule
    - **NOT_APPLICABLE** — the rule doesn't apply to any resources in this account (e.g. RDS rule in an account with no RDS instances)
    - **INSUFFICIENT_DATA** — Config hasn't evaluated this rule yet — wait a few more minutes

---

## Part 3: Enable Security Hub

```bash
# ─── Enable Security Hub ──────────────────────────────────────────────────────
aws securityhub enable-security-hub \
  --enable-default-standards \
  --profile iron-bank
# --enable-default-standards activates:
#   • AWS Foundational Security Best Practices (FSBP)
#   • CIS AWS Foundations Benchmark v1.4.0

echo "Security Hub enabled. Initial findings take 30–60 minutes to populate."

# ─── Check which security standards are active ────────────────────────────────
aws securityhub describe-standards-subscriptions \
  --profile iron-bank \
  --query 'StandardsSubscriptions[*].{Standard:StandardsArn,Status:StandardsStatus}' \
  --output table

# ─── Get your Security Hub summary score ─────────────────────────────────────
# (Run after 30+ minutes — findings need time to be evaluated)
aws securityhub get-findings \
  --filters '{
    "SeverityLabel": [
      {"Value": "CRITICAL", "Comparison": "EQUALS"},
      {"Value": "HIGH",     "Comparison": "EQUALS"}
    ],
    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
    "RecordState":    [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
  }' \
  --profile iron-bank \
  --query 'Findings[*].{Title:Title,Severity:Severity.Label,Resource:Resources[0].Type}' \
  --output table | head -30

# Count total findings by severity
aws securityhub get-findings \
  --filters '{
    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
    "RecordState":    [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
  }' \
  --profile iron-bank \
  --query 'length(Findings)'
```

---

## Part 4: Build a Security Dashboard Script

This is your Month 6 Week 2 deliverable — a Python script that queries Security Hub and Config to give you a quick security posture summary.

```python
#!/usr/bin/env python3
"""
security_posture.py — AWS Security Posture Dashboard
Iron Bank Training — Month 6 Week 2

Queries Security Hub and AWS Config to summarise your account's
security compliance status in one report.
"""

import boto3
from collections import defaultdict


AWS_PROFILE = "iron-bank"
AWS_REGION  = "us-east-1"


def get_session():
    """Return a boto3 session using the iron-bank named profile."""
    return boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)


def get_security_hub_summary(session):
    """
    Pull open Security Hub findings grouped by severity.
    Returns a dict: {severity: count}
    """
    client = session.client("securityhub")
    severity_counts = defaultdict(int)

    # We use a paginator because Security Hub can return thousands of findings
    # A paginator automatically handles the "next page" calls for us
    paginator = client.get_paginator("get_findings")

    pages = paginator.paginate(
        Filters={
            # Only count findings that are still open (not resolved or suppressed)
            "WorkflowStatus": [{"Value": "NEW",    "Comparison": "EQUALS"}],
            "RecordState":    [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        }
    )

    for page in pages:
        for finding in page["Findings"]:
            # Each finding has a severity label: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
            severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
            severity_counts[severity] += 1

    return dict(severity_counts)


def get_config_compliance(session):
    """
    Get compliance status for each Config Rule.
    Returns a list of (rule_name, compliance_status) tuples.
    """
    client = session.client("config")

    response = client.describe_compliance_by_config_rule()

    results = []
    for rule in response.get("ComplianceByConfigRules", []):
        name   = rule["ConfigRuleName"]
        status = rule["Compliance"]["ComplianceType"]
        results.append((name, status))

    return results


def print_dashboard(hub_summary, config_rules):
    """Print a formatted security posture report."""
    print("\n" + "=" * 60)
    print("  🏦 Iron Bank — Security Posture Dashboard")
    print("=" * 60)

    # ── Security Hub section ──────────────────────────────────────
    print("\n🛡️  Security Hub — Open Findings")
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

    total = sum(hub_summary.values())
    for severity in severity_order:
        count = hub_summary.get(severity, 0)
        # Build a simple bar chart with "█" characters
        bar   = "█" * min(count, 30)    # Cap bar at 30 chars so it fits in terminal
        print(f"  {severity:<15} {count:>4}  {bar}")
    print(f"  {'TOTAL':<15} {total:>4}")

    # ── Config Rules section ──────────────────────────────────────
    print("\n📋  AWS Config — Rule Compliance")
    compliant     = [r for r in config_rules if r[1] == "COMPLIANT"]
    non_compliant = [r for r in config_rules if r[1] == "NON_COMPLIANT"]

    for name, status in config_rules:
        # Use a traffic-light emoji to make it scannable
        icon = "✅" if status == "COMPLIANT" else "❌" if status == "NON_COMPLIANT" else "⚪"
        print(f"  {icon}  {name:<45} {status}")

    # ── Summary score ─────────────────────────────────────────────
    if config_rules:
        score = int(len(compliant) / len(config_rules) * 100)
        print(f"\n📊  Config Compliance Score: {score}% ({len(compliant)}/{len(config_rules)} rules passing)")

    # ── Action items ──────────────────────────────────────────────
    if hub_summary.get("CRITICAL", 0) > 0 or hub_summary.get("HIGH", 0) > 0:
        print(f"\n⚠️   Action Required: {hub_summary.get('CRITICAL',0)} CRITICAL + "
              f"{hub_summary.get('HIGH',0)} HIGH findings need investigation")
    else:
        print("\n✅  No CRITICAL or HIGH findings — good posture!")

    if non_compliant:
        print(f"🔧  {len(non_compliant)} Config rule(s) NON_COMPLIANT — review and remediate:")
        for name, _ in non_compliant:
            print(f"    • {name}")

    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    session = get_session()

    print("Querying Security Hub findings...")
    hub_summary = get_security_hub_summary(session)

    print("Querying AWS Config compliance...")
    config_rules = get_config_compliance(session)

    print_dashboard(hub_summary, config_rules)
```

```bash
# Save and run the script
python3 security_posture.py

# Add to your iron-bank-terraform project
mkdir -p ~/projects/iron-bank-tf/scripts
cp security_posture.py ~/projects/iron-bank-tf/scripts/
git add scripts/security_posture.py
git commit -m "feat: security posture dashboard script — Month 6 Week 2"
git push
```

---

## 🧹 Cleanup

!!! abstract "🧹 Cleanup — Config and Security Hub both incur costs if left running"

```bash
# ─── Security Hub ─────────────────────────────────────────────────────────────
aws securityhub disable-security-hub --profile iron-bank

# ─── Config Rules (delete before stopping recorder) ──────────────────────────
for RULE in s3-bucket-public-access-prohibited root-account-mfa-enabled iam-password-policy vpc-flow-logs-enabled; do
  aws configservice delete-config-rule \
    --config-rule-name $RULE \
    --profile iron-bank
  echo "Deleted rule: $RULE"
done

# ─── Config Recorder ──────────────────────────────────────────────────────────
aws configservice stop-configuration-recorder \
  --configuration-recorder-name iron-bank-recorder \
  --profile iron-bank

aws configservice delete-configuration-recorder \
  --configuration-recorder-name iron-bank-recorder \
  --profile iron-bank

aws configservice delete-delivery-channel \
  --delivery-channel-name iron-bank-channel \
  --profile iron-bank

# ─── S3 bucket (must empty before deleting) ───────────────────────────────────
aws s3 rm s3://$CONFIG_BUCKET --recursive --profile iron-bank
aws s3api delete-bucket --bucket $CONFIG_BUCKET --profile iron-bank

# ─── IAM Role ─────────────────────────────────────────────────────────────────
aws iam detach-role-policy \
  --role-name AWSConfigRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWS_ConfigRole \
  --profile iron-bank
aws iam delete-role --role-name AWSConfigRole --profile iron-bank

echo "✅ Config, Security Hub, and all related resources deleted"
```

---

## Checklist

- [ ] AWS Config recorder enabled and running
- [ ] Config S3 bucket created with correct bucket policy
- [ ] 4 Config Rules created and evaluated
- [ ] Compliance results reviewed — understand what NON_COMPLIANT means for each rule
- [ ] Security Hub enabled with CIS + FSBP standards
- [ ] `security_posture.py` runs and displays findings grouped by severity
- [ ] Script committed to GitHub as part of `iron-bank-terraform/scripts/`
- [ ] Can explain the difference between Config and Security Hub (recorder vs aggregator)
- [ ] **Security Hub disabled**
- [ ] **All Config Rules deleted**
- [ ] **Config recorder stopped and deleted**
- [ ] **S3 Config bucket emptied and deleted**
- [ ] **Bill verified $0**
