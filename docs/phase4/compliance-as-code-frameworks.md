# Month 11 — Week 1: Compliance as Code

!!! abstract "💰 Cost: ~$2–5 — AWS Config rules (first 10 rules free in most accounts, then $0.001/rule/evaluation)"

!!! info "Background Context"
    If you've worked with Azure Policy and Secure Score, AWS Config + conformance packs + OPA is the direct equivalent. "Compliance as Code" means your compliance posture is version-controlled, peer-reviewed, and deployed the same way as application code — not a manual spreadsheet someone updates quarterly.

---

## What is Compliance as Code?

Traditional compliance: a security team manually checks controls quarterly and updates a spreadsheet.

Compliance as Code: the controls are written as code (Config rules, OPA policies, Checkov checks) that run continuously and alert immediately when something drifts out of compliance.

```
Code Change (Terraform PR)
    → Checkov checks IaC against compliance policies (pre-deploy)
    → Config rules check deployed resources continuously (post-deploy)
    → Security Hub aggregates findings across both layers
    → Monthly compliance report generated automatically
```

---

## Part 1: AWS Config Conformance Packs

A **conformance pack** is a collection of Config rules + remediation actions deployed as a single unit. AWS provides pre-built packs for CIS, NIST, PCI-DSS, and HIPAA.

### Deploy the AWS Foundational Security Best Practices Conformance Pack

```bash
# First, confirm Config is enabled (you did this in Month 6, Week 2)
aws configservice describe-configuration-recorders \
  --profile iron-bank \
  --query 'ConfigurationRecorders[0].name' \
  --output text
# → default  (if you see this, Config is on)

# If Config is not enabled, re-enable it:
# aws configservice put-configuration-recorder --configuration-recorder ...
# (refer back to aws-config-security-hub.md)

# ── List available conformance pack templates ─────────────────────────────────
# AWS posts sample templates at:
# https://github.com/awslabs/aws-config-rules/tree/master/aws-config-conformance-packs

# ── Deploy AWS Foundational Security Best Practices ───────────────────────────
# This pack contains 67 rules covering IAM, S3, VPC, CloudTrail, KMS, and more

aws configservice put-conformance-pack \
  --conformance-pack-name "iron-bank-fsbp" \
  --template-s3-uri "s3://aws-config-conformance-packs-us-east-1/AWS-Foundational-Security-Best-Practices.yaml" \
  --profile iron-bank \
  --region us-east-1

# Wait for deployment (takes 1-3 minutes)
aws configservice describe-conformance-packs \
  --conformance-pack-names "iron-bank-fsbp" \
  --profile iron-bank \
  --query 'ConformancePackDetails[0].ConformancePackState' \
  --output text
# → CREATE_COMPLETE  (when ready)

# ── Check compliance score ────────────────────────────────────────────────────
aws configservice get-conformance-pack-compliance-summary \
  --conformance-pack-names "iron-bank-fsbp" \
  --profile iron-bank \
  --query 'ConformancePackComplianceSummaryList[0]'
# Shows: COMPLIANT count and NON_COMPLIANT count across all 67 rules
```

### View Specific Non-Compliant Rules

```bash
# Get all non-compliant rules in the conformance pack
aws configservice get-conformance-pack-compliance-details \
  --conformance-pack-name "iron-bank-fsbp" \
  --filters ComplianceType=NON_COMPLIANT \
  --profile iron-bank \
  --query 'ConformancePackRuleComplianceList[*].ConfigRuleName' \
  --output text
```

---

## Part 2: Write a Custom Config Rule (Python Lambda)

AWS Config lets you write custom rules as Lambda functions. This rule checks that all EC2 instances have IMDSv2 enforced (from Month 7 — the Capital One breach prevention):

```bash
# First, create the Lambda function code
mkdir -p ~/projects/config-rules
cat > ~/projects/config-rules/check_imdsv2.py << 'EOF'
import json
import boto3

# This function is called by AWS Config every time an EC2 instance is
# created, modified, or when a periodic evaluation runs.

def evaluate_compliance(configuration_item):
    """
    Check if an EC2 instance has IMDSv2 required (not just optional).
    
    configuration_item: a dict containing the resource's current config
    Returns: 'COMPLIANT', 'NON_COMPLIANT', or 'NOT_APPLICABLE'
    """
    # Only evaluate EC2 instances — skip other resource types
    if configuration_item['resourceType'] != 'AWS::EC2::Instance':
        return 'NOT_APPLICABLE'

    # The configuration contains the instance's full AWS config as a JSON string
    config = json.loads(configuration_item['configuration'])
    
    # Get the MetadataOptions from the instance config
    # metadataOptions.httpTokens = 'required' means IMDSv2 is enforced
    # metadataOptions.httpTokens = 'optional' means IMDSv1 still allowed (VULNERABLE)
    metadata_options = config.get('metadataOptions', {})
    http_tokens = metadata_options.get('httpTokens', 'optional')
    
    if http_tokens == 'required':
        return 'COMPLIANT'
    else:
        return 'NON_COMPLIANT'


def lambda_handler(event, context):
    """
    AWS Lambda entry point. Config passes an invokingEvent with resource details.
    """
    config_client = boto3.client('config')
    
    # Parse the event from Config
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event['configurationItem']
    result_token = event['resultToken']
    
    # Evaluate
    compliance = evaluate_compliance(configuration_item)
    
    # Report back to Config
    config_client.put_evaluations(
        Evaluations=[{
            'ComplianceResourceType': configuration_item['resourceType'],
            'ComplianceResourceId': configuration_item['resourceId'],
            'ComplianceType': compliance,
            'Annotation': 'IMDSv2 must be required, not optional',
            'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
        }],
        ResultToken=result_token
    )
    
    return {'compliance': compliance}
EOF

echo "Custom Config rule Lambda written"
```

Deploy the Lambda and register the Config rule:

```bash
cd ~/projects/config-rules

# Zip the Lambda function
zip check_imdsv2.zip check_imdsv2.py

# Create the IAM role for Lambda (needs to call config:PutEvaluations)
LAMBDA_ROLE=$(aws iam create-role \
  --role-name iron-bank-config-rule-role \
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]
  }' \
  --profile iron-bank \
  --query 'Role.Arn' --output text)

aws iam attach-role-policy \
  --role-name iron-bank-config-rule-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole \
  --profile iron-bank

aws iam put-role-policy \
  --role-name iron-bank-config-rule-role \
  --policy-name config-put-evaluations \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Action":"config:PutEvaluations","Resource":"*"}]
  }' \
  --profile iron-bank

sleep 10   # Wait for IAM propagation

# Create the Lambda function
LAMBDA_ARN=$(aws lambda create-function \
  --function-name iron-bank-check-imdsv2 \
  --runtime python3.12 \
  --role $LAMBDA_ROLE \
  --handler check_imdsv2.lambda_handler \
  --zip-file fileb://check_imdsv2.zip \
  --profile iron-bank \
  --region us-east-1 \
  --query 'FunctionArn' --output text)

echo "Lambda ARN: $LAMBDA_ARN"

# Give Config permission to invoke this Lambda
ACCOUNT_ID=$(aws sts get-caller-identity --profile iron-bank --query Account --output text)
aws lambda add-permission \
  --function-name iron-bank-check-imdsv2 \
  --statement-id config-invoke \
  --action lambda:InvokeFunction \
  --principal config.amazonaws.com \
  --source-account $ACCOUNT_ID \
  --profile iron-bank

# Register the Config rule
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "iron-bank-imdsv2-required",
    "Description": "Checks that all EC2 instances require IMDSv2",
    "Scope": {"ComplianceResourceTypes": ["AWS::EC2::Instance"]},
    "Source": {
      "Owner": "CUSTOM_LAMBDA",
      "SourceIdentifier": "'"$LAMBDA_ARN"'",
      "SourceDetails": [{"EventSource":"aws.config","MessageType":"ConfigurationItemChangeNotification"}]
    }
  }' \
  --profile iron-bank

echo "✅ Custom Config rule deployed"
```

---

## Part 3: Automate Compliance Reporting with Python

```bash
cat > ~/projects/config-rules/compliance_report.py << 'EOF'
"""
compliance_report.py — generates a human-readable compliance summary
from AWS Config conformance packs.

Run with: python3 compliance_report.py --profile iron-bank --pack iron-bank-fsbp
"""
import boto3
import argparse
from datetime import datetime
from collections import defaultdict

def get_compliance_details(client, pack_name):
    """Fetch all rule compliance results from a conformance pack."""
    results = []
    paginator = client.get_paginator('get_conformance_pack_compliance_details')
    
    for page in paginator.paginate(ConformancePackName=pack_name):
        results.extend(page['ConformancePackRuleComplianceList'])
    
    return results

def generate_report(pack_name, results):
    """Turn raw compliance data into a readable report."""
    compliant   = [r for r in results if r['ComplianceType'] == 'COMPLIANT']
    non_compliant = [r for r in results if r['ComplianceType'] == 'NON_COMPLIANT']
    total = len(results)
    
    score = (len(compliant) / total * 100) if total > 0 else 0
    
    print(f"\n{'='*60}")
    print(f"  Compliance Report: {pack_name}")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*60}")
    print(f"\n  Score: {score:.1f}% ({len(compliant)}/{total} rules passing)\n")
    
    bar_len = 40
    filled = int(bar_len * score / 100)
    bar = '█' * filled + '░' * (bar_len - filled)
    color = 'PASS' if score >= 80 else ('WARN' if score >= 60 else 'FAIL')
    print(f"  [{bar}] {color}\n")
    
    if non_compliant:
        print(f"  ❌ NON-COMPLIANT Rules ({len(non_compliant)}):")
        for rule in sorted(non_compliant, key=lambda x: x['ConfigRuleName']):
            print(f"     • {rule['ConfigRuleName']}")
        print()
    
    print(f"  ✅ Compliant: {len(compliant)} rules")
    print(f"{'='*60}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', default='iron-bank')
    parser.add_argument('--pack', default='iron-bank-fsbp')
    args = parser.parse_args()
    
    session = boto3.Session(profile_name=args.profile, region_name='us-east-1')
    client = session.client('config')
    
    print(f"Fetching compliance data for: {args.pack}")
    results = get_compliance_details(client, args.pack)
    generate_report(args.pack, results)

if __name__ == '__main__':
    main()
EOF

python3 ~/projects/config-rules/compliance_report.py --profile iron-bank --pack iron-bank-fsbp
```

---

## Part 4: PCI-DSS Compliance Mapping

**PCI-DSS (Payment Card Industry Data Security Standard)** requires that if you process credit cards, you protect cardholder data with specific controls. AWS Config rules automate compliance checks for PCI-DSS requirements.

### Key PCI-DSS Requirements and AWS Config Rules

| PCI-DSS Requirement | Control | AWS Config Rule |
|---|---|---|
| **1.2** Network Access Control | Restrict access to cardholder data | Restrict Security Group ingress, VPC Flow Logs |
| **2.1** Default Passwords | Change default credentials | IAM password policy, RDS default port changes |
| **3.4** Encryption at Rest | Encrypt cardholder data | S3 encryption, RDS encryption, EBS encryption |
| **4.1** Encryption in Transit | TLS for data in flight | CloudFront HTTPS, ALB HTTPS, RDS encryption |
| **8.1** User Access Control | Unique user IDs | IAM user access keys, MFA requirements |
| **8.3** MFA | Multi-factor authentication | IAM user MFA enabled, console login MFA |
| **10.2** Logging | Complete logging of user actions | CloudTrail enabled, S3 access logging, VPC Flow Logs |
| **10.3** Log Protection | Protect and review logs | CloudTrail log file validation, S3 versioning |

### Deploy PCI-DSS Conformance Pack

AWS provides a pre-built PCI-DSS v3.2.1 conformance pack:

```bash
# Deploy the AWS-managed PCI-DSS conformance pack
aws configservice put-conformance-pack \
  --conformance-pack-name "iron-bank-pci-dss" \
  --template-s3-uri "s3://aws-config-conformance-packs-us-east-1/PCI-DSS-v3.2.1.yaml" \
  --profile iron-bank \
  --region us-east-1

# Wait for deployment
aws configservice describe-conformance-packs \
  --conformance-pack-names "iron-bank-pci-dss" \
  --profile iron-bank \
  --query 'ConformancePackDetails[0].ConformancePackState' \
  --output text

# Check compliance
aws configservice get-conformance-pack-compliance-summary \
  --conformance-pack-names "iron-bank-pci-dss" \
  --profile iron-bank \
  --query 'ConformancePackComplianceSummaryList[0]'
```

---

## Part 5: HIPAA Compliance Mapping

**HIPAA (Health Insurance Portability and Accountability Act)** protects health information. If you store or process patient data, HIPAA requires encryption, audit logging, access controls, and breach notification.

### HIPAA Security Rule Requirements and AWS Config Rules

| HIPAA Control | Requirement | AWS Config Rule |
|---|---|---|
| **Encryption & Decryption (§164.312(a)(2)(ii))** | Encrypt PHI (Protected Health Information) | RDS encryption, S3 encryption, KMS customer-managed keys |
| **Audit Controls (§164.312(b))** | Logging of all access to PHI | CloudTrail enabled, CloudWatch Logs, S3 access logging |
| **Access Controls (§164.312(a)(2)(i))** | Unique user IDs, access restrictions | IAM users (no shared accounts), MFA, Security Groups |
| **Transmission Security (§164.312(e)(1))** | Protect data in transit | CloudFront HTTPS only, VPN/TLS for API calls |
| **Integrity (§164.312(c)(1))** | Detect tampering | CloudTrail log file validation, versioning, change notifications |

### Key Differences from PCI-DSS

- **PCI-DSS:** Focuses on payment card data — encryption, network isolation
- **HIPAA:** Focuses on patient privacy — audit logging, access control, breach notification

### Deploy HIPAA Conformance Pack

```bash
aws configservice put-conformance-pack \
  --conformance-pack-name "iron-bank-hipaa" \
  --template-s3-uri "s3://aws-config-conformance-packs-us-east-1/HIPAA.yaml" \
  --profile iron-bank \
  --region us-east-1
```

---

## Part 6: SOC2 Type II Compliance Mapping

**SOC2 (Service Organization Control 2)** is an audit standard that assesses whether your organization has controls around:
- **CC6:** Logical access controls
- **CC7:** System monitoring and logging
- **A1:** Availability
- **C1:** Confidentiality
- **P1:** Privacy

### SOC2 Pillars and AWS Config Rules

| SOC2 Pillar | Control | AWS Config Rule | Why It Matters |
|---|---|---|---|
| **Logical Access (CC6)** | Prevent unauthorized access | IAM policies, Security Groups, NACLs | Who can access what? Are there default policies that are too permissive? |
| **Monitoring (CC7)** | Detect unauthorized access | CloudTrail, CloudWatch, Config rules | Can you detect when something goes wrong? Are logs stored securely? |
| **Change Management (CC6)** | Track who changed what | CloudTrail API logging, Config change tracking | Who made production changes? Can you audit changes? |
| **Encryption (C1)** | Protect data | KMS, S3 SSE, RDS encryption | Is data encrypted at rest and in transit? |
| **Backup & Recovery (A1)** | Restore from incidents | RDS automated backups, S3 versioning, snapshot testing | Can you recover from accidental deletion? Can you restore a database? |

### Understanding SOC2 Audits

A SOC2 audit requires:
1. **Design Phase:** Your controls are documented in writing
2. **Operating Effectiveness Phase:** Auditors verify your controls actually work for 6+ months

Config rules help both phases:
- **Design:** Document controls as Config rules (version-controlled, auditable)
- **Operating Effectiveness:** AWS provides compliance reports showing rule evaluations over time

### Create a SOC2 Evidence Report

```bash
# Generate a report showing compliance trends
python3 ~/projects/config-rules/compliance_report.py \
  --profile iron-bank \
  --pack iron-bank-fsbp  # FSBP covers many SOC2 controls

# Save to file for audit team
python3 ~/projects/config-rules/compliance_report.py \
  --profile iron-bank \
  --pack iron-bank-fsbp > /tmp/compliance_evidence.txt

# Share with auditors
echo "Compliance evidence generated in /tmp/compliance_evidence.txt"
```

---

## Part 7: ISO 27001 Compliance Mapping

**ISO 27001** is an international standard for information security management. It covers:
- **A.5:** Access Control
- **A.8:** Security Operations
- **A.12:** Operations Security
- **A.13:** Communications Security
- **A.14:** System Acquisition & Maintenance

### ISO 27001 vs. SOC2

| Aspect | ISO 27001 | SOC2 |
|--------|-----------|------|
| **Geographic Scope** | International (used globally) | Primarily North American |
| **Audit Type** | Third-party certification | Service auditor review |
| **Controls** | 114 detailed controls across 14 domains | 5 trust principles |
| **Certification** | ISO 27001 certificate (renewable every 3 years) | SOC2 Report (Type I or Type II) |

### ISO 27001 Controls and AWS Config Rules

| ISO 27001 Domain | Control | AWS Config Rule |
|---|---|---|
| **A.5 Access Control** | User authentication | IAM password policy, MFA, security groups |
| **A.8 Security Operations** | Logging & monitoring | CloudTrail, CloudWatch, VPC Flow Logs |
| **A.12 Operations Security** | Change management | Config rules with auto-remediation, CloudTrail |
| **A.13 Communications Security** | Data in transit encryption | HTTPS enforcement, VPC encryption |
| **A.14 System Acquisition** | Secure configuration | Checkov (IaC scanning), Config conformance packs |

### Mapping Existing Config Rules to ISO 27001

```bash
# Create a mapping document linking Config rules to ISO 27001 controls
cat > ~/projects/config-rules/iso27001_mapping.txt << 'EOF'
ISO 27001 Control | AWS Config Rule | Evidence
─────────────────────────────────────────────────────────────
A.5.1.1 (Policy)  | IAM Policy Check | Policy review in IAM console
A.8.1 (Logging)   | CloudTrail Enabled | CloudTrail audit trail
A.8.2 (Monitoring) | Config Rule Evaluations | Config Dashboard compliance score
A.9.2 (Access)    | RESTRICTED_INCOMING_TRAFFIC | Security Group audit
A.10.1.1 (Crypto) | S3 Encryption Enabled | S3 bucket SSE status
A.12.5.1 (Logs)   | CloudTrail Log Validation | Log integrity proof
EOF

cat ~/projects/config-rules/iso27001_mapping.txt
```

---

## Part 8: Unified Compliance Dashboard

For organizations that must comply with **multiple frameworks** (PCI-DSS + HIPAA + SOC2 + ISO), AWS Config + Security Hub provides a unified view:

```bash
# Enable Security Hub (aggregates Config findings across multiple frameworks)
aws securityhub create-hub \
  --profile iron-bank \
  --region us-east-1 2>/dev/null || echo "Security Hub already enabled"

# Link Config to Security Hub
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
  StandardsArn=arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0 \
  --profile iron-bank

# View consolidated compliance findings
aws securityhub get-compliance-summary \
  --profile iron-bank \
  --query 'ComplianceSummary'
```

### Interpreting Compliance Overlap

Some Config rules satisfy **multiple compliance frameworks**:

- `s3-bucket-server-side-encryption-enabled` → PCI-DSS 3.4, HIPAA §164.312, SOC2 C1, ISO 27001 A.13
- `cloudtrail-enabled` → PCI-DSS 10.2, HIPAA §164.312(b), SOC2 CC7, ISO 27001 A.8

This means deploying one Config rule can help **multiple audit teams** — eliminating redundant security controls.

---

## 🧹 Cleanup

```bash
# Delete the custom Config rule
aws configservice delete-config-rule \
  --config-rule-name iron-bank-imdsv2-required \
  --profile iron-bank

# Delete the Lambda function
aws lambda delete-function \
  --function-name iron-bank-check-imdsv2 \
  --profile iron-bank

# Delete the IAM role (must detach policies first)
aws iam detach-role-policy \
  --role-name iron-bank-config-rule-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole \
  --profile iron-bank
aws iam delete-role-policy \
  --role-name iron-bank-config-rule-role \
  --policy-name config-put-evaluations \
  --profile iron-bank
aws iam delete-role \
  --role-name iron-bank-config-rule-role \
  --profile iron-bank

# Delete the conformance pack (this does NOT delete the underlying Config rules)
aws configservice delete-conformance-pack \
  --conformance-pack-name iron-bank-fsbp \
  --profile iron-bank

echo "✅ Compliance as Code lab cleaned up"
```

---

## Checklist

**Core Compliance as Code**
- [ ] AWS Config confirmed running (`describe-configuration-recorders` returns a recorder)
- [ ] Foundational Security Best Practices conformance pack deployed — `CREATE_COMPLETE`
- [ ] Non-compliant rules listed — understand what at least 3 of them check
- [ ] Custom IMDSv2 Lambda Config rule written — understand each line of Python
- [ ] Custom rule deployed and registered with Config
- [ ] `compliance_report.py` run — compliance score visible in terminal
- [ ] Can explain: conformance pack vs individual Config rule (one sentence each)

**PCI-DSS Compliance**
- [ ] PCI-DSS conformance pack deployed (`s3://aws-config-conformance-packs-us-east-1/PCI-DSS-v3.2.1.yaml`)
- [ ] Compliance score visible — understand non-compliant rules
- [ ] Can map at least 3 PCI-DSS requirements to AWS Config rules

**HIPAA Compliance**
- [ ] HIPAA conformance pack deployed
- [ ] Can explain difference: PCI-DSS (payment data) vs HIPAA (patient data)
- [ ] Understand why RDS encryption + CloudTrail are critical for HIPAA

**SOC2 Compliance**
- [ ] Understand SOC2 Type II audit structure (6-month operating effectiveness period)
- [ ] Can explain: CC6 (access control), CC7 (monitoring)
- [ ] Config rules provide evidence for SOC2 auditors

**ISO 27001 Compliance**
- [ ] Can map Config rules to ISO 27001 domains (A.5, A.8, A.12, A.13, A.14)
- [ ] Understand difference: ISO 27001 (international certification) vs SOC2 (US audit)
- [ ] Created iso27001_mapping.txt with control-to-Config rule mapping

**Unified Compliance**
- [ ] Security Hub enabled
- [ ] Understand that one Config rule can satisfy multiple frameworks
- [ ] Example: s3-bucket-server-side-encryption-enabled → PCI-DSS + HIPAA + SOC2 + ISO 27001
- [ ] Can explain compliance overlap to auditors

**Cleanup**
- [ ] All resources deleted — Config rule, Lambda, IAM role, conformance packs
- [ ] AWS bill back to baseline

