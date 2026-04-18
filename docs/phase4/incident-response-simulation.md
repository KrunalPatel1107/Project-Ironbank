# Month 12 — Week 3: Incident Response Capstone Simulation

!!! abstract "💰 Cost: ~$5–10 (simulate an incident, then cleanup)"
    This week you deliberately trigger security alerts, detect them, investigate, and respond. It's a high-stakes simulation of a real breach scenario. All resources are cleaned up by week's end.

!!! danger "🚨 This Week Is High-Pressure (Good Practice)"
    You'll simulate an attack, discover evidence in CloudTrail, detect anomalies in GuardDuty, and respond under time pressure. This is intentional — it mirrors how incidents actually feel. By the end of the week, you'll have a documented incident response playbook and confidence in your detection/response capabilities.

!!! info "Why This Matters"
    Security gates (Weeks 1–2, Months 10) prevent *some* attacks. But not all. Real security is: **Assume Breach**. Build the capability to detect, investigate, and respond to incidents. This week you become an incident responder.

---

## Scenario: What Happened?

**Timeline:**
- **Day 1 (Monday)**: An attacker compromises an EC2 instance (via unpatched vulnerability)
- **Day 1**: Attacker assumes a higher-privilege IAM role (lateral movement)
- **Day 1**: Attacker creates new IAM user and access key (backdoor)
- **Day 2 (Tuesday)**: New access key is used to list S3 buckets (reconnaissance)
- **Day 2**: Attacker downloads sensitive data from S3 (exfiltration)
- **Day 3 (Wednesday)**: You detect the anomalies and trigger the incident response playbook
- **Day 3–4**: Investigation, containment, eradication
- **Day 5 (Friday)**: Post-incident review and lessons learned

**Your role:** Incident Response Team (detection, investigation, containment, eradication, recovery)

---

## Part 1: Create Incident Response Playbook

Before you respond to an incident, you need a playbook. Create `docs/iron-bank-ir-playbook.md`:

```markdown
# Iron Bank Incident Response Playbook

## Quick Reference — Incident Types

### Type 1: Compromised IAM User / Access Key

**Indicators:**
- CloudTrail shows API calls from unusual geographic location
- GuardDuty alert: "UnauthorizedAccess:IAMUser/MaliciousIPCaller"
- Access key found in git history (Gitleaks alert)
- Unusual volume of API calls in short time

**Immediate Response (< 5 minutes):**
1. Deactivate the access key immediately
2. Detach all policies from the user
3. Notify security team
4. Begin investigation

**Investigation (< 2 hours):**
- CloudTrail: Timeline of all API calls using this key
- S3 logs: Did they access sensitive data?
- VPC Flow Logs: Did they exfiltrate data?
- IAM roles: Did they escalate privileges?

**Recovery (< 8 hours):**
- Delete the compromised user entirely
- Rotate all other credentials
- Implement SCP to prevent similar attacks
- Notify affected customers if data was exfiltrated

### Type 2: Lateral Movement (EC2 → IAM Role)

**Indicators:**
- CloudTrail shows AssumeRole from EC2 instance IP
- GuardDuty alert: "UnauthorizedAccess:EC2/RoleAnomaly"
- High volume of IAM API calls from EC2

**Immediate Response:**
1. Terminate the EC2 instance (preserve EBS for forensics)
2. Detach permissions from the role the attacker escalated to
3. Review what the attacker did after escalating

**Root Cause:**
- EC2 role had excessive permissions (should be least privilege)
- Trust policy allowed AssumeRole from too many sources

### Type 3: Data Exfiltration (S3 / RDS)

**Indicators:**
- Unusual S3 GetObject API calls
- GuardDuty alert: "Policy:S3/ExceptionOnPrivilegedAPICalls"
- S3 access logs show large downloads
- Egress traffic spike

**Immediate Response:**
1. Determine if data was sensitive (PII, secrets)
2. Revoke access temporarily (bucket policy, security groups)
3. Notify legal/compliance (GDPR, HIPAA, PCI-DSS notification reqs)

**Recovery:**
- Rotate any secrets that may have been exposed
- Change RDS master passwords
- Enable S3 versioning + Object Lock (prevent deletion by attacker)
```

---

## Part 2: Simulating an Incident

Create a controlled incident to practice detection and response.

### Step 1: Create the Attack Vector

Create a test IAM user (the "attacker"):

```bash
# Create attacker user
aws iam create-user --user-name attacker-test --profile iron-bank

# Create access key for attacker
ATTACKER_CREDS=$(aws iam create-access-key --user-name attacker-test --profile iron-bank)

# Extract credentials for later use
ATTACKER_KEY=$(echo $ATTACKER_CREDS | jq -r '.AccessKey.AccessKeyId')
ATTACKER_SECRET=$(echo $ATTACKER_CREDS | jq -r '.AccessKey.SecretAccessKey')

# Give attacker S3 access (simulating that they stole these permissions)
aws iam attach-user-policy \
  --user-name attacker-test \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess \
  --profile iron-bank

echo "Attacker credentials created:"
echo "  Access Key: $ATTACKER_KEY"
echo "  Secret Key: $ATTACKER_SECRET"
echo ""
echo "Save these for the attack simulation"
```

### Step 2: Simulate the Attack

Now use the attacker's credentials to perform reconnaissance and exfiltration:

```bash
# Configure AWS CLI with attacker credentials
export AWS_ACCESS_KEY_ID=$ATTACKER_KEY
export AWS_SECRET_ACCESS_KEY=$ATTACKER_SECRET
export AWS_DEFAULT_REGION=us-east-1

# ATTACK PHASE 1: Reconnaissance
echo "[*] Attacker: Listing all S3 buckets..."
aws s3 ls

echo "[*] Attacker: Listing contents of each bucket..."
for bucket in $(aws s3 ls | awk '{print $3}'); do
  echo "  Bucket: $bucket"
  aws s3 ls s3://$bucket --recursive --max-items 5 2>/dev/null || echo "    (error or no permission)"
done

# ATTACK PHASE 2: Exfiltration (simulated)
echo "[*] Attacker: Attempting to download data..."
aws s3 ls s3://iron-bank-data/sensitive/ || echo "Bucket not accessible or doesn't exist"

# Clean up attacker session
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

echo ""
echo "✓ Attack simulation complete"
echo "  Multiple CloudTrail events generated"
echo "  GuardDuty should detect anomalies within 5 minutes"
```

### Step 3: Detection — Find the Evidence

Now you're the incident response team. Detect the attack:

#### Detection Method 1: CloudTrail

```bash
# Search CloudTrail for the attacker's access key
echo "[*] Searching CloudTrail for attacker activities..."

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=$ATTACKER_KEY \
  --profile iron-bank \
  --output table

# Output shows:
# - EventTime: When did the attack occur?
# - EventName: What did they do? (ListBuckets, GetObject, etc.)
# - SourceIPAddress: Where did they attack from?
```

#### Detection Method 2: GuardDuty

```bash
# Check GuardDuty findings
echo "[*] Checking GuardDuty for threats..."

DETECTOR_ID=$(aws guardduty list-detectors --profile iron-bank --query 'DetectorIds[0]' --output text)

aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --profile iron-bank \
  --output table

# Look for:
# - Type: UnauthorizedAccess:IAMUser/MaliciousIPCaller
# - Severity: High or Critical
```

#### Detection Method 3: Security Hub

```bash
# Check aggregated findings
aws securityhub get-findings \
  --filters '{"Type": [{"Value": "Security Best Practices", "Comparison": "PREFIX"}]}' \
  --profile iron-bank \
  --output table | head -20
```

### Step 4: Investigation — Build the Timeline

```bash
# Get ALL events from the attacker's access key, sorted by time
echo "[*] Building attack timeline..."

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=$ATTACKER_KEY \
  --profile iron-bank \
  --query 'Events[*].[EventTime,EventName,SourceIPAddress,Username]' \
  --output table

# Sample output:
# 2026-04-15 10:05:20+00:00  ListBuckets                203.0.113.45  attacker-test
# 2026-04-15 10:05:22+00:00  GetBucketLocation          203.0.113.45  attacker-test
# 2026-04-15 10:05:25+00:00  ListBucket                 203.0.113.45  attacker-test
# 2026-04-15 10:05:30+00:00  GetObject (sensitive/)     203.0.113.45  attacker-test
# ...

# Questions to answer:
# - How long did the attack last?
# - How many buckets were accessed?
# - How much data was accessed?
# - What was the geographic source?
```

### Step 5: Containment — Stop the Bleeding

Immediately disable the compromised credentials:

```bash
echo "[*] CONTAINMENT: Deactivating compromised access key..."

# Deactivate the access key
aws iam update-access-key \
  --user-name attacker-test \
  --access-key-id $ATTACKER_KEY \
  --status Inactive \
  --profile iron-bank

# Verify it's now inactive
aws iam get-access-key-last-used --access-key-id $ATTACKER_KEY --profile iron-bank

# Try to use it (should fail now)
export AWS_ACCESS_KEY_ID=$ATTACKER_KEY
export AWS_SECRET_ACCESS_KEY=$ATTACKER_SECRET
aws s3 ls 2>&1 | grep -i "invalid\|unauthorized" && echo "✓ Key is now disabled" || echo "⚠ Key still works!"

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
```

### Step 6: Eradication — Remove the Attacker

Delete all traces of the compromised user:

```bash
echo "[*] ERADICATION: Removing compromised user..."

# Detach all policies
echo "  - Detaching policies..."
aws iam list-attached-user-policies --user-name attacker-test --profile iron-bank \
  | jq -r '.AttachedPolicies[].PolicyArn' \
  | while read arn; do
    aws iam detach-user-policy --user-name attacker-test --policy-arn "$arn" --profile iron-bank
  done

# Delete all access keys
echo "  - Deleting access keys..."
aws iam list-access-keys --user-name attacker-test --profile iron-bank \
  | jq -r '.AccessKeyMetadata[].AccessKeyId' \
  | while read key; do
    aws iam delete-access-key --user-name attacker-test --access-key-id "$key" --profile iron-bank
  done

# Delete the user
echo "  - Deleting user..."
aws iam delete-user --user-name attacker-test --profile iron-bank

echo "✓ Compromised user completely removed"
```

### Step 7: Recovery & Hardening

Verify the account is clean and implement preventive measures:

```bash
echo "[*] RECOVERY: Verifying account is clean..."

# Check for other suspicious users
echo "  Users in account:"
aws iam list-users --profile iron-bank --output table

# Implement SCPs to prevent similar attacks
echo ""
echo "  Recommended SCPs:"
echo "    - Deny access key creation (force use of temporary credentials)"
echo "    - Deny privilege escalation (assume role only with MFA)"
echo "    - Deny disabling GuardDuty/CloudTrail (prevent evidence destruction)"

echo ""
echo "✓ Recovery phase complete"
```

---

## Part 3: Post-Incident Review

Write a brief incident report:

```markdown
# Incident Report: Test Breach (April 15, 2026)

## Summary
Simulated IAM user compromise resulted in unauthorized access to S3 buckets.

## Timeline
- 10:05 AM: Attacker gains access key
- 10:05 AM – 10:10 AM: Reconnaissance (ListBuckets, GetBucketLocation)
- 10:10 AM – 10:15 AM: Data exfiltration (GetObject on sensitive data)
- 10:20 AM: Incident detected (GuardDuty alert)
- 10:25 AM: Access key deactivated (containment)
- 10:45 AM: User deleted (eradication)

## Root Cause
- IAM user created with S3FullAccess (should be bucket-specific)
- No MFA enforcement for IAM users
- No automated detection/alerting

## Impact
- Sensitive data accessed (estimated 50MB)
- No data confirmed exfiltrated (lab simulation)
- No unauthorized modifications (only read access)

## Lessons Learned
1. Principle of Least Privilege: User should have S3 read-only on specific buckets
2. Automation: Detection took 15 minutes (should be < 1 minute via GuardDuty)
3. Containment: Deactivating key should be automated (Lambda on GuardDuty alert)
4. Prevention: SCPs should deny access key creation (force STS tokens)

## Improvements
1. Implement SCP: Deny iam:CreateAccessKey
2. Implement SCP: Deny sts:AssumeRole without MFA
3. Create Lambda: Auto-deactivate key on GuardDuty UnauthorizedAccess alert
4. Set CloudWatch alarm: Alert on 10+ API errors in 5 minutes
5. Enable CloudTrail log validation: Detect tampering
```

---

## Deliverables

- [ ] Incident Response Playbook created (`docs/iron-bank-ir-playbook.md`)
- [ ] Attack simulation completed (attacker user created)
- [ ] Detection methods tested (CloudTrail, GuardDuty, Security Hub)
- [ ] Investigation completed (timeline built, evidence documented)
- [ ] Containment executed (access key deactivated)
- [ ] Eradication completed (user deleted)
- [ ] Hardening measures identified (SCPs, Lambda, alarms)
- [ ] Post-incident report written
- [ ] All test resources cleaned up

---

## Next: Week 4 — Documentation & CCSP

With incident response proven, document your architecture and prepare for CCSP.

**↓ Next: [Portfolio Documentation & CCSP Exam](portfolio-documentation-ccsp.md)**

### 1.3 — Access Keys Rotated Every 90 Days

```bash
# List all IAM users with their access key ages
aws iam generate-credential-report \
  --profile iron-bank > /dev/null

sleep 5  # Wait for report generation

aws iam get-credential-report \
  --profile iron-bank \
  --query 'Content' \
  --output text | base64 -d | \
  python3 -c "
import sys, csv, datetime
reader = csv.DictReader(sys.stdin)
today = datetime.date.today()
print(f'{'User':<25} {'Key Age (days)':<20} {'Status'}')
print('-' * 60)
for row in reader:
    if row.get('access_key_1_active') == 'true':
        key_date = row.get('access_key_1_last_rotated', 'N/A')
        if key_date and key_date != 'N/A':
            age = (today - datetime.date.fromisoformat(key_date[:10])).days
            status = '✅ OK' if age < 90 else '❌ ROTATE NOW'
            print(f'{row[\"user\"]:<25} {age:<20} {status}')
"
```

### 1.4 — No Inline Policies on Users (Use Groups)

```bash
# Find IAM users with inline policies (CIS 1.16 violation)
for user in $(aws iam list-users --profile iron-bank --query 'Users[*].UserName' --output text); do
    policies=$(aws iam list-user-policies \
      --user-name $user \
      --profile iron-bank \
      --query 'PolicyNames' \
      --output text)
    if [ -n "$policies" ]; then
        echo "❌ $user has inline policies: $policies"
    fi
done
echo "✅ IAM inline policy check complete"
```

---

## Part 2: CIS Section 3 — Logging Requirements

### 3.1 — CloudTrail Enabled in All Regions

```bash
# Verify your CloudTrail is a multi-region trail
aws cloudtrail describe-trails \
  --profile iron-bank \
  --query 'trailList[*].{Name:Name,MultiRegion:IsMultiRegionTrail,LogValidation:LogFileValidationEnabled}' \
  --output table
# Expected:
# Name: iron-bank-trail  MultiRegion: True  LogValidation: True

# If IsMultiRegionTrail is False, update it:
aws cloudtrail update-trail \
  --name iron-bank-trail \
  --is-multi-region-trail \
  --profile iron-bank
```

### 3.2 — CloudTrail Logs Encrypted with KMS

```bash
# Check if your trail encrypts logs with a CMK
aws cloudtrail describe-trails \
  --profile iron-bank \
  --query 'trailList[*].KMSKeyId' \
  --output text
# → arn:aws:kms:...  (good)
# → None             (bad — add KMS encryption)

# If not encrypted, add KMS:
# First, note your CloudTrail S3 bucket name
TRAIL_BUCKET=$(aws cloudtrail describe-trails \
  --profile iron-bank \
  --query 'trailList[0].S3BucketName' --output text)

# Create a KMS key for CloudTrail (or use an existing one from Month 9)
KMS_ID=$(aws kms create-key \
  --description "iron-bank CloudTrail encryption key" \
  --profile iron-bank \
  --query KeyMetadata.KeyId --output text)

# Update the trail to use the key
aws cloudtrail update-trail \
  --name iron-bank-trail \
  --kms-key-id $KMS_ID \
  --profile iron-bank

echo "✅ CloudTrail now encrypted with CMK: $KMS_ID"
```

### 3.3 — CloudWatch Metric Filters for CIS Events

CIS requires CloudWatch alarms for 15 specific event types. Here are the 3 most important:

```bash
# Get your CloudWatch log group name (where CloudTrail sends logs)
LOG_GROUP="/aws/cloudtrail/iron-bank"

# ── CIS 4.1: Unauthorized API calls alarm ─────────────────────────────────────
aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "UnauthorizedAPICalls" \
  --filter-pattern '{ ($.errorCode = "AccessDenied") || ($.errorCode = "UnauthorizedOperation") }' \
  --metric-transformations \
    metricName=UnauthorizedAPICalls,metricNamespace=CISBenchmark,metricValue=1 \
  --profile iron-bank

aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-1-UnauthorizedAPICalls" \
  --alarm-description "CIS 4.1 — Detects unauthorized API calls" \
  --metric-name UnauthorizedAPICalls \
  --namespace CISBenchmark \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions $SNS_ARN \
  --profile iron-bank

# ── CIS 4.3: Root account usage alarm ────────────────────────────────────────
aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "RootAccountUsage" \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  --metric-transformations \
    metricName=RootAccountUsage,metricNamespace=CISBenchmark,metricValue=1 \
  --profile iron-bank

aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-3-RootAccountUsage" \
  --alarm-description "CIS 4.3 — Detects root account API usage" \
  --metric-name RootAccountUsage \
  --namespace CISBenchmark \
  --statistic Sum \
  --period 60 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions $SNS_ARN \
  --profile iron-bank

# ── CIS 4.4: IAM policy changes alarm ────────────────────────────────────────
aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "IAMPolicyChanges" \
  --filter-pattern '{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = SetDefaultPolicyVersion) }' \
  --metric-transformations \
    metricName=IAMPolicyChanges,metricNamespace=CISBenchmark,metricValue=1 \
  --profile iron-bank

aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-4-IAMPolicyChanges" \
  --alarm-description "CIS 4.4 — Detects IAM policy changes" \
  --metric-name IAMPolicyChanges \
  --namespace CISBenchmark \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions $SNS_ARN \
  --profile iron-bank

echo "✅ 3 CIS CloudWatch alarms created"
```

---

## Part 3: CIS Section 5 — Networking

### 5.1 — No Unrestricted Inbound Traffic on Common Ports

```bash
# Check all security groups for dangerous inbound rules (0.0.0.0/0 on sensitive ports)
aws ec2 describe-security-groups \
  --profile iron-bank \
  --query "SecurityGroups[*].{
    GroupId:GroupId,
    GroupName:GroupName,
    DangerousRules:IpPermissions[?
      (FromPort==22 || FromPort==3389 || FromPort==0) &&
      IpRanges[?CidrIp=='0.0.0.0/0']
    ]
  }" \
  --output json | python3 -c "
import json, sys
groups = json.load(sys.stdin)
found = False
for g in groups:
    if g.get('DangerousRules'):
        print(f'❌ {g[\"GroupName\"]} ({g[\"GroupId\"]}) — unrestricted inbound on sensitive port')
        found = True
if not found:
    print('✅ No security groups with unrestricted inbound on SSH/RDP/all')
"
```

### 5.2 — Default VPC Security Group Blocks All Traffic

```bash
# The default SG in your default VPC should have no inbound rules
# (Your iron-bank resources should use custom SGs, not the default)
aws ec2 describe-security-groups \
  --filters Name=group-name,Values=default \
  --profile iron-bank \
  --query 'SecurityGroups[*].{VPC:VpcId,Inbound:IpPermissions,Outbound:IpPermissionsEgress}' \
  --output json | python3 -c "
import json, sys
groups = json.load(sys.stdin)
for g in groups:
    inbound_count = len(g.get('Inbound', []))
    print(f'VPC {g[\"VPC\"]}: {inbound_count} inbound rules in default SG')
    if inbound_count == 0:
        print('  ✅ CIS 5.4 COMPLIANT — default SG has no inbound rules')
    else:
        print('  ❌ CIS 5.4 NON-COMPLIANT — default SG should have no inbound rules')
        print('  Fix: remove all inbound rules from the default security group')
"
```

---

## Part 4: Generate Your CIS Compliance Report

```bash
cat > ~/projects/iron-bank-fortress/scripts/cis_report.py << 'EOF'
"""
cis_report.py — pull CIS Benchmark results from Security Hub and generate a report.
Requires Security Hub with CIS AWS Foundations Benchmark standard enabled.

Run: python3 scripts/cis_report.py --profile iron-bank
"""
import boto3
import argparse
from collections import defaultdict

def get_cis_findings(client):
    """Get all CIS Benchmark findings from Security Hub."""
    paginator = client.get_paginator('get_findings')
    findings = []
    
    for page in paginator.paginate(
        Filters={
            'GeneratorId': [{'Value': 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark', 'Comparison': 'PREFIX'}],
            'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
        }
    ):
        findings.extend(page['Findings'])
    
    return findings

def report(findings):
    by_status = defaultdict(list)
    for f in findings:
        status = f.get('Compliance', {}).get('Status', 'UNKNOWN')
        by_status[status].append(f.get('Title', 'Unknown'))
    
    total = len(findings)
    passed = len(by_status.get('PASSED', []))
    failed = len(by_status.get('FAILED', []))
    score = (passed / total * 100) if total > 0 else 0
    
    print(f"\n{'='*65}")
    print(f"  CIS AWS Foundations Benchmark — Compliance Report")
    print(f"{'='*65}")
    print(f"\n  Score: {score:.0f}% ({passed}/{total} controls passing)\n")
    
    bar = '█' * int(score / 2.5) + '░' * (40 - int(score / 2.5))
    print(f"  [{bar}]\n")
    
    if failed > 0:
        print(f"  ❌ Failed Controls ({failed}):")
        for title in sorted(by_status['FAILED'])[:15]:
            print(f"     • {title[:70]}")
        if failed > 15:
            print(f"     ... and {failed - 15} more")
    
    print(f"\n  ✅ Passing: {passed} controls")
    print(f"{'='*65}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', default='iron-bank')
    args = parser.parse_args()
    
    session = boto3.Session(profile_name=args.profile, region_name='us-east-1')
    client = session.client('securityhub')
    
    findings = get_cis_findings(client)
    if not findings:
        print("No CIS findings found. Ensure Security Hub is enabled with CIS standard.")
        return
    report(findings)

if __name__ == '__main__':
    main()
EOF

python3 ~/projects/iron-bank-fortress/scripts/cis_report.py --profile iron-bank
```

---

## 🧹 Cleanup

```bash
# Delete the KMS key created for CloudTrail (schedule for 7 days — minimum)
if [ -n "$KMS_ID" ]; then
    aws kms schedule-key-deletion \
      --key-id $KMS_ID \
      --pending-window-in-days 7 \
      --profile iron-bank
fi

# Delete CIS CloudWatch alarms
for alarm in CIS-1-UnauthorizedAPICalls CIS-3-RootAccountUsage CIS-4-IAMPolicyChanges; do
    aws cloudwatch delete-alarms --alarm-names $alarm --profile iron-bank
done

# Delete CloudWatch metric filters
for filter in UnauthorizedAPICalls RootAccountUsage IAMPolicyChanges; do
    aws logs delete-metric-filter \
      --log-group-name "/aws/cloudtrail/iron-bank" \
      --filter-name $filter \
      --profile iron-bank 2>/dev/null || true
done

# Destroy Capstone infrastructure
cd ~/projects/iron-bank-fortress
./cleanup.sh

echo "✅ Week 3 complete — all resources destroyed"
```

---

## Checklist

- [ ] Root account MFA verified in Console — CIS 1.1 checked
- [ ] Root access keys confirmed absent — `AccountAccessKeysPresent = 0`
- [ ] Credential report generated — all access keys under 90 days old (or rotated)
- [ ] No IAM users with inline policies — CIS 1.16 verified
- [ ] CloudTrail multi-region confirmed — `IsMultiRegionTrail: True`
- [ ] CloudTrail log file validation enabled — `LogFileValidationEnabled: True`
- [ ] 3 CIS CloudWatch metric filters created (unauthorized API calls, root usage, IAM changes)
- [ ] 3 corresponding alarms created and linked to SNS email
- [ ] No security groups with 0.0.0.0/0 on port 22 or 3389
- [ ] Default VPC security group has no inbound rules
- [ ] `cis_report.py` run — CIS compliance score visible
- [ ] **All resources destroyed** — cleanup.sh confirmed run

