# Month 12 — Special: Incident Response at Scale & Post-Mortems

!!! abstract "💰 Cost: Free (Lambda, EventBridge, CloudWatch, SNS already deployed)"

!!! danger "Why Incident Response at Scale Matters"
    Phase 4 m12-week3 taught IR capstone (simulated scenario). This expansion teaches **production IR**: when a real breach happens across multiple AWS accounts, multiple regions, multiple services simultaneously, you need:
    - **Runbooks**: proven procedures so your team doesn't panic or make mistakes
    - **War rooms**: structured incident management with clear roles, communication, escalation
    - **Blameless post-mortems**: learning without blame, fixing root causes, preventing recurrence
    - **Automated remediation**: stop the attack in seconds, not hours
    
    Netflix, Stripe, and all hyperscale companies automate 80% of IR. Your team can too.

!!! info "Background Context"
    Phase 4 m12-week3 taught IR mechanics (5-phase investigation). This expansion teaches IR operations: scaling IR to production incidents, learning from incidents, and preventing repeats. Together: IR mechanics + IR operations = mature security program.

---

## Part 1: Incident Runbooks by Scenario

Runbooks are decision trees. When X happens, do Y. No guessing, no Slack debates.

### Runbook Structure

```markdown
# Runbook: [Incident Type]

## Detection Signal
- Alert name: [alert that triggers this runbook]
- Severity: [CRITICAL/HIGH/MEDIUM]
- False positive rate: [estimated %]
- Lead time: [how fast must we act]

## Immediate Actions (0-5 minutes)
- Who: [role, e.g., on-call engineer, security lead, SRE]
- Step 1: [action]
- Step 2: [action]
- Validation: [how to confirm each step worked]

## Investigation (5-30 minutes)
- What to check: [AWS Config, CloudTrail, logs, metrics]
- Expected vs. actual: [what normal looks like vs. attack pattern]
- Key queries: [bash/SQL commands to extract evidence]
- Decision tree: [if this, then...; if that, then...]

## Containment (30-60 minutes)
- Isolate: [kill sessions, block IPs, disable credentials]
- Stop bleeding: [if data exfiltration, kill outbound connections]
- Preserve evidence: [copy logs/data to S3 for forensics]

## Recovery (1-4 hours)
- Restore: [revert to known-good state]
- Patch: [fix the vulnerability]
- Validation: [confirm systems are healthy]

## Communication
- Who to notify: [CISO, legal, customers, AWS support]
- Message template: [what to say before you know full details]
- Update cadence: [every 15 min during active incident]

## Lessons Learned Template
- Root cause: [why it happened]
- Detection gap: [why we didn't catch it sooner]
- Improvements: [prevent next time]
```

### Runbook: Compromised AWS Credential

```bash
# Runbook: Compromised API Key / Access Key

## Detection Signal
- PagerDuty alert: "AccessKey used from unknown IP"
- Severity: CRITICAL
- False positive rate: ~5% (legitimate VPN + dev machines)
- Lead time: IMMEDIATE (attacker has active access)

## Immediate Actions (0-5 min)
Who: On-call engineer + Security lead (page immediately)

Step 1: Confirm the alert is real
  - AWS CLI: aws iam get-access-key-last-used --access-key-id AKIA...
  - Check: When was it last used? From what IP?
  - Slack bot posts: "Key AKIA:xyz last used 2 minutes ago from 203.0.113.5 (not known good)"
  
Step 2: Disable the compromised key IMMEDIATELY (no more API calls)
  - aws iam update-access-key-status --access-key-id AKIA:xyz --status Inactive
  - Confirm: aws iam list-access-keys --user-name $username | grep AKIA:xyz
  - Expected: "Status": "Inactive" ✅
  
Step 3: Issue immediate notification
  - Slack: "#security-critical: CRITICAL - AccessKey AKIA:xyz disabled (compromised from 203.0.113.5)"
  - Timeline: [Current time] - Key disabled, investigating
  
Validation:
  - aws iam test-iam-permissions --access-key-id AKIA:xyz
  - Expected: "UnauthorizedOperation" (key is truly disabled) ✅

## Investigation (5-30 min)
What to check:
  - CloudTrail: What did the attacker DO with this key?
  - GuardDuty: Any threat detected with this key?
  - Config: Any resources modified/deleted?
  - S3: Any unauthorized bucket access/export?

Key queries:

```bash
# CloudTrail: Find all actions with this key in the last 1 hour
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA:xyz \
  --max-results 50 | jq '.Events[] | {eventName, eventTime, sourceIPAddress, errorCode}'

# Expected: List of API calls (some may be failed auth attempts, some successful)
# PRIORITY: Look for:
#   - CreateAccessKey (attacker creating MORE keys)
#   - AssumeRole (lateral movement)
#   - GetSecretValue (accessing secrets)
#   - CreateDBSnapshot / DescribeDBInstances (database exfil)
#   - ListBuckets / GetObject (S3 data exfil)

# S3: Find large downloads from this IP in the last hour
aws s3api get-bucket-logging --bucket my-bucket
# Then search CloudTrail for S3 GetObject calls from 203.0.113.5
```

Expected vs. Actual:
- Normal: Access key used from known IP (office, VPN, CI/CD pipeline)
- Attack: Access key used from unknown IP + followed by suspicious API calls (secret access, credential creation, etc.)

Decision Tree:
- IF attacker only called DescribeInstances and ListBuckets
  - THEN: Reconnaissance only. Proceed to Containment.
  - ACTION: Kill other sessions, rotate all secrets, monitor for escalation.
  
- IF attacker called CreateAccessKey
  - THEN: Likely lateral movement. Multiple credentials now compromised.
  - ACTION: Disable ALL keys for this user, rotate ALL Secrets Manager entries.
  - ESCALATION: Alert CISO (attacker can persist even if original key is disabled).
  
- IF attacker called CopyDBSnapshot or GetObject on PII bucket
  - THEN: Data exfiltration confirmed.
  - ACTION: Contact legal immediately (potential breach notification required).
  - SCOPE: How much PII was accessed? From CloudTrail: "requestParameters.bucketName" + "key" (file path).

## Containment (30-60 min)
Goal: Stop attacker from doing more damage, preserve evidence.

Kill Active Sessions:
```bash
# Find all active sessions using this key
aws ec2 describe-security-groups --filters "Name=group-id,Values=sg-*" \
  | jq '.SecurityGroups[] | select(.GroupName == "allow-from-203.0.113.5")'

# Optionally: Revoke all inbound rules from attacker IP
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxx \
  --protocol tcp \
  --port 22 \
  --cidr 203.0.113.5/32

# Or: Kill EC2 instance if attacker has shell access
aws ec2 terminate-instances --instance-ids i-xxx
# (only if you're confident attacker gained EC2 shell)
```

Preserve Evidence:
```bash
# Copy CloudTrail logs to S3 for forensics
aws s3 cp s3://cloudtrail-logs/AWSLogs/ACCOUNT/CloudTrail/... \
         s3://forensics-bucket/incident-20260415-akia-xyz/ \
         --recursive

# Copy GuardDuty findings
aws guardduty list-findings --detector-id xxx --finding-criteria '{"Criterion":{"updatedAt":{"Gte":1713148800000}}}' | jq . > /tmp/guardduty-findings.json
aws s3 cp /tmp/guardduty-findings.json s3://forensics-bucket/incident-20260415-akia-xyz/guardduty.json
```

## Recovery (1-4 hours)
1. Create new access key for the compromised user
   ```bash
   aws iam create-access-key --user-name $username
   # Output new key to secure location (1Password, Vault, not Slack!)
   ```

2. Rotate all secrets that might have been exposed
   ```bash
   # If attacker accessed Secrets Manager:
   aws secretsmanager list-secrets | jq '.SecretList[].Name'
   # For each secret, rotate immediately:
   aws secretsmanager rotate-secret --secret-id prod/db/password
   ```

3. Apply additional detection
   ```bash
   # CloudWatch alarm: Page if ANY API call from 203.0.113.5
   aws cloudwatch put-metric-alarm \
     --alarm-name attacker-ip-activity \
     --alarm-actions arn:aws:sns:us-east-1:ACCOUNT:security-alerts \
     --metric-name APICallsFromIP \
     --namespace SecurityMetrics \
     --statistic Sum \
     --period 60 \
     --threshold 1 \
     --comparison-operator GreaterThanOrEqualToThreshold
   ```

## Communication
- **Immediate (0-5 min):** "#security-critical: CRITICAL - AccessKey AKIA:xyz disabled due to compromise from 203.0.113.5. Investigating scope and severity."
- **At 10 min:** "Update: CloudTrail shows attacker accessed [list resources]. No evidence of data exfil yet. Continuing investigation."
- **At 30 min:** "Update: Contained. Data exfil: [yes/no]. Affected customers: [list]. Recovery ETA: [time]."
- **Post-incident:** Full timeline + root cause + lessons learned posted to #security + Wiki.

## Lessons Learned Template
**Root Cause:** How was the key compromised?
- [ ] Hardcoded in GitHub repo
- [ ] Logged in error messages
- [ ] Shared in Slack/email
- [ ] Phishing / social engineering
- [ ] Supply chain compromise
- [ ] Unknown / under investigation

**Detection Gap:** Why didn't we catch it sooner?
- [ ] No IP-based anomaly detection
- [ ] CloudTrail not monitored in real-time
- [ ] No Lambda-based auto-disable for suspicious activity
- [ ] Poor secret rotation discipline

**Improvements:** Prevention + Detection + Automation
- [ ] Implement OIDC (eliminate long-lived keys)
- [ ] Add IP allowlist enforcement
- [ ] Automated key rotation (90-day max)
- [ ] Lambda auto-disable for >5 failed auth attempts
- [ ] GitLeaks in CI/CD to catch commits before they happen
```

### Runbook: Data Exfiltration (S3)

```bash
# Runbook: Large S3 Data Export / Bucket Copy

## Detection Signal
- CloudWatch alarm: "S3GetObject calls > 10GB/min from unusual IP"
- Severity: CRITICAL (data may be leaving AWS)
- Lead time: SECONDS (active exfiltration ongoing)

## Immediate Actions (0-5 min)
Who: On-call engineer + Data security lead + CISO (notify immediately)

Step 1: Confirm the alert
  - aws s3api list-bucket-metrics-configurations --bucket prod-data
  - Recent GET count: [how many objects?]
  - Recent PUT count to external destination: [if any]
  
Step 2: Kill outbound connectivity from suspected instance
  - Find source IP from CloudTrail
  - aws ec2 modify-security-group-rules --group-id sg-xxx --rules '[{"GroupId":"sg-xxx","IpProtocol":"-1","CidrIp":"0.0.0.0/0"}]' (block ALL outbound)
  
Step 3: Snapshot bucket + database for forensics
  - S3: aws s3 sync s3://prod-data s3://forensics-bucket/exfil-incident-date/prod-data/ --profile forensics
  - RDS: aws rds create-db-snapshot --db-instance-identifier prod-postgres --db-snapshot-identifier forensics-incident-date
  
Validation:
  - Confirm outbound connections are blocked: ping 8.8.8.8 from instance → timeout ✅

## Investigation (5-30 min)
What was accessed?
  ```bash
  # CloudTrail: Find all S3 GetObject calls from attacker in last 1 hour
  aws athena start-query-execution \
    --query-string "SELECT eventTime, userIdentity, requestParameters, sourceIPAddress 
                    FROM cloudtrail_logs 
                    WHERE eventName='GetObject' 
                    AND sourceIPAddress='203.0.113.5' 
                    AND eventTime > NOW() - INTERVAL '1 hour' 
                    ORDER BY eventTime DESC" \
    --result-configuration OutputLocation=s3://query-results/
  
  # Results: List of all files accessed, their size, timestamp
  # PRIORITY: Identify if sensitive data (PII, secrets, source code) was accessed
  ```

How much data left?
  ```bash
  # S3 access logs: Find PutObject/CopyObject to external buckets/IPs
  aws s3api get-bucket-logging --bucket prod-data
  # Parse logs for unusual PUT destinations
  ```

Containment: Block all access from attacker IP
  ```bash
  # VPC: Add NACL rule to deny 203.0.113.5
  aws ec2 create-network-acl-entry \
    --network-acl-id acl-xxx \
    --rule-number 100 \
    --protocol -1 \
    --port-range From=0,To=65535 \
    --cidr-block 203.0.113.5/32 \
    --egress false
  ```

## Recovery (1-4 hours)
1. Audit all S3 bucket policies + object ACLs
   ```bash
   aws s3api get-bucket-policy --bucket prod-data
   # Ensure no public-read or external account access
   ```

2. Enable versioning + MFA delete (prevent future exfil)
   ```bash
   aws s3api put-bucket-versioning --bucket prod-data --versioning-configuration Status=Enabled,MFADelete=Enabled
   ```

3. Enable S3 Object Lock (WORM: write-once-read-many)
   ```bash
   aws s3api put-object-lock-configuration --bucket prod-data \
     --object-lock-configuration 'ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=GOVERNANCE,Years=7}}'
   ```

## Communication
- **Immediate:** "CRITICAL - Data exfiltration detected. [N] GB from s3://prod-data accessed from 203.0.113.5 in [time]. Investigating scope and customer impact."
- **At 15 min:** "Update: [List of accessed files]. Sensitive data status: [Yes/No]. Attacker connectivity killed."
- **At 30 min:** "Update: Scope confirmed. [N] records of PII accessed. Legal notification required per [regulation]. Customers: [list]."
- **Post-incident:** Breach notification letters, credit monitoring offers, regulatory notifications.
```

---

## Part 2: War Room Procedures

When an incident escalates to CRITICAL, establish a war room. Clear structure prevents chaos.

### War Room Setup

**Location:** Slack channel `#war-room-{incident-id}` + Google Meet link pinned

**Roles (assign immediately):**
1. **Incident Commander (IC)**: Decides priorities, routes decisions, manages communication. (CISO or senior engineer)
2. **Lead Investigator**: Digs into logs, finds root cause. (Security engineer)
3. **Lead Responder**: Executes containment, recovery. (SRE or DevOps)
4. **Communications Officer**: Updates stakeholders, legal, customers. (Product / Legal)
5. **Scribe**: Documents timeline, decisions, evidence. (Any senior IC)

**Ground Rules:**
- IC has authority. No debates in Slack; IC decides.
- All actions logged: "IC decision: Block IP 203.0.113.5 → approved → SRE executing."
- No post-mortems during incident. Focus on recovery only.
- Slack updates every 5-10 minutes (situational awareness).

### War Room Checklist

```bash
# When IC opens war room:
☐ Create #war-room-{incident-id} Slack channel
☐ Start Google Meet, pin link to channel topic
☐ Post incident summary (what, when, impact?)
☐ Assign roles: IC, investigator, responder, comms, scribe
☐ Set update frequency: Every 5 min for first 30 min, then every 15 min
☐ Notify: CISO, CFO, CTO, Customer Success, Legal
☐ Set escalation: If unresolved in 1 hour → page executive on-call
☐ Open Google Doc for timeline (shared live editing)
  - Format: [TIME] [WHO] [ACTION] [RESULT]
  - Example: 14:32 SRE-Alex Disabled AccessKey AKIA:xyz → Confirmed inactive in CloudTrail
☐ Create S3 bucket for forensics: s3://forensics-incident-{date-time}/
☐ Enable CloudTrail/Config/Guard Duty logging to forensics bucket (preserve evidence)

# Every 5 minutes (first 30 min):
☐ Lead Investigator: "Status on root cause?"
☐ Lead Responder: "Status on containment?"
☐ Comms Officer: "Any customer escalations?"
☐ Scribe: Update timeline + decisions made
☐ IC: Decide next actions (escalate? call AWS support? notify regulators?)

# Decision Log (post to #war-room channel):
[14:45] IC decision: Shut down prod-api instance 1 (potential attacker shell)
        Lead Responder approved: "Shell access confirmed via unauthorized SSH session"
        Action: EC2 terminate instance i-0x1b2c3d4e5f6g7h8i9
        Result: Instance terminated. Monitoring other instances for lateral movement.

[14:50] IC decision: Notify legal team (data exfil confirmed)
        Comms Officer approved: "203.0.113.5 accessed PII in s3://prod-customers (34 records, SSN + emails)"
        Action: Sent encrypted alert to legal@company.com
        Result: Legal standing by. Will assess breach notification requirements.

[15:05] IC decision: Open AWS support case (Severity 1 - potential AWS account compromise)
        Approved: "Need AWS's help to check for persistence (rootkit, CloudTrail disabling, etc.)"
        Action: Support case opened #123456789
        Result: AWS assigned security engineer. ETA 15 minutes.
```

### Escalation Decision Tree

```
Is incident ongoing?
├─ YES → Severity = CRITICAL
│  ├─ Attacker still in system? YES → Page on-call engineer + CISO immediately
│  ├─ Data still exfiltrating? YES → Kill network, isolate instance, page network team
│  └─ Unknown scope? YES → Assume worst case, page forensics team
│
└─ NO → Severity = HIGH
   ├─ Data confirmed accessed/exfiltrated? YES → Page CISO + Legal
   ├─ Customer data involved? YES → Page CFO (prepare breach notification budget)
   └─ Public disclosure likely? YES → Page CEO + PR (prepare statement)
```

---

## Part 3: Blameless Post-Mortems

Post-mortems must be **blameless** to encourage reporting near-misses. The goal is learning, not punishment.

### Post-Mortem Template

**Schedule:** 24-48 hours after incident (not immediately; let emotions cool)

**Attendees:** IC, Lead Investigator, Lead Responder, Comms Officer, Scribe, anyone who wants to attend

**Format:** 60 minutes, structured discussion

```markdown
# Post-Mortem: [Incident Name] — Date YYYY-MM-DD

## Executive Summary
**What happened?** 1-2 sentence executive summary
**When?** Start time - End time (duration: N minutes)
**Impact?** [N records accessed, N minutes downtime, N customers affected]
**Root cause?** [Single sentence]

## Timeline
[TIME] [WHAT HAPPENED]
14:32 CloudWatch alarm fired: AccessKey from unknown IP
14:35 On-call engineer acknowledged alert
14:38 Key disabled
14:45 IC opened war room, scope investigation started
15:10 S3 data exfil confirmed
15:30 Attacker IP blocked, connectivity killed
16:15 Recovery complete, S3 policies hardened

## Root Cause Analysis

**Question: Why did this happen?**

Not: "Engineer was careless" (blame)
Yes: "Access key was hardcoded in GitHub repo" (technical fact)

**The "5 Whys":**
1. Why was the S3 bucket accessed from 203.0.113.5?
   → Access key was exposed (hardcoded in repo)

2. Why was the access key in the repo?
   → No pre-commit hook to scan for secrets (GitLeaks not enabled)

3. Why is there no pre-commit hook?
   → Not prioritized in onboarding or engineering standards

4. Why was it not prioritized?
   → DevEx team (2 people) maxed out on other work

5. Why didn't we detect this sooner?
   → No real-time alerting on unknown IP access (IP allowlist not enforced)

**Systemic causes (not human error):**
- [ ] Missing tooling (GitLeaks, pre-commit)
- [ ] Missing process (key rotation, IP allowlisting)
- [ ] Missing training (how to NOT commit secrets)
- [ ] Missing monitoring (real-time CloudTrail processing)
- [ ] Overwork / understaffing

## Detection & Response Analysis

**Questions to answer:**

1. How did we detect this?
   - Good: CloudWatch alarm on unknown IP ✅
   - Gap: 3-minute detection delay (ideal: <30 seconds) ❌
   - Improvement: Lambda-based real-time processing

2. How fast did we respond?
   - From alert to action: 6 minutes (GOOD)
   - From action to containment: 52 minutes (SLOW)
   - Why slow? → Investigator was unsure which S3 buckets to prioritize
   - Improvement: Pre-built CloudTrail Athena queries in runbook

3. What did we do right?
   - ✅ Key was disabled immediately (stopped API calls)
   - ✅ War room established quickly (clear comms)
   - ✅ Evidence preserved (forensics S3 bucket)
   - ✅ Legal notified early (breach notification timeline met)

4. What could we have done better?
   - ❌ No IP allowlist (allowed 203.0.113.5 to access S3)
   - ❌ No real-time S3 access monitoring (found exfil via CloudTrail, not S3 metrics)
   - ❌ No automated runbook (investigator manually wrote CloudTrail queries)
   - ❌ War room decision log unclear (who approved which action? took 13 min to decide)

## Action Items (Prioritized)

**CRITICAL (implement within 1 week):**
- [ ] Enable GitLeaks in GitHub Actions (prevent secrets commits)
  - Owner: DevEx Team
  - Effort: 4 hours
  - Validation: Commit test secret to branch → check workflow fails ✅

- [ ] Implement IP allowlist for S3 bucket access (403 errors from non-approved IPs)
  - Owner: Security + SRE
  - Effort: 8 hours
  - Validation: Test from unknown IP → access denied ✅

**HIGH (implement within 1 month):**
- [ ] Real-time CloudTrail Athena queries (auto-triggered by Lambda)
  - Owner: Security team
  - Effort: 20 hours
  - Validation: Simulate exfil → alert within 30 seconds ✅

- [ ] Update access key rotation policy (90 days → 45 days)
  - Owner: Security + Identity team
  - Effort: 4 hours
  - Validation: Audit: no keys older than 45 days ✅

**MEDIUM (implement within 1 quarter):**
- [ ] ML-based anomaly detection on CloudTrail (detect unusual patterns)
  - Owner: Data Science + Security
  - Effort: 40 hours
  - Validation: Test on historical incident data → model catches 90%+ of attacks ✅

- [ ] Runbook automation (Lambda execute runbook steps automatically)
  - Owner: Security automation team
  - Effort: 30 hours
  - Validation: Runbook executes without manual clicks ✅

## Blameless Culture Commitment

**We are not investigating WHO made a mistake. We are investigating WHAT systemic issues allowed this incident.**

Examples of blame vs. improvement:

Blame ❌:
- "Engineer committed secrets to the repo (fired? written up?)"

Improvement ✅:
- "We don't have GitLeaks pre-commit hook → let's add it"
- "We don't train developers on secret management → let's add training"
- "We don't rotate keys frequently → let's automate 45-day rotation"

If an incident was caused by:
- Bad tool: We fix the tool
- Bad process: We fix the process
- Bad training: We improve training
- Bad decision: We improve decision-making framework

**Not:** "Bad person" (that's blame, which discourages reporting)

---

## Part 4: Automated Remediation Playbooks

Runbooks are manual. Automated playbooks execute steps without human click.

### Auto-Remediation: Disable Exposed Access Key

```python
# Lambda: auto-remediation for exposed key

import boto3
import json
from datetime import datetime, timedelta

iam = boto3.client('iam')
sns = boto3.client('sns')
logs = boto3.client('logs')

def lambda_handler(event, context):
    """
    Triggered by CloudWatch alarm: "AccessKey used from unknown IP"
    Auto-remediates: Disable the key + notify team
    """
    
    # Extract key ID from CloudTrail event
    access_key_id = event['detail']['requestParameters']['accessKeyId']
    source_ip = event['detail']['sourceIPAddress']
    user_name = event['detail']['userIdentity']['principalId']
    
    print(f"Auto-remediation triggered: Key {access_key_id} from {source_ip}")
    
    # Step 1: Verify key is actually compromised (not false positive)
    # Check if IP is in known-good allowlist
    known_ips = get_known_good_ips()
    
    if source_ip in known_ips:
        print(f"IP {source_ip} is in allowlist. No action.")
        return {
            'statusCode': 200,
            'remediation': 'skipped_whitelisted_ip',
            'details': f'IP {source_ip} is known good (VPN/office)'
        }
    
    # Step 2: Disable the key
    try:
        iam.update_access_key_status(
            UserName=user_name,
            AccessKeyId=access_key_id,
            Status='Inactive'
        )
        print(f"Key {access_key_id} disabled")
    except Exception as e:
        print(f"ERROR disabling key: {e}")
        return {
            'statusCode': 500,
            'error': f'Failed to disable key: {e}'
        }
    
    # Step 3: Extract recent API calls with this key (investigate what attacker did)
    try:
        response = iam.get_access_key_last_used(AccessKeyId=access_key_id)
        last_used_time = response['AccessKeyLastUsed']['LastUsedDate']
        last_service = response['AccessKeyLastUsed']['ServiceName']
        print(f"Last used: {last_used_time} by service: {last_service}")
        
        # Query CloudTrail for all calls in the last 1 hour
        ct = boto3.client('cloudtrail')
        events = ct.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'AccessKeyId', 'AttributeValue': access_key_id}
            ],
            MaxResults=50,
            StartTime=datetime.utcnow() - timedelta(hours=1)
        )
        
        # Parse events and check for high-risk actions
        suspicious_actions = []
        for event in events['Events']:
            event_name = event['EventName']
            if event_name in ['CreateAccessKey', 'CreateUser', 'GetSecretValue', 'AssumeRole']:
                suspicious_actions.append(event_name)
        
        print(f"Suspicious actions detected: {suspicious_actions}")
        
    except Exception as e:
        print(f"Error querying CloudTrail: {e}")
        suspicious_actions = []
    
    # Step 4: Notify team
    severity = 'CRITICAL' if suspicious_actions else 'HIGH'
    message = f"""
🚨 {severity}: Compromised AccessKey Disabled

Key: {access_key_id}
User: {user_name}
Source IP: {source_ip}
Last Used: {last_used_time}
Service: {last_service}

Action Taken: Key disabled (no more API calls possible)

Suspicious Activity Detected:
{json.dumps(suspicious_actions, indent=2) if suspicious_actions else 'None (reconnaissance only)'}

Next Steps:
1. Review CloudTrail events: {access_key_id}
2. Check if user's other keys were compromised
3. Rotate secrets accessed with this key
4. Update runbook: IP {source_ip} detected
"""
    
    sns.publish(
        TopicArn='arn:aws:sns:us-east-1:ACCOUNT:security-critical',
        Subject=f'{severity}: Compromised AccessKey Disabled',
        Message=message
    )
    
    # Step 5: Return remediation details for logging
    return {
        'statusCode': 200,
        'remediation': 'key_disabled',
        'key': access_key_id,
        'reason': f'Unauthorized use from {source_ip}',
        'suspicious_actions': suspicious_actions,
        'team_notified': True
    }

def get_known_good_ips():
    """Return list of known-good IPs (VPN, offices, CI/CD)"""
    return [
        '10.0.0.0/8',        # Internal network
        '203.0.113.10/32',   # Office IP
        '203.0.113.20/32',   # VPN gateway
        '54.239.0.0/16',     # AWS S3 endpoint
    ]
```

### Auto-Remediation: Block S3 Bucket Public Access

```python
# Lambda: auto-remediation for S3 bucket exposed

import boto3
from datetime import datetime

s3 = boto3.client('s3')
sns = boto3.client('sns')

def lambda_handler(event, context):
    """
    Triggered by: GuardDuty finding "S3 Bucket Public"
    Auto-remediates: Block all public access to bucket
    """
    
    bucket_name = event['detail']['resource']['s3BucketDetails'][0]['name']
    print(f"Auto-remediation: Blocking public access to {bucket_name}")
    
    try:
        # Apply S3 Block Public Access (prevents any public access)
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        print(f"Public access blocked on {bucket_name}")
        
        # Notify team
        sns.publish(
            TopicArn='arn:aws:sns:us-east-1:ACCOUNT:security-alerts',
            Subject=f'AUTO-REMEDIATED: S3 Bucket {bucket_name} Public Access Blocked',
            Message=f"""
S3 bucket was public. Auto-remediation applied:

Bucket: {bucket_name}
Action: S3 Block Public Access enabled (all 4 settings)
Time: {datetime.utcnow().isoformat()}

This was automated. Verify the bucket should not be public.
If intentional (e.g., static website hosting), revert and add exception to runbook.

Review bucket policy: aws s3api get-bucket-policy --bucket {bucket_name}
"""
        )
        
        return {
            'statusCode': 200,
            'remediation': 'public_access_blocked',
            'bucket': bucket_name
        }
        
    except Exception as e:
        sns.publish(
            TopicArn='arn:aws:sns:us-east-1:ACCOUNT:security-critical',
            Subject=f'ERROR: Failed to remediate S3 bucket {bucket_name}',
            Message=f"Error: {e}\n\nManual review required."
        )
        raise
```

---

## Part 5: IR Metrics & KPIs

Track IR performance to improve over time.

```yaml
# IR Metrics

Metric: Mean Time to Detect (MTTD)
  Definition: Time from incident start to alert firing
  Current: 180 minutes (manual audit discovery)
  Target: 5 minutes (real-time CloudTrail alerting)
  How to improve:
    - Lambda-based real-time CloudTrail processing
    - GuardDuty + custom detections
    - CloudWatch anomaly detection

Metric: Mean Time to Respond (MTTR)
  Definition: Time from alert to first action (disable key, block IP, etc.)
  Current: 6 minutes (on-call engineer awareness + decision)
  Target: 30 seconds (automated runbook execution)
  How to improve:
    - Automated Lambda playbooks (disable key, block IP)
    - PagerDuty escalation (page if not acked within 2 min)
    - War room auto-creation (Slack webhook)

Metric: Mean Time to Resolve (MTRR)
  Definition: Time from incident start to full recovery
  Current: 4 hours
  Target: 30 minutes
  How to improve:
    - Automated incident response (stop bleeding first)
    - Automation: rotate secrets, restore backups, patch
    - Regular IR drills (team practices scenarios)

Metric: False Positive Rate
  Definition: % of alerts that are not real incidents
  Current: 15% (high noise, team ignores alerts)
  Target: <5%
  How to improve:
    - IP allowlisting (fewer unknown IP alerts)
    - Baseline learning (ML anomaly detection)
    - Team feedback loop (adjust thresholds weekly)

Metric: Detection Capability (by scenario)
  Definition: % of incidents we catch before customer reports
  Track per scenario:
    - Compromised credential: 90% (improve: add ML detection)
    - Data exfiltration: 70% (improve: enable S3 metrics + Lambda)
    - Privilege escalation: 85% (improve: monitor IAM changes)
    - Malware infection: 40% (improve: add endpoint detection)

Metric: Incident Severity Distribution
  Definition: Count incidents by severity
  Track: % CRITICAL vs. HIGH vs. MEDIUM
  Target: 80% CRITICAL incidents resolved <1 hour
           90% HIGH incidents resolved <4 hours
           100% MEDIUM incidents triaged <24 hours

Metric: Post-Mortem Action Item Completion
  Definition: % of action items completed within assigned SLA
  Target: 100% CRITICAL items within 1 week
          100% HIGH items within 1 month
          80% MEDIUM items within 1 quarter
  How: Track in spreadsheet, review in weekly security meeting
```

---

## 🧹 Cleanup

```bash
# No persistent resources to clean up
# (War room channels are archived, not deleted)

echo "✅ IR at Scale training materials ready"
```

---

## Checklist

**Runbooks & Automation**
- [ ] Create runbook for top 5 incident scenarios (credential compromise, data exfil, IAM changes, resource deletion, DDoS)
- [ ] Each runbook has: detection signal, immediate actions, investigation steps, containment, recovery
- [ ] Test runbook: simulate incident, execute runbook steps manually, verify they work
- [ ] Automate runbook: convert manual steps to Lambda playbooks

**War Room Procedures**
- [ ] Define war room roles: IC, Investigator, Responder, Comms, Scribe
- [ ] Create Slack template for `#war-room-{incident-id}` channel
- [ ] Train team on war room protocol (decision log, escalation, updates every 5 min)
- [ ] Run 2 war room drills/year (practice before incident happens)

**Blameless Post-Mortems**
- [ ] Post-mortem template in Wiki (executive summary, timeline, root cause, action items)
- [ ] Schedule post-mortem 24-48 hours after incident (not immediately)
- [ ] Facilitate with emphasis: "Why did the system allow this?" not "Who made the mistake?"
- [ ] Track action items in spreadsheet with owners + due dates
- [ ] Review completion monthly (security team meeting)

**Automated Remediation**
- [ ] Create Lambda playbook for auto-disable compromised key
- [ ] Create Lambda playbook for auto-block public S3 buckets
- [ ] Create Lambda playbook for auto-block suspicious IPs (security group rules)
- [ ] Test playbooks: trigger manually, verify actions execute correctly
- [ ] Set SNS notifications for all auto-remediations (team stays informed)

**IR Metrics**
- [ ] Dashboard: MTTD, MTTR, MTRR, false positive rate (update after each incident)
- [ ] Monthly review: Which metrics improved? Which regressed? Why?
- [ ] Trend analysis: Is detection getting faster? Are runbooks working?
- [ ] Team alignment: Share metrics in security standup (celebrate improvements)

**Production Readiness**
- [ ] All runbooks tested and approved by IC team
- [ ] War room protocol documented and team trained
- [ ] Automated playbooks in production + tested monthly
- [ ] Post-mortem process defined + practiced
- [ ] IR metrics tracked + reviewed monthly

---

## Integration with Phase 4

This IR at scale expansion strengthens:
- **Phase 4 m12-week3:** IR capstone simulation → automated runbooks + war room procedures
- **Phase 4 compliance-automation-cloudtrail-config:** Compliance automation + IR metrics in weekly reporting
- **Phase 4 observability-monitoring-siem:** Real-time alerting + IR detection (metrics trigger runbooks)

---

## Real-World Scenarios

**Scenario 1: Ransomware Detection & Auto-Response**
```
Time 03:15: GuardDuty detects unusual EC2 behavior (crypto-mining process)
Time 03:16: Lambda auto-remediation: 
  - Snapshot EBS volumes (evidence + recovery)
  - Isolate instance (kill network)
  - Notify on-call engineer + CISO
Time 03:20: IC opens war room, investigation confirms ransomware variant X
Time 03:30: Attacker can't spread (network isolated), damage limited to 1 instance
Time 03:45: Restore from snapshot, apply patch, restore service
Recovery Time: 30 minutes (thanks to automation)
```

**Scenario 2: Regulatory Breach (SOC2 Audit)**
```
Time 10:00: Customer support reports "PII in error logs"
Time 10:05: IC opens war room, Lead Investigator queries CloudTrail
Time 10:20: Confirmed: PII (names, emails) in application error logs for 72 hours
Impact: ~500 users potentially exposed
Time 10:30: Legal notified, breach notification process started
Time 11:00: First customer notification (SOC2 requires <24 hours)
Time 14:00: Post-mortem: error logging should scrub PII
Action: Implement PII scrubber in logging library, add pre-commit validation
Prevention: No more PII in logs (automated)
```

You now have **production-grade incident response**. 🚨

