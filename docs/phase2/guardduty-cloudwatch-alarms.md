# Month 6 — Week 1: GuardDuty & CloudWatch Alarms

!!! danger "💰 Cost Warning"
    - **GuardDuty:** First 30 days free trial, then ~$1–4/month for a quiet lab account. **Disable it after the lab.**
    - **CloudWatch Alarms:** First 10 alarms are free. You'll create 3–4, all within free tier.
    - **SNS Email notifications:** Free for under 1,000 emails/month.

!!! info "If you know the Microsoft security stack"
    GuardDuty = Microsoft Defender for Cloud (threat detection + alerts). CloudWatch Alarms + SNS = Azure Monitor Alerts + Action Groups. If you've built Sentinel analytics rules before, this week you build the AWS equivalent. The concepts are identical; only the console and CLI differ.

---

## What Is GuardDuty?

GuardDuty is AWS's managed **threat detection service**. You don't install agents or manage rules — you turn it on and it continuously analyses three data sources:

| Data Source | What It Detects |
|---|---|
| **CloudTrail logs** | Unusual API calls — e.g. `root` account used, credentials used from a new country |
| **VPC Flow Logs** | Port scans, unusual traffic patterns, communication with known malicious IPs |
| **DNS logs** | EC2 instances querying known malware C2 domains |

GuardDuty generates **findings** — each finding has a severity (Low / Medium / High / Critical), a type, and a detailed description of what was detected. Think of it as a SIEM that's pre-tuned for AWS.

??? note "GuardDuty vs CloudTrail — what's the difference?"
    **CloudTrail** is a raw audit log — it records every API call made in your account (who called what, when, from where). It answers "what happened?"

    **GuardDuty** analyses CloudTrail (and other sources) to detect *suspicious patterns* across those events. It answers "should I be worried about what happened?"

    You need both: CloudTrail for forensics, GuardDuty for real-time alerting.

---

## Part 1: Enable GuardDuty

```bash
# ─── Enable GuardDuty in your account ────────────────────────────────────────
DETECTOR_ID=$(aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES \
  --profile iron-bank \
  --query DetectorId --output text)

echo "GuardDuty Detector ID: $DETECTOR_ID"
# Save this — you need it for every subsequent GuardDuty command

# ─── Verify it's enabled ──────────────────────────────────────────────────────
aws guardduty get-detector \
  --detector-id $DETECTOR_ID \
  --profile iron-bank \
  --query '{Status:Status,FrequencyMinutes:FindingPublishingFrequency}' \
  --output table
# Expected: Status=ENABLED, FrequencyMinutes=FIFTEEN_MINUTES
```

!!! tip "Finding Publishing Frequency"
    `FIFTEEN_MINUTES` means GuardDuty updates existing findings every 15 minutes. New findings are always published immediately. Use `ONE_HOUR` or `SIX_HOURS` in production to reduce SNS notification noise.

---

## Part 2: Generate a Sample Finding

GuardDuty findings take time to appear organically. AWS provides a way to generate realistic sample findings instantly — great for testing your alerting pipeline before real threats appear.

```bash
# ─── Generate sample findings (all finding types, fake data) ─────────────────
aws guardduty create-sample-findings \
  --detector-id $DETECTOR_ID \
  --finding-types \
    "UnauthorizedAccess:EC2/SSHBruteForce" \
    "Recon:EC2/PortProbeUnprotectedPort" \
    "CryptoCurrency:EC2/BitcoinTool.B!DNS" \
    "Trojan:EC2/BlackholeTraffic" \
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B" \
  --profile iron-bank

echo "Sample findings created. Waiting 30 seconds for them to appear..."
sleep 30

# ─── List all current findings ────────────────────────────────────────────────
aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --profile iron-bank \
  --query 'FindingIds' \
  --output table

# ─── Get details on the first finding ─────────────────────────────────────────
FINDING_ID=$(aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --profile iron-bank \
  --query 'FindingIds[0]' --output text)

aws guardduty get-findings \
  --detector-id $DETECTOR_ID \
  --finding-ids $FINDING_ID \
  --profile iron-bank \
  --query 'Findings[0].{Type:Type,Severity:Severity,Title:Title,Description:Description}' \
  --output table
```

??? note "Understanding a GuardDuty finding type"
    Finding types follow the format: `ThreatPurpose:ResourceTypeAffected/ThreatFamilyName.DetectionMechanism`

    - `UnauthorizedAccess:EC2/SSHBruteForce` → someone is brute-forcing SSH on your EC2 instance
    - `CryptoCurrency:EC2/BitcoinTool.B!DNS` → an EC2 instance is querying crypto mining pool domains
    - `Recon:EC2/PortProbeUnprotectedPort` → someone is scanning your instance for open ports

    Severity 7.0+ = High (page someone now). 4.0–6.9 = Medium (investigate today). Below 4.0 = Low (review weekly).

---

## Part 3: Filter & Suppress Findings

In real environments you'll want to suppress known-good activity (e.g. your deployment pipeline hitting the API from a fixed IP) so alerts stay meaningful.

```bash
# ─── List only HIGH severity findings ────────────────────────────────────────
aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "severity": {
        "Gte": 7
      }
    }
  }' \
  --profile iron-bank \
  --query 'FindingIds' \
  --output table

# ─── Archive (suppress) sample findings so they don't create alert fatigue ───
ALL_FINDING_IDS=$(aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --profile iron-bank \
  --query 'FindingIds' \
  --output json)

aws guardduty archive-findings \
  --detector-id $DETECTOR_ID \
  --finding-ids $ALL_FINDING_IDS \
  --profile iron-bank

echo "Sample findings archived"
```

---

## Part 4: SNS Topic + Email Alerting

SNS (Simple Notification Service) is the AWS messaging bus. You create a **topic**, subscribe your email, and then anything that publishes to that topic sends you an email. Think of it as Azure Action Groups.

```bash
# ─── Create an SNS Topic for security alerts ─────────────────────────────────
TOPIC_ARN=$(aws sns create-topic \
  --name iron-bank-security-alerts \
  --profile iron-bank \
  --query TopicArn --output text)
echo "SNS Topic: $TOPIC_ARN"

# ─── Subscribe your email to the topic ───────────────────────────────────────
# Replace with your actual email address
aws sns subscribe \
  --topic-arn $TOPIC_ARN \
  --protocol email \
  --notification-endpoint "your@email.com" \
  --profile iron-bank

echo "Check your email and click the confirmation link before continuing!"
# AWS sends a confirmation email — you MUST click it or SNS won't deliver messages

# ─── Manually test the topic ─────────────────────────────────────────────────
aws sns publish \
  --topic-arn $TOPIC_ARN \
  --subject "Iron Bank Test Alert" \
  --message "GuardDuty alerting pipeline is working correctly." \
  --profile iron-bank
# You should receive this email within ~30 seconds
```

---

## Part 5: CloudWatch Alarm → SNS for GuardDuty Findings

GuardDuty publishes metrics to CloudWatch. You'll create an alarm that triggers when any HIGH severity finding appears.

```bash
# ─── Create CloudWatch Metric Filter for GuardDuty HIGH findings ─────────────
# GuardDuty sends finding events to CloudWatch Events (EventBridge)
# First, create an EventBridge rule that routes HIGH findings → SNS

aws events put-rule \
  --name "guardduty-high-severity" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [{"numeric": [">=", 7.0]}]
    }
  }' \
  --state ENABLED \
  --description "Route GuardDuty HIGH severity findings to SNS" \
  --profile iron-bank

# ─── Add SNS as the target of this EventBridge rule ──────────────────────────
# Get the rule ARN first
RULE_ARN=$(aws events describe-rule \
  --name "guardduty-high-severity" \
  --profile iron-bank \
  --query RuleArn --output text)

aws events put-targets \
  --rule "guardduty-high-severity" \
  --targets "[{
    \"Id\": \"sns-target\",
    \"Arn\": \"$TOPIC_ARN\",
    \"InputTransformer\": {
      \"InputPathsMap\": {
        \"severity\": \"$.detail.severity\",
        \"type\": \"$.detail.type\",
        \"region\": \"$.region\",
        \"account\": \"$.account\"
      },
      \"InputTemplate\": \"\\\"GuardDuty HIGH Finding\\\\nAccount: <account>\\\\nRegion: <region>\\\\nType: <type>\\\\nSeverity: <severity>\\\"\"
    }
  }]" \
  --profile iron-bank

echo "EventBridge rule → SNS pipeline created"

# ─── Allow EventBridge to publish to your SNS topic ──────────────────────────
aws sns add-permission \
  --topic-arn $TOPIC_ARN \
  --label "EventBridge-GuardDuty" \
  --aws-account-id $(aws sts get-caller-identity --profile iron-bank --query Account --output text) \
  --action-name Publish \
  --profile iron-bank

# ─── Test the pipeline: generate a HIGH finding ───────────────────────────────
aws guardduty create-sample-findings \
  --detector-id $DETECTOR_ID \
  --finding-types "UnauthorizedAccess:EC2/SSHBruteForce" \
  --profile iron-bank

echo "HIGH finding created — check your email in ~2 minutes"
```

---

## Part 6: Verify Everything in the Console

```bash
# ─── Summary: show your full detection setup ──────────────────────────────────
echo "=== GuardDuty Status ==="
aws guardduty get-detector \
  --detector-id $DETECTOR_ID \
  --profile iron-bank \
  --query '{Status:Status,UpdatedAt:UpdatedAt}' \
  --output table

echo "=== SNS Subscriptions ==="
aws sns list-subscriptions-by-topic \
  --topic-arn $TOPIC_ARN \
  --profile iron-bank \
  --query 'Subscriptions[*].{Protocol:Protocol,Endpoint:Endpoint,Status:SubscriptionArn}' \
  --output table

echo "=== EventBridge Rules ==="
aws events list-rules \
  --profile iron-bank \
  --query 'Rules[?starts_with(Name, `guardduty`)].{Name:Name,State:State}' \
  --output table
```

---

## 🧹 Cleanup

!!! abstract "🧹 Cleanup — GuardDuty has a cost after the trial period"

```bash
# Delete EventBridge rule (remove targets first)
aws events remove-targets \
  --rule "guardduty-high-severity" \
  --ids "sns-target" \
  --profile iron-bank

aws events delete-rule \
  --name "guardduty-high-severity" \
  --profile iron-bank

# Delete SNS subscription and topic
SUBSCRIPTION_ARN=$(aws sns list-subscriptions-by-topic \
  --topic-arn $TOPIC_ARN \
  --profile iron-bank \
  --query 'Subscriptions[0].SubscriptionArn' --output text)

aws sns unsubscribe --subscription-arn $SUBSCRIPTION_ARN --profile iron-bank
aws sns delete-topic --topic-arn $TOPIC_ARN --profile iron-bank

# Disable GuardDuty LAST — this is the most important cleanup step
aws guardduty delete-detector \
  --detector-id $DETECTOR_ID \
  --profile iron-bank

echo "✅ GuardDuty disabled, SNS topic deleted, EventBridge rule removed"
```

!!! warning "Don't skip the GuardDuty delete"
    GuardDuty is free for the first 30 days. After that it charges per GB of log data analysed. In an active account it can reach $1–5/month. Always delete the detector after the lab.

---

## Checklist

- [ ] GuardDuty enabled — Detector ID saved
- [ ] Sample findings generated and reviewed (understand finding type format)
- [ ] At least one HIGH severity finding inspected in detail
- [ ] SNS topic created with email subscription confirmed
- [ ] Test email received from SNS
- [ ] EventBridge rule routes HIGH GuardDuty findings → SNS
- [ ] End-to-end test: sample finding → email received
- [ ] Can explain GuardDuty vs CloudTrail (different tools, complementary roles)
- [ ] **GuardDuty detector deleted — most important cleanup step**
- [ ] **SNS topic and EventBridge rule deleted**
- [ ] **Bill verified $0**
