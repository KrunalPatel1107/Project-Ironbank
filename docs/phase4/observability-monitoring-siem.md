# Month 6 — Special: Observability, Monitoring & Alerting for Security

!!! abstract "💰 Cost: $10-50/month — CloudWatch, Prometheus (free), optional SIEM ($80-200/mo)"

!!! danger "Why Security Observability Matters"
    Phase 2 guardduty-cloudwatch-alarms taught GuardDuty (threat detection). This expansion teaches **real-time security monitoring**: detecting anomalies the moment they happen, not hours/days later. When a compromised credential is used, when unusual API calls spike, when a database is accessed from a new IP — you need to know in seconds, not during a security audit. Netflix, AWS, and all cloud-native companies do this. Without observability, you're flying blind.

!!! info "Background Context"
    Phase 4 m11 taught compliance automation (passive evidence collection). This expansion teaches active monitoring (real-time threats). Together: compliance = prove what happened, observability = detect when it's happening now.

---

## Part 1: Security Metrics & KPIs

Define what "normal" looks like, so anomalies stand out.

### Key Security Metrics

```
Authentication Metrics:
  - Failed login attempts per minute (threshold: >10/min = alert)
  - Unique IPs attempting login from (threshold: >5 new IPs/hour = alert)
  - MFA bypass attempts (threshold: any = immediate alert)
  - Password reset rate (threshold: >20/hour = potential attack)

Authorization Metrics:
  - Denied API calls per minute (threshold: >50/min = alert)
  - Privilege escalation attempts (threshold: any = immediate alert)
  - Cross-account access attempts (threshold: >5/hour = alert)
  - Role assumption failures (threshold: >10/min = alert)

Data Access Metrics:
  - S3 bucket access from unusual IP (threshold: any = alert)
  - Database large data export (threshold: >1GB/min = alert)
  - Sensitive field access (PII, SSN, CC#) (threshold: any = alert)
  - Data deleted (threshold: any = alert)

Infrastructure Metrics:
  - Security group modified (threshold: any = alert)
  - IAM policy changed (threshold: any = alert)
  - CloudTrail logging disabled (threshold: any = immediate alert)
  - SSL certificate expires soon (threshold: <30 days = alert)

Network Metrics:
  - Unusual port opened (threshold: any non-standard = investigate)
  - DDoS detection triggered (threshold: >1Gbps = alert)
  - Unusual geographic access (threshold: >10 countries/hour = alert)
  - Suspicious domains accessed (threshold: any blacklist match = alert)
```

### Define Baselines

```bash
# CloudWatch Anomaly Detection
# Learn "normal" traffic patterns, alert on deviations

aws cloudwatch put-metric-alarm \
  --alarm-name failed-login-anomaly \
  --alarm-description "Alert on unusual failed login spike" \
  --metric-name FailedLoginsPerMinute \
  --namespace SecurityMetrics \
  --statistic Average \
  --anomaly-detector-config '{"Stat": "p50"}' \
  --threshold-metric-id m1 \
  --metrics-queries '[
    {
      "id": "m1",
      "label": "Failed Logins",
      "returnData": true,
      "metricStat": {
        "metric": {"namespace": "SecurityMetrics", "metricName": "FailedLoginsPerMinute"},
        "period": 60,
        "stat": "Average"
      }
    }
  ]'

# This alarm uses machine learning to detect when failed logins deviate
# from normal patterns, even if absolute number is low
```

---

## Part 2: Real-Time Alerting Architecture

Multi-layer alerting ensures critical events reach on-call immediately.

```
Event Flow:
┌──────────────────┐
│ CloudTrail logs  │
│ GuardDuty alerts │
│ VPC Flow logs    │
│ Config changes   │
└────────┬─────────┘
         │
    ┌────▼─────┐
    │ CloudWatch│────→ Athena (complex queries)
    │ Logs      │────→ Lambda (real-time processing)
    │ Metrics   │
    └────┬─────┘
         │
    ┌────▼──────────────┐
    │ SNS Topic          │ (immediate)
    │ PagerDuty          │ (page on-call)
    │ Slack              │ (team notification)
    │ Email              │ (low-priority)
    └───────────────────┘
```

### Lab: Real-Time Alert Chain

```bash
# Step 1: Create CloudWatch Log Group
aws logs create-log-group --log-group-name /aws/security/alerts

# Step 2: Parse CloudTrail logs in real-time
cat > lambda/security-alert-lambda.py << 'EOF'
import json
import boto3
import base64

sns = boto3.client('sns')
pagerduty = boto3.client('events')

def lambda_handler(event, context):
    """Real-time security event processor"""
    
    # Parse CloudWatch Logs data
    payload = json.loads(gzip.decompress(
        base64.b64decode(event['awslogs']['data'])
    ))
    
    for log_event in payload['logEvents']:
        message = json.loads(log_event['message'])
        event_name = message.get('eventName')
        
        # CRITICAL: Unauthorized root credential use
        if event_name == 'GetSessionToken' and \
           message.get('userIdentity', {}).get('rootUser'):
            
            alert_msg = f"""
🚨 CRITICAL: Root account used!
Time: {message['eventTime']}
IP: {message['sourceIPAddress']}
User: {message['userIdentity']['arn']}
Action: {event_name}

Immediate action: Check root account activity log
            """
            
            # Page on-call immediately (PagerDuty)
            pagerduty.put_events(
                Entries=[{
                    'Source': 'SecurityMonitoring',
                    'DetailType': 'SecurityEvent',
                    'Detail': json.dumps({
                        'severity': 'CRITICAL',
                        'message': alert_msg,
                        'event': message
                    })
                }]
            )
            
            # Also notify Slack
            requests.post(
                os.environ['SLACK_WEBHOOK'],
                json={'text': alert_msg}
            )
        
        # HIGH: Console login from unusual IP
        elif event_name == 'ConsoleLogin':
            user_ip = message['sourceIPAddress']
            
            # Check if IP is in known good list
            if user_ip not in KNOWN_GOOD_IPS:
                # Get baseline for this user
                baseline = get_user_baseline(message['userIdentity']['principalId'])
                
                if is_anomalous(user_ip, baseline):
                    alert_msg = f"⚠️ Console login from unusual IP: {user_ip}"
                    
                    sns.publish(
                        TopicArn='arn:aws:sns:us-east-1:ACCOUNT:security-alerts',
                        Subject='Unusual Console Login',
                        Message=alert_msg
                    )

EOF
```

### Alert Routing (Severity-Based)

```yaml
# Alert severity determines routing

CRITICAL (Page on-call immediately):
  - Root account activity
  - IAM policy changes
  - CloudTrail disabled
  - Unauthorized data access
  - Active security incident
  Route: PagerDuty + Slack #security-critical

HIGH (Notify team within 5 min):
  - Unusual login location
  - Multiple failed auth
  - Security group opened
  - Large data export
  Route: Slack #security-alerts + email

MEDIUM (Log & track):
  - Config drift detected
  - SSL cert expiring soon
  - Unusual API patterns
  Route: CloudWatch dashboard + weekly report

LOW (Informational):
  - Normal activity with minor anomaly
  - Successful remediation
  - Policy compliance check
  Route: CloudWatch logs only
```

---

## Part 3: CloudWatch Dashboard & SIEM Integration

**CloudWatch** aggregates AWS logs; **SIEM** correlates across clouds.

### CloudWatch Security Dashboard

```bash
# Create comprehensive security dashboard
cat > security-dashboard.json << 'EOF'
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "title": "Failed Authentication Attempts",
        "metrics": [
          ["SecurityMetrics", "FailedLogins", {"stat": "Sum"}],
          [".", "FailedMFAAttempts", {"stat": "Sum"}],
          [".", "PasswordResetSpike", {"stat": "Sum"}]
        ],
        "yAxis": {"left": {"min": 0}},
        "period": 60,
        "stat": "Sum"
      }
    },
    {
      "type": "log",
      "properties": {
        "title": "Unauthorized API Calls",
        "query": "fields @timestamp, eventName, errorCode | filter errorCode like /Unauthorized|AccessDenied|InvalidParameterValue/ | stats count() as denials by eventName | sort denials desc",
        "region": "us-east-1"
      }
    },
    {
      "type": "metric",
      "properties": {
        "title": "Infrastructure Changes",
        "metrics": [
          ["AWS/Config", "NonCompliantResources"],
          ["SecurityMetrics", "SecurityGroupModified"],
          [".", "IAMPolicyChanged"],
          [".", "CloudTrailDisabled"]
        ]
      }
    },
    {
      "type": "log",
      "properties": {
        "title": "Sensitive Data Access",
        "query": "fields @timestamp, userIdentity.principalId, eventName, requestParameters | filter eventName like /GetObject|Query|Scan/ and requestParameters like /SSN|password|credit_card/ | stats count() as accesses by userIdentity.principalId",
        "region": "us-east-1"
      }
    }
  ]
}
EOF

aws cloudwatch put-dashboard \
  --dashboard-name SecurityMonitoring \
  --dashboard-body file://security-dashboard.json
```

### SIEM Integration (Splunk)

```bash
# Stream CloudTrail + VPC Flow logs to Splunk

# Create CloudWatch Logs subscription to Splunk
aws logs put-subscription-filter \
  --log-group-name /aws/cloudtrail/iron-bank \
  --filter-name "send-to-splunk" \
  --filter-pattern "" \
  --destination-arn arn:aws:logs:us-east-1:ACCOUNT:destination:splunk-http

# In Splunk, create correlation rules
# Example: Alert if login fails 10x THEN success from different IP (password spray attack)

search_query = """
index=aws sourcetype=aws:cloudtrail eventName=ConsoleLogin errorCode=*
| stats count as failures by userIdentity.principalId, sourceIPAddress
| where failures > 10
| fields userIdentity.principalId, sourceIPAddress, failures
| join type=left userIdentity.principalId
  [search index=aws sourcetype=aws:cloudtrail eventName=ConsoleLogin errorCode="" 
   | fields userIdentity.principalId, sourceIPAddress
   | rename sourceIPAddress as successIP]
| where sourceIPAddress != successIP
| alert
"""
```

---

## Part 4: Anomaly Detection with Machine Learning

Use GuardDuty + custom ML models to detect novel attacks.

```python
# Lambda: ML-based anomaly detection

import boto3
import json
from sklearn.isolation_forest import IsolationForest
import numpy as np

def lambda_handler(event, context):
    """Detect anomalous CloudTrail patterns using ML"""
    
    # Extract features from CloudTrail events
    features = []
    for log_event in event['logEvents']:
        message = json.loads(log_event['message'])
        
        feature_vector = [
            hour_of_day(message['eventTime']),
            number_of_api_calls_this_hour(),
            is_weekend(message['eventTime']),
            geographic_distance_from_usual(message['sourceIPAddress']),
            api_call_frequency_anomaly(message['eventName']),
        ]
        
        features.append(feature_vector)
    
    # Train Isolation Forest on historical data
    model = load_model('s3://models/cloudtrail-anomaly-model.pkl')
    
    # Predict: -1 = anomaly, 1 = normal
    predictions = model.predict(features)
    
    anomalies = []
    for i, pred in enumerate(predictions):
        if pred == -1:  # Anomaly detected
            anomalies.append(event['logEvents'][i])
    
    if anomalies:
        # Alert on detected anomalies
        sns.publish(
            TopicArn='arn:aws:sns:us-east-1:ACCOUNT:ml-security-alerts',
            Subject=f'ML Anomaly Detected: {len(anomalies)} events',
            Message=json.dumps(anomalies[:5])  # First 5
        )
    
    return {
        'statusCode': 200,
        'anomalies_detected': len(anomalies)
    }
```

---

## Part 5: Write an Observability Finding

```bash
cat > ~/observability-finding.md << 'EOF'
# Finding: No Real-Time Security Monitoring — Breaches Go Undetected for Days

**Severity:** Critical  
**Component:** Monitoring & Alerting (Detection)  

## Description
Security events logged to CloudTrail, but no real-time processing.
A compromised API key, a mass data export, or a privilege escalation happens,
but nobody finds out until the monthly security audit (30 days later).

## Impact
- Attacker has 30 days to exfiltrate data
- Lateral movement undetected for weeks
- Incident response slow (by the time you know, damage is done)

## Compliance Gap
- PCI-DSS 10.3.2: "Detect unauthorized access to cardholder data within 24 hours"
  Status: FAILING (30-day detection window)
- HIPAA: "Detect ePHI breaches immediately"
  Status: FAILING (no alerting)

## Remediation
1. **Real-time log processing:** Lambda parses CloudTrail in real-time
2. **Alert rules:** 20+ rules for critical events (root access, IAM changes, data export)
3. **Alerting channels:** PagerDuty (page on-call), Slack (team), email (low-priority)
4. **Dashboards:** Real-time security metrics (failed logins, denied API calls, etc.)
5. **SIEM integration:** Splunk correlates events across AWS, on-prem, third-party

## Effort
- Initial: 40 hours (design metrics, write Lambda, setup alerting)
- Ongoing: 5 hours/month (tune alerts, reduce false positives)

## Result
- Detection time: 30 days → 5 minutes
- Incident response time: Days → Hours
- Compliance: Failing → Passing
EOF

cat ~/observability-finding.md
```

---

## 🧹 Cleanup

```bash
rm -f ~/observability-finding.md
rm -f security-dashboard.json

echo "✅ Observability & Alerting lab cleaned up"
```

---

## Checklist

**Security Metrics & KPIs**
- [ ] Define "normal" baselines for key metrics
- [ ] Can explain: failed logins, denied APIs, privilege escalation
- [ ] Know CloudWatch anomaly detection (ML-based)
- [ ] Can create custom metrics for your app

**Real-Time Alerting**
- [ ] Can write Lambda to process CloudTrail events
- [ ] Understand alert severity routing (critical → PagerDuty, high → Slack)
- [ ] Know alert fatigue prevention (tune thresholds to reduce false positives)
- [ ] Can integrate with PagerDuty, Slack, email

**CloudWatch Dashboards**
- [ ] Can create security dashboards (auth metrics, API denials, infra changes)
- [ ] Know CloudWatch Logs Insights queries
- [ ] Understand time-series visualization (trends over time)
- [ ] Can export metrics for compliance reports

**SIEM Integration**
- [ ] Know Splunk, ELK, Datadog options
- [ ] Can configure log forwarding (subscription filters)
- [ ] Understand correlation rules (event A + event B = incident)
- [ ] Know retention policies (7 years for PCI-DSS)

**Anomaly Detection**
- [ ] Know GuardDuty capabilities (threat detection)
- [ ] Can implement ML-based anomaly detection (Isolation Forest)
- [ ] Understand false positive tuning
- [ ] Know when to alert vs. investigate

**Production Readiness**
- [ ] All critical events have alert rules configured
- [ ] On-call rotation trained on alert response
- [ ] Runbooks for each alert type (documented)
- [ ] Alert tuning ongoing (false positive reduction)
- [ ] Weekly metrics review (trends, gaps)

---

## Integration with Phase 4

This observability expansion strengthens:
- **Phase 2 guardduty-cloudwatch-alarms:** GuardDuty + real-time alerting
- **Phase 4 m11:** Compliance automation + real-time detection
- **Phase 4 m12-week3:** IR has full context (logs, metrics, alerts)

---

## Real-World Scenarios

**Scenario 1: Detect Compromised Credentials**
```
Time 00:00: Attacker uses stolen AWS access key
Time 00:01: CloudTrail logs API calls from unknown IP
Time 00:02: Lambda detects anomaly (5 failed calls + 1 success = spray attack)
Time 00:03: PagerDuty alerts on-call engineer
Time 00:05: Engineer locks down the key, blocks IP
Attacker damage: 5 minutes (before they do anything serious)
```

**Scenario 2: Detect Data Exfiltration**
```
Time 10:00: Employee's credentials compromised
Time 10:05: Attacker downloads 1GB from S3 (unusual)
Time 10:06: CloudWatch anomaly triggers (5GB/min threshold)
Time 10:07: Slack alert #security-alerts
Time 10:10: Team investigates, kills the session
Data lost: Seconds of exfiltration (instead of hours)
```

You now have **real-time security visibility**. 👁️
