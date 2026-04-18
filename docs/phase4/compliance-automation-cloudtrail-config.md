# Month 11 — Special: Continuous Compliance & Audit Automation

!!! abstract "💰 Cost: $5-30/month — CloudTrail logging, Athena queries, optional dashboarding"

!!! danger "Why Continuous Compliance Matters"
    Auditors ask: "Prove that your infrastructure meets PCI-DSS / HIPAA / SOC2." Phase 4 m11-week1 covers Config rules. This expansion teaches **continuous compliance**: automatically collecting evidence, generating reports, and proving compliance to auditors without manual spreadsheets. Netflix, AWS, and all regulated companies do this. Without automation, compliance = expensive manual work; with automation, compliance = evidence flowing continuously to audit systems.

!!! info "Background Context"
    Phase 2 m4 taught CloudTrail basics. Phase 4 m11-week1 taught Config rules. This expansion ties them together: CloudTrail (what happened) + Config (what exists) + Athena (analysis) + Lambda (remediation) = continuous compliance proof.

---

## Part 1: CloudTrail Deep Dive — Audit Trail Foundation

CloudTrail records **every API call** made to AWS. It's your forensic evidence log.

### CloudTrail Setup for Compliance

```bash
# Enable CloudTrail across all regions
aws cloudtrail create-trail \
  --name iron-bank-compliance-trail \
  --s3-bucket-name iron-bank-cloudtrail-logs \
  --is-multi-region-trail \
  --is-organization-trail  # Logs all accounts in organization
  --enable-log-file-validation  # Detect tampering

# Start logging
aws cloudtrail start-logging \
  --trail-name iron-bank-compliance-trail

# Verify logging
aws cloudtrail get-trail-status \
  --trail-name iron-bank-compliance-trail

# Output:
# {
#   "IsLogging": true,
#   "LatestDeliveryTime": "2024-01-15T14:30:00Z",
#   "S3BucketName": "iron-bank-cloudtrail-logs",
#   "CloudTrailARN": "arn:aws:cloudtrail:us-east-1:ACCOUNT:trail/iron-bank-compliance-trail"
# }
```

### CloudTrail Event Analysis

```bash
# Query CloudTrail logs with Athena (SQL-based analysis)

# Step 1: Create Athena table from CloudTrail logs
aws athena start-query-execution \
  --query-string "
    CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail_logs (
      eventVersion STRING,
      userIdentity STRUCT<
        type:STRING,
        principalId:STRING,
        arn:STRING,
        accountId:STRING,
        invokeIdTime:STRING,
        accessKeyId:STRING,
        userName:STRING>,
      eventTime STRING,
      eventSource STRING,
      eventName STRING,
      awsRegion STRING,
      sourceIPAddress STRING,
      userAgent STRING,
      errorCode STRING,
      errorMessage STRING,
      requestParameters STRING,
      responseElements STRING,
      additionalEventData STRING,
      requestId STRING,
      eventId STRING,
      resources ARRAY<STRUCT<
        arn:STRING,
        accountId:STRING,
        type:STRING>>,
      eventType STRING,
      recipientAccountId STRING,
      sharedEventID STRING,
      vpcEndpointId STRING
    )
    PARTITIONED BY (region STRING, year STRING, month STRING, day STRING)
    ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
    STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
    OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
    LOCATION 's3://iron-bank-cloudtrail-logs/AWSLogs/'
  " \
  --query-execution-context Database=default \
  --result-configuration OutputLocation=s3://athena-results/

# Step 2: Query for security-relevant events
aws athena start-query-execution \
  --query-string "
    SELECT
      eventTime,
      userIdentity.principalId,
      eventName,
      sourceIPAddress,
      requestParameters,
      errorCode
    FROM cloudtrail_logs
    WHERE eventName IN (
      'CreateSecurityGroup',
      'AuthorizeSecurityGroupIngress',
      'ModifyDBInstance',
      'CreateDBInstance',
      'DeleteBucket',
      'PutBucketAcl'
    )
    AND eventTime >= '2024-01-01'
    ORDER BY eventTime DESC
  " \
  --query-execution-context Database=default \
  --result-configuration OutputLocation=s3://athena-results/
```

### Detecting Unauthorized Access (Compliance Evidence)

```bash
# Query for failed authentication attempts (PCI-DSS requirement)
aws athena start-query-execution \
  --query-string "
    SELECT
      eventTime,
      userIdentity.principalId,
      sourceIPAddress,
      errorCode,
      errorMessage,
      COUNT(*) as attempt_count
    FROM cloudtrail_logs
    WHERE errorCode IN ('UnauthorizedOperation', 'AccessDenied', 'InvalidParameterValue')
    AND eventTime >= date_format(current_timestamp - interval '7' day, '%Y-%m-%dT%H:%i:%SZ')
    GROUP BY
      eventTime,
      userIdentity.principalId,
      sourceIPAddress,
      errorCode,
      errorMessage
    HAVING COUNT(*) > 5  -- Alert if >5 failures from same IP
    ORDER BY eventTime DESC
  " \
  --query-execution-context Database=default \
  --result-configuration OutputLocation=s3://athena-results/
```

---

## Part 2: AWS Config Rules for Continuous Compliance

Config tracks resource **configuration state** (what exists, how it's configured).

### PCI-DSS Compliance Config Rules

```bash
# Rule 1: Require encryption for all RDS instances
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "rds-encryption-enabled",
    "Description": "Checks that RDS instances have encryption enabled (PCI-DSS 3.4)",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "RDS_STORAGE_ENCRYPTED"
    },
    "Scope": {
      "ComplianceResourceTypes": ["AWS::RDS::DBInstance"]
    }
  }'

# Rule 2: Ensure S3 buckets block public access
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "s3-block-public-access",
    "Description": "Ensures S3 Block Public Access is enabled (PCI-DSS 1.3)",
    "Source": {
      "Owner": "CUSTOM_LAMBDA",
      "SourceIdentifier": "arn:aws:lambda:us-east-1:ACCOUNT:function:s3-block-public-check",
      "SourceDetails": [{
        "EventSource": "aws.config",
        "MessageType": "ConfigurationItemChangeNotification"
      }]
    }
  }'

# Rule 3: Ensure CloudTrail is enabled and logging
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "cloudtrail-enabled",
    "Description": "Ensures CloudTrail is enabled (HIPAA, PCI-DSS, SOC2)",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "CLOUD_TRAIL_ENABLED"
    }
  }'

# Rule 4: Require VPC Flow Logs on all VPCs
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "vpc-flow-logs-enabled",
    "Description": "Ensures VPC Flow Logs are enabled (ISO 27001 A.13.2.3)",
    "Source": {
      "Owner": "CUSTOM_LAMBDA",
      "SourceIdentifier": "arn:aws:lambda:us-east-1:ACCOUNT:function:vpc-flow-logs-check"
    }
  }'

# Rule 5: Enforce MFA for all users
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "mfa-enabled-for-iam-console-access",
    "Description": "Ensures MFA enabled for all IAM users (PCI-DSS 8.3.4)",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
    }
  }'
```

### Check Compliance Status

```bash
# Get compliance aggregator dashboard
aws configservice describe-compliance-by-config-rule \
  --query 'ComplianceByConfigRules[*].[ConfigRuleName,Compliance.ComplianceType]' \
  --output table

# Output:
# ───────────────────────────────────────────────
# ConfigRuleName              ComplianceType
# ───────────────────────────────────────────────
# rds-encryption-enabled      COMPLIANT       ✅
# s3-block-public-access      COMPLIANT       ✅
# cloudtrail-enabled          COMPLIANT       ✅
# vpc-flow-logs-enabled       NON_COMPLIANT   ❌
# mfa-enabled-for-iam-console COMPLIANT       ✅
# ───────────────────────────────────────────────

# Get non-compliant resources
aws configservice list-non-compliant-resources \
  --query 'NonCompliantResources' \
  --output table
```

---

## Part 3: Automated Remediation with Lambda

When Config detects non-compliance, Lambda can auto-fix it.

```python
# Lambda function: Auto-enable S3 Block Public Access

import boto3
import json

s3 = boto3.client('s3')

def lambda_handler(event, context):
    """
    Auto-remediate: If S3 bucket doesn't have Block Public Access enabled,
    enable it automatically
    """
    
    # Parse Config change notification
    config_item = json.loads(event['configurationItem'])
    bucket_name = config_item['resourceName']
    
    print(f"Remediating bucket: {bucket_name}")
    
    try:
        # Enable Block Public Access
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        print(f"✅ Bucket {bucket_name} now has Block Public Access enabled")
        
        # Report to Config as remediated
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Remediated {bucket_name}',
                'action': 'PutPublicAccessBlock'
            })
        }
        
    except Exception as e:
        print(f"❌ Error remediating {bucket_name}: {str(e)}")
        
        # Send alert to security team
        sns = boto3.client('sns')
        sns.publish(
            TopicArn='arn:aws:sns:us-east-1:ACCOUNT:security-alerts',
            Subject=f'S3 Auto-Remediation Failed: {bucket_name}',
            Message=f'Failed to enable Block Public Access on {bucket_name}. Manual intervention required.\n\nError: {str(e)}'
        )
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }
```

### Config Remediation Action

```bash
# Create Config Remediation Action to trigger Lambda
aws configservice put-remediation-configs \
  --remediation-configs '[
    {
      "ConfigRuleName": "s3-block-public-access",
      "TargetType": "SSM_DOCUMENT",
      "TargetIdentifier": "AWS-PublishSNSMessage",
      "TargetVersion": "1",
      "Parameters": {
        "AutomationAssumeRole": {
          "StaticValue": {
            "Values": ["arn:aws:iam::ACCOUNT:role/ConfigRemediation"]
          }
        },
        "TopicArn": {
          "StaticValue": {
            "Values": ["arn:aws:sns:us-east-1:ACCOUNT:compliance-remediation"]
          }
        },
        "Message": {
          "StaticValue": {
            "Values": ["S3 bucket {{ResourceId}} requires Block Public Access"]
          }
        }
      },
      "Automatic": true,
      "MaximumAutomaticAttempts": 10,
      "AutomationAssumeRole": "arn:aws:iam::ACCOUNT:role/ConfigRemediation"
    }
  ]'

# Now whenever a resource becomes non-compliant,
# Config automatically triggers remediation
```

---

## Part 4: Compliance Reporting Dashboard

Generate evidence for auditors automatically.

```bash
# Create CloudWatch Dashboard for compliance metrics
cat > compliance-dashboard.json << 'EOF'
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/Config", "ComplianceScore", {"stat": "Average"}],
          [".", "NonCompliantResources", {"stat": "Sum"}]
        ],
        "period": 300,
        "stat": "Average",
        "region": "us-east-1",
        "title": "Compliance Overview"
      }
    },
    {
      "type": "log",
      "properties": {
        "query": "fields @timestamp, eventName, errorCode | filter errorCode like /Unauthorized|AccessDenied/ | stats count() as failures by eventName",
        "region": "us-east-1",
        "title": "Failed Authorization Attempts (Security)"
      }
    },
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/Config", "RuleEvaluations"],
          [".", "ComplianceFailures"]
        ],
        "title": "Config Rule Evaluations"
      }
    }
  ]
}
EOF

# Create the dashboard
aws cloudwatch put-dashboard \
  --dashboard-name ComplianceDashboard \
  --dashboard-body file://compliance-dashboard.json
```

### Automated Compliance Reports

```python
# Lambda: Generate compliance report for PCI-DSS audit

import boto3
from datetime import datetime, timedelta
import json

config = boto3.client('config')
athena = boto3.client('athena')
s3 = boto3.client('s3')

def lambda_handler(event, context):
    """
    Generate PCI-DSS compliance report
    Executed weekly via EventBridge
    """
    
    # Get compliance summary
    compliance = config.describe_compliance_by_config_rule()
    
    report = {
        'report_date': datetime.now().isoformat(),
        'compliance_summary': {
            'compliant': 0,
            'non_compliant': 0,
            'rules': []
        },
        'pci_dss_findings': {
            'requirement_1': [],  # Firewall configuration
            'requirement_2': [],  # Default passwords
            'requirement_3': [],  # Cardholder data protection
            'requirement_4': [],  # Encryption in transit
            # ... etc
        },
        'remediation_actions': []
    }
    
    for rule in compliance['ComplianceByConfigRules']:
        rule_name = rule['ConfigRuleName']
        compliance_type = rule['Compliance']['ComplianceType']
        
        if compliance_type == 'COMPLIANT':
            report['compliance_summary']['compliant'] += 1
        else:
            report['compliance_summary']['non_compliant'] += 1
            report['compliance_summary']['rules'].append(rule_name)
    
    # Query CloudTrail for security events
    query = """
        SELECT
          eventTime,
          eventName,
          userIdentity.arn,
          sourceIPAddress,
          COUNT(*) as count
        FROM cloudtrail_logs
        WHERE eventTime >= date_format(current_timestamp - interval '7' day, '%Y-%m-%dT%H:%i:%SZ')
        AND eventName IN (
          'CreateSecurityGroup',
          'AuthorizeSecurityGroupIngress',
          'ModifyDBInstance',
          'DeleteBucket'
        )
        GROUP BY eventTime, eventName, userIdentity.arn, sourceIPAddress
        ORDER BY eventTime DESC
    """
    
    # Execute Athena query
    response = athena.start_query_execution(
        QueryString=query,
        QueryExecutionContext={'Database': 'default'},
        ResultConfiguration={'OutputLocation': 's3://athena-results/'}
    )
    
    # Save report
    s3.put_object(
        Bucket='compliance-reports',
        Key=f"pci-dss/report-{datetime.now().strftime('%Y-%m-%d')}.json",
        Body=json.dumps(report, indent=2)
    )
    
    print(f"✅ Compliance report generated: {report['compliance_summary']}")
    
    return {
        'statusCode': 200,
        'body': json.dumps(report)
    }
```

---

## Part 5: SIEM Integration (Splunk, Datadog)

Send logs to third-party SIEM for advanced correlation:

```yaml
# EventBridge rule: Forward CloudTrail logs to Splunk

Name: forward-to-splunk
EventBusName: default
EventPattern:
  source:
    - aws.cloudtrail
  detail-type:
    - AWS API Call via CloudTrail

Targets:
  - Arn: "arn:aws:lambda:us-east-1:ACCOUNT:function:send-to-splunk"
    RoleArn: "arn:aws:iam::ACCOUNT:role/EventBridgeRole"
  - Arn: "arn:aws:logs:us-east-1:ACCOUNT:destination:splunk-http"
    RoleArn: "arn:aws:iam::ACCOUNT:role/EventBridgeRole"
    HttpParameters:
      PathParameterValues: []
      HeaderParameters:
        Authorization: "Bearer ${{ secrets.SPLUNK_HEC_TOKEN }}"
      QueryStringParameters: {}
```

---

## Part 6: Write a Compliance Finding

```bash
cat > ~/compliance-finding.md << 'EOF'
# Finding: No Continuous Compliance Monitoring — Breaches Detected Too Late

**Severity:** Critical  
**Component:** Compliance & Audit (Monitoring)  

## Description
Compliance checks happen quarterly during manual audits. Unencrypted databases, 
public S3 buckets, and disabled CloudTrail exist in production for months undetected.

## Compliance Impact
- PCI-DSS 10.1: "Maintain audit trail of all system components"
  Status: FAILING (no continuous logging)
- HIPAA: "Audit logging required for all ePHI access"
  Status: FAILING (no real-time detection)
- SOC2: "Security incidents detected within 24 hours"
  Status: FAILING (detected in quarterly audits)

## Remediation
1. **Enable CloudTrail:** Multi-region, organization-wide logging
2. **Create Config rules:** For each compliance requirement (10+ rules)
3. **Setup auto-remediation:** Lambda functions fix non-compliance
4. **Generate reports:** Weekly dashboard for management
5. **SIEM integration:** Real-time alerting (Splunk, Datadog)

## Effort
- Initial: 40 hours (setup CloudTrail, Config rules, Lambda, reporting)
- Ongoing: 5 hours/month (rule tuning, report review)

## Result
- Detection time: 3 months → 5 minutes
- Compliance status: Unknown → Always visible
- Audit prep time: 80 hours → 1 hour (data already collected)
EOF

cat ~/compliance-finding.md
```

---

## 🧹 Cleanup

```bash
rm -f ~/compliance-finding.md
rm -f compliance-dashboard.json

echo "✅ Continuous Compliance lab cleaned up"
```

---

## Checklist

**CloudTrail Deep Dive**
- [ ] Enabled CloudTrail across all regions
- [ ] Configured organization trail (logs all accounts)
- [ ] Enabled log file validation (detect tampering)
- [ ] Created Athena table for CloudTrail analysis
- [ ] Can query CloudTrail for security events

**Config Rules for Compliance**
- [ ] Created Config rules for PCI-DSS requirements
- [ ] Know difference between AWS-managed and custom rules
- [ ] Can check compliance status across resources
- [ ] Understand remediation actions
- [ ] Can map rules to compliance frameworks

**Automated Remediation**
- [ ] Can write Lambda remediation functions
- [ ] Understand Config Remediation Actions
- [ ] Know auto-remediation safety (automatic vs. manual approval)
- [ ] Can test remediation in non-prod first

**Compliance Reporting**
- [ ] Can generate CloudWatch compliance dashboards
- [ ] Can query CloudTrail with Athena for audit reports
- [ ] Know what evidence auditors need
- [ ] Can export reports to compliance systems

**SIEM Integration**
- [ ] Know Splunk, Datadog, ELK as SIEM options
- [ ] Can configure EventBridge forwarding
- [ ] Understand log aggregation benefits
- [ ] Know retention policies (7 years for PCI-DSS)

**Production Readiness**
- [ ] CloudTrail enabled and logging
- [ ] Log retention configured (per compliance)
- [ ] Config rules cover all compliance requirements
- [ ] Auto-remediation tested and approved
- [ ] Compliance reports sent to stakeholders weekly
- [ ] Audit trail monitored and alerted

---

## Integration with Phase 4

This Continuous Compliance expansion strengthens:
- **Phase 4 m11-week1:** Config rules now fully automated
- **Phase 4 m11-week2:** SCPs + Config rules + Athena = complete governance
- **Phase 4 m12-week3:** IR uses CloudTrail logs for forensics

---

## Compliance Framework Coverage

After implementing this expansion:

| Framework | Coverage | Evidence |
|---|---|---|
| **PCI-DSS** | 8/12 requirements | CloudTrail, Config, encrypted databases |
| **HIPAA** | 6/10 requirements | Audit logging, access controls, encryption |
| **SOC2** | 9/15 criteria | Continuous monitoring, alerting, reports |
| **ISO 27001** | 12/35 controls | Logging, incident detection, documentation |

You now have **continuous compliance automation**. Auditors will be impressed. 🎓
