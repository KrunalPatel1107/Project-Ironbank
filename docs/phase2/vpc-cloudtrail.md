# Month 4 — Week 1: VPC & CloudTrail

!!! danger "💰 Cost"
    VPC, Subnets, Route Tables, IGW, Security Groups, CloudTrail (1 trail) = **FREE**. NAT Gateway ($32/mo) is NOT created until Week 3 — don't jump ahead.

!!! info "Background Context"
    VPC Security Groups = Azure NSGs. CloudTrail = Azure Activity Log. If you've done SOC or incident response work, you already know these concepts — this week you build the AWS equivalent.

## Build a VPC from Scratch

```bash
# Step 1: Create the VPC
VPC_ID=$(aws ec2 create-vpc \
  --cidr-block 10.0.0.0/16 \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=Iron-Bank-VPC}]' \
  --profile iron-bank \
  --query Vpc.VpcId --output text)
echo "VPC: $VPC_ID"
# 10.0.0.0/16 = 65,536 IPs. /16 means first 2 octets fixed.

# Step 2: Enable DNS
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames --profile iron-bank

# Step 3: Public subnet
PUB=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID --cidr-block 10.0.1.0/24 --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=Public-1a}]' \
  --profile iron-bank --query Subnet.SubnetId --output text)

# Step 4: Private subnet
PRIV=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID --cidr-block 10.0.2.0/24 --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=Private-1a}]' \
  --profile iron-bank --query Subnet.SubnetId --output text)

# Step 5: Internet Gateway
IGW=$(aws ec2 create-internet-gateway --profile iron-bank \
  --query InternetGateway.InternetGatewayId --output text)
aws ec2 attach-internet-gateway --internet-gateway-id $IGW --vpc-id $VPC_ID --profile iron-bank

# Step 6: Route table for public subnet
RT=$(aws ec2 create-route-table --vpc-id $VPC_ID --profile iron-bank \
  --query RouteTable.RouteTableId --output text)
aws ec2 create-route --route-table-id $RT --destination-cidr-block 0.0.0.0/0 \
  --gateway-id $IGW --profile iron-bank
aws ec2 associate-route-table --route-table-id $RT --subnet-id $PUB --profile iron-bank

# Step 7: Security Group
MY_IP=$(curl -s https://checkip.amazonaws.com)
SG=$(aws ec2 create-security-group --group-name web-sg --description "Web SG" \
  --vpc-id $VPC_ID --profile iron-bank --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id $SG \
  --protocol tcp --port 22 --cidr ${MY_IP}/32 --profile iron-bank

echo "SAVE THESE: VPC=$VPC_ID PUB=$PUB PRIV=$PRIV IGW=$IGW RT=$RT SG=$SG"
```

## 🧹 Cleanup

```bash
aws ec2 delete-security-group --group-id $SG --profile iron-bank
aws ec2 delete-subnet --subnet-id $PUB --profile iron-bank
aws ec2 delete-subnet --subnet-id $PRIV --profile iron-bank
aws ec2 delete-route-table --route-table-id $RT --profile iron-bank
aws ec2 detach-internet-gateway --internet-gateway-id $IGW --vpc-id $VPC_ID --profile iron-bank
aws ec2 delete-internet-gateway --internet-gateway-id $IGW --profile iron-bank
aws ec2 delete-vpc --vpc-id $VPC_ID --profile iron-bank
echo "✅ All VPC resources deleted"
```

!!! tip "If cleanup commands fail"
    AWS Console → VPC → Your VPCs → select → Actions → Delete VPC. The console handles dependency order for you.

## Checklist

- [ ] Created VPC with public + private subnets
- [ ] Created IGW and Route Table
- [ ] Created Security Group (SSH from your IP only)
- [ ] Understand CIDR notation ([cidr.xyz](https://cidr.xyz/))
- [ ] **All resources cleaned up**
- [ ] Verified $0 in Billing

---

# Part 2: CloudTrail Forensics & Log Analysis

!!! abstract "New in Month 4"
    CloudTrail logs every API call made in your account. This section teaches you to **read those logs forensically** — to detect lateral movement, unauthorized access, and reconstruct timelines during incident investigations.

!!! info "Why Forensics Matter"
    If you've worked in a SOC or done incident response, you already know that **logs are evidence**. In the cloud, CloudTrail is your primary evidence source. Learning to analyze CloudTrail logs is critical for detecting compromises and answering "Who accessed what, when, and did they modify anything?"

---

## Forensics Concept 1: Understanding CloudTrail Logs

**CloudTrail** records every AWS API call with:
- **Who**: Principal (IAM user, role, AWS service)
- **What**: API action (e.g., `CreateSecurityGroup`, `ModifyDBInstance`)
- **When**: Timestamp (UTC)
- **Where**: Source IP, User-Agent
- **Result**: Success/Failure, error message
- **Resources**: What resource was modified (e.g., `sg-12345`)

Each log entry is a JSON object delivered to an S3 bucket.

### Sample CloudTrail Log Entry

```json
{
  "eventVersion": "1.07",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAI23HZFYTQ5UXB7LCE",
    "arn": "arn:aws:iam::123456789012:user/alice",
    "accountId": "123456789012",
    "userName": "alice",
    "invokeBy": "signin.amazonaws.com"
  },
  "eventTime": "2026-04-15T14:23:45Z",
  "eventSource": "ec2.amazonaws.com",
  "eventName": "ModifySecurityGroupIngress",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.45",
  "userAgent": "aws-cli/2.15.0",
  "requestParameters": {
    "groupId": "sg-0a1b2c3d4e5f67g8h",
    "ipPermissions": [
      {
        "ipProtocol": "tcp",
        "fromPort": 3306,
        "toPort": 3306,
        "ipRanges": [
          {
            "cidrIp": "0.0.0.0/0",
            "description": "Allow RDS from anywhere"
          }
        ]
      }
    ]
  },
  "responseElements": {
    "return": true
  },
  "requestId": "a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6",
  "eventID": "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p",
  "eventType": "AwsApiCall",
  "recipientAccountId": "123456789012"
}
```

**Reading this log:**
- **alice** (IAM user) at **14:23:45 UTC** from IP **203.0.113.45** modified Security Group **sg-0a1b2c3d4e5f67g8h**
- **Action**: Added inbound rule allowing TCP port 3306 (RDS/MySQL) from **0.0.0.0/0** (anywhere)
- **Risk**: RDS is now exposed to the internet — potential for credential theft if database is compromised
- **Question for investigation**: Did alice intend to open RDS to the internet? Is this authorized?

---

## Forensics Concept 2: Timeline Reconstruction

In an incident, you need to answer: "What happened, in what order?"

### Example Scenario: Unauthorized S3 Access

```
14:15 - alice logs into AWS console from 203.0.113.45
14:16 - alice creates new IAM user "service-account"
14:17 - alice attaches AdministratorAccess policy to "service-account"
14:18 - "service-account" creates access key
14:19 - access key used from 198.51.100.10 (different IP, different country)
14:20 - 198.51.100.10 lists all S3 buckets
14:21 - 198.51.100.10 downloads 500GB of data from "customer-pii-bucket"
14:22 - 198.51.100.10 creates new IAM policy to hide tracks (modifies CloudTrail config)
14:23 - S3 bucket deleted (attempt to hide evidence)
```

**Timeline tells the story**: alice's account was either compromised or malicious. The attacker:
1. Created a backdoor user
2. Used that user from a different location
3. Exfiltrated data
4. Tried to cover tracks

---

## Forensics Concept 3: Lateral Movement Detection

**Lateral movement** = Attacker goes from one resource to another (e.g., EC2 → RDS, user → admin).

### Indicators of Lateral Movement in CloudTrail

```
// Red flag 1: Unexpected AssumeRole call
{
  "eventName": "AssumeRole",
  "userIdentity": {
    "principalId": "AIDA...",  // EC2 instance role
    "arn": "arn:aws:iam::123456789012:role/ec2-instance-role"
  },
  "requestParameters": {
    "roleArn": "arn:aws:iam::123456789012:role/AdminRole",  // Jumping to admin role!
    "roleSessionName": "malicious-session"
  },
  "sourceIPAddress": "10.0.2.5"  // Internal IP — EC2 inside VPC
}

// Red flag 2: Credential theft (access key created, used immediately from different IP)
{
  "eventName": "CreateAccessKey",
  "userIdentity": { "principalId": "AIDAI..." }
}

// Minutes later, from different IP:
{
  "eventName": "ListBuckets",
  "userIdentity": { "principalId": "AIDAI..." },  // Same access key created above
  "sourceIPAddress": "203.0.113.100"  // DIFFERENT IP from creation
}
```

---

## Forensics Lab 1: Enable CloudTrail & Capture Logs

### Step 1: Create S3 Bucket for Logs

```bash
# Create bucket (CloudTrail logs go here)
TRAIL_BUCKET="iron-bank-cloudtrail-logs-$(date +%s)"
aws s3api create-bucket \
  --bucket $TRAIL_BUCKET \
  --region us-east-1 \
  --profile iron-bank

# Enable versioning (so attacker can't delete versions to hide evidence)
aws s3api put-bucket-versioning \
  --bucket $TRAIL_BUCKET \
  --versioning-configuration Status=Enabled \
  --profile iron-bank

# Block public access (so logs aren't exposed)
aws s3api put-public-access-block \
  --bucket $TRAIL_BUCKET \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --profile iron-bank

echo "Bucket created: $TRAIL_BUCKET"
```

### Step 2: Create CloudTrail Trail

```bash
# Create the trail (logs all API calls in this region)
TRAIL_NAME="iron-bank-trail"

aws cloudtrail create-trail \
  --name $TRAIL_NAME \
  --s3-bucket-name $TRAIL_BUCKET \
  --region us-east-1 \
  --profile iron-bank

# Start logging
aws cloudtrail start-logging \
  --name $TRAIL_NAME \
  --profile iron-bank

echo "Trail created and logging started: $TRAIL_NAME"

# Verify it's running
aws cloudtrail describe-trails \
  --trail-name-list $TRAIL_NAME \
  --profile iron-bank
```

### Step 3: Generate Test Events

```bash
# This command will be logged by CloudTrail
aws ec2 describe-instances --profile iron-bank

# This will also be logged
aws s3api list-buckets --profile iron-bank

# Wait 2 minutes for logs to deliver to S3
sleep 120

# List the logs S3 delivered
aws s3 ls s3://$TRAIL_BUCKET --recursive --profile iron-bank
```

!!! tip "CloudTrail Delivery Delay"
    CloudTrail typically delivers logs **within 15 minutes**. For labs, wait 2–5 minutes before checking.

---

## Forensics Lab 2: Analyze Logs (JSON Parsing)

### Step 1: Download Logs from S3

```bash
# Create local directory
mkdir -p cloudtrail-logs

# Download all trail logs
aws s3 sync s3://$TRAIL_BUCKET cloudtrail-logs/ --profile iron-bank

# CloudTrail compresses logs as gzip JSON
# Decompress them
cd cloudtrail-logs
find . -name "*.gz" -exec gunzip {} \;
cd ..

# Now you have JSON files
ls -lh cloudtrail-logs/
```

### Step 2: Parse CloudTrail Logs (Python Script)

Create a file `scripts/analyze-cloudtrail.py`:

```python
#!/usr/bin/env python3
"""
CloudTrail Log Analyzer
Parses CloudTrail logs from S3 and extracts key forensic indicators.

Why this matters:
  - CloudTrail logs are compressed JSON files in S3
  - Each file contains multiple events
  - Manual parsing is tedious and error-prone
  - This script automates the extraction of suspicious patterns

Author: Iron Bank Training
"""

import json
import gzip
import os
import sys
from pathlib import Path
from datetime import datetime

def analyze_cloudtrail_logs(log_dir: str):
    """
    Read CloudTrail logs and extract key events.
    
    Args:
        log_dir: Directory containing CloudTrail log files
    
    Returns:
        None (prints to stdout)
    """
    
    # List of dangerous API calls to flag
    suspicious_actions = {
        "CreateAccessKey",        # Creating backdoor credential
        "CreateUser",             # Creating new admin user
        "AttachUserPolicy",       # Adding permissions to user
        "ModifySecurityGroupIngress",  # Opening network access
        "ModifyDBInstance",       # Tampering with database
        "DeleteTrail",            # Hiding evidence
        "StopLogging",            # Disabling logs
        "DisableLogging",         # Disabling logs
        "PutBucketPolicy",        # Modifying access controls
        "AssumeRole",             # Privilege escalation
        "GetSecretValue",         # Accessing secrets
    }
    
    # Statistics
    total_events = 0
    suspicious_count = 0
    errors = 0
    
    # Track access keys created (for later use from different IP)
    keys_created = []
    keys_used = []
    
    log_path = Path(log_dir)
    
    # Find all JSON files (CloudTrail logs)
    for json_file in log_path.glob("**/*.json"):
        print(f"\n[*] Reading {json_file.name}...")
        
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            # CloudTrail format: { "Records": [ {...}, {...}, ... ] }
            events = data.get("Records", [])
            
            for event in events:
                total_events += 1
                
                event_name = event.get("eventName", "UNKNOWN")
                event_time = event.get("eventTime", "UNKNOWN")
                user_identity = event.get("userIdentity", {})
                principal = user_identity.get("principalId", "UNKNOWN")
                source_ip = event.get("sourceIPAddress", "UNKNOWN")
                
                # Flag suspicious events
                if event_name in suspicious_actions:
                    suspicious_count += 1
                    print(f"\n  ⚠️  SUSPICIOUS: {event_name}")
                    print(f"      Principal: {principal}")
                    print(f"      Time: {event_time}")
                    print(f"      Source IP: {source_ip}")
                    
                    # Additional details
                    if event_name == "CreateAccessKey":
                        response = event.get("responseElements", {})
                        access_key = response.get("accessKey", {})
                        keys_created.append({
                            "AccessKeyId": access_key.get("accessKeyId"),
                            "Principal": principal,
                            "Time": event_time
                        })
                        print(f"      New Access Key: {access_key.get('accessKeyId')}")
                    
                    elif event_name == "AssumeRole":
                        request = event.get("requestParameters", {})
                        target_role = request.get("roleArn", "UNKNOWN")
                        print(f"      Target Role: {target_role}")
                        print(f"      ⚠️  LATERAL MOVE DETECTED")
                    
                    elif event_name in ["ModifySecurityGroupIngress", "ModifySecurityGroupEgress"]:
                        request = event.get("requestParameters", {})
                        sg_id = request.get("groupId", "UNKNOWN")
                        print(f"      Security Group: {sg_id}")
                        print(f"      ⚠️  NETWORK RULE MODIFIED")
                
                # Track access key usage
                try:
                    if user_identity.get("type") == "AssumedRole":
                        # Access key ID is in the principalId after the colon
                        access_key_part = principal.split(":")[-1]
                        if len(access_key_part) == 20 and access_key_part.startswith("AKIA"):
                            keys_used.append({
                                "AccessKeyId": access_key_part,
                                "Time": event_time,
                                "SourceIP": source_ip,
                                "Action": event_name
                            })
                except:
                    pass
        
        except json.JSONDecodeError as e:
            print(f"  ❌ ERROR reading {json_file}: {e}")
            errors += 1
        except Exception as e:
            print(f"  ❌ ERROR: {e}")
            errors += 1
    
    # Summary
    print(f"\n\n{'='*60}")
    print(f"FORENSICS SUMMARY")
    print(f"{'='*60}")
    print(f"Total events analyzed: {total_events}")
    print(f"Suspicious events flagged: {suspicious_count}")
    print(f"Parse errors: {errors}")
    
    # Check for access key reuse from different IPs
    if keys_created and keys_used:
        print(f"\n{'='*60}")
        print(f"ACCESS KEY CREATION → USAGE TIMELINE")
        print(f"{'='*60}")
        print("(Suspicious if key created in US, used 5 minutes later in China)")
    
    print(f"\n{'='*60}")
    print(f"RECOMMENDATIONS")
    print(f"{'='*60}")
    if suspicious_count > 0:
        print("⚠️  HIGH-PRIORITY ACTIONS:")
        print("  1. Review each suspicious event in AWS Console")
        print("  2. Check if actions were authorized")
        print("  3. Revoke unauthorized credentials (DeleteAccessKey, DetachPolicy)")
        print("  4. Implement SCPs to restrict dangerous actions (see Month 6)")
        print("  5. Enable GuardDuty (Month 6) for anomaly detection")
    else:
        print("✅ No suspicious events detected in this timeframe")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze-cloudtrail.py <log_directory>")
        print("Example: python analyze-cloudtrail.py ./cloudtrail-logs")
        sys.exit(1)
    
    log_dir = sys.argv[1]
    
    if not os.path.isdir(log_dir):
        print(f"Error: Directory {log_dir} not found")
        sys.exit(1)
    
    analyze_cloudtrail_logs(log_dir)
```

### Step 3: Run the Analysis

```bash
# Make script executable
chmod +x scripts/analyze-cloudtrail.py

# Run analysis
python3 scripts/analyze-cloudtrail.py cloudtrail-logs/

# Expected output:
# ✅ Total events analyzed: 12
# ✅ Suspicious events flagged: 0 (unless you did something risky)
# ✅ Parse errors: 0
```

---

## Forensics Lab 3: Detect Lateral Movement

### Scenario: Simulating a Compromised EC2 Instance

```bash
# Step 1: Create an EC2 instance (don't actually do this yet—for planning)
# This instance will have an IAM role

# Step 2: EC2 instance assumes a role with higher privileges
# CloudTrail logs the AssumeRole call from EC2's internal IP

# Step 3: Analysis shows:
#   - AssumeRole called from 10.0.2.5 (private IP = EC2 inside VPC)
#   - Target role = AdminRole
#   - Result = Success
#   ⚠️  LATERAL MOVEMENT DETECTED

# Step 4: Revoke the role immediately
aws iam delete-role-policy \
  --role-name ec2-instance-role \
  --policy-name AdminAccess \
  --profile iron-bank
```

---

## 🧹 Cleanup

```bash
# Stop logging
aws cloudtrail stop-logging --name $TRAIL_NAME --profile iron-bank

# Delete the trail
aws cloudtrail delete-trail --name $TRAIL_NAME --profile iron-bank

# Delete the S3 bucket
aws s3 rm s3://$TRAIL_BUCKET --recursive --profile iron-bank
aws s3api delete-bucket --bucket $TRAIL_BUCKET --profile iron-bank

# Clean up local logs
rm -rf cloudtrail-logs/

echo "✅ CloudTrail cleanup complete"
```

---

## Checklist (Forensics Extension)

- [ ] Understand CloudTrail log structure (JSON format)
- [ ] Created CloudTrail trail and S3 bucket
- [ ] Generated test events (describe-instances, list-buckets)
- [ ] Downloaded logs from S3
- [ ] Ran Python forensics script on logs
- [ ] Identified at least one suspicious action
- [ ] Understand timeline reconstruction technique
- [ ] Understand lateral movement detection
- [ ] **All resources cleaned up**

---

## Next: Week 2 — Subnets & Routing

Now that you understand your threat model and can read audit logs, you're ready to design a multi-tier network architecture.

**↓ Next: [Week 2: Subnets & Routing](subnets-routing.md)**
