# Project: VPC Flow Logs Analyzer

!!! danger "💰 Cost Warning"
    VPC Flow Logs to **CloudWatch Logs** cost ~$0.50/GB ingested. For this lab, you'll generate minimal traffic — expect **< $0.01**.
    Flow logs to **S3** are cheaper for long-term storage but harder to query — we use CloudWatch here.
    **Clean up the CloudWatch Log Group when done** — retained logs cost $0.03/GB/month.

!!! info "If you know Azure or Sentinel"
    VPC Flow Logs = Azure NSG Flow Logs / Azure Network Watcher. If you've built KQL queries in Sentinel against network logs, this week you build the AWS equivalent — reading flow log entries and writing a Python analyzer. The analysis skills transfer directly.

---

## What Are VPC Flow Logs?

Flow Logs capture **metadata** about network traffic in your VPC. They do **not** capture packet contents — just the connection details:

```
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
```

Example log entry:
```
2 123456789012 eni-abc12345 10.0.1.5 10.0.2.10 54321 22 6 10 840 1680000000 1680000060 ACCEPT OK
```

Breaking that down:
- `10.0.1.5` → `10.0.2.10` — source to destination IP
- `54321` → `22` — source port to destination port (port 22 = SSH)
- Protocol `6` = TCP
- `ACCEPT` — Security Group allowed this connection
- `REJECT` would mean a Security Group or NACL blocked it

!!! tip "Security Use Cases"
    - Detect port scans (many rejected connections from one source)
    - Find unexpected outbound connections (data exfiltration indicators)
    - Confirm Security Group rules are working as expected
    - Satisfy compliance requirements (PCI-DSS, SOC 2 require network logging)

---

## Part 1: Rebuild the VPC and Enable Flow Logs

```bash
# ─── Step 1: Recreate the VPC (if cleaned up after Week 3) ───────────────────
VPC_ID=$(aws ec2 create-vpc \
  --cidr-block 10.0.0.0/16 \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=Iron-Bank-VPC}]' \
  --profile iron-bank \
  --query Vpc.VpcId --output text)
echo "VPC: $VPC_ID"

# ─── Step 2: Create an IAM role for Flow Logs to write to CloudWatch ─────────
# Flow Logs needs permission to write to your CloudWatch log group
# First, create the trust policy — this says "allow the Flow Logs service to assume this role"
cat > /tmp/flow-logs-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Create the IAM role
ROLE_ARN=$(aws iam create-role \
  --role-name Iron-Bank-FlowLogs-Role \
  --assume-role-policy-document file:///tmp/flow-logs-trust.json \
  --profile iron-bank \
  --query Role.Arn --output text)
echo "Role ARN: $ROLE_ARN"

# Attach the policy that allows writing to CloudWatch Logs
cat > /tmp/flow-logs-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Resource": "*"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name Iron-Bank-FlowLogs-Role \
  --policy-name FlowLogs-CloudWatch-Policy \
  --policy-document file:///tmp/flow-logs-policy.json \
  --profile iron-bank

echo "✅ IAM Role configured"

# ─── Step 3: Create a CloudWatch Log Group ───────────────────────────────────
# This is where the flow logs will be written — like a container for log streams
aws logs create-log-group \
  --log-group-name /aws/vpc/iron-bank-flow-logs \
  --profile iron-bank

# Set retention to 7 days — so you don't accumulate charges indefinitely
aws logs put-retention-policy \
  --log-group-name /aws/vpc/iron-bank-flow-logs \
  --retention-in-days 7 \
  --profile iron-bank

echo "✅ CloudWatch Log Group created with 7-day retention"

# ─── Step 4: Enable Flow Logs on the VPC ─────────────────────────────────────
FLOW_LOG_ID=$(aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids $VPC_ID \
  --traffic-type ALL \          # Capture ACCEPT, REJECT, and ALL traffic
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/iron-bank-flow-logs \
  --deliver-logs-permission-arn $ROLE_ARN \
  --profile iron-bank \
  --query FlowLogIds[0] --output text)
echo "Flow Log ID: $FLOW_LOG_ID"

# Verify flow logs are enabled
aws ec2 describe-flow-logs \
  --filter "Name=resource-id,Values=$VPC_ID" \
  --profile iron-bank \
  --query 'FlowLogs[*].{ID:FlowLogId,Status:FlowLogStatus,Destination:LogGroupName}' \
  --output table
```

??? note "Why ALL traffic, not just REJECT?"
    For security monitoring, you want to see both allowed and denied traffic. `REJECT` alone tells you what's being blocked — but `ALL` lets you also spot unusual *allowed* connections that might indicate a compromised instance talking to an attacker's server.

---

## Part 2: Generate Traffic and View Logs

```bash
# ─── Step 5: Launch an EC2 instance to generate traffic ──────────────────────
# Create a minimal subnet and SG for the test instance
PUB=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID --cidr-block 10.0.1.0/24 --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=Test-Subnet}]' \
  --profile iron-bank --query Subnet.SubnetId --output text)

IGW=$(aws ec2 create-internet-gateway --profile iron-bank \
  --query InternetGateway.InternetGatewayId --output text)
aws ec2 attach-internet-gateway --internet-gateway-id $IGW --vpc-id $VPC_ID --profile iron-bank

RT=$(aws ec2 create-route-table --vpc-id $VPC_ID --profile iron-bank \
  --query RouteTable.RouteTableId --output text)
aws ec2 create-route --route-table-id $RT \
  --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW --profile iron-bank
aws ec2 associate-route-table --route-table-id $RT --subnet-id $PUB --profile iron-bank

MY_IP=$(curl -s https://checkip.amazonaws.com)
SG=$(aws ec2 create-security-group --group-name test-sg --description "Test SG" \
  --vpc-id $VPC_ID --profile iron-bank --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id $SG \
  --protocol tcp --port 22 --cidr ${MY_IP}/32 --profile iron-bank

AMI=$(aws ec2 describe-images --owners amazon \
  --filters "Name=name,Values=al2023-ami-2023*-x86_64" "Name=state,Values=available" \
  --profile iron-bank \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' --output text)

aws ec2 create-key-pair --key-name flow-test-key --profile iron-bank \
  --query KeyMaterial --output text > ~/.ssh/flow-test-key.pem
chmod 400 ~/.ssh/flow-test-key.pem

INSTANCE=$(aws ec2 run-instances \
  --image-id $AMI --instance-type t2.micro \
  --key-name flow-test-key --security-group-ids $SG \
  --subnet-id $PUB --associate-public-ip-address \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=Flow-Test}]' \
  --profile iron-bank --query 'Instances[0].InstanceId' --output text)

aws ec2 wait instance-running --instance-ids $INSTANCE --profile iron-bank

INSTANCE_IP=$(aws ec2 describe-instances --instance-ids $INSTANCE \
  --profile iron-bank \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
echo "Instance IP: $INSTANCE_IP"

# Connect and generate some traffic
ssh -i ~/.ssh/flow-test-key.pem ec2-user@$INSTANCE_IP \
  "curl -s https://amazon.com > /dev/null; ping -c 3 8.8.8.8; exit"

# ─── Step 6: Wait then view the flow logs ────────────────────────────────────
# Flow logs have a ~10 minute delay before appearing in CloudWatch
echo "Waiting 5 minutes for logs to appear..."
sleep 300

# List log streams inside your log group (each ENI gets its own stream)
aws logs describe-log-streams \
  --log-group-name /aws/vpc/iron-bank-flow-logs \
  --profile iron-bank \
  --query 'logStreams[*].logStreamName' \
  --output table

# Read the actual log events from the first stream
STREAM=$(aws logs describe-log-streams \
  --log-group-name /aws/vpc/iron-bank-flow-logs \
  --profile iron-bank \
  --query 'logStreams[0].logStreamName' --output text)

aws logs get-log-events \
  --log-group-name /aws/vpc/iron-bank-flow-logs \
  --log-stream-name "$STREAM" \
  --profile iron-bank \
  --query 'events[*].message' \
  --output text | head -20
```

---

## Part 3: Flow Log Analyzer Script (Python)

This is your **Month 4 project deliverable** — a Python script that reads flow logs from CloudWatch and summarizes security-relevant findings. Push this to GitHub.

```bash
# Create the project directory
mkdir -p ~/projects/flow-log-analyzer
cd ~/projects/flow-log-analyzer
python3 -m venv venv
source venv/bin/activate
pip install boto3
```

```python
#!/usr/bin/env python3
"""
flow_analyzer.py — VPC Flow Log Security Analyzer
Iron Bank Training — Month 4 Project

Connects to CloudWatch Logs, reads VPC flow log entries,
and reports: rejected connections, top talkers, unusual ports.
"""

import boto3          # AWS SDK for Python
import json           # For formatting output
from collections import defaultdict  # Like a regular dict but auto-creates missing keys


# ─── Configuration ────────────────────────────────────────────────────────────
LOG_GROUP = "/aws/vpc/iron-bank-flow-logs"   # The CloudWatch log group you created
AWS_PROFILE = "iron-bank"                     # Your named profile (never use default)
HOURS_BACK = 1                                # How many hours of logs to analyze


def get_log_events(hours_back=1):
    """
    Fetch all flow log events from CloudWatch for the last N hours.
    Returns a list of raw log strings.
    """
    import time

    # Create a CloudWatch Logs client using your named profile
    session = boto3.Session(profile_name=AWS_PROFILE)
    client = session.client("logs", region_name="us-east-1")

    # Calculate the start time in milliseconds (CloudWatch uses epoch milliseconds)
    start_time_ms = int((time.time() - (hours_back * 3600)) * 1000)

    events = []  # We'll collect all log messages here

    # First, list all log streams in the group (one per network interface)
    streams_response = client.describe_log_streams(
        logGroupName=LOG_GROUP,
        orderBy="LastEventTime",
        descending=True,      # Most recent first
        limit=50              # Check up to 50 streams
    )

    for stream in streams_response.get("logStreams", []):
        stream_name = stream["logStreamName"]

        # Fetch events from this stream
        response = client.get_log_events(
            logGroupName=LOG_GROUP,
            logStreamName=stream_name,
            startTime=start_time_ms,
            startFromHead=True    # Read oldest first so events are in chronological order
        )

        for event in response.get("events", []):
            events.append(event["message"])  # The raw flow log string

    return events


def parse_flow_log(line):
    """
    Parse a single VPC flow log line into a dictionary.
    Flow log format: version account-id interface-id srcaddr dstaddr srcport dstport
                     protocol packets bytes start end action log-status
    """
    fields = line.strip().split()

    # If the line doesn't have exactly 14 fields, it's malformed — skip it
    if len(fields) < 14:
        return None

    return {
        "src_ip":    fields[3],    # Source IP address
        "dst_ip":    fields[4],    # Destination IP address
        "src_port":  fields[5],    # Source port (random high port for outbound connections)
        "dst_port":  fields[6],    # Destination port (the service being accessed)
        "protocol":  fields[7],    # 6=TCP, 17=UDP, 1=ICMP
        "packets":   int(fields[8]) if fields[8] != "-" else 0,
        "bytes":     int(fields[9]) if fields[9] != "-" else 0,
        "action":    fields[12],   # ACCEPT or REJECT
        "status":    fields[13],   # OK, NODATA, SKIPDATA
    }


def analyze(events):
    """
    Analyze parsed flow log entries and return a security summary.
    """
    rejected = []                        # All REJECT entries
    top_talkers = defaultdict(int)       # src_ip → total bytes sent
    rejected_ports = defaultdict(int)    # dst_port → number of rejections
    suspicious_ports = {21, 23, 3389, 1433, 3306, 6379}  # FTP, Telnet, RDP, MSSQL, MySQL, Redis

    for line in events:
        entry = parse_flow_log(line)
        if not entry:
            continue  # Skip malformed lines

        # Track total bytes per source IP (who's sending the most data?)
        top_talkers[entry["src_ip"]] += entry["bytes"]

        if entry["action"] == "REJECT":
            rejected.append(entry)
            # Count which destination ports are being rejected most
            rejected_ports[entry["dst_port"]] += 1

    return {
        "total_events":     len(events),
        "total_rejected":   len(rejected),
        "reject_rate":      f"{(len(rejected)/max(len(events),1)*100):.1f}%",
        # Sort top talkers by bytes descending, take top 5
        "top_talkers":      sorted(top_talkers.items(), key=lambda x: x[1], reverse=True)[:5],
        # Sort rejected ports by count descending, take top 10
        "top_rejected_ports": sorted(rejected_ports.items(), key=lambda x: x[1], reverse=True)[:10],
        # Flag any rejections aimed at known sensitive service ports
        "suspicious_rejects": [r for r in rejected if int(r["dst_port"]) in suspicious_ports],
    }


def print_report(summary):
    """Print the analysis to the console in a readable format."""
    print("\n" + "="*60)
    print("  🏦 Iron Bank — VPC Flow Log Security Report")
    print("="*60)

    print(f"\n📊 Summary")
    print(f"  Total log events:  {summary['total_events']}")
    print(f"  Rejected packets:  {summary['total_rejected']} ({summary['reject_rate']})")

    print(f"\n🔝 Top Talkers (by bytes sent)")
    for ip, bytes_sent in summary["top_talkers"]:
        print(f"  {ip:<18} {bytes_sent:>10,} bytes")

    print(f"\n🚫 Most Rejected Destination Ports")
    for port, count in summary["top_rejected_ports"]:
        print(f"  Port {port:<6} rejected {count:>5} times")

    if summary["suspicious_rejects"]:
        print(f"\n⚠️  Suspicious Rejected Connections ({len(summary['suspicious_rejects'])} found)")
        for r in summary["suspicious_rejects"][:5]:  # Show at most 5
            print(f"  {r['src_ip']} → port {r['dst_port']} (REJECT)")
    else:
        print(f"\n✅ No suspicious port activity detected")

    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    print("Fetching flow logs from CloudWatch...")
    events = get_log_events(hours_back=HOURS_BACK)

    if not events:
        print("No log events found. Wait ~10 minutes after enabling flow logs.")
    else:
        summary = analyze(events)
        print_report(summary)
```

```bash
# Run the analyzer
python3 flow_analyzer.py

# Push to GitHub
git init
git add flow_analyzer.py
git commit -m "feat: VPC Flow Log Security Analyzer - Month 4 Project"
git remote add origin https://github.com/<your-username>/vpc-flow-analyzer.git
git push -u origin main
```

---

## 🧹 Cleanup

!!! abstract "🧹 Cleanup — This month uses real AWS resources"

```bash
# Terminate EC2 instance
aws ec2 terminate-instances --instance-ids $INSTANCE --profile iron-bank
aws ec2 wait instance-terminated --instance-ids $INSTANCE --profile iron-bank

# Delete Security Group
aws ec2 delete-security-group --group-id $SG --profile iron-bank

# Delete Route Table and Subnet
aws ec2 disassociate-route-table \
  --association-id $(aws ec2 describe-route-tables --route-table-ids $RT \
    --profile iron-bank \
    --query 'RouteTables[0].Associations[0].RouteTableAssociationId' --output text) \
  --profile iron-bank
aws ec2 delete-route-table --route-table-id $RT --profile iron-bank
aws ec2 delete-subnet --subnet-id $PUB --profile iron-bank

# Detach and delete IGW
aws ec2 detach-internet-gateway --internet-gateway-id $IGW --vpc-id $VPC_ID --profile iron-bank
aws ec2 delete-internet-gateway --internet-gateway-id $IGW --profile iron-bank

# Delete Flow Log
aws ec2 delete-flow-logs --flow-log-ids $FLOW_LOG_ID --profile iron-bank

# Delete CloudWatch Log Group (this stops ongoing storage charges)
aws logs delete-log-group \
  --log-group-name /aws/vpc/iron-bank-flow-logs \
  --profile iron-bank

# Delete IAM Role and Policy
aws iam delete-role-policy \
  --role-name Iron-Bank-FlowLogs-Role \
  --policy-name FlowLogs-CloudWatch-Policy \
  --profile iron-bank
aws iam delete-role --role-name Iron-Bank-FlowLogs-Role --profile iron-bank

# Delete VPC
aws ec2 delete-vpc --vpc-id $VPC_ID --profile iron-bank

# Delete key pair
aws ec2 delete-key-pair --key-name flow-test-key --profile iron-bank
rm ~/.ssh/flow-test-key.pem

echo "✅ All Month 4 resources deleted"
```

---

## Month 4 Summary

You've now built the full VPC foundation that real AWS cloud environments run on:

| Week | What You Built | Skill Gained |
|---|---|---|
| 1 | VPC + IGW + basic subnets + SG | Core networking primitives |
| 2 | Multi-AZ subnets + Route Tables + NACLs | Subnet isolation & routing |
| 3 | Layered Security Groups + Bastion Host | Zero-trust network design |
| 4 | VPC Flow Logs + Python analyzer | Network security monitoring |

---

## Checklist

- [ ] Enabled VPC Flow Logs to CloudWatch with 7-day retention
- [ ] Created IAM role for Flow Logs (understand why it's needed)
- [ ] Generated traffic and confirmed logs appear in CloudWatch
- [ ] Read and interpreted raw flow log entries manually
- [ ] `flow_analyzer.py` runs successfully and outputs a report
- [ ] Script pushed to GitHub as your Month 4 project
- [ ] Understand the difference between ACCEPT and REJECT entries
- [ ] **CloudWatch Log Group deleted** (ongoing cost if left)
- [ ] **All EC2, VPC, and IAM resources cleaned up**
- [ ] **Billing console checked — balance $0**
