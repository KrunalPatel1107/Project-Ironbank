# Project: AWS Security Scanner

!!! abstract "💰 Cost: $0 — Read-only API calls"

!!! info "Goal"
    Combine S3 + IAM + Security Group audits into one CLI tool. This is GitHub portfolio piece #2.

## What is argparse?

`argparse` is a built-in Python module that lets your script accept **arguments from the command line** — just like how `grep` accepts flags like `-c` or `-n`, or how `aws s3 ls --profile iron-bank` accepts `--profile`.

Without argparse:
```bash
python3 aws_scanner.py    # always uses hardcoded settings
```

With argparse:
```bash
python3 aws_scanner.py --profile iron-bank --region us-east-1 --output report.json
# OR change the values:
python3 aws_scanner.py --profile my-other-account --region eu-west-1 --output eu_report.json
```

You define what flags exist (`--profile`, `--region`, etc.), and argparse automatically reads them from the command line, shows a `--help` message, and gives errors if required arguments are missing.

## Build the Scanner

Combine your Week 3 scripts into a single tool with `argparse`:

```python
# aws_scanner.py — AWS Security Audit Tool
# This script combines all your Week 3 checks into one tool.

import boto3      # AWS library
import json       # for saving results
import argparse   # for command-line arguments (--profile, --region, etc.)
from datetime import datetime, timezone   # for calculating how old an access key is


# ============================================================
# FUNCTION: audit_s3
# Checks every S3 bucket for missing encryption or public access.
# Takes "session" as input (the AWS connection).
# Returns a list of "findings" (problems found).
# ============================================================
def audit_s3(session):
    """Check S3 buckets for encryption and public access."""
    s3 = session.client('s3')   # Create an S3 client from the session
    findings = []               # Empty list — we'll add problems here

    buckets = s3.list_buckets()['Buckets']   # Get all bucket names
    for bucket in buckets:
        name = bucket['Name']
        issues = []     # Problems for THIS specific bucket

        # Try to get encryption config. If it fails → no encryption set.
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
        except Exception:
            issues.append("No encryption")

        # Try to get public access block. If all 4 settings aren't True → issue.
        try:
            pab = s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
            # all([...]) returns True only if every item in the list is True
            if not all([pab.get('BlockPublicAcls'), pab.get('BlockPublicPolicy'),
                       pab.get('IgnorePublicAcls'), pab.get('RestrictPublicBuckets')]):
                issues.append("Public access not fully blocked")
        except Exception:
            issues.append("No public access block")

        # If any issues found for this bucket, add it to our findings list
        if issues:
            findings.append({"resource": name, "type": "S3", "issues": issues})

    return findings    # Send the list of problems back to whoever called this function


# ============================================================
# FUNCTION: audit_iam
# Checks every IAM user for: no MFA, or access keys older than 90 days.
# ============================================================
def audit_iam(session):
    """Check IAM users for MFA and key age."""
    iam = session.client('iam')
    findings = []

    for user in iam.list_users()['Users']:    # Loop through every IAM user
        name = user['UserName']
        issues = []

        # Check MFA: if the list of MFA devices is empty → no MFA
        if not iam.list_mfa_devices(UserName=name)['MFADevices']:
            issues.append("No MFA enabled")

        # Check access key age
        for key in iam.list_access_keys(UserName=name)['AccessKeyMetadata']:
            # Calculate age: current time minus creation date = timedelta
            # .days converts the timedelta object to a plain number of days
            age = (datetime.now(timezone.utc) - key['CreateDate']).days
            if age > 90 and key['Status'] == 'Active':
                # Only show first 8 chars of key ID (don't expose the full key)
                issues.append(f"Access key {key['AccessKeyId'][:8]}... is {age} days old")

        if issues:
            findings.append({"resource": name, "type": "IAM User", "issues": issues})

    return findings


# ============================================================
# FUNCTION: audit_security_groups
# Checks for Security Groups that allow port 22 (SSH) or 3389 (RDP)
# open to the entire internet (0.0.0.0/0).
# ============================================================
def audit_security_groups(session):
    """Check for overly permissive security groups."""
    ec2 = session.client('ec2')
    findings = []

    for sg in ec2.describe_security_groups()['SecurityGroups']:
        issues = []
        # IpPermissions = the inbound rules for this security group
        for rule in sg.get('IpPermissions', []):
            # IpRanges = the IP address ranges allowed by this rule
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':    # 0.0.0.0/0 = the entire internet
                    port = rule.get('FromPort', 'all')
                    if port in [22, 3389, 'all']:              # SSH, RDP, or all ports
                        issues.append(f"Port {port} open to 0.0.0.0/0 (world)")

        if issues:
            findings.append({"resource": sg['GroupId'], "type": "Security Group", "issues": issues})

    return findings


# ============================================================
# COMMAND-LINE INTERFACE (argparse)
# This block runs when you execute the script.
# It reads the --profile, --region, --output flags you typed.
# ============================================================

# Create the argument parser
parser = argparse.ArgumentParser(description="AWS Security Scanner")

# Add arguments — each one becomes a flag you can use on the command line
# "default" = what to use if the user doesn't provide the flag
# "help"    = the description shown when user runs: python3 aws_scanner.py --help
parser.add_argument("--profile", default="iron-bank", help="AWS CLI profile")
parser.add_argument("--region",  default="us-east-1", help="AWS region")
parser.add_argument("--output",  default="report.json", help="Output file")

# Actually read what the user typed on the command line
args = parser.parse_args()
# Now: args.profile = "iron-bank" (or whatever they typed)
#      args.region  = "us-east-1" (or whatever they typed)
#      args.output  = "report.json" (or whatever they typed)

# Create the AWS session using the chosen profile and region
session = boto3.Session(profile_name=args.profile, region_name=args.region)

print("🔍 AWS Security Scanner")
print(f"   Profile: {args.profile} | Region: {args.region}\n")

# ---- RUN ALL THREE AUDIT FUNCTIONS ----
all_findings = []    # Combined list of all findings from all 3 checks

# .extend() adds ALL items from a list into another list
# (vs .append() which adds the whole list as one item)
all_findings.extend(audit_s3(session))
all_findings.extend(audit_iam(session))
all_findings.extend(audit_security_groups(session))

# ---- PRINT RESULTS ----
for f in all_findings:
    print(f"  ❌ [{f['type']}] {f['resource']}")
    for issue in f['issues']:
        print(f"      → {issue}")

# ---- SAVE TO JSON FILE ----
with open(args.output, "w") as f:
    json.dump({"scan_date": str(datetime.now()), "findings": all_findings}, f, indent=2)

print(f"\n📄 {len(all_findings)} findings saved to {args.output}")
```

### Usage

```bash
python aws_scanner.py --profile iron-bank --region us-east-1 --output report.json
```

## Push to GitHub

```bash
mkdir -p ~/projects/aws-security-scanner && cd ~/projects/aws-security-scanner
cp ~/projects/python-security/aws_scanner.py .
cp ~/projects/python-security/s3_audit.py .
cp ~/projects/python-security/iam_audit.py .

# Create requirements.txt
echo "boto3" > requirements.txt

# Create README, init, push (like Month 1 Week 4)
git init && git add . && git commit -m "Initial commit: AWS Security Scanner"
# Create repo on github.com → push
```

## 🧹 Cleanup

```bash
rm -f report.json s3_audit_results.json
deactivate    # Deactivate virtual environment
```

## ✅ Month 2 Complete Checklist

- [ ] Python fundamentals: variables, loops, functions, files, errors
- [ ] Can parse JSON and make HTTP requests
- [ ] boto3 installed and working with `--profile iron-bank`
- [ ] S3 audit script complete
- [ ] IAM audit script complete
- [ ] Security Group audit script complete
- [ ] Combined into `aws_scanner.py` with argparse CLI
- [ ] Pushed to GitHub as `aws-security-scanner` repo
- [ ] All test AWS resources cleaned up

!!! success "🎉 Month 2 Complete!"
    You can now write Python security tools. Proceed to **Month 3: AWS Core & CCP Exam**.
