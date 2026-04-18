# Month 2 — Week 3: boto3 — AWS SDK for Python

!!! abstract "💰 Cost: $0 — boto3 read-only API calls are free"

!!! info "What does boto3 do?"
    boto3 is the official AWS library for Python. It lets your Python scripts talk directly to AWS services — the same things you do in the AWS Console (clicking around), but automated in code. Instead of manually clicking "list buckets" in the Console, you write one Python script that checks ALL your buckets at once and saves a report. This is what cloud security automation looks like in the real world.

## Setup

```bash
# Activate your virtual environment
cd ~/projects/python-security
source venv/bin/activate

# Install boto3
pip install boto3
```

!!! warning "Prerequisite"
    You need AWS CLI configured with `--profile iron-bank` from Month 3 setup. If you haven't done that yet, skip to Month 3 Setup first, then come back here.

## Your First boto3 Script: S3 Audit

```python
# s3_audit.py — Check every S3 bucket for encryption and public access
import boto3    # the AWS library
import json     # for saving our results to a JSON file

# ---- CONNECT TO AWS ----
# boto3.Session creates a connection to AWS using your saved credentials.
# profile_name='iron-bank' tells it to use the [iron-bank] profile
# from ~/.aws/credentials (the one you set up in Month 3 setup).
session = boto3.Session(profile_name='iron-bank')

# session.client('s3') creates an "S3 client" — an object with methods
# that map to S3 API actions. Think of it as a remote control for S3.
s3 = session.client('s3')

# ---- GET ALL BUCKETS ----
# s3.list_buckets() calls the AWS API and returns a dictionary.
# The 'Buckets' key contains a list of bucket dictionaries.
response = s3.list_buckets()
buckets = response['Buckets']     # Each item looks like: {"Name": "my-bucket", "CreationDate": ...}
print(f"Auditing {len(buckets)} buckets...\n")

findings = []     # Start with an empty list — we'll append problems here

# ---- CHECK EACH BUCKET ----
for bucket in buckets:          # Loop through every bucket in your account
    name = bucket['Name']       # Get the bucket's name from the dictionary
    issues = []                 # Empty list for THIS bucket's problems

    # CHECK 1: Is encryption enabled?
    # We use try/except because if a bucket has NO encryption setting,
    # AWS throws an error instead of returning empty data.
    try:
        enc = s3.get_bucket_encryption(Bucket=name)
        # enc is a deeply nested dictionary. We need to dig into it:
        # enc
        #  └── 'ServerSideEncryptionConfiguration'
        #       └── 'Rules'  (a list)
        #            └── [0]  (first item in the list)
        #                 └── 'ApplyServerSideEncryptionByDefault'
        #                      └── 'SSEAlgorithm'  ← this is what we want
        algo = enc['ServerSideEncryptionConfiguration']['Rules'][0]\
                  ['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
        print(f"  ✅ {name} — Encrypted ({algo})")
    except Exception:
        # If AWS throws any error here, it means there's no encryption
        print(f"  ❌ {name} — NO ENCRYPTION!")
        issues.append("No server-side encryption configured")

    # CHECK 2: Is public access blocked?
    try:
        pab = s3.get_public_access_block(Bucket=name)
        config = pab['PublicAccessBlockConfiguration']
        # all() returns True only if EVERY item in the list is True
        # config.get('Key', False) returns the value, or False if the key is missing
        all_blocked = all([
            config.get('BlockPublicAcls', False),
            config.get('BlockPublicPolicy', False),
            config.get('IgnorePublicAcls', False),
            config.get('RestrictPublicBuckets', False)
        ])
        if not all_blocked:
            issues.append("Public access not fully blocked")
            print(f"  ⚠️  {name} — Public access partially open!")
    except Exception:
        issues.append("No public access block configured")
        print(f"  ❌ {name} — No public access block!")

    # If this bucket had any issues, add it to our findings list
    if issues:
        findings.append({"bucket": name, "issues": issues})

# ---- SAVE RESULTS ----
with open("s3_audit_results.json", "w") as f:
    json.dump(findings, f, indent=2)    # Save all findings as pretty JSON

print(f"\n{'='*40}")
print(f"{len(findings)} buckets have issues.")
print(f"Results saved to s3_audit_results.json")
```

```bash
# Run it:
python3 s3_audit.py
```

## IAM Audit Script

```python
# iam_audit.py — Find users without MFA and with old access keys
import boto3
from datetime import datetime, timezone

session = boto3.Session(profile_name='iron-bank')
iam = session.client('iam')

users = iam.list_users()['Users']
print(f"Auditing {len(users)} IAM users...\n")

for user in users:
    name = user['UserName']

    # Check MFA
    mfa = iam.list_mfa_devices(UserName=name)['MFADevices']
    if not mfa:
        print(f"  ❌ {name} → NO MFA ENABLED")

    # Check access key age
    keys = iam.list_access_keys(UserName=name)['AccessKeyMetadata']
    for key in keys:
        created = key['CreateDate']
        age_days = (datetime.now(timezone.utc) - created).days
        if age_days > 90 and key['Status'] == 'Active':
            print(f"  ⚠️  {name} → Key {key['AccessKeyId'][:8]}... is {age_days} days old")
```

## 🧹 Cleanup

```bash
rm -f s3_audit_results.json    # Delete generated report
# If you created test S3 buckets:
aws s3 rb s3://test-bucket-name --force --profile iron-bank
```

## Checklist

- [ ] boto3 installed in virtual environment
- [ ] S3 audit script working (checks encryption + public access)
- [ ] IAM audit script working (checks MFA + key age)
- [ ] Understand `session.client('service')` pattern
- [ ] Can parse nested JSON responses from AWS APIs
