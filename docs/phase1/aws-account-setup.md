# Setup: AWS Account

!!! danger "⚠️ FIRST THING: Set a Billing Alarm!"
    AWS charges are real money. Before creating ANY resources:

    1. AWS Console → search "Billing" → Billing Preferences → **Enable Free Tier Usage Alerts**
    2. Search "CloudWatch" → Alarms → Create Alarm
        - Metric: Billing → Total Estimated Charge
        - Threshold: Greater than **$5**
        - Notification: Enter your email
    3. This emails you if your bill exceeds $5

!!! abstract "💰 Free Tier Limits (12 months)"
    - 750 hrs/month EC2 t2.micro
    - 5 GB S3 storage
    - 25 GB DynamoDB
    - 1 million Lambda requests
    - CloudTrail: 1 trail free
    - IAM: always free

## Install AWS CLI

=== "Ubuntu/WSL"
    ```bash
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip
    unzip awscliv2.zip
    sudo ./aws/install
    rm -rf aws awscliv2.zip    # Clean up installer
    aws --version
    ```

=== "macOS"
    ```bash
    brew install awscli
    aws --version
    ```

## Create IAM Admin User (Iron Bank Day 1)

1. Go to [AWS Console](https://console.aws.amazon.com) → log in as Root
2. **Enable MFA on Root:** IAM → Add MFA → scan QR code with authenticator app
3. **Create Admin User:** IAM → Users → Create User → name: `terraform-admin`
4. **Attach Policy:** Select "Attach policies directly" → search `AdministratorAccess` → check it
5. **Create Access Keys:** Click user → Security Credentials → Create Access Key → CLI
6. **⚠️ COPY BOTH KEYS NOW** — the Secret Key is shown only once!

## Configure Named Profile

```bash
aws configure --profile iron-bank
# AWS Access Key ID:     [paste your key]
# AWS Secret Access Key: [paste your secret — you won't see it again]
# Default region name:   us-east-1
# Default output format: json
```

!!! tip "Why `--profile iron-bank`?"
    Named profiles prevent accidentally deploying to the wrong account. Without a profile, AWS CLI uses "default" — which could be your employer's production account. Named profiles are a safety mechanism.

## Verify

```bash
aws sts get-caller-identity --profile iron-bank
# Expected: "Arn": "arn:aws:iam::123456789012:user/terraform-admin"
# If you see ":root" → you used root credentials. STOP and redo!
```

## What Costs Money vs What Doesn't

| Free ✅ | Costs Money ⚠️ |
|---|---|
| S3 (5GB), IAM, KMS (20K requests) | EC2 instances (if running beyond free tier) |
| CloudTrail (1 trail), CLI calls | **NAT Gateway: $32/month!** |
| Security Groups, VPCs, Subnets | **ALB: $16/month!** |
| GuardDuty (30-day trial) | Elastic IPs (unattached: $3.60/month) |
| Config (500 evals/month) | EBS volumes (if not deleted with instance) |

!!! danger "Golden Rule"
    **If you created it, destroy it when done practicing.** Terraform makes re-creating fast.

## Checklist

- [ ] AWS free-tier account created
- [ ] Billing alarm set at $5
- [ ] Root user has MFA enabled
- [ ] `terraform-admin` IAM user created (NOT root)
- [ ] AWS CLI installed and `aws --version` works
- [ ] CLI configured with `--profile iron-bank`
- [ ] `aws sts get-caller-identity` shows terraform-admin (NOT root)
