# Month 3 — Week 1: IAM Deep Dive

!!! abstract "💰 Cost: $0 — IAM is always free"

!!! info "Background Context"
    AWS IAM = Entra ID / Azure AD. IAM Policies = Azure RBAC. IAM Roles = Managed Identities. The concepts are identical — only the JSON syntax changes.

## Iron Bank Day 2: Create an IAM Role

```bash
# Get your account ID
ACCOUNT_ID=$(aws sts get-caller-identity --profile iron-bank --query Account --output text)
echo "Account ID: $ACCOUNT_ID"

# Create the trust policy (who can assume this role)
cat > trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${ACCOUNT_ID}:root" },
    "Action": "sts:AssumeRole"
  }]
}
EOF

# Create the role
aws iam create-role \
  --role-name IronBank-Auditor \
  --assume-role-policy-document file://trust-policy.json \
  --profile iron-bank

# Verify
aws iam get-role --role-name IronBank-Auditor --profile iron-bank
```

??? note "What each part means"
    - `Effect: Allow` — we're granting permission (could be Deny)
    - `Principal` — who we trust (the root account, which includes terraform-admin)
    - `Action: sts:AssumeRole` — the action of "putting on the role" temporarily
    - A **Role** is like a temporary uniform. A **User** is like a permanent badge.

## Write an IAM Policy from Scratch

This is critical for the AWS Security Specialty exam:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3Read",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::iron-bank-vault-*",
        "arn:aws:s3:::iron-bank-vault-*/*"
      ]
    },
    {
      "Sid": "AllowCloudWatchLogs",
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:us-east-1:*:log-group:/iron-bank/*"
    }
  ]
}
```

!!! tip "Azure Parallel"
    This IAM policy = Azure RBAC custom role definition. `Effect: Allow` = `Actions: []` in Azure. `Resource: arn:...` = `AssignableScopes` in Azure.

## Practice: flAWS.cloud

Complete [flAWS.cloud](http://flaws.cloud/) — a free CTF that teaches AWS security through real misconfigurations.

## 🧹 Cleanup

```bash
aws iam delete-role --role-name IronBank-Auditor --profile iron-bank
rm trust-policy.json
```

## Checklist

- [ ] Created IAM Role via CLI
- [ ] Understand Trust Policy vs Permission Policy
- [ ] Can write IAM policies in JSON from scratch
- [ ] Understand ARN format: `arn:aws:service:region:account:resource`
- [ ] Completed flAWS.cloud Level 1–3
- [ ] All IAM resources cleaned up
