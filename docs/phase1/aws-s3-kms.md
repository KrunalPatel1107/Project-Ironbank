# Month 3 — Week 2: S3 & KMS (Iron Bank Days 4–5)

!!! abstract "💰 Cost: $0 — S3 (5GB free), KMS (20K requests free)"

## Create an Encrypted S3 Bucket (Iron Bank Day 4)

```bash
# Create a bucket (name must be globally unique)
BUCKET="iron-bank-practice-$(date +%s)"
aws s3api create-bucket \
  --bucket "$BUCKET" \
  --region us-east-1 \
  --profile iron-bank
echo "Created: $BUCKET"

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket "$BUCKET" \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
  --profile iron-bank

# Block all public access (Iron Bank Day 5)
aws s3api put-public-access-block \
  --bucket "$BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
  --profile iron-bank

# Verify with your Python scanner from Month 2!
python3 ~/projects/python-security/s3_audit.py
```

## Understanding KMS

```bash
# KMS = Key Management Service (like Azure Key Vault)
# SSE-S3: Amazon manages the key (simplest, free)
# SSE-KMS: You manage the key (more control, audit trail)

# Create a KMS key
KEY_ID=$(aws kms create-key \
  --description "Iron Bank practice key" \
  --profile iron-bank \
  --query KeyMetadata.KeyId --output text)
echo "KMS Key: $KEY_ID"
```

!!! danger "💰 KMS key deletion"
    If you delete a KMS key, all data encrypted with it becomes **permanently unreadable**. AWS enforces a 7–30 day waiting period.

## 🧹 Cleanup (IMPORTANT!)

```bash
# Delete S3 bucket (must be empty first)
aws s3 rm s3://$BUCKET --recursive --profile iron-bank
aws s3api delete-bucket --bucket $BUCKET --profile iron-bank

# Schedule KMS key deletion (7-day minimum waiting period)
aws kms schedule-key-deletion \
  --key-id $KEY_ID \
  --pending-window-in-days 7 \
  --profile iron-bank

# Verify nothing is left
aws s3 ls --profile iron-bank    # No practice buckets
```

## Checklist

- [ ] Created encrypted S3 bucket via CLI
- [ ] Applied public access block (all 4 settings)
- [ ] Created KMS key
- [ ] Understand SSE-S3 vs SSE-KMS
- [ ] Verified with Python scanner
- [ ] **All S3 buckets deleted**
- [ ] **KMS key scheduled for deletion**
