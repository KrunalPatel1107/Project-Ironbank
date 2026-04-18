#!/bin/bash

# ════════════════════════════════════════════════════════════════════════════
# Setup GitHub OIDC Provider for AWS
# ════════════════════════════════════════════════════════════════════════════
#
# Purpose:
#   Configure AWS to trust GitHub Actions OIDC tokens for temporary credentials.
#   This allows GitHub workflows to assume AWS roles WITHOUT long-lived keys.
#
# What this script does:
#   1. Creates an OIDC provider in AWS (one-time per account)
#   2. Creates an IAM role that GitHub workflows can assume
#   3. Outputs the role ARN for use in your workflows
#
# Security benefit:
#   ✓ No long-lived AWS credentials in GitHub
#   ✓ Temporary tokens (1 hour TTL)
#   ✓ Automatic audit trail (CloudTrail shows GitHub commit/branch/repo)
#   ✓ Fine-grained access control per repository/workflow
#
# Usage:
#   ./setup-github-oidc.sh <GITHUB_USERNAME> <GITHUB_REPO> <AWS_REGION>
#
#   Example:
#   ./setup-github-oidc.sh your-github-username iron-bank-pipeline us-east-1
#
# Author: Iron Bank Training
# Date: April 2026
# ════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ════════════════════════════════════════════════════════════════════════════
# INPUT VALIDATION
# ════════════════════════════════════════════════════════════════════════════

if [ $# -lt 3 ]; then
  echo "Usage: $0 <GITHUB_USERNAME> <GITHUB_REPO> <AWS_REGION>"
  echo ""
  echo "Examples:"
  echo "  $0 your-github-username iron-bank-pipeline us-east-1"
  echo "  $0 myusername my-repo eu-west-1"
  exit 1
fi

GITHUB_ORG="$1"       # e.g., "your-github-username"
GITHUB_REPO="$2"      # e.g., "iron-bank-pipeline"
AWS_REGION="$3"       # e.g., "us-east-1"
AWS_PROFILE="${4:-iron-bank}"  # Default to iron-bank profile

echo "[*] Setting up GitHub OIDC for AWS"
echo "    GitHub Org:  $GITHUB_ORG"
echo "    GitHub Repo: $GITHUB_REPO"
echo "    AWS Region:  $AWS_REGION"
echo "    AWS Profile: $AWS_PROFILE"
echo ""

# ════════════════════════════════════════════════════════════════════════════
# STEP 1: Create OIDC Provider in AWS (one-time per account)
# ════════════════════════════════════════════════════════════════════════════

echo "[1/3] Creating OIDC provider (allows GitHub to authenticate)..."

# The thumbprint for GitHub's OIDC token endpoint (as of April 2024)
# This is a hash of GitHub's SSL certificate chain for token.actions.githubusercontent.com
GITHUB_OIDC_THUMBPRINT="6938fd4d98bab03faadb97b34396831e3780aea1"

# Check if provider already exists
EXISTING_PROVIDER=$(aws iam list-open-id-connect-providers \
  --profile "$AWS_PROFILE" \
  --query 'OpenIDConnectProviderList[?OpenIDConnectProviderArn==`arn:aws:iam::'$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query Account --output text)':oidc-provider/token.actions.githubusercontent.com`]' \
  --output text 2>/dev/null || echo "")

if [ -z "$EXISTING_PROVIDER" ]; then
  # Provider doesn't exist, create it
  aws iam create-open-id-connect-provider \
    --url "https://token.actions.githubusercontent.com" \
    --client-id-list "sts.amazonaws.com" \
    --thumbprint-list "$GITHUB_OIDC_THUMBPRINT" \
    --profile "$AWS_PROFILE"

  echo "✓ OIDC provider created"
else
  echo "✓ OIDC provider already exists (skipped)"
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 2: Create IAM Role for GitHub Workflows
# ════════════════════════════════════════════════════════════════════════════

echo "[2/3] Creating IAM role for GitHub workflows..."

# Get current AWS account ID
AWS_ACCOUNT=$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query Account --output text)

# Role name based on repository
ROLE_NAME="github-${GITHUB_REPO}-deploy"

# Create trust policy (allows GitHub to assume the role)
# The condition restricts this role to ONLY the specified GitHub repository
TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:${GITHUB_ORG}/${GITHUB_REPO}:*"
        }
      }
    }
  ]
}
EOF
)

# Create the role (or skip if exists)
if aws iam get-role --role-name "$ROLE_NAME" --profile "$AWS_PROFILE" 2>/dev/null; then
  echo "✓ IAM role '$ROLE_NAME' already exists (skipped)"
else
  # Save trust policy to temp file
  TRUST_POLICY_FILE=$(mktemp)
  echo "$TRUST_POLICY" > "$TRUST_POLICY_FILE"

  # Create the role
  aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "file://$TRUST_POLICY_FILE" \
    --profile "$AWS_PROFILE" \
    --description "Role for GitHub Actions to deploy $GITHUB_REPO"

  # Clean up temp file
  rm "$TRUST_POLICY_FILE"

  echo "✓ IAM role '$ROLE_NAME' created"
fi

# ════════════════════════════════════════════════════════════════════════════
# STEP 3: Attach Permissions to the Role
# ════════════════════════════════════════════════════════════════════════════

echo "[3/3] Attaching permissions to the role..."

# For this lab, we attach EC2FullAccess
# In production, use a more restrictive policy (e.g., EC2 launch only, S3 read-only, etc.)
POLICY_ARN="arn:aws:iam::aws:policy/AmazonEC2FullAccess"

# Check if policy is already attached
if aws iam list-attached-role-policies \
  --role-name "$ROLE_NAME" \
  --profile "$AWS_PROFILE" \
  --query "AttachedPolicies[?PolicyArn=='$POLICY_ARN']" \
  --output text 2>/dev/null | grep -q "$POLICY_ARN"; then
  echo "✓ Policy already attached (skipped)"
else
  aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "$POLICY_ARN" \
    --profile "$AWS_PROFILE"

  echo "✓ Policy attached: $POLICY_ARN"
fi

# ════════════════════════════════════════════════════════════════════════════
# OUTPUT: Information Needed for Workflows
# ════════════════════════════════════════════════════════════════════════════

ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT}:role/${ROLE_NAME}"

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "SUCCESS! GitHub OIDC is configured"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "Role ARN to use in your workflows:"
echo "  $ROLE_ARN"
echo ""
echo "Example workflow (.github/workflows/deploy.yml):"
echo ""
cat << EXAMPLE_WORKFLOW
name: Deploy with OIDC

on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v2
      with:
        role-to-assume: $ROLE_ARN
        aws-region: $AWS_REGION

    - name: Deploy
      run: |
        aws ec2 describe-instances --region $AWS_REGION
        aws sts get-caller-identity
EXAMPLE_WORKFLOW

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "NEXT STEPS:"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "1. Copy the role ARN above"
echo "2. Create .github/workflows/oidc-test.yml in your repo (see example above)"
echo "3. Replace the role-to-assume value with: $ROLE_ARN"
echo "4. Push to GitHub and watch the Actions tab"
echo ""
echo "For more details, see: m10-week1.md (OIDC section)"
echo ""
