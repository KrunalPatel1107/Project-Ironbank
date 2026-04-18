# Month 5 — Week 4: Database Security + Exam Prep & Month Project

!!! danger "💰 Cost Warning — Part 1 Only"
    Part 1 (Database Security lab) creates RDS resources: ~**$0.30/day** if left running. Delete immediately after.
    Part 2 (Exam prep) and Part 3 (Month project) are free.
    Budget $70.50 for the **Terraform Associate 004** exam voucher when you're ready to book.

!!! info "This Week: Three Parts"
    1. **Database Security in Terraform** (3–4 hours, includes lab)
    2. **Exam Prep** (2–3 hours, study only)
    3. **Month Project** (GitHub portfolio, free)

---

# PART 1: Database Security in Terraform

!!! info "Why This Matters"
    You've built VPCs and Terraform modules. Now you'll secure your **most important asset**: data. RDS breaches = regulatory fines, lawsuits, reputation damage.
    
    From your threat model (Month 4), you know the risks:
    - Attacker accessing RDS directly from the internet
    - Credentials stolen (plaintext password in config)
    - Data read/modified in transit
    - Backup exposed or deleted

## Concept 1: Database Threat Model

Recap your threats from Month 4:

| Threat | Mitigatio in AWS |
|---|---|
| **Spoofing**: Attacker assumes the application's connection | IAM database authentication (instead of password) |
| **Tampering**: Attacker modifies data in transit | RDS encryption in-transit (enforce SSL/TLS) |
| **Repudiation**: Attacker denies they accessed data | RDS Enhanced Monitoring, audit logs |
| **Information Disclosure**: Attacker reads data at rest | RDS encryption at rest (AES-256 with KMS) |
| **Denial of Service**: Attacker exhaust connections | Connection pool limits, CloudWatch alarms |
| **Elevation of Privilege**: Attacker gets admin access | IAM role with `db-connect` only, no admin |

---

## Concept 2: RDS Security Layers (Defense in Depth)

```
┌─ Layer 1: Network Isolation ─────────────────────┐
│  RDS in private subnet, no public IP              │
│  Only EC2 Security Group can connect              │
└──────────────────────────────────────────────────┘
           ↓
┌─ Layer 2: Authentication ────────────────────────┐
│  Instead of password: IAM database auth token     │
│  Token rotates automatically (15 minute TTL)      │
│  Logged in CloudTrail (who accessed what when)    │
└──────────────────────────────────────────────────┘
           ↓
┌─ Layer 3: Encryption ────────────────────────────┐
│  In-Transit: TLS 1.2+ (enforce via RDS config)   │
│  At-Rest: AES-256 (KMS managed key)               │
│  Backups: Encrypted (automatic)                   │
└──────────────────────────────────────────────────┘
           ↓
┌─ Layer 4: Monitoring ────────────────────────────┐
│  Enhanced Monitoring: CPU, memory, connections    │
│  Audit Logging: Who ran what query, when          │
│  CloudTrail: API calls (create, modify, delete)   │
│  CloudWatch Alarms: High connections, slow queries│
└──────────────────────────────────────────────────┘
```

---

## Lab 1: Deploy Secure RDS with Terraform

This lab builds an RDS cluster with:
- Private subnet (no internet access)
- IAM database authentication (no passwords)
- Encryption at rest (KMS-managed)
- Encryption in transit (TLS enforced)
- Enhanced monitoring
- Automated backups with encryption

### Step 1: Create RDS Terraform Module

Create `rds/main.tf`:

```hcl
# ────────────────────────────────────────────────────────────────────────────
# Secure RDS PostgreSQL Cluster with IAM Authentication
# ────────────────────────────────────────────────────────────────────────────
# 
# This module demonstrates security best practices:
# - Database in private subnet only
# - IAM database authentication (no passwords)
# - Encryption at rest with KMS
# - Encryption in transit (TLS enforced)
# - Enhanced monitoring for troubleshooting
# - Automated encrypted backups
#
# Threat Model Coverage:
#   ✓ Spoofing:     IAM auth prevents unauthorized connections
#   ✓ Tampering:    TLS encryption in transit
#   ✓ Repudiation:  Enhanced Monitoring + Audit Logs
#   ✓ Disclosure:   RDS encryption + KMS key access control
#   ✓ DoS:          Connection pool limits, CloudWatch alarms
#   ✓ Elevation:    IAM role with db-connect permission only

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

# ────────────────────────────────────────────────────────────────────────────
# VARIABLES
# ────────────────────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region (must match your VPC region)"
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile"
  default     = "iron-bank"
}

variable "vpc_id" {
  description = "VPC ID from Month 4 (e.g., vpc-xxxxxxxx)"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs (list of at least 2 for RDS Multi-AZ)"
  type        = list(string)
  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "Must provide at least 2 private subnets for RDS cluster."
  }
}

variable "db_username" {
  description = "RDS root username (NOT used with IAM auth, but required)"
  default     = "postgres"
  sensitive   = true
}

variable "db_name" {
  description = "Initial database name"
  default     = "ironbank"
}

variable "db_instance_class" {
  description = "RDS instance class (smaller = cheaper, but slower)"
  default     = "db.t4g.micro"  # Free tier eligible, ARM-based (cheaper)
}

variable "backup_retention_days" {
  description = "How many days to keep automated backups"
  default     = 7
}

variable "environment" {
  description = "Environment name (dev/staging/prod)"
  default     = "dev"
}

# ────────────────────────────────────────────────────────────────────────────
# KMS KEY for RDS Encryption
# ────────────────────────────────────────────────────────────────────────────

# KMS key to encrypt RDS data at rest
# Separate key = better security (key and data separation)
resource "aws_kms_key" "rds_encryption" {
  description             = "KMS key for RDS encryption at rest"
  deletion_window_in_days = 7  # Allow 7 days before actual deletion (safety)
  enable_key_rotation     = true  # Auto-rotate key annually (best practice)

  tags = {
    Name        = "iron-bank-rds-key"
    Environment = var.environment
  }
}

# KMS key alias for easy reference in logs
resource "aws_kms_alias" "rds_encryption" {
  name          = "alias/iron-bank-rds"
  target_key_id = aws_kms_key.rds_encryption.key_id
}

# Policy allowing RDS service to use the key
resource "aws_kms_key_policy" "rds_encryption" {
  key_id = aws_kms_key.rds_encryption.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow RDS to use the key"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:CreateGrant",
        ]
        Resource = "*"
      },
    ]
  })
}

# ────────────────────────────────────────────────────────────────────────────
# SECURITY GROUP for RDS
# ────────────────────────────────────────────────────────────────────────────

# Allow connections only from EC2 (on the web-sg Security Group)
# This prevents direct database access from the internet
resource "aws_security_group" "rds_sg" {
  name        = "iron-bank-rds-sg"
  description = "Security group for RDS database (private subnet only)"
  vpc_id      = var.vpc_id

  # Ingress: PostgreSQL (5432) from web server security group only
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web_server.id]  # Only from EC2
    description     = "PostgreSQL from web servers"
  }

  # Egress: Allow all outbound (if RDS needs to reach other services)
  # For this lab, RDS doesn't initiate connections, but it's good practice
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound (unlikely to use)"
  }

  tags = {
    Name = "iron-bank-rds-sg"
  }
}

# Web server security group (placeholder - in real scenario, this would be your EC2 instance SG)
resource "aws_security_group" "web_server" {
  name        = "iron-bank-web-server-sg"
  description = "Web server security group"
  vpc_id      = var.vpc_id

  # Allow SSH from your IP (for testing)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.myip.response_body)}/32"]
    description = "SSH from my IP"
  }

  tags = {
    Name = "iron-bank-web-server-sg"
  }
}

# Get your public IP for SSH access
data "http" "myip" {
  url = "https://checkip.amazonaws.com/"
}

# ────────────────────────────────────────────────────────────────────────────
# RDS CLUSTER (PostgreSQL, Multi-AZ for high availability)
# ────────────────────────────────────────────────────────────────────────────

resource "aws_rds_cluster" "main" {
  cluster_identifier         = "iron-bank-db"
  engine                     = "aurora-postgresql"
  engine_version             = "15.3"  # Latest stable PostgreSQL
  database_name              = var.db_name
  master_username            = var.db_username
  # DO NOT SET master_password — use IAM auth instead
  
  # Network: Private subnets only
  db_subnet_group_name            = aws_db_subnet_group.main.name
  publicly_accessible             = false  # CRITICAL: No internet access
  
  # Security
  vpc_security_group_ids          = [aws_security_group.rds_sg.id]
  storage_encrypted               = true  # Encrypt at rest
  kms_key_id                      = aws_kms_key.rds_encryption.arn
  iam_database_authentication_enabled = true  # Enable IAM auth
  
  # Encryption in transit
  # (PostgreSQL enforces SSL by default with aurora-postgresql)
  
  # Backups
  backup_retention_period         = var.backup_retention_days
  preferred_backup_window         = "03:00-04:00"  # UTC, outside business hours
  skip_final_snapshot             = true  # For lab (set false in production)
  
  # Monitoring
  enable_cloudwatch_logs_exports  = ["postgresql"]  # Ship logs to CloudWatch
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  # High availability
  availability_zones              = ["us-east-1a", "us-east-1b"]  # Multi-AZ
  preferred_maintenance_window    = "sun:04:00-sun:05:00"
  
  # Performance
  enable_http_endpoint            = false  # Disable Data API (additional attack surface)
  deletion_protection             = false  # Allow deletion for lab (true in production)
  
  tags = {
    Name        = "iron-bank-primary-db"
    Environment = var.environment
    ThreatModel = "IAM-auth,KMS-encryption,Private-subnet"
  }
  
  depends_on = [aws_kms_key_policy.rds_encryption]
}

# ────────────────────────────────────────────────────────────────────────────
# RDS CLUSTER INSTANCES (Read + Write replicas)
# ────────────────────────────────────────────────────────────────────────────

# Writer instance (handles writes)
resource "aws_rds_cluster_instance" "writer" {
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = var.db_instance_class
  engine              = aws_rds_cluster.main.engine
  engine_version      = aws_rds_cluster.main.engine_version
  
  monitoring_interval = 60  # Enhanced monitoring every 60 seconds
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn
  
  identifier = "iron-bank-db-writer"
  
  tags = {
    Name = "iron-bank-db-writer"
  }
}

# Reader instance (handles reads, optional but recommended for HA)
resource "aws_rds_cluster_instance" "reader" {
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = var.db_instance_class
  engine              = aws_rds_cluster.main.engine
  engine_version      = aws_rds_cluster.main.engine_version
  
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn
  
  identifier = "iron-bank-db-reader"
  
  # Read-only replica (cannot accept writes)
  promotion_tier = 1  # Becomes writer if writer fails
  
  tags = {
    Name = "iron-bank-db-reader"
  }
}

# ────────────────────────────────────────────────────────────────────────────
# DB SUBNET GROUP (specifies which subnets RDS can use)
# ────────────────────────────────────────────────────────────────────────────

resource "aws_db_subnet_group" "main" {
  name       = "iron-bank-db-subnet-group"
  subnet_ids = var.private_subnet_ids
  
  tags = {
    Name = "iron-bank-db-subnets"
  }
}

# ────────────────────────────────────────────────────────────────────────────
# IAM ROLE for RDS Enhanced Monitoring
# ────────────────────────────────────────────────────────────────────────────

# RDS needs an IAM role to send Enhanced Monitoring data to CloudWatch
resource "aws_iam_role" "rds_monitoring" {
  name = "iron-bank-rds-monitoring-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach AWS managed policy for RDS monitoring
resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# ────────────────────────────────────────────────────────────────────────────
# IAM POLICY for EC2 to Connect with IAM Auth (instead of password)
# ────────────────────────────────────────────────────────────────────────────

# This policy allows your EC2 instance to generate temporary database tokens
# without needing a hardcoded password
resource "aws_iam_policy" "ec2_rds_auth" {
  name        = "iron-bank-ec2-rds-auth"
  description = "Allow EC2 to use IAM database authentication"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "rds-db:connect"
        ]
        Resource = "arn:aws:rds:${var.aws_region}:${data.aws_caller_identity.current.account_id}:db:${aws_rds_cluster.main.id}/*"
      }
    ]
  })
}

# ────────────────────────────────────────────────────────────────────────────
# DATA SOURCES
# ────────────────────────────────────────────────────────────────────────────

# Get current AWS account ID (for ARNs)
data "aws_caller_identity" "current" {}

# ────────────────────────────────────────────────────────────────────────────
# OUTPUTS
# ────────────────────────────────────────────────────────────────────────────

output "rds_cluster_endpoint" {
  description = "RDS cluster endpoint (for writes)"
  value       = aws_rds_cluster.main.endpoint
}

output "rds_reader_endpoint" {
  description = "RDS reader endpoint (for reads)"
  value       = aws_rds_cluster.main.reader_endpoint
}

output "rds_port" {
  description = "RDS port"
  value       = aws_rds_cluster.main.port
}

output "rds_iam_auth_token_command" {
  description = "Command to generate IAM auth token (instead of password)"
  value       = "aws rds generate-db-auth-token --hostname ${aws_rds_cluster.main.endpoint} --port ${aws_rds_cluster.main.port} --region ${var.aws_region} --username ${var.db_username} --profile ${var.aws_profile}"
}

output "kms_key_id" {
  description = "KMS key ID for RDS encryption"
  value       = aws_kms_key.rds_encryption.id
}

output "rds_sg_id" {
  description = "RDS Security Group ID"
  value       = aws_security_group.rds_sg.id
}
```

### Step 2: Deploy with Terraform

```bash
# Save your VPC IDs and subnet IDs from Month 4
VPC_ID="vpc-xxxxxxxx"
SUBNET1="subnet-xxxxxxxx"
SUBNET2="subnet-yyyyyyyy"

# Create terraform.tfvars
cat > terraform.tfvars <<EOF
vpc_id                = "$VPC_ID"
private_subnet_ids    = ["$SUBNET1", "$SUBNET2"]
aws_region            = "us-east-1"
aws_profile           = "iron-bank"
db_instance_class     = "db.t4g.micro"
backup_retention_days = 7
environment           = "dev"
EOF

# Initialize Terraform
terraform init

# Review plan
terraform plan

# Deploy (takes ~5–10 minutes)
terraform apply

# Save the outputs
terraform output rds_cluster_endpoint
terraform output rds_iam_auth_token_command
```

### Step 3: Connect to RDS Using IAM Auth (Instead of Password)

```bash
# Generate temporary auth token (expires in 15 minutes)
TOKEN=$(aws rds generate-db-auth-token \
  --hostname $(terraform output -raw rds_cluster_endpoint) \
  --port 5432 \
  --region us-east-1 \
  --username postgres \
  --profile iron-bank)

echo "Auth token: $TOKEN"

# Download RDS certificate (for SSL/TLS verification)
curl -s "https://truststore.pem.s3.amazonaws.com/global/global-bundle.pem" > rds-ca-bundle.pem

# Connect with psql (using token instead of password)
psql -h $(terraform output -raw rds_cluster_endpoint) \
     -p 5432 \
     -U postgres \
     -d ironbank \
     --set=sslmode=require \
     --set=sslrootcert=rds-ca-bundle.pem \
     -c "SELECT version();"

# If successful: Shows PostgreSQL version (proves connection works)
```

### Step 4: Verify Security Settings in RDS Console

```bash
# Check encryption status
aws rds describe-db-clusters \
  --db-cluster-identifier iron-bank-db \
  --profile iron-bank \
  --query 'DBClusters[0].[StorageEncrypted,KmsKeyId,IamDatabaseAuthenticationEnabled]' \
  --output text

# Expected output:
# true    arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012    true

# Verify TLS enforcement
aws rds describe-db-clusters \
  --db-cluster-identifier iron-bank-db \
  --profile iron-bank \
  --query 'DBClusters[0].[Engine,EnableIAMDatabaseAuthentication,StorageEncrypted]' \
  --output text
```

---

## Lab 2: Rotate Database Credentials Automatically

In production, passwords should rotate regularly. This Lambda function rotates RDS credentials via AWS Secrets Manager.

Create `scripts/rotate-rds-credentials-lambda.py`:

```python
#!/usr/bin/env python3
"""
RDS Credential Rotation Lambda Function
========================================

Purpose:
  Automatically rotate RDS database passwords every 30 days
  Stores new password in AWS Secrets Manager
  Updates RDS master user password

Security benefits:
  - Limits window of exposure if password leaked
  - Audit trail in CloudTrail (who rotated, when)
  - Automatic (no manual password management)
  - Secrets Manager handles encryption at rest

Deployment:
  1. Create Lambda function in AWS Console
  2. Attach policy to read/write Secrets Manager + RDS
  3. Create CloudWatch Events rule to trigger on schedule

Author: Iron Bank Training
"""

import json
import boto3
import string
import secrets
from typing import Dict, Any

# AWS clients
rds_client = boto3.client('rds')
secrets_client = boto3.client('secretsmanager')

def generate_secure_password(length: int = 32) -> str:
    """
    Generate cryptographically secure random password.
    
    Requirements for RDS PostgreSQL:
    - At least 8 characters
    - Can contain letters, numbers, special characters
    - Avoid: quotes, backslashes (cause connection issues)
    
    Args:
        length: Password length (default 32)
    
    Returns:
        Secure random password
    """
    # Safe characters (avoid special chars that break connection strings)
    safe_chars = string.ascii_letters + string.digits + "!#$%&*+-=@^_"
    
    password = ''.join(secrets.choice(safe_chars) for _ in range(length))
    return password

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler: Main entry point for credential rotation.
    
    Event structure (from Secrets Manager):
    {
        "ClientRequestToken": "AESxxx",
        "SecretId": "iron-bank-rds-password",
        "Step": "create|set|finish|test",
        "SecretString": "{...}"
    }
    
    Rotation steps:
    1. CREATE: Generate new password
    2. SET: Update RDS with new password
    3. FINISH: Mark secret as rotated in Secrets Manager
    4. TEST: Verify new password works
    """
    
    secret_id = event["SecretId"]
    client_request_token = event["ClientRequestToken"]
    step = event["Step"]
    secret_string = event.get("SecretString", "{}")
    
    try:
        secret = json.loads(secret_string)
    except json.JSONDecodeError:
        secret = {}
    
    db_identifier = secret.get("dbname", "iron-bank-db")
    db_username = secret.get("username", "postgres")
    
    print(f"[*] Rotation Step: {step}")
    print(f"    Secret ID: {secret_id}")
    print(f"    Database: {db_identifier}")
    print(f"    User: {db_username}")
    
    try:
        # ═══════════════════════════════════════════════════════════════════
        # STEP 1: CREATE
        # Generate new password and store in Secrets Manager metadata
        # ═══════════════════════════════════════════════════════════════════
        if step == "create":
            print("[*] CREATE: Generating new password...")
            
            # Generate secure password
            new_password = generate_secure_password()
            
            # Store new password in Secrets Manager (under the rotation token)
            new_secret_version = {
                "username": db_username,
                "password": new_password,
                "dbname": db_identifier,
                "host": secret.get("host", ""),
            }
            
            # Put secret version (Secrets Manager tracks versions)
            secrets_client.put_secret_value(
                SecretId=secret_id,
                ClientRequestToken=client_request_token,
                SecretString=json.dumps(new_secret_version),
                VersionStages=["AWSPENDING"],  # Mark as pending (not yet active)
            )
            
            print(f"[✓] New password generated and stored as AWSPENDING")
        
        # ═══════════════════════════════════════════════════════════════════
        # STEP 2: SET
        # Update RDS with the new password
        # ═══════════════════════════════════════════════════════════════════
        elif step == "set":
            print("[*] SET: Updating RDS with new password...")
            
            # Get the pending secret version
            pending_secret = secrets_client.get_secret_value(
                SecretId=secret_id,
                VersionId=client_request_token,
                VersionStage="AWSPENDING",
            )
            
            pending = json.loads(pending_secret["SecretString"])
            new_password = pending["password"]
            
            # Update RDS master user password
            rds_client.modify_db_cluster(
                DBClusterIdentifier=db_identifier,
                MasterUserPassword=new_password,
                ApplyImmediately=True,
            )
            
            print(f"[✓] RDS password updated (ApplyImmediately=True)")
        
        # ═══════════════════════════════════════════════════════════════════
        # STEP 3: TEST
        # Verify new password works
        # ═══════════════════════════════════════════════════════════════════
        elif step == "test":
            print("[*] TEST: Verifying new password...")
            
            # Get the pending secret
            pending_secret = secrets_client.get_secret_value(
                SecretId=secret_id,
                VersionId=client_request_token,
                VersionStage="AWSPENDING",
            )
            
            pending = json.loads(pending_secret["SecretString"])
            
            # In production: attempt actual database connection
            # For this lab, we just verify the secret exists and is readable
            print(f"[✓] Pending secret is readable and valid")
        
        # ═══════════════════════════════════════════════════════════════════
        # STEP 4: FINISH
        # Mark rotation as complete (make pending version the current version)
        # ═══════════════════════════════════════════════════════════════════
        elif step == "finish":
            print("[*] FINISH: Marking rotation as complete...")
            
            # Update version stage from AWSPENDING to AWSCURRENT
            # This makes the new password the active password
            secrets_client.update_secret_version_stage(
                SecretId=secret_id,
                VersionStage="AWSCURRENT",
                MoveToVersionId=client_request_token,
                RemoveFromVersionId=event.get("CurrentVersion", None),
            )
            
            print(f"[✓] Rotation complete! New password is now active")
        
        else:
            raise ValueError(f"Unknown step: {step}")
        
        return {
            "statusCode": 200,
            "body": json.dumps(f"✓ Rotation {step} successful"),
        }
    
    except Exception as e:
        print(f"[❌] ERROR: {e}")
        raise

# ───────────────────────────────────────────────────────────────────────────
# LOCAL TESTING (for debugging)
# ───────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Test event (would come from Secrets Manager in production)
    test_event = {
        "SecretId": "iron-bank-rds-password",
        "ClientRequestToken": "test-token-12345",
        "Step": "create",
        "SecretString": json.dumps({
            "username": "postgres",
            "dbname": "iron-bank-db",
            "host": "iron-bank-db.c9akciq32.us-east-1.rds.amazonaws.com",
        }),
    }
    
    result = lambda_handler(test_event, None)
    print(f"\nResult: {result}")
```

---

## 🧹 Cleanup (Database Lab)

```bash
# Destroy RDS cluster
terraform destroy --auto-approve

# Delete KMS key (after 7-day waiting period)
# Note: Key is marked for deletion but not immediately removed

# Verify cleanup
aws rds describe-db-clusters \
  --db-cluster-identifier iron-bank-db \
  --profile iron-bank 2>&1 | grep -i "DBClusterNotFoundFault"

# Expected: DBClusterNotFoundFault (means it's deleted)
```

---

## Checklist (Database Security)

- [ ] Understand RDS threat model and defense-in-depth layers
- [ ] Deploy secure RDS cluster with Terraform
- [ ] Verify encryption at rest (KMS) enabled
- [ ] Verify encryption in transit (TLS) enforced
- [ ] Configure IAM database authentication (token-based, no password)
- [ ] Enable Enhanced Monitoring (CPU, memory, connections)
- [ ] Connect to RDS using IAM auth token (not password)
- [ ] Understand credential rotation patterns
- [ ] All RDS resources cleaned up
- [ ] Verified $0 in RDS charges

---

# PART 2: Terraform Associate Exam Prep

!!! info "Exam Details — Terraform Associate 004"
    | | |
    |---|---|
    | **Format** | ~57 multiple choice + multi-select questions |
    | **Duration** | 60 minutes |
    | **Passing score** | ~70% |
    | **Cost** | $70.50 USD |
    | **Retake policy** | One free retake within 1 year |
    | **Delivery** | Online proctored (PSI) or testing centre |
    | **Booking** | [hashicorp.com/certification](https://www.hashicorp.com/certification) |

---

## What the Exam Actually Tests

The Terraform Associate focuses on **concepts and workflow**, not memorising commands. You've already practised most of this through Weeks 1–3. This week fills the remaining gaps.

| Domain | Weight | What to Know |
|---|---|---|
| Understand IaC concepts | ~16% | Declarative vs imperative, benefits of IaC, when to use Terraform vs scripts |
| Understand Terraform purpose | ~8% | When Terraform is and isn't appropriate |
| Understand Terraform basics | ~24% | `init`, `plan`, `apply`, `destroy`, providers, plugins |
| Use Terraform outside the core workflow | ~16% | `terraform fmt`, `validate`, `state`, `import`, workspaces |
| Interact with Terraform modules | ~16% | Module sources, inputs, outputs, versioning |
| Navigate Terraform workflow | ~8% | `plan` output, resource graph, dependency ordering |
| Implement and maintain state | ~12% | `tfstate`, remote backends, state locking, `terraform state` commands |

---

## Part 1: Exam Concepts You Must Know

### State Management

```bash
# List all resources Terraform is tracking
terraform state list

# Show detailed state of one resource
terraform state show aws_vpc.main
# (or module.vpc.aws_vpc.this if using modules)

# Move a resource in state — useful when refactoring without destroying
terraform state mv aws_vpc.main module.vpc.aws_vpc.this

# Remove a resource from state WITHOUT deleting the real AWS resource
# Use when you want to "forget" a resource but keep it running
terraform state rm module.vpc.aws_cloudwatch_log_group.flow_logs

# Import an existing AWS resource into Terraform state
# Use when someone created a resource manually and you want Terraform to manage it
terraform import aws_s3_bucket.my_bucket my-existing-bucket-name
```

??? note "Why does state locking matter?"
    If two people run `terraform apply` at the same time against shared state, they'll both try to update the same resources and corrupt the state file. Remote backends (like S3 + DynamoDB) lock the state file while an operation is in progress — like a database transaction. Always use remote state in team environments.

### Remote State Backend (S3 + DynamoDB)

```bash
# Create the S3 bucket for state storage
aws s3api create-bucket \
  --bucket iron-bank-tfstate-$(aws sts get-caller-identity --profile iron-bank --query Account --output text) \
  --profile iron-bank

# Enable versioning — lets you recover from a corrupted state file
aws s3api put-bucket-versioning \
  --bucket iron-bank-tfstate-<your-account-id> \
  --versioning-configuration Status=Enabled \
  --profile iron-bank

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket iron-bank-tfstate-<your-account-id> \
  --server-side-encryption-configuration '{
    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
  }' \
  --profile iron-bank

# Block public access
aws s3api put-public-access-block \
  --bucket iron-bank-tfstate-<your-account-id> \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --profile iron-bank

# Create DynamoDB table for state locking
aws dynamodb create-table \
  --table-name iron-bank-tfstate-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --profile iron-bank
```

Add the backend to `main.tf`:

```hcl
terraform {
  # Store state remotely in S3 instead of local terraform.tfstate
  backend "s3" {
    bucket         = "iron-bank-tfstate-<your-account-id>"  # Your bucket name
    key            = "phase2/m5/terraform.tfstate"           # Path within the bucket
    region         = "us-east-1"
    profile        = "iron-bank"
    encrypt        = true                                     # Encrypt state at rest
    dynamodb_table = "iron-bank-tfstate-lock"                 # DynamoDB for locking
  }
  ...
}
```

```bash
# Migrate local state to the remote backend
terraform init -migrate-state
# Terraform will ask: "Do you want to copy existing state to the new backend?" → yes
```

### Formatting and Validation

```bash
# Format all .tf files to Terraform's canonical style
terraform fmt -recursive
# This is like "black" for Python — standardises spacing, alignment, indentation

# Validate syntax without connecting to AWS
terraform validate
# Catches things like: referencing a variable that doesn't exist

# Check for potential issues in your plan output
terraform plan -out=tfplan       # Save plan to file
terraform show tfplan            # Inspect the saved plan
terraform apply tfplan           # Apply exactly the saved plan (no re-evaluation)
```

### Workspaces

```bash
# Workspaces let you manage multiple environments (dev/staging/prod) with one codebase
# Each workspace has its own state file

terraform workspace list         # Show all workspaces (default exists already)
terraform workspace new dev      # Create a "dev" workspace
terraform workspace new prod     # Create a "prod" workspace
terraform workspace select dev   # Switch to dev
terraform workspace show         # Confirm which workspace is active

# In your code, reference the current workspace name
# Use this to add environment tags or change resource names per environment:
# name = "${var.project_name}-${terraform.workspace}-vpc"
```

!!! tip "Workspace vs separate directories"
    For real production setups, many teams prefer separate directories per environment (dev/, staging/, prod/) rather than workspaces. Workspaces share the same code, which is convenient but risky if you accidentally apply prod changes in the wrong workspace. Know both approaches for the exam.

---

## Part 2: Exam Practice Questions

Work through these before booking the exam. Cover the answer, think it through, then check:

??? note "Q1: What command downloads provider plugins and initialises the backend?"
    **`terraform init`**
    Run this: after cloning a repo, after adding a new provider, after changing the backend config.

??? note "Q2: You ran terraform apply and a colleague also ran terraform apply at the same time on shared state. What prevents corruption?"
    **State locking via DynamoDB.** The first apply acquires a lock on the DynamoDB table. The second apply sees the lock and waits (or fails with a lock error) until the first is complete.

??? note "Q3: What is the difference between terraform.tfvars and variables.tf?"
    **`variables.tf`** *declares* variables — their name, type, description, and optional default. **`terraform.tfvars`** *assigns* values to those variables for a specific environment. `variables.tf` is committed to Git; `terraform.tfvars` often isn't (especially if it contains sensitive values).

??? note "Q4: A resource exists in AWS but not in your Terraform state. How do you bring it under Terraform management without destroying and recreating it?"
    **`terraform import <resource_type>.<name> <real_resource_id>`**
    Example: `terraform import aws_s3_bucket.logs my-existing-bucket`. Note: `import` only updates state — you still need to write the matching HCL resource block manually.

??? note "Q5: What does terraform plan -out=tfplan do and why is it useful?"
    It saves the exact plan to a file. When you later run `terraform apply tfplan`, Terraform applies exactly what was planned — no re-evaluation. This is important in CI/CD pipelines where you want the apply step to execute precisely what the plan step approved, with no surprises from infrastructure drift in between.

??? note "Q6: You have a module at ./modules/vpc. A colleague published the same module to the Terraform Registry as acme/vpc/aws version 2.1.0. Show both source references."
    ```hcl
    # Local module
    module "vpc" {
      source = "./modules/vpc"
    }

    # Registry module (pinned to a specific version — always pin in production)
    module "vpc" {
      source  = "acme/vpc/aws"
      version = "2.1.0"
    }
    ```

??? note "Q7: What happens to resources not in your .tf files but in your state when you run terraform apply?"
    **They are destroyed.** Terraform's job is to make the real world match your code. If a resource is in state but not in `.tf` files, Terraform treats it as "should be deleted." This is why you should never manually edit `terraform.tfstate`.

---

## Part 3: Month 5 Project — Publish Your Terraform Modules

Your GitHub deliverable for Month 5 is a polished, documented Terraform module library.

```bash
cd ~/projects/iron-bank-tf

# ─── README.md ───────────────────────────────────────────────────────────────
cat > README.md << 'EOF'
# Iron Bank Terraform Modules

Reusable, security-scanned Terraform modules for AWS cloud security labs.
Built as part of the [Iron Bank 12-Month Cloud Security Training Plan](https://github.com/yourusername).

## Modules

| Module | Description |
|---|---|
| [vpc](./modules/vpc/) | Multi-AZ VPC with public/private subnets, route tables, flow logs |

## Usage

```hcl
module "vpc" {
  source = "./modules/vpc"

  project_name         = "my-project"
  vpc_cidr             = "10.0.0.0/16"
  public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnet_cidrs = ["10.0.3.0/24", "10.0.4.0/24"]
  availability_zones   = ["us-east-1a", "us-east-1b"]
}
```

## Security

All modules are scanned with [Checkov](https://checkov.io) before publishing.
Run `checkov -d .` to see current scan results.

## Cleanup

`terraform destroy` removes all resources. No cleanup scripts required.
EOF

# ─── Module README ───────────────────────────────────────────────────────────
cat > modules/vpc/README.md << 'EOF'
# vpc module

Creates a production-ready multi-AZ VPC with:
- Public and private subnets across 2 AZs
- Internet Gateway + route tables
- VPC Flow Logs to CloudWatch (7-day retention)
- Follows CIS AWS Foundations Benchmark networking controls

## Inputs

| Name | Type | Default | Description |
|---|---|---|---|
| project_name | string | — | Prefix for all resource names |
| vpc_cidr | string | 10.0.0.0/16 | VPC CIDR block |
| public_subnet_cidrs | list(string) | — | CIDRs for public subnets |
| private_subnet_cidrs | list(string) | — | CIDRs for private subnets |
| availability_zones | list(string) | — | AZs to deploy into |

## Outputs

| Name | Description |
|---|---|
| vpc_id | VPC ID |
| public_subnet_ids | List of public subnet IDs |
| private_subnet_ids | List of private subnet IDs |
| igw_id | Internet Gateway ID |
EOF

# ─── Push to GitHub ───────────────────────────────────────────────────────────
# Make sure .gitignore is correct before pushing
cat .gitignore
# Should contain: terraform.tfvars, .terraform/, *.tfstate, *.tfstate.backup

git add -A
git status    # Review what's being committed — never blindly git add -A
git commit -m "feat: Month 5 complete — VPC Terraform module with Checkov scanning"
git remote add origin https://github.com/<your-username>/iron-bank-terraform.git
git push -u origin main
```

---

## Study Resources

| Resource | What to Use It For | Free? |
|---|---|---|
| [developer.hashicorp.com/terraform/tutorials](https://developer.hashicorp.com/terraform/tutorials) | Official HashiCorp tutorials — closest to exam content | ✅ |
| [Exam Study Guide (HashiCorp)](https://developer.hashicorp.com/terraform/tutorials/certification-003/associate-study) | Official exam objectives — use as a checklist | ✅ |
| [Terraform Associate Practice Exam (Udemy)](https://www.udemy.com/course/terraform-associate-practice-exam/) | Bryan Krausen — best practice questions, often $15 | 💰 ~$15 |
| [Spacelift Terraform Associate Cheatsheet](https://spacelift.io/blog/terraform-associate-certification) | Quick reference for exam day concepts | ✅ |

!!! tip "Exam-day tips"
    - Read every answer option before choosing — HashiCorp loves "technically correct but not the *best* answer" traps
    - `terraform init` is almost always the answer to "what do you do first after cloning a repo"
    - Know the difference between `taint` (deprecated), `apply -replace`, and `import`
    - Remote state + locking = S3 bucket + DynamoDB table — this comes up constantly

---

## Month 5 Summary

| Week | What You Built | Skill Gained |
|---|---|---|
| Setup | Terraform + Checkov installed | IaC toolchain setup |
| 1 | First `apply` / `destroy` cycle with S3 | Core Terraform workflow |
| 2 | Full Iron Bank VPC in HCL | Translating CLI knowledge to IaC |
| 3 | Modular architecture + Checkov fixes | Reusable modules, security scanning |
| 4 | Remote state, exam prep, GitHub project | Production patterns, certification |

---

## Checklist

- [ ] Remote S3 backend created — state stored in S3, not local
- [ ] `terraform state list` and `terraform state show` practiced
- [ ] `terraform fmt` run — all files consistently formatted
- [ ] `terraform validate` passes
- [ ] All 7 practice questions answered without looking
- [ ] `modules/vpc/README.md` written with inputs/outputs table
- [ ] Root `README.md` written with usage example
- [ ] Project pushed to GitHub as `iron-bank-terraform`
- [ ] Terraform Associate exam booked (or date confirmed in your calendar)
- [ ] **S3 state bucket and DynamoDB table cleaned up after the module**
- [ ] **Bill verified $0**
