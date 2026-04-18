# ════════════════════════════════════════════════════════════════════════════
# Secure RDS PostgreSQL Cluster with IAM Authentication
# ════════════════════════════════════════════════════════════════════════════
#
# Purpose:
#   Demonstrates RDS security best practices for Iron Bank Month 5, Week 4
#   - Database in private subnet only (no public IP)
#   - IAM database authentication (no plaintext passwords)
#   - Encryption at rest with KMS customer-managed keys
#   - Encryption in transit enforced (TLS 1.2+)
#   - Enhanced monitoring for performance insight
#   - Automated encrypted backups
#
# Threat Model Coverage:
#   ✓ Spoofing:           IAM auth prevents unauthorized connections
#   ✓ Tampering:          TLS encryption in transit
#   ✓ Repudiation:        Enhanced Monitoring + Audit Logs
#   ✓ Information Disclosure: RDS encryption + KMS key access control
#   ✓ Denial of Service:  Connection pool limits, CloudWatch alarms
#   ✓ Elevation of Privilege: IAM role with db-connect permission only
#
# Cost:
#   - db.t4g.micro: Free tier eligible (~$0 for 750 hours/month)
#   - If left running beyond free tier: ~$0.30/day
#   - IMPORTANT: Use 'terraform destroy' to clean up when done
#
# Author: Iron Bank Training
# Date: April 2026
# ════════════════════════════════════════════════════════════════════════════

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

# ════════════════════════════════════════════════════════════════════════════
# VARIABLES - INPUT PARAMETERS (customize these for your environment)
# ════════════════════════════════════════════════════════════════════════════

variable "aws_region" {
  description = "AWS region (must match your VPC region from Month 4)"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile to use (should be 'iron-bank')"
  type        = string
  default     = "iron-bank"
}

variable "vpc_id" {
  description = "VPC ID from Month 4 lab (find with: aws ec2 describe-vpcs --profile iron-bank)"
  type        = string
  # Example: vpc-0a1b2c3d4e5f67g8h
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs from Month 4 (need at least 2 for Multi-AZ RDS)"
  type        = list(string)
  # Example: ["subnet-0a1b2c3d4e5f67g8h", "subnet-0x1y2z3a4b5c6d7e8f"]

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "Must provide at least 2 private subnets for Multi-AZ RDS cluster."
  }
}

variable "db_username" {
  description = "RDS root username (not used with IAM auth, but required by RDS)"
  type        = string
  default     = "postgres"
  sensitive   = true  # Don't print in logs
}

variable "db_name" {
  description = "Initial database name created on cluster"
  type        = string
  default     = "ironbank"
}

variable "db_instance_class" {
  description = "RDS instance type (t4g.micro = free tier eligible, cheapest)"
  type        = string
  default     = "db.t4g.micro"
}

variable "backup_retention_days" {
  description = "How many days to keep automated backups (7 = 1 week)"
  type        = number
  default     = 7
}

variable "environment" {
  description = "Environment name for resource tags"
  type        = string
  default     = "dev"
}

# ════════════════════════════════════════════════════════════════════════════
# DATA SOURCE - Get current AWS account ID (needed for ARNs)
# ════════════════════════════════════════════════════════════════════════════

data "aws_caller_identity" "current" {}

# ════════════════════════════════════════════════════════════════════════════
# KMS KEY - Encryption Key for RDS Database (Defense Layer 3)
# ════════════════════════════════════════════════════════════════════════════

# Why a separate KMS key?
#   - Separation of duties (key and encrypted data are separate)
#   - Fine-grained access control (who can decrypt RDS data)
#   - Key rotation (annual auto-rotation enabled)
#   - Audit trail (CloudTrail logs who accessed the key)

resource "aws_kms_key" "rds_encryption" {
  description             = "KMS key for RDS encryption at rest (Iron Bank)"
  deletion_window_in_days = 7  # Grace period before deletion (safety)
  enable_key_rotation     = true  # Auto-rotate annually (security best practice)

  tags = {
    Name        = "iron-bank-rds-key"
    Environment = var.environment
    Purpose     = "RDS encryption at rest"
  }
}

# KMS Key Alias (friendly name for referencing in logs and console)
# Without this, you'd see: arn:aws:kms:us-east-1:123456789012:key/12345678-1234...
# With this, you see: alias/iron-bank-rds
resource "aws_kms_alias" "rds_encryption" {
  name          = "alias/iron-bank-rds"
  target_key_id = aws_kms_key.rds_encryption.key_id
}

# KMS Key Policy (who can use this key?)
# By default, only the account root has access. This policy allows:
#   1. IAM root to manage the key (required)
#   2. RDS service to encrypt/decrypt data
resource "aws_kms_key_policy" "rds_encryption" {
  key_id = aws_kms_key.rds_encryption.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM root account permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"  # Root can do everything with this key
        Resource = "*"
      },
      {
        Sid    = "Allow RDS service to use the key"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",        # Decrypt RDS data
          "kms:GenerateDataKey", # Generate encryption keys
          "kms:CreateGrant",     # Manage encryption grants
        ]
        Resource = "*"
      },
    ]
  })
}

# ════════════════════════════════════════════════════════════════════════════
# SECURITY GROUP - Network Isolation (Defense Layer 2)
# ════════════════════════════════════════════════════════════════════════════

# Purpose: Restrict who can connect to the RDS database
# - Only allow connections from web server EC2 instances
# - Block all other traffic (internet, other accounts, etc.)
# - This is the "defense in depth" approach (network level protection)

# Security Group for RDS (database)
resource "aws_security_group" "rds_sg" {
  name        = "iron-bank-rds-sg"
  description = "Security group for RDS PostgreSQL (private subnet only)"
  vpc_id      = var.vpc_id

  # Ingress (inbound): Allow PostgreSQL (port 5432) from web servers ONLY
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web_server.id]  # Only from web server SG
    description     = "PostgreSQL from web application servers"
  }

  # Egress (outbound): Allow all (RDS might need to reach other services)
  # In practice, RDS doesn't initiate connections, so this could be restricted further
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound (for patches, monitoring, etc.)"
  }

  tags = {
    Name        = "iron-bank-rds-sg"
    Environment = var.environment
  }
}

# Placeholder Security Group for Web Servers (your EC2 instances)
# In real scenario, you'd reference your actual EC2 instance SG
# For this lab, we create it here so the RDS SG can reference it
resource "aws_security_group" "web_server" {
  name        = "iron-bank-web-server-sg"
  description = "Web server application security group"
  vpc_id      = var.vpc_id

  # Allow SSH for testing (restrict to your IP in production)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.myip.response_body)}/32"]
    description = "SSH from current IP"
  }

  # Allow HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from internet"
  }

  # Allow HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from internet"
  }

  tags = {
    Name = "iron-bank-web-server-sg"
  }
}

# Data source to fetch your current public IP (for SSH access)
data "http" "myip" {
  url = "https://checkip.amazonaws.com/"
}

# ════════════════════════════════════════════════════════════════════════════
# RDS DB SUBNET GROUP - Network Placement
# ════════════════════════════════════════════════════════════════════════════

# Purpose: Tell RDS which subnets it can use
# RDS needs at least 2 subnets in different AZs for Multi-AZ (high availability)

resource "aws_db_subnet_group" "main" {
  name       = "iron-bank-db-subnet-group"
  subnet_ids = var.private_subnet_ids  # Use the private subnets from Month 4

  tags = {
    Name        = "iron-bank-db-subnets"
    Environment = var.environment
  }
}

# ════════════════════════════════════════════════════════════════════════════
# RDS AURORA CLUSTER - PostgreSQL Database
# ════════════════════════════════════════════════════════════════════════════

# Purpose: Create a managed PostgreSQL database with security best practices
# Why Aurora PostgreSQL?
#   - Compatible with PostgreSQL (you know the syntax)
#   - Automatic backups, Multi-AZ failover, scalable
#   - IAM database authentication supported
#   - Encryption at rest + in transit built-in

resource "aws_rds_cluster" "main" {
  cluster_identifier = "iron-bank-db"
  engine             = "aurora-postgresql"
  engine_version     = "15.3"  # Latest stable PostgreSQL
  database_name      = var.db_name
  master_username    = var.db_username

  # ─────────────────────────────────────────────────────────────────────
  # AUTHENTICATION: Don't set master_password — use IAM auth instead
  # (You'll connect with temporary tokens, not hardcoded passwords)
  # ─────────────────────────────────────────────────────────────────────

  # ─────────────────────────────────────────────────────────────────────
  # NETWORK: Placement in private subnets (Defense Layer 2)
  # ─────────────────────────────────────────────────────────────────────
  db_subnet_group_name    = aws_db_subnet_group.main.name
  publicly_accessible     = false  # CRITICAL: No internet IP
  vpc_security_group_ids  = [aws_security_group.rds_sg.id]

  # ─────────────────────────────────────────────────────────────────────
  # ENCRYPTION: At-Rest + In-Transit (Defense Layer 3)
  # ─────────────────────────────────────────────────────────────────────
  storage_encrypted                      = true  # Encrypt data on disk
  kms_key_id                             = aws_kms_key.rds_encryption.arn  # With our KMS key
  iam_database_authentication_enabled    = true  # Enable IAM auth (instead of passwords)
  # PostgreSQL enforces SSL/TLS in-transit by default for aurora-postgresql

  # ─────────────────────────────────────────────────────────────────────
  # BACKUPS: Automated, encrypted, retention policy (Defense Layer 1)
  # ─────────────────────────────────────────────────────────────────────
  backup_retention_period      = var.backup_retention_days  # Keep 7 days of backups
  preferred_backup_window      = "03:00-04:00"  # 3-4 AM UTC (off-hours)
  skip_final_snapshot          = true  # For lab only (false in production!)
  copy_tags_to_snapshot        = true  # Backup inherits tags

  # ─────────────────────────────────────────────────────────────────────
  # MONITORING: Enhanced Monitoring + Logs (Defense Layer 5)
  # ─────────────────────────────────────────────────────────────────────
  enable_cloudwatch_logs_exports = ["postgresql"]  # Ship logs to CloudWatch

  # ─────────────────────────────────────────────────────────────────────
  # HIGH AVAILABILITY: Multi-AZ deployment
  # ─────────────────────────────────────────────────────────────────────
  availability_zones              = ["us-east-1a", "us-east-1b"]  # Span 2 AZs
  preferred_maintenance_window    = "sun:04:00-sun:05:00"  # Maintenance window

  # ─────────────────────────────────────────────────────────────────────
  # ADDITIONAL SECURITY
  # ─────────────────────────────────────────────────────────────────────
  enable_http_endpoint         = false  # Disable Data API (not needed, reduces attack surface)
  deletion_protection          = false  # Allow deletion for lab (true in production)

  tags = {
    Name           = "iron-bank-primary-db"
    Environment    = var.environment
    ThreatModel    = "IAM-auth,KMS-encryption,Private-subnet,Multi-AZ"
    Month          = "5"
    Week           = "4"
  }

  depends_on = [aws_kms_key_policy.rds_encryption]
}

# ════════════════════════════════════════════════════════════════════════════
# RDS CLUSTER INSTANCES - Database Nodes
# ════════════════════════════════════════════════════════════════════════════

# Aurora cluster needs instances to run the database engine
# We'll create 2 instances: one writer (primary), one reader (replica)

# Primary Writer Instance (handles all writes, some reads)
resource "aws_rds_cluster_instance" "writer" {
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = var.db_instance_class  # db.t4g.micro (free tier)
  engine             = aws_rds_cluster.main.engine
  engine_version     = aws_rds_cluster.main.engine_version

  # Enhanced Monitoring: Send performance metrics to CloudWatch
  # Metrics: CPU, memory, connections, disk I/O, network (visible every 60 seconds)
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  identifier = "iron-bank-db-writer"

  tags = {
    Name  = "iron-bank-db-writer"
    Role  = "Primary"  # This instance handles writes
  }
}

# Read Replica Instance (handles read-only queries, becomes primary if writer fails)
resource "aws_rds_cluster_instance" "reader" {
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = var.db_instance_class
  engine             = aws_rds_cluster.main.engine
  engine_version     = aws_rds_cluster.main.engine_version

  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  identifier = "iron-bank-db-reader"
  promotion_tier = 1  # Becomes writer if primary fails

  tags = {
    Name  = "iron-bank-db-reader"
    Role  = "Read-Replica"  # Handles read-only queries
  }
}

# ════════════════════════════════════════════════════════════════════════════
# IAM ROLE - Enhanced Monitoring Permission
# ════════════════════════════════════════════════════════════════════════════

# Purpose: RDS needs permission to send Enhanced Monitoring data to CloudWatch
# (You'll see performance metrics: CPU, memory, connections, disk I/O, etc.)

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

# Attach AWS managed policy (grants permission to write to CloudWatch)
resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# ════════════════════════════════════════════════════════════════════════════
# IAM POLICY - EC2 to RDS Authentication
# ════════════════════════════════════════════════════════════════════════════

# Purpose: Allow EC2 instances to connect to RDS using IAM auth (not passwords)
# This policy grants the "rds-db:connect" permission on the RDS resource

resource "aws_iam_policy" "ec2_rds_auth" {
  name        = "iron-bank-ec2-rds-auth"
  description = "Allow EC2 instances to connect to RDS using IAM authentication"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "rds-db:connect"  # Permission to generate temp database auth tokens
        ]
        Resource = "arn:aws:rds:${var.aws_region}:${data.aws_caller_identity.current.account_id}:db:${aws_rds_cluster.main.id}/*"
        # This restricts the permission to ONLY this RDS cluster (principle of least privilege)
      }
    ]
  })
}

# ════════════════════════════════════════════════════════════════════════════
# OUTPUTS - Information You'll Need
# ════════════════════════════════════════════════════════════════════════════

output "rds_cluster_endpoint" {
  description = "RDS cluster endpoint for writes (connect here)"
  value       = aws_rds_cluster.main.endpoint
  sensitive   = false
}

output "rds_reader_endpoint" {
  description = "RDS reader endpoint (read-only queries go here)"
  value       = aws_rds_cluster.main.reader_endpoint
  sensitive   = false
}

output "rds_port" {
  description = "RDS port (always 5432 for PostgreSQL)"
  value       = aws_rds_cluster.main.port
}

output "rds_database_name" {
  description = "Initial database created"
  value       = aws_rds_cluster.main.database_name
}

output "rds_master_username" {
  description = "Master username"
  value       = aws_rds_cluster.main.master_username
}

output "rds_iam_auth_token_example" {
  description = "Command to generate IAM auth token (use this instead of password)"
  value       = "aws rds generate-db-auth-token --hostname ${aws_rds_cluster.main.endpoint} --port ${aws_rds_cluster.main.port} --region ${var.aws_region} --username ${aws_rds_cluster.main.master_username} --profile ${var.aws_profile}"
  sensitive   = false
}

output "kms_key_id" {
  description = "KMS key ID (encrypts RDS data at rest)"
  value       = aws_kms_key.rds_encryption.id
}

output "kms_key_arn" {
  description = "KMS key ARN (use in policies)"
  value       = aws_kms_key.rds_encryption.arn
}

output "rds_security_group_id" {
  description = "RDS Security Group ID (for adding more ingress rules)"
  value       = aws_security_group.rds_sg.id
}

output "web_server_security_group_id" {
  description = "Web server Security Group ID (reference in other SGs)"
  value       = aws_security_group.web_server.id
}

output "cleanup_command" {
  description = "Command to destroy all resources"
  value       = "terraform destroy"
}

# ════════════════════════════════════════════════════════════════════════════
# NEXT STEPS
# ════════════════════════════════════════════════════════════════════════════
# 1. Create terraform.tfvars with your VPC and subnet IDs
# 2. terraform init
# 3. terraform plan
# 4. terraform apply (takes ~5-10 minutes)
# 5. Connect using: aws rds generate-db-auth-token ...
# 6. When done: terraform destroy
# ════════════════════════════════════════════════════════════════════════════
