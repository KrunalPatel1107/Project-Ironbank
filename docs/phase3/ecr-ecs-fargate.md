# Month 9 — Week 2: ECR & ECS Fargate

!!! danger "💰 Cost Warning"
    - **ECR:** $0.10/GB/month storage. A small image (~100MB) costs ~$0.01/month. **Delete the image after the lab.**
    - **ECS Fargate:** ~$0.04/vCPU/hour + $0.004/GB/hour. Running a 0.25 vCPU / 0.5GB task for 2 hours = **~$0.02**. **Always `terraform destroy` when done.**
    - **No NAT Gateway** — use VPC Interface Endpoints to keep private tasks reachable by ECR and SSM without paying $32/month.

!!! info "Background Context"
    ECS Fargate = serverless containers. You write a task definition (like a pod spec), AWS runs the container on managed infrastructure — no EC2 to patch. This is how most AWS-native teams deploy microservices. Combining this with ECR scanning means every deployment automatically checks for CVEs before going live.

---

## Architecture This Week

```
ECR Repository (stores your Docker image)
       ↓  push
ECS Cluster → Fargate Task (runs your container)
       ↑
  Task Role (IAM — least privilege, no long-term keys)
  Secrets Manager (DB passwords, API keys — not env vars)
  VPC Private Subnet (no public IP on the task)
```

---

## Part 1: Push Your Secure Image to ECR

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --profile iron-bank --query Account --output text)
REGION="us-east-1"
REPO_NAME="iron-bank-app"

# ─── Create an ECR repository ─────────────────────────────────────────────────
aws ecr create-repository \
  --repository-name $REPO_NAME \
  --image-scanning-configuration scanOnPush=true \
  --encryption-configuration encryptionType=AES256 \
  --profile iron-bank \
  --region $REGION

# scanOnPush=true = Trivy-equivalent scan runs automatically on every push
# encryptionType=AES256 = images encrypted at rest in S3

ECR_URI="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${REPO_NAME}"
echo "ECR URI: $ECR_URI"

# ─── Authenticate Docker to ECR ───────────────────────────────────────────────
aws ecr get-login-password \
  --region $REGION \
  --profile iron-bank | \
docker login \
  --username AWS \
  --password-stdin \
  "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

# ─── Build, tag, and push your secure image ──────────────────────────────────
docker build -t iron-bank-app ~/projects/secure-app/
docker tag iron-bank-app:latest "${ECR_URI}:latest"
docker push "${ECR_URI}:latest"

echo "✅ Image pushed to ECR"

# ─── Check the ECR scan results ───────────────────────────────────────────────
# Wait ~30 seconds for the scan to complete
sleep 30
aws ecr describe-image-scan-findings \
  --repository-name $REPO_NAME \
  --image-id imageTag=latest \
  --profile iron-bank \
  --region $REGION \
  --query 'imageScanFindings.findingSeverityCounts'
# Expected output: {"CRITICAL": 0, "HIGH": 2, ...} — your alpine image should be clean
```

---

## Part 2: Deploy to ECS Fargate via Terraform

```bash
cd ~/projects/iron-bank-tf
mkdir -p modules/ecs
touch modules/ecs/main.tf modules/ecs/variables.tf modules/ecs/outputs.tf
```

**`modules/ecs/variables.tf`:**

```hcl
variable "project_name"    { type = string }
variable "vpc_id"          { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "ecr_image_uri"   { type = string }
variable "task_cpu"        { type = number; default = 256 }   # 256 = 0.25 vCPU
variable "task_memory"     { type = number; default = 512 }   # MB
```

**`modules/ecs/main.tf`:**

```hcl
# ─── ECS Cluster ──────────────────────────────────────────────────────────────
resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"    # CloudWatch Container Insights — monitoring and logging
  }

  tags = { Project = var.project_name }
}

# ─── IAM Task Execution Role (used by ECS to pull the image and send logs) ────
resource "aws_iam_role" "execution" {
  name = "${var.project_name}-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
  # Allows: ECR pull, CloudWatch Logs write, Secrets Manager read for secrets injection
}

# ─── IAM Task Role (what YOUR application code can access) ────────────────────
# This is different from the Execution Role — it's the runtime identity of your app
resource "aws_iam_role" "task" {
  name = "${var.project_name}-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Add only the permissions your app actually needs (least privilege)
# Example: if your app reads from S3:
# resource "aws_iam_role_policy" "task_s3" {
#   role   = aws_iam_role.task.id
#   policy = jsonencode({ Statement = [{ Effect="Allow", Action=["s3:GetObject"], Resource="arn:aws:s3:::my-bucket/*" }] })
# }

# ─── CloudWatch Log Group ─────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${var.project_name}"
  retention_in_days = 7    # Lab: 7 days. Production: 90+ days
  tags = { Project = var.project_name }
}

# ─── ECS Task Definition ──────────────────────────────────────────────────────
resource "aws_ecs_task_definition" "app" {
  family                   = "${var.project_name}-task"
  network_mode             = "awsvpc"          # Required for Fargate
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([{
    name  = "app"
    image = var.ecr_image_uri    # Full ECR URI with tag

    # Port mapping — only expose the port your app needs
    portMappings = [{ containerPort = 3000, protocol = "tcp" }]

    # CloudWatch log configuration
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.app.name
        awslogs-region        = "us-east-1"
        awslogs-stream-prefix = "ecs"
      }
    }

    # Security hardening at the task level
    readonlyRootFilesystem = true    # Container can't write to its filesystem
    user                   = "1001" # Match the UID you set in the Dockerfile

    # Environment variables — NO secrets here, use Secrets Manager
    environment = [
      { name = "NODE_ENV",  value = "production" },
      { name = "LOG_LEVEL", value = "info" }
    ]

    # Secrets from Secrets Manager — injected as env vars at runtime
    # secrets = [{
    #   name      = "DB_PASSWORD"
    #   valueFrom = "arn:aws:secretsmanager:us-east-1:123456789:secret:iron-bank/db-password"
    # }]
  }])

  tags = { Project = var.project_name }
}

# ─── Security Group for the ECS Task ──────────────────────────────────────────
resource "aws_security_group" "ecs_task" {
  name        = "${var.project_name}-ecs-task-sg"
  description = "Security group for ECS Fargate tasks"
  vpc_id      = var.vpc_id

  # No inbound — tasks are private (accessed via internal load balancer or SSM)
  egress {
    description = "Allow all outbound (for ECR pull, CloudWatch, Secrets Manager)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = var.project_name }
}

# ─── ECS Service ──────────────────────────────────────────────────────────────
resource "aws_ecs_service" "app" {
  name            = "${var.project_name}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 1         # Run 1 task — increase for production
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids  # Private subnets — no public IP
    security_groups  = [aws_security_group.ecs_task.id]
    assign_public_ip = false   # Private task — only accessible internally
  }

  tags = { Project = var.project_name }
}
```

**`modules/ecs/outputs.tf`:**

```hcl
output "cluster_name"  { value = aws_ecs_cluster.main.name }
output "service_name"  { value = aws_ecs_service.app.name }
output "task_role_arn" { value = aws_iam_role.task.arn }
```

```bash
# Call the module from root main.tf
cat >> ~/projects/iron-bank-tf/main.tf << 'EOF'

module "ecs" {
  source = "./modules/ecs"

  project_name       = var.project_name
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  ecr_image_uri      = "${var.ecr_image_uri}"
}
EOF

# Add to variables.tf
cat >> ~/projects/iron-bank-tf/variables.tf << 'EOF'

variable "ecr_image_uri" {
  description = "Full ECR image URI including tag"
  type        = string
  default     = ""
}
EOF

# Deploy
cd ~/projects/iron-bank-tf
terraform init
terraform plan
terraform apply
# Type: yes
```

---

## Part 3: Verify the Running Task

```bash
# ─── Find the running task ─────────────────────────────────────────────────────
CLUSTER=$(terraform output -raw cluster_name 2>/dev/null || echo "iron-bank-cluster")

TASK_ARN=$(aws ecs list-tasks \
  --cluster $CLUSTER \
  --profile iron-bank \
  --query 'taskArns[0]' --output text)
echo "Task ARN: $TASK_ARN"

# ─── Describe the task ────────────────────────────────────────────────────────
aws ecs describe-tasks \
  --cluster $CLUSTER \
  --tasks $TASK_ARN \
  --profile iron-bank \
  --query 'tasks[0].{Status:lastStatus,Health:healthStatus,IP:attachments[0].details[?name==`privateIPv4Address`].value|[0]}' \
  --output table

# ─── Check the logs ───────────────────────────────────────────────────────────
aws logs get-log-events \
  --log-group-name "/ecs/iron-bank" \
  --log-stream-name "ecs/app/$(echo $TASK_ARN | cut -d/ -f3)" \
  --profile iron-bank \
  --query 'events[*].message' \
  --output text 2>/dev/null | head -20

# ─── Connect to the task via ECS Exec (SSM — no SSH needed) ──────────────────
# First enable it on the service:
aws ecs update-service \
  --cluster $CLUSTER \
  --service "iron-bank-service" \
  --enable-execute-command \
  --profile iron-bank

aws ecs execute-command \
  --cluster $CLUSTER \
  --task $TASK_ARN \
  --container app \
  --interactive \
  --command "/bin/sh"
# Opens a shell inside the running Fargate task — like SSH but through SSM
```

---

## 🧹 Cleanup

!!! abstract "🧹 Cleanup — ECS + ECR both cost money when left running"

```bash
# Destroy all ECS/VPC resources
cd ~/projects/iron-bank-tf
terraform destroy
# Type: yes

# Delete ECR repository and all images
aws ecr delete-repository \
  --repository-name iron-bank-app \
  --force \
  --profile iron-bank \
  --region us-east-1

# Remove local Docker images
docker image rm iron-bank-app:latest "${ECR_URI}:latest" 2>/dev/null

echo "✅ All ECS, ECR, and VPC resources deleted"
```

---

## Checklist

- [ ] ECR repository created with `scanOnPush=true` and AES256 encryption
- [ ] Docker logged in to ECR and image pushed successfully
- [ ] ECR scan results reviewed — understand CRITICAL/HIGH count
- [ ] ECS cluster, task definition, and service created via Terraform module
- [ ] Task runs in a **private subnet** with `assign_public_ip = false`
- [ ] Container runs as UID 1001 — `readonlyRootFilesystem = true`
- [ ] Task logs visible in CloudWatch
- [ ] ECS Exec (`execute-command`) used to open a shell — no SSH or Bastion needed
- [ ] `terraform destroy` executed — ECR repository deleted
- [ ] **Bill verified < $0.05**

