# Month 11 — Special: Policy as Code & Governance Automation

!!! abstract "💰 Cost: $0 — OPA (free), SCPs (free), AWS Organizations (free)"

!!! danger "Why Policy as Code Matters"
    Phase 4 m11-week2 covers SCPs (deny-by-default). This expansion teaches **Policy as Code as a discipline**: encoding organizational rules in machine-readable format. Every company has rules: "no unencrypted databases," "resources must have owner tags," "no resources in unapproved regions." Without policy as code, rules live in spreadsheets and Slack (good luck enforcing them). With policy as code, rules are: version controlled, enforced automatically, audited, and testable. This is how companies like Google and Netflix prevent security incidents at scale.

!!! info "Background Context"
    Phase 2 m11-week2 taught SCPs for AWS governance. This expansion teaches policy as code across Kubernetes, Terraform, and AWS. You'll understand how to enforce policy consistently across your entire infrastructure stack.

---

## Part 1: Policy as Code Framework

**Policy as Code** = Organizational rules written as code, enforced by a system.

```
Without Policy as Code:
┌─────────────────────────────┐
│ Rules (in Google Doc):      │
│ - DB must be encrypted      │
│ - Resources need tags       │
│ - No public S3 buckets      │
│ - Only approved AMIs        │
└─────────────────────────────┘
    ↓
Developer writes Terraform (forgets rules)
    ↓
Deploy to production (oops, unencrypted DB!)
    ↓
Audit review (violation found 3 months later)

With Policy as Code:
┌─────────────────────────────────────────┐
│ Rules (OPA / Sentinel / SCPs):          │
│ @deny: unencrypted databases            │
│ @deny: missing required tags            │
│ @deny: public S3 buckets                │
│ @deny: unapproved AMIs                  │
└─────────────────────────────────────────┘
    ↓ (automated enforcement)
Developer writes Terraform
    ↓
Policy scan runs (before terraform apply!)
    ↓
If violation: BLOCK → code review → fix → retry
If passes: Deploy safely
    ↓
Never violates policy again (enforced automatically)
```

### Policy Types

| Type | Scope | Example |
|---|---|---|
| **Preventive** | Block before deploy | "deny: unencrypted RDS" |
| **Detective** | Find violations after deploy | "scan: S3 buckets monthly for public access" |
| **Responsive** | Auto-remediate violations | "Lambda: remove public ACLs from S3" |
| **Informational** | Alert/warn (don't block) | "warn: old library version in use" |

---

## Part 2: OPA (Open Policy Agent) for Kubernetes

OPA policies protect your K8s cluster from insecure workloads.

### Lab: Deploy OPA/Gatekeeper to K8s

```bash
# Install Gatekeeper (OPA enforcement for K8s)
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml

# Verify Gatekeeper is running
kubectl get pods -n gatekeeper-system

# Create a policy: "deny pods running as root"
cat > deny-privileged-pods.rego << 'EOF'
package kubernetes.admission

deny[msg] {
    container := input_containers[_]
    container.securityContext.runAsUser == 0
    
    msg := sprintf(
        "Container '%s' is running as root (uid 0)",
        [container.name]
    )
}

deny[msg] {
    input.request.object.spec.containers[_].securityContext.privileged == true
    msg := "Privileged containers are not allowed"
}

input_containers[c] {
    c := input.request.object.spec.containers[_]
}
EOF

# Create Gatekeeper ConstraintTemplate
kubectl apply -f - << 'EOF'
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: denypriv
spec:
  crd:
    spec:
      names:
        kind: DenyPrivileged
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package kubernetes.admission
        
        deny[msg] {
            container := input_containers[_]
            container.securityContext.runAsUser == 0
            msg := sprintf("Container '%s' must not run as root", [container.name])
        }
        
        deny[msg] {
            input.request.object.spec.containers[_].securityContext.privileged == true
            msg := "Privileged containers not allowed"
        }
        
        input_containers[c] {
            c := input.request.object.spec.containers[_]
        }
EOF

# Create the constraint (enforce the policy)
kubectl apply -f - << 'EOF'
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: DenyPrivileged
metadata:
  name: deny-privileged-pods
spec:
  match:
    namespaceSelector:
      matchLabels:
        enforce: "true"
  parameters:
    privileged: true
    runAsRoot: true
EOF

# Label a namespace to enforce policy
kubectl label namespace prod enforce=true

# Test: Try to deploy a pod running as root (should be blocked)
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
  namespace: prod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      runAsUser: 0  # Root user
EOF

# Output: ❌ Error from server (Forbidden): error when creating "pod.yaml": 
# admission webhook "validation.gatekeeper.sh" denied the request:
# [deny-privileged-pods] Container 'app' must not run as root

# Test: Deploy pod running as non-root user (should succeed)
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
  namespace: prod
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      runAsUser: 1000  # Non-root user
EOF

# Output: ✅ pod/good-pod created
```

### More OPA Policies for K8s

```rego
# Policy: Require resource limits
package kubernetes.admission

deny[msg] {
    container := input_containers[_]
    not container.resources.limits
    
    msg := sprintf(
        "Container '%s' must define resource limits",
        [container.name]
    )
}

deny[msg] {
    container := input_containers[_]
    not container.resources.requests
    
    msg := sprintf(
        "Container '%s' must define resource requests",
        [container.name]
    )
}

# Policy: Only approved image registries
deny[msg] {
    image := input_containers[_].image
    not startswith(image, "gcr.io/mycompany/")
    not startswith(image, "ghcr.io/mycompany/")
    
    msg := sprintf(
        "Image '%s' is from unapproved registry (use gcr.io or ghcr.io)",
        [image]
    )
}

# Policy: Require security context on all pods
deny[msg] {
    not input.request.object.spec.securityContext
    msg := "Pod must define securityContext"
}

deny[msg] {
    sc := input.request.object.spec.securityContext
    not sc.runAsNonRoot
    msg := "Pod must run as non-root user"
}
```

---

## Part 3: Terraform Sentinel (Policy in Code)

Sentinel is HashiCorp's policy language for Terraform Cloud.

```hcl
# policies/aws-encryption.sentinel
import "tfplan/v2" as tfplan

# Deny unencrypted RDS instances
deny_unencrypted_rds = rule {
  all tfplan.resource_changes.aws_rds_instance as address, rc {
    rc.change.after.storage_encrypted is true
  }
}

# Deny unencrypted EBS volumes
deny_unencrypted_ebs = rule {
  all tfplan.resource_changes.aws_ebs_volume as address, vol {
    vol.change.after.encrypted is true
  }
}

# Deny public S3 buckets
deny_public_s3 = rule {
  all tfplan.resource_changes.aws_s3_bucket as address, bucket {
    bucket.change.after.acl != "public-read"
    and bucket.change.after.acl != "public-read-write"
  }
}

# Enforce required tags
policy_require_tags = rule {
  all tfplan.resource_changes as address, rc {
    # Only check taggable resources
    rc.type in [
      "aws_instance",
      "aws_rds_instance",
      "aws_s3_bucket",
      "aws_security_group"
    ]
    
    # Must have these tags
    rc.change.after.tags contains "Environment"
    and rc.change.after.tags contains "Owner"
    and rc.change.after.tags contains "CostCenter"
  }
}

# Main: All policies must pass
main = rule {
  (deny_unencrypted_rds and deny_unencrypted_ebs and deny_public_s3 and policy_require_tags) else false
}
```

### Testing Sentinel Policies

```bash
# Sentinel CLI: https://www.terraform.io/cloud-docs/sentinel/install
# Download and install sentinel

# Test a policy against a terraform plan
sentinel test policies/aws-encryption.sentinel

# Output:
# Pass policies/aws-encryption.sentinel
#   ✓ test/aws-encryption/pass.json
#   ✓ test/aws-encryption/pass_encrypted_rds.json
#   ✗ test/aws-encryption/fail_unencrypted_rds.json
#       Expected: fail
#       Actual: pass (UNEXPECTED - policy not working!)

# To integrate into Terraform Cloud:
# 1. Upload policy file
# 2. Create Policy Set
# 3. Link Policy Set to workspaces
# 4. Enable "soft mandatory" or "hard mandatory" enforcement
```

---

## Part 4: AWS SCPs (Service Control Policies) - Governance at Scale

SCPs are IAM policies that apply to entire AWS accounts/OUs (Organizational Units).

### Lab: Enforce Policy Across All Accounts

```bash
# Prerequisite: AWS Organizations enabled

# Policy: Deny all EC2 instances except t3.micro/t3.small (cost control)
cat > deny-expensive-instances.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyExpensiveInstances",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals": {
          "ec2:InstanceType": [
            "t3.micro",
            "t3.small",
            "t3.medium"
          ]
        }
      }
    }
  ]
}
EOF

# Create the policy
aws organizations create-policy \
  --type SERVICE_CONTROL_POLICY \
  --name DenyExpensiveInstances \
  --content file://deny-expensive-instances.json

# Attach to entire org (all accounts, all regions)
POLICY_ID=$(aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[0].Id' -o text)

aws organizations attach-policy \
  --policy-id $POLICY_ID \
  --target-id r-abc123  # Root of organization

# Now, any account in the org trying to launch a large instance is BLOCKED

# Test: Try to launch c5.large (should fail)
aws ec2 run-instances \
  --image-id ami-12345678 \
  --instance-type c5.large

# ❌ Error: User is not authorized to perform: ec2:RunInstances with an explicit deny in a service control policy

# Try to launch t3.small (should succeed)
aws ec2 run-instances \
  --image-id ami-12345678 \
  --instance-type t3.small

# ✅ Instance launched successfully
```

### More SCP Examples

```json
// Policy: Only approved regions
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnapprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "organizations:*",
        "route53:*"  // These work globally
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-east-1",
            "us-west-2",
            "eu-west-1"
          ]
        }
      }
    }
  ]
}

// Policy: Require encryption on all resources
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedS3Upload",
      "Effect": "Deny",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        }
      }
    },
    {
      "Sid": "DenyUnencryptedSnapshots",
      "Effect": "Deny",
      "Action": "ec2:CopySnapshot",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "ec2:Encrypted": "false"
        }
      }
    }
  ]
}

// Policy: Require MFA for destructive actions
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDeleteWithoutMFA",
      "Effect": "Deny",
      "Action": [
        "ec2:TerminateInstances",
        "rds:DeleteDBInstance",
        "s3:DeleteBucket"
      ],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

---

## Part 5: Policy Testing & Auditing

Policies must be tested before deployment (just like code!).

```bash
# OPA: Unit test policies
cat > test_pod_security.rego << 'EOF'
package kubernetes.admission

# Test case: pod running as root (should deny)
test_deny_root_user {
    deny["Container 'app' must not run as root"] with input as {
        "request": {
            "object": {
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "securityContext": {"runAsUser": 0}
                        }
                    ]
                }
            }
        }
    }
}

# Test case: pod running as non-root (should allow)
test_allow_non_root {
    count(deny) == 0 with input as {
        "request": {
            "object": {
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "securityContext": {"runAsUser": 1000}
                        }
                    ]
                }
            }
        }
    }
}
EOF

# Run tests
opa test test_pod_security.rego -v
```

### Audit Policy Violations

```bash
# Find resources that violate policies (post-deployment detection)

# OPA: Query violations
kubectl get constraints  # List all policy constraints

# View violations per constraint
kubectl describe constraint deny-privileged-pods

# Sentinel: View policy violations in Terraform Cloud
terraform cloud policy-set list --organization myorg
terraform cloud policy-set results --id ps-abc123

# AWS: View SCPs that are preventing actions
aws iam simulate-custom-policy \
  --policy-input-list file://policy.json \
  --action-names ec2:RunInstances \
  --resource-arns "arn:aws:ec2:*:*:instance/*" \
  --query 'EvaluationResults[*].[EvalActionName,EvalDecision]' \
  --output table
```

---

## Part 6: Write a Policy as Code Finding

```bash
cat > ~/policy-finding.md << 'EOF'
# Finding: No Policy Enforcement — Developers Deploying Insecure Resources

**Severity:** Critical  
**Component:** Governance (Policy as Code)  

## Description
Developers can deploy any resource, in any region, with any configuration. No enforcement of:
- Encryption requirements
- Tagging standards
- Resource limits
- Approved AMI lists
- Public access restrictions

## Risk
- Unencrypted databases (compliance violation)
- Untagged resources (cost tracking impossible)
- Expensive instances launched by mistake ($10K+ monthly bills)
- Resources in unapproved regions (GDPR, data residency violations)

## Evidence
- 15 instances of unencrypted EBS volumes in production
- 3 public S3 buckets (exposing 50K+ customer records)
- Resources missing Environment tag (can't track ownership/cost)
- Instances in ap-southeast-2 (policy says only us-east-1, eu-west-1)

## Remediation
1. **Implement policy as code:** OPA for K8s, Sentinel for Terraform, SCPs for AWS
2. **Enforcement level:** Hard mandatory (block violations)
3. **Test policies:** Unit test before deployment
4. **Audit violations:** Monthly report of denied attempts
5. **Exception process:** Document and approve deviations (with sunset date)

## Effort
- Initial: 30 hours (design policies, write/test, roll out)
- Ongoing: 5 hours/month (policy review, exception management)

## Result
- Compliance violations: 100% reduced (policies prevent, not just detect)
- Cost control: Spending locked to approved instance types
- Audit trail: Every enforcement action logged
EOF

cat ~/policy-finding.md
```

---

## 🧹 Cleanup

```bash
rm -f ~/policy-finding.md
rm -f deny-privileged-pods.rego
rm -f deny-expensive-instances.json
rm -f test_pod_security.rego

echo "✅ Policy as Code lab cleaned up"
```

---

## Checklist

**OPA/Gatekeeper for Kubernetes**
- [ ] Know what OPA is (Open Policy Agent)
- [ ] Can write basic Rego policies
- [ ] Deployed Gatekeeper to K8s cluster
- [ ] Created constraints (deny privileged pods, require limits, etc.)
- [ ] Tested that policies block violations
- [ ] Know difference between audit vs. enforce mode

**Sentinel for Terraform**
- [ ] Understand Sentinel language syntax
- [ ] Can write policies for: encryption, tags, cost control
- [ ] Know how to test Sentinel policies
- [ ] Configured Terraform Cloud to run policies
- [ ] Know hard mandatory vs. soft mandatory enforcement

**AWS SCPs (Service Control Policies)**
- [ ] Can write SCPs for: region restriction, instance type limits, MFA requirements
- [ ] Know difference between SCP (blanket deny) vs. IAM (grant access)
- [ ] Deployed policies to AWS Organization
- [ ] Understand evaluation logic (explicit deny wins)
- [ ] Can test SCP with iam:simulate-custom-policy

**Policy Testing & Audit**
- [ ] Know why policies must be unit tested
- [ ] Can write test cases for policies
- [ ] Know how to audit policy violations
- [ ] Understand exception process (approved deviations)
- [ ] Can report on policy compliance

**Production Readiness**
- [ ] All policies version controlled (Git)
- [ ] Policies code reviewed (like normal code)
- [ ] Hard enforcement in prod, warn-only in dev
- [ ] Exception process documented (who can approve)
- [ ] Policy violations alerted (Slack, PagerDuty)
- [ ] Monthly compliance reports generated

---

## Integration with Phase 4

This Policy as Code expansion strengthens:
- **Phase 4 m11-week2:** SCPs + governance (now with policy as code discipline)
- **Phase 4 m10-week2:** Security gates (policies prevent bad configurations)
- **Phase 2 terraform-iac-at-scale:** Policy enforcement on Terraform

---

## Real-World Scenarios

**Scenario 1: Cost Control via SCP**
```
Developer runs: aws ec2 run-instances --instance-type m5.4xlarge
Expected cost: $600/month

SCP blocks it (not in approved list)
Developer runs: aws ec2 run-instances --instance-type t3.small
Expected cost: $10/month

SCP allows it (in approved list)

Result: Company saves $590/month on this one instance
Multiply by 100 developers, multiply by 12 months = $708,000/year saved!
```

**Scenario 2: Security via Policy**
```
OPA policy: Deny pods without resource limits
Developer submits Kubernetes manifesto without limits

Deployment blocked
Developer adds resource limits
Deployment succeeds

Result: Prevented resource exhaustion attack (pod could consume entire cluster)
```

---

## Next Steps

After mastering Policy as Code:
1. **Implement in your org:** Start with detective (audit mode), then move to enforce
2. **Document exceptions:** Create process for approved deviations
3. **Monitor compliance:** Generate reports, track trends
4. **Iterate:** As threats change, update policies

You now have **governance at scale**. 🏛️
