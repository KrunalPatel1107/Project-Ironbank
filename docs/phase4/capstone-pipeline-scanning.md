# Month 12 — Week 2: Pipeline & Scanning Integration

!!! danger "💰 Cost Reminder"
    Keep running `./cleanup.sh` every evening. This week adds the CI/CD pipeline targeting your Capstone infrastructure. Estimated daily cost while deployed: **~$2.50/day** (NAT Gateway + ALB + ECS). Build and test in short sprints, destroy between sessions.

!!! info "Background Context"
    This week you connect the `iron-bank-pipeline` (Month 10) to the `iron-bank-fortress` infrastructure (Week 1). In enterprise environments this is called "platform engineering" — the pipeline is itself a product that the security team owns and operates. Hiring managers at mid-senior DevSecOps roles look for candidates who've actually done this end-to-end, not just the individual components.

---

## Architecture: Pipeline → Fortress

```
Developer pushes code
    ↓
Gate 1: Semgrep SAST         → blocks on insecure code
Gate 2: Gitleaks secrets     → blocks on committed secrets
Gate 3: Checkov IaC          → blocks on Terraform misconfigs
    ↓ all pass
PR merged → Gate 4: Trivy    → builds and scans image, pushes to ECR
    ↓ clean image in ECR
Gate 5: ZAP DAST             → scans the deployed Fargate task
    ↓ all pass
ECS service updated          → pulls new image, rolling deployment
    ↓
GuardDuty + CloudTrail + Security Hub monitoring live traffic
```

---

## Part 1: Connect the Pipeline to the Fortress Infrastructure

Update `gate4-container.yml` to trigger an ECS rolling deployment after a clean image is pushed:

```bash
# In your iron-bank-pipeline repo, update gate4-container.yml
# Add this step AFTER the "Push to ECR" step:

cat >> .github/workflows/gate4-container.yml << 'EOF'

    # ── Step 5: Trigger ECS rolling deployment ────────────────────────────────
    - name: Deploy to ECS Fargate
      if: github.ref == 'refs/heads/main' && success()
      run: |
        # Tell ECS to use the new image — it will do a rolling update
        # (stops old tasks one by one, starts new ones, verifies health before continuing)
        aws ecs update-service \
          --cluster iron-bank-fortress-cluster \
          --service iron-bank-fortress-service \
          --force-new-deployment \
          --profile iron-bank \
          --region us-east-1

        echo "⏳ Waiting for deployment to stabilize..."

        # Wait for the deployment to complete (polls every 15 seconds, times out at 10 min)
        aws ecs wait services-stable \
          --cluster iron-bank-fortress-cluster \
          --services iron-bank-fortress-service \
          --profile iron-bank \
          --region us-east-1

        echo "✅ ECS deployment complete"
EOF
```

### Verify Deployment Works End to End

```bash
# 1. Make a trivial change to src/app.js
echo "// version bump $(date)" >> src/app.js

# 2. Create a PR
git checkout -b feat/pipeline-test
git add -A
git commit -m "test: verify full pipeline integration"
git push -u origin feat/pipeline-test
# Open PR on GitHub — watch all gates run

# 3. Merge the PR — Gate 4 should build, scan, push, and deploy
# Watch the ECS service update in the AWS Console:
# ECS → Clusters → iron-bank-fortress-cluster → Services → Deployments tab

# 4. Confirm the new task is running
aws ecs describe-services \
  --cluster iron-bank-fortress-cluster \
  --services iron-bank-fortress-service \
  --profile iron-bank \
  --query 'services[0].deployments[*].{Status:status,DesiredCount:desiredCount,RunningCount:runningCount}' \
  --output table
```

Expected output:

```
----------------------------------------------
| PRIMARY  | 1 | 1 |   ← new deployment running
| ACTIVE   | 1 | 0 |   ← old task draining (or gone)
----------------------------------------------
```

---

## Part 2: Add Trivy Scanning to the Fortress ECR Repository

Enable ECR enhanced scanning (uses AWS Inspector under the hood — more comprehensive than basic Trivy):

```bash
# Enhanced scanning uses AWS Inspector v2 for continuous CVE monitoring
# It scans images on push AND re-scans as new CVEs are published

aws ecr put-registry-scanning-configuration \
  --scan-type ENHANCED \
  --rules '[{
    "repositoryFilters": [{
      "filter": "iron-bank",
      "filterType": "WILDCARD"
    }],
    "scanFrequency": "CONTINUOUS_SCAN"
  }]' \
  --profile iron-bank \
  --region us-east-1

# CONTINUOUS_SCAN = ECR re-scans your existing images when new CVEs drop
# This means an image that was clean yesterday might be flagged today
# (because a new CVE was published for a library it contains)

# Check current scan findings for your image
aws ecr describe-image-scan-findings \
  --repository-name iron-bank-app \
  --image-id imageTag=latest \
  --profile iron-bank \
  --query 'imageScanFindings.enhancedFindings[?severity==`CRITICAL`].{CVE:packageVulnerabilityDetails.vulnerabilityId,Package:packageVulnerabilityDetails.vulnerablePackages[0].name}' \
  --output table
```

### Set Up ECR Finding Notifications

Get alerted when ECR scans find a new CRITICAL CVE:

```bash
# Create an EventBridge rule that fires when ECR finds a CRITICAL vulnerability
aws events put-rule \
  --name "iron-bank-ecr-critical-cve" \
  --event-pattern '{
    "source": ["aws.inspector2"],
    "detail-type": ["Inspector2 Finding"],
    "detail": {
      "severity": ["CRITICAL"],
      "status": ["ACTIVE"],
      "resources": [{
        "type": ["AWS_ECR_CONTAINER_IMAGE"]
      }]
    }
  }' \
  --state ENABLED \
  --profile iron-bank

# Get your SNS topic ARN from Month 6 (if still exists) or create a new one
SNS_ARN=$(aws sns create-topic \
  --name iron-bank-ecr-alerts \
  --profile iron-bank \
  --query TopicArn --output text)

aws sns subscribe \
  --topic-arn $SNS_ARN \
  --protocol email \
  --notification-endpoint your@email.com \
  --profile iron-bank

# Connect EventBridge to SNS
aws events put-targets \
  --rule iron-bank-ecr-critical-cve \
  --targets "[{\"Id\": \"ecr-to-sns\", \"Arn\": \"$SNS_ARN\"}]" \
  --profile iron-bank

# Allow EventBridge to publish to SNS
aws sns set-topic-attributes \
  --topic-arn $SNS_ARN \
  --attribute-name Policy \
  --attribute-value '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":{"Service":"events.amazonaws.com"},
      "Action":"sns:Publish",
      "Resource":"'"$SNS_ARN"'"
    }]
  }' \
  --profile iron-bank

echo "✅ ECR critical CVE alerts configured → email: your@email.com"
```

---

## Part 3: Automated Security Report Generation

Build a weekly security report that combines findings from all sources:

```bash
cat > ~/projects/iron-bank-fortress/scripts/weekly_report.py << 'EOF'
"""
weekly_report.py — aggregate security findings from ECR, Security Hub, and GuardDuty
into a single Markdown report. Save as reports/YYYY-MM-DD-security-report.md

Run: python3 scripts/weekly_report.py --profile iron-bank
"""
import boto3
import argparse
from datetime import datetime, timedelta

def get_ecr_critical_findings(ecr_client, repo_name):
    """Get CRITICAL CVE count from the most recent ECR scan."""
    try:
        response = ecr_client.describe_image_scan_findings(
            repositoryName=repo_name,
            imageId={'imageTag': 'latest'}
        )
        counts = response.get('imageScanFindings', {}).get('findingSeverityCounts', {})
        return counts.get('CRITICAL', 0), counts.get('HIGH', 0)
    except Exception:
        return 0, 0

def get_guardduty_findings(gd_client):
    """Get HIGH/CRITICAL GuardDuty findings from the last 7 days."""
    detector_id = gd_client.list_detectors()['DetectorIds']
    if not detector_id:
        return []
    
    response = gd_client.list_findings(
        DetectorId=detector_id[0],
        FindingCriteria={
            'Criterion': {
                'severity': {'Gte': 7},    # 7.0+ = HIGH, 9.0+ = CRITICAL
                'updatedAt': {
                    'Gte': int((datetime.now() - timedelta(days=7)).timestamp() * 1000)
                }
            }
        },
        MaxResults=20
    )
    return response.get('FindingIds', [])

def generate_markdown_report(ecr_critical, ecr_high, gd_finding_count):
    """Generate a Markdown security report."""
    now = datetime.now().strftime('%Y-%m-%d')
    
    status = '🟢 GREEN' if ecr_critical == 0 and gd_finding_count == 0 else \
             '🟡 YELLOW' if ecr_critical == 0 else '🔴 RED'
    
    report = f"""# Iron Bank Fortress — Weekly Security Report
**Date:** {now}  
**Overall Status:** {status}

---

## Container Security (ECR)

| Severity | Count | Action Required |
|---|---|---|
| CRITICAL | {ecr_critical} | {'⚠️ Patch immediately' if ecr_critical > 0 else '✅ Clean'} |
| HIGH | {ecr_high} | {'Review within 7 days' if ecr_high > 0 else '✅ Clean'} |

---

## Threat Detection (GuardDuty)

**Active HIGH/CRITICAL findings (last 7 days):** {gd_finding_count}

{'⚠️ Review GuardDuty console immediately.' if gd_finding_count > 0 else '✅ No active threats detected.'}

---

## Recommended Actions

"""
    if ecr_critical > 0:
        report += f"1. 🔴 Update base image in Dockerfile — {ecr_critical} CRITICAL CVEs in current image\n"
    if gd_finding_count > 0:
        report += f"2. ⚠️ Investigate {gd_finding_count} GuardDuty findings in AWS Console\n"
    if ecr_critical == 0 and gd_finding_count == 0:
        report += "- No immediate actions required. Continue monitoring.\n"
    
    report += f"\n---\n*Generated by iron-bank weekly_report.py on {now}*\n"
    return report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', default='iron-bank')
    args = parser.parse_args()
    
    session = boto3.Session(profile_name=args.profile, region_name='us-east-1')
    ecr = session.client('ecr')
    gd = session.client('guardduty')
    
    print("Gathering security findings...")
    ecr_critical, ecr_high = get_ecr_critical_findings(ecr, 'iron-bank-app')
    gd_findings = get_guardduty_findings(gd)
    
    report = generate_markdown_report(ecr_critical, ecr_high, len(gd_findings))
    
    # Save to reports folder
    import os
    os.makedirs('reports', exist_ok=True)
    filename = f"reports/{datetime.now().strftime('%Y-%m-%d')}-security-report.md"
    with open(filename, 'w') as f:
        f.write(report)
    
    print(report)
    print(f"✅ Report saved to: {filename}")

if __name__ == '__main__':
    main()
EOF

python3 ~/projects/iron-bank-fortress/scripts/weekly_report.py --profile iron-bank
```

---

## 🧹 End-of-Day Cleanup

```bash
# Run your cleanup.sh script from Week 1
cd ~/projects/iron-bank-fortress
./cleanup.sh

# Additionally, remove the ECR scanning configuration if desired:
aws ecr put-registry-scanning-configuration \
  --scan-type BASIC \
  --rules '[]' \
  --profile iron-bank 2>/dev/null || true

echo "✅ Week 2 complete — run cleanup.sh every evening"
```

---

## Checklist

- [ ] Gate 4 updated — ECS deployment triggered after clean image pushed
- [ ] End-to-end pipeline test: PR → gates → merge → deploy confirmed
- [ ] `aws ecs describe-services` shows PRIMARY deployment running
- [ ] ECR enhanced scanning enabled with `CONTINUOUS_SCAN`
- [ ] EventBridge rule created — email alert on CRITICAL CVE in ECR
- [ ] `weekly_report.py` run — Markdown report generated in `reports/`
- [ ] Understand: what is a rolling deployment and why it's safe
- [ ] `cleanup.sh` run — no resources running overnight

