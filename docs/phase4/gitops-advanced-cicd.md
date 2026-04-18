# Month 10 — Special: Advanced CI/CD Pipeline Orchestration (GitOps)

!!! abstract "💰 Cost: $0-20/month — GitHub Actions free tier, self-hosted runners optional"

!!! danger "Why GitOps Matters"
    Phase 4 m10-week1-4 covers basic GitHub Actions and security gates. This expansion teaches **GitOps**: using Git as the single source of truth for both application code AND infrastructure state. Netflix, Uber, and all cloud-native companies use GitOps. Your deployment should be: commit code → Git webhook → CI pipeline validates → CD pipeline syncs desired state to production. No manual deployments. No "run terraform apply in Slack."

!!! info "Background Context"
    Azure DevOps Pipelines → GitHub Actions. Azure Kubernetes Service deployments → ArgoCD (GitOps controller). This expansion transforms you from "writes CI/CD scripts" to "architects deployment strategies."

---

## Part 1: GitOps Principles & Architecture

**GitOps** = Infrastructure and application state declared in Git, automatically synced to production.

```
Traditional Deployment:
┌──────────┐     ┌─────────┐     ┌─────────────┐
│  Code    │ --> │CI Pipeline → Manual Deploy → │ AWS/K8s │
│ in Git   │     │(runs tests)   (run scripts)  │         │
└──────────┘     └─────────────────────────────┘
                 ❌ Manual step (error-prone)
                 ❌ Hard to audit who deployed what
                 ❌ Easy to forget to update Git

GitOps Deployment:
┌──────────┐     ┌──────────────┐     ┌────────────────────┐     ┌─────────┐
│  Git     │ --> │ CI Validates │ --> │ GitOps Controller  │ --> │AWS/K8s  │
│ (desired)│     │ + merges     │     │ (watches Git)      │     │(actual) │
└──────────┘     └──────────────┘     └────────────────────┘     └─────────┘
✅ Entire history in Git (audit trail)
✅ Git is source of truth (what's in Git = what's in prod)
✅ Automatic sync (if Git differs from prod, controller fixes it)
✅ Declarative (describe desired state, controller handles transitions)
```

### GitOps Controller Options

| Controller | Best For | Deployment | Sync |
|---|---|---|---|
| **ArgoCD** | Kubernetes | Native K8s custom resource | Pull-based (watches Git) |
| **Flux CD** | Kubernetes | Helm charts, Kustomize | Pull-based (watches Git) |
| **Spinnaker** | Multi-cloud | EC2, ECS, Lambda, K8s | Push-based (triggered by CI) |
| **GitHub Actions** | Simple | Single app, AWS Lambda | Push-based (triggered by code commit) |

---

## Part 2: Multi-Environment Promotion Strategy

Safe deployments require **dev → staging → prod** progression with automated promotion:

```
Git Branches:
├── main (production code)
│   ├── tagged: v1.0.0, v1.0.1, ...  ← Each tag = production release
│   └── Webhook: any commit/tag triggers CD pipeline
├── staging (staging environment)
│   └── Webhook: any commit triggers CD to staging
└── develop (development)
    └── PR required before merge to main

Deployment Flow:

Developer commits code
         ↓
Create PR (develop → main)
         ↓
CI Pipeline Runs (tests, SAST, security gates)
         ↓
Code Review + Approval
         ↓
Merge to main (automatic if checks pass)
         ↓
Git Tag: v1.0.1
         ↓
CD Pipeline Triggered (builds container, pushes to registry)
         ↓
Deploy to Staging (ArgoCD syncs)
         ↓
Automated Tests on Staging
         ↓
Manual Approval (via GitHub / Slack)
         ↓
Deploy to Production (blue-green or canary)
         ↓
Monitor for errors
         ↓
If errors: Rollback to v1.0.0 (revert Git tag)
```

### Blue-Green Deployment with ArgoCD

```yaml
# argocd-application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: iron-bank-app
  namespace: argocd
spec:
  # Git repository as source of truth
  source:
    repoURL: https://github.com/myorg/iron-bank
    targetRevision: v1.0.1  # Git tag = exact version deployed
    path: kubernetes/prod   # K8s manifests in Git
  
  # Destination: production cluster
  destination:
    server: https://kubernetes.default.svc
    namespace: prod
  
  # Sync policy: automatic when Git changes
  syncPolicy:
    automated:
      prune: true    # Remove old resources if Git doesn't have them
      selfHeal: true # Fix any manual changes (sync back to Git)
    syncOptions:
    - CreateNamespace=true

  # Blue-Green deployment strategy
  # Step 1: Create "green" deployment with new image
  # Step 2: Test green (health checks pass)
  # Step 3: Switch traffic (blue → green)
  # Step 4: Keep blue as rollback
```

### Canary Deployment (Traffic Gradual)

```yaml
# argocd-canary.yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout  # Argo Rollouts (extends K8s Deployment)
metadata:
  name: iron-bank-app
spec:
  replicas: 10
  
  strategy:
    canary:
      steps:
      - setWeight: 10   # Send 10% traffic to new version
        duration: 5m    # Watch for errors for 5 min
      - setWeight: 50   # Increase to 50%
        duration: 5m
      - setWeight: 100  # Full traffic (done)
  
  template:
    spec:
      containers:
      - name: app
        image: myapp:v1.0.1
```

---

## Part 3: Rollback Strategy & Disaster Recovery

When a deployment breaks production, you need **instant rollback**.

### Git-Based Rollback

```bash
# Production is at v1.0.1 (broken)
# Need to rollback to v1.0.0

# Step 1: Revert Git tag
git tag -d v1.0.1
git push origin :refs/tags/v1.0.1

# Step 2: Create new tag pointing to previous commit
git tag v1.0.1-rollback
git push origin v1.0.1-rollback

# OR simpler: tag the previous commit
git tag v1.0.2 v1.0.0  # v1.0.2 = old v1.0.0 code
git push origin v1.0.2

# Step 3: Webhook triggers CD → deploys v1.0.2
# ArgoCD watches Git, sees new tag, syncs to cluster automatically
# Rollback complete in <2 min!
```

### Instant Rollback via Helm

```bash
# Helm keeps history of releases
helm list -a                    # Show all releases
helm history myapp              # Show release history
# NAME       REVISION  STATUS     CHART    VERSION DATE
# myapp      1         superseded myapp:1.0.0     
# myapp      2         superseded myapp:1.0.1
# myapp      3         DEPLOYED   myapp:1.0.1     ← Current (broken)

# Rollback to previous revision (v1.0.0)
helm rollback myapp 2

# Rollback complete instantly! All pods running v1.0.0 again
```

### Emergency Change Process (Break Glass)

```
What if you need to deploy a critical security patch ASAP?

Standard process (too slow):
  PR → Code review → Tests → Tag → CD → Deploy (30 min+)

Emergency process (fast):
  1. Patch applied directly in production (violation of GitOps, but necessary)
  2. Immediately create PR to update Git (within 1 hour)
  3. Code review of the PR happens post-deployment
  4. If PR rejected, revert production to Git state

Implementation:
cat > .github/workflows/emergency-deploy.yml << 'EOF'
name: Emergency Deploy (Break Glass)

on:
  workflow_dispatch:  # Manual trigger only (no automation)
    inputs:
      patch_branch:
        description: Git branch with emergency patch
        required: true

jobs:
  emergency:
    runs-on: ubuntu-latest
    environment: production  # Requires additional approval
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.inputs.patch_branch }}
      
      - name: Deploy (emergency)
        run: |
          # Bypass normal checks (DANGER!)
          terraform apply -auto-approve
          
      - name: Create Issue for Review
        run: |
          # Force code review POST-deployment
          gh issue create \
            --title "EMERGENCY PATCH DEPLOYED - REVIEW REQUIRED" \
            --body "Emergency patch was deployed. Must review PR within 1 hour."
EOF
```

---

## Part 4: Pipeline Configuration as Code

All pipeline definitions should be **version controlled** and **code reviewed**.

```yaml
# .github/workflows/deploy-multi-env.yml
name: Multi-Environment Deployment

on:
  push:
    tags:
      - 'v*'  # Only deploy on version tags (v1.0.0, v1.0.1, etc)

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  # ===== STAGE 1: Build =====
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write
    
    outputs:
      image-digest: ${{ steps.image.outputs.digest }}
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Docker buildx
        uses: docker/setup-buildx-action@v2
      
      - name: Build and push image
        id: image
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.ref_name }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

  # ===== STAGE 2: Deploy to Staging =====
  deploy-staging:
    needs: build
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to staging
        run: |
          # Update staging K8s manifests to new image
          kustomize edit set image app=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.ref_name }}
          kubectl apply -k kubernetes/staging
          kubectl rollout status deployment/iron-bank -n staging
      
      - name: Run smoke tests
        run: |
          pytest tests/smoke/
      
      - name: Report to Slack
        if: always()
        run: |
          curl -X POST ${{ secrets.SLACK_WEBHOOK }} \
            -d "{\"text\": \"Staging deployment: ${{ job.status }}\"}"

  # ===== STAGE 3: Approval Gate (manual) =====
  approval:
    needs: deploy-staging
    runs-on: ubuntu-latest
    environment: production  # Requires manual approval in GitHub
    steps:
      - run: echo "Manual approval granted for production deployment"

  # ===== STAGE 4: Deploy to Production =====
  deploy-production:
    needs: [build, approval]
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to production (blue-green)
        run: |
          # Create "green" deployment
          TEMP_VERSION=$(date +%s)
          kustomize edit set image app=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.ref_name }}
          
          kubectl apply -k kubernetes/prod-blue-green
          kubectl rollout status deployment/iron-bank-green -n prod
          
          # Run health checks
          sleep 30
          curl -f https://iron-bank.com/health || exit 1
          
          # Switch traffic (blue → green)
          kubectl patch service iron-bank -p '{"spec":{"selector":{"version":"green"}}}'
          
          # Keep blue as rollback
          echo "Rollback to blue: kubectl patch service iron-bank -p '{\"spec\":{\"selector\":{\"version\":\"blue\"}}}'"
      
      - name: Notify team
        run: |
          # Send notification with rollback command
          curl -X POST ${{ secrets.SLACK_WEBHOOK }} \
            -d "{\"text\": \"Production deployed ${{ github.ref_name }}. Rollback: \`kubectl patch service iron-bank -p '{\"spec\":{\"selector\":{\"version\":\"blue\"}}}'\`\"}"
      
      - name: On failure - Alert on-call
        if: failure()
        run: |
          curl -X POST ${{ secrets.PAGERDUTY_WEBHOOK }} \
            -d "{\"routing_key\": \"${{ secrets.PAGERDUTY_KEY }}\", \"event_action\": \"trigger\", \"payload\": {\"summary\": \"Production deployment failed\"}}"

  # ===== STAGE 5: Post-Deployment Monitoring =====
  monitor:
    needs: deploy-production
    if: always()
    runs-on: ubuntu-latest
    steps:
      - name: Wait 5 minutes for stability
        run: sleep 300
      
      - name: Check error rates
        run: |
          ERROR_RATE=$(curl -s "https://prometheus.internal/query?query=rate(errors_total[5m])" | jq '.data.result[0].value[1]')
          
          if (( $(echo "$ERROR_RATE > 0.05" | bc -l) )); then
            echo "ERROR RATE TOO HIGH: $ERROR_RATE"
            # Trigger automatic rollback
            exit 1
          fi
      
      - name: Auto-rollback on high errors
        if: failure()
        run: |
          echo "Auto-rollback triggered"
          kubectl patch service iron-bank -p '{"spec":{"selector":{"version":"blue"}}}'
```

---

## Part 5: Pipeline Observability & Debugging

Monitor your pipelines to catch issues early:

```bash
# GitHub Actions: View logs
gh run list --repo myorg/iron-bank
gh run view <RUN_ID> --log

# GitHub Actions: Debug failing steps
# Add 'debug: true' to step for verbose output
- name: Debug
  run: |
    set -x  # Enable debug output
    terraform plan
    set +x  # Disable

# CloudWatch Logs: Monitor deployments
aws logs filter-log-events \
  --log-group-name /aws/codepipeline/iron-bank \
  --filter-pattern "ERROR" \
  --start-time $(date -d '1 hour ago' +%s)000

# Metrics: Pipeline success rate
aws cloudwatch get-metric-statistics \
  --namespace AWS/CodePipeline \
  --metric-name SuccessfulExecutions \
  --start-time 2024-01-01 \
  --end-time 2024-02-01 \
  --period 86400
```

---

## Part 6: Write a CI/CD Finding

```bash
cat > ~/cicd-finding.md << 'EOF'
# Finding: No Automated Rollback Capability — Manual Deployments at Risk

**Severity:** High  
**Component:** CI/CD Pipeline (Deployment)  

## Description
Deployments are manual (run terraform apply in Slack). If a bad deployment reaches prod:
1. Manual effort to identify which version is broken
2. Manual rollback (run terraform destroy, then reapply old code)
3. 30-60 min downtime while team figures it out

## Risk
- Production outages due to slow rollback
- Data loss if rollback steps incorrect
- Difficult to trace who deployed what (no audit trail)
- SLA violations (promised 99.9% uptime)

## Remediation
1. **Implement GitOps:** Git = source of truth
2. **Automated promotions:** dev → staging → prod
3. **Instant rollback:** Revert Git tag (1-min recovery)
4. **Blue-green deployments:** Keep old version running, switch traffic instantly
5. **Approval gates:** Manual step in pipeline for prod changes

## Effort
- Initial: 20 hours (setup ArgoCD / GitHub Actions)
- Ongoing: 2 hours/month (maintain pipeline)

## Result
- Rollback time: 30-60 min → 1-2 min
- Deployment safety: manual → automated + tested
- Audit trail: none → complete (all in Git)
EOF

cat ~/cicd-finding.md
```

---

## 🧹 Cleanup

```bash
rm -f ~/cicd-finding.md

echo "✅ Advanced CI/CD lab cleaned up"
```

---

## Checklist

**GitOps Fundamentals**
- [ ] Understand GitOps principles (Git = source of truth)
- [ ] Know difference between push vs pull-based deployment
- [ ] Can explain why GitOps is safer than manual deploys
- [ ] Know ArgoCD, Flux, Spinnaker options

**Multi-Environment Promotion**
- [ ] Can design dev → staging → prod pipeline
- [ ] Understand approval gates and when to use them
- [ ] Know how to tag releases in Git
- [ ] Can implement automated testing between environments

**Blue-Green & Canary**
- [ ] Understand blue-green deployment (instant switch, instant rollback)
- [ ] Understand canary deployment (gradual traffic shift)
- [ ] Know when to use each strategy
- [ ] Can implement traffic switching in K8s

**Rollback Strategies**
- [ ] Know how to rollback via Git tag revert
- [ ] Understand Helm rollback command
- [ ] Know emergency change process ("break glass")
- [ ] Can explain rollback time SLA (target: <5 min)

**Pipeline as Code**
- [ ] All pipeline definitions in Git (version controlled)
- [ ] Can explain why pipeline code needs code review
- [ ] Know how to test pipeline changes (dry-run)
- [ ] Understand pipeline versioning (different for each app version)

**Production Readiness**
- [ ] Multi-env promotion documented and tested
- [ ] Automated tests run before production deploy
- [ ] Manual approval gate for production
- [ ] Instant rollback tested and documented
- [ ] On-call team trained on emergency procedures
- [ ] Post-deployment monitoring configured (auto-alert on errors)

---

## Integration with Phase 4

This CI/CD expansion strengthens:
- **Phase 4 m10-week-1-4:** Adds production deployment strategies
- **Phase 4 m11-week1-2:** Compliance + governance through pipeline
- **Phase 4 m12-week3:** IR capabilities enhanced (fast rollback = fast recovery)

---

## Real-World Scenarios

**Scenario 1: Bad Code Reaches Production**
```
10:00 AM: Deploy v1.0.1
10:05 AM: Monitoring alert: error rate 20%
10:06 AM: Run: git tag v1.0.1-bad && git tag v1.0.0 v1.0.2 && git push
10:07 AM: Webhook triggers, ArgoCD syncs to v1.0.0
10:08 AM: Rollback complete, error rate back to 0.1%
Downtime: 8 minutes
```

**Scenario 2: Emergency Security Patch**
```
11:00 AM: Security vulnerability discovered
11:05 AM: Patch written and tested in feature branch
11:10 AM: Emergency approve button clicked (GitHub environment)
11:15 AM: Patch deployed to production
11:20 AM: Confirmed: vulnerability closed
Action time: 20 minutes (beats manual by 40+ min)
```

You now have **enterprise-grade CI/CD orchestration**. 🚀
