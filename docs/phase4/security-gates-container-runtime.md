# Month 10 — Week 3: Container & Runtime Security Gates

!!! abstract "💰 Cost: $0-5 — GitHub Actions + optional Falco monitoring on test cluster"

!!! danger "This Week: Defense in Depth for Containers"
    Week 2 gates stop vulnerable code from merging. This week, you add three layers of container security:
    1. **Scan container images** for vulnerable dependencies (Trivy — build-time)
    2. **Enforce pod security standards** (no privileged containers, no root — deployment-time)
    3. **Monitor runtime behavior** (Falco detects suspicious syscalls and processes — runtime)
    
    If an attacker somehow bypasses Weeks 1–2, these gates catch them at build, deploy, and runtime.

!!! info "Background Context"
    Microsoft Defender for Containers scans ACR images and monitors AKS runtime. This week you build the cloud-native equivalent: Trivy for build-time scanning, Pod Security Standards for enforcing security, and Falco for runtime threat detection. Combined with Week 2's gates, you now have **defense in depth**: prevent bad code, prevent bad images, prevent bad behavior.

---

## Gate 4: Trivy Container Image Scanning

The pattern this gate follows:

```
PR merged → Docker image built → Trivy scans the image → Gate fails if CRITICAL CVEs found → Image not pushed to ECR
```

This prevents a vulnerable base image (e.g., an old Node.js with a known RCE) from ever reaching your container registry.

```bash
cat > .github/workflows/gate4-container.yml << 'EOF'
# ─────────────────────────────────────────────────────────────────────────────
# Gate 4: Container Image Scanning with Trivy
# Triggers: on pushes to main that change Dockerfile or src/
# What it does:
#   1. Builds the Docker image
#   2. Scans it with Trivy for CRITICAL and HIGH CVEs
#   3. Fails if CRITICAL CVEs are found
#   4. If clean, pushes to ECR (only on main branch)
# ─────────────────────────────────────────────────────────────────────────────
name: Gate 4 — Container Scan (Trivy)

on:
  push:
    branches: [main]
    paths:
      - 'Dockerfile'    # Only run when the Dockerfile changes
      - 'src/**'        # Or when source code changes (needs a new image build)
  pull_request:
    branches: [main]
    paths:
      - 'Dockerfile'
      - 'src/**'

env:
  AWS_REGION: us-east-1
  ECR_REPOSITORY: iron-bank-app

jobs:
  build-and-scan:
    name: Build Image and Trivy Scan
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    # ── Step 1: Build the Docker image ────────────────────────────────────────
    - name: Build Docker image
      run: |
        docker build \
          -t iron-bank-app:${{ github.sha }} \
          -t iron-bank-app:latest \
          .
        # github.sha = the full commit hash (e.g. a1b2c3d4e5...)
        # Tagging with the commit hash makes every image uniquely traceable
        # "Which commit produced this image?" — answered by the tag

    # ── Step 2: Scan with Trivy ───────────────────────────────────────────────
    - name: Run Trivy vulnerability scan
      uses: aquasecurity/trivy-action@master
      # Official Trivy GitHub Action from Aqua Security (Trivy's creator)
      with:
        image-ref: iron-bank-app:${{ github.sha }}
        format: sarif             # Output as SARIF for GitHub Security tab
        output: trivy-results.sarif
        severity: CRITICAL,HIGH   # Only report CRITICAL and HIGH findings
        exit-code: '1'            # Exit with code 1 (failure) if findings found
                                  # This is what makes the gate actually block

    # ── Step 3: Upload findings to GitHub Security tab ────────────────────────
    - name: Upload Trivy SARIF to GitHub Security
      if: always()    # Upload even if Trivy found issues (so you can see findings)
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: trivy-results.sarif
        category: trivy-container
      continue-on-error: true

    # ── Step 4: Push to ECR (only if scan passed AND we're on main) ───────────
    - name: Configure AWS credentials
      if: github.ref == 'refs/heads/main' && success()
      # success() = all previous steps passed (including Trivy gate)
      # This means we only push to ECR if the image is clean
      uses: aws-actions/configure-aws-credentials@v4
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: ${{ env.AWS_REGION }}

    - name: Login to ECR
      if: github.ref == 'refs/heads/main' && success()
      id: login-ecr
      uses: aws-actions/amazon-ecr-login@v2

    - name: Push to ECR
      if: github.ref == 'refs/heads/main' && success()
      run: |
        ECR_URI=${{ steps.login-ecr.outputs.registry }}/${{ env.ECR_REPOSITORY }}
        docker tag iron-bank-app:${{ github.sha }} $ECR_URI:${{ github.sha }}
        docker tag iron-bank-app:latest $ECR_URI:latest
        docker push $ECR_URI:${{ github.sha }}
        docker push $ECR_URI:latest
        echo "✅ Pushed clean image to ECR: $ECR_URI:${{ github.sha }}"
EOF
```

### Setting Up AWS Secrets for the Workflow

The workflow needs AWS credentials to push to ECR. Store them as GitHub Secrets (never in code):

1. Go to your GitHub repo → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Add `AWS_ACCESS_KEY_ID` — the access key for your `iron-bank` IAM user
4. Add `AWS_SECRET_ACCESS_KEY` — the secret key for the same user

The IAM user needs this minimal policy to push to ECR:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:PutImage",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload"
      ],
      "Resource": "*"
    }
  ]
}
```

!!! tip "Use OIDC for production (no long-lived keys)"
    In production, use GitHub Actions OIDC (OpenID Connect) instead of static AWS keys. OIDC gives GitHub Actions a temporary token that lasts only for the workflow run — no long-lived secrets to rotate or leak. Look up `aws-actions/configure-aws-credentials` with `role-to-assume` for the OIDC approach when you're comfortable with IAM roles.

### Add a Dockerfile to the Repo

If you don't have one from Month 9:

??? note "Why does this Dockerfile use Node.js?"
    Because the `src/app.js` test target file you created in Week 2 is a Node.js file (JavaScript running on a server). The Dockerfile just packages it into a container so Trivy and ZAP have something to scan. You don't need to understand Node.js — this is the same test-target bait file from Week 2, just containerized. The security concepts (Trivy scanning the image for CVEs, ZAP testing the running app) are the same regardless of what language runs inside.

    If your real work eventually involves Python apps, you'd use `FROM python:3.11-alpine` and `CMD ["python3", "app.py"]` instead. The workflow YAML would stay identical — only these two lines change.

```bash
cat > Dockerfile << 'EOF'
# Base image: Node.js 20 on Alpine Linux (minimal, security-focused)
# We use Node because our src/app.js test file is a Node.js application.
# For a Python app you would use: FROM python:3.11-alpine instead.
FROM node:20-alpine AS runtime

# Create a non-root user to run the app (security best practice)
# Never run containers as root — Trivy checks for this!
RUN addgroup -r appgroup -g 1001 && \
    adduser  -r -u 1001 -G appgroup -s /sbin/nologin appuser

WORKDIR /app

# Copy only the src/ folder, owned by our non-root user
COPY --chown=appuser:appgroup src/ ./src/

# Create a minimal package.json (Node needs this to know the project exists)
RUN echo '{"name":"iron-bank","version":"1.0.0"}' > package.json

# Switch from root to the non-root user we created above
USER appuser

# Document that the app listens on port 3000
EXPOSE 3000

# Start the app
CMD ["node", "src/app.js"]
EOF

git add Dockerfile .github/workflows/gate4-container.yml
git commit -m "feat: add Gate 4 container scan"
git push
```

**Expected output in the Actions tab:**

```
✅ Build Docker image        (builds iron-bank-app:abc1234)
❌ Run Trivy vulnerability scan
   CRITICAL: 0
   HIGH: 2
   (gate fails if HIGH findings found — adjust severity to CRITICAL-only if needed)
```

!!! tip "Tuning the severity threshold"
    When first rolling out this gate, start with `severity: CRITICAL` only (so `HIGH` findings don't block). Once your image is clean of CRITICAL CVEs, add `HIGH`. This prevents the gate from immediately breaking your pipeline on day one.

---

## Gate 5: Pod Security Standards (Deployment-Time Enforcement)

**Threat Model Connection:** Preventing privilege escalation inside the cluster (if an attacker breaks out of the application into the container, can they escape to the host with `CAP_SYS_ADMIN`? Can they read secrets from the mounted token?)

Kubernetes Pod Security Standards (PSS) replace the older Pod Security Policy. They enforce that pods meet minimum security requirements:

| Standard | Rules |
|----------|-------|
| **Restricted** | No privileged containers, no root, no `CAP_SYS_ADMIN`, read-only root filesystem, drop `NET_RAW` |
| **Baseline** | Blocks obvious attacks (e.g., privileged mode), but allows many weak configs |
| **Unrestricted** | No enforcement (default in most clusters) |

### Deploy Pod Security Standards

```bash
# First, check your Kubernetes cluster version (PSS requires v1.24+)
kubectl version --short
# → v1.28.0  (good, supports PSS)

# Apply Pod Security Standards to a namespace
kubectl label namespace default \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

# Test it — try to deploy a privileged pod
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged
spec:
  containers:
  - name: app
    image: alpine
    securityContext:
      privileged: true  # ← This will be rejected
EOF

# Expected error:
#   Error from server (Forbidden): error when creating "...": pods "test-privileged" is forbidden:
#   violates PodSecurity "restricted:latest": privileged (pod or container running in privileged mode)
```

### Deploy a Compliant Pod

```bash
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test-compliant
spec:
  securityContext:
    runAsNonRoot: true       # ← Must run as non-root
    runAsUser: 1001          # ← Specific UID
    fsGroup: 1001            # ← File system group
    seccompProfile:
      type: RuntimeDefault   # ← System call filtering
  
  containers:
  - name: app
    image: alpine
    securityContext:
      allowPrivilegeEscalation: false  # ← Can't escalate to root
      readOnlyRootFilesystem: true     # ← Root FS is read-only
      capabilities:
        drop: ["ALL"]        # ← Drop all Linux capabilities
        add: ["NET_BIND_SERVICE"]  # ← Add only what's needed
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  
  volumes:
  - name: tmp
    emptyDir: {}  # ← Writable tmp directory
EOF

# Verify it's running
kubectl get pods test-compliant
kubectl logs test-compliant
```

### Enforce PSS at the Cluster Level

For production, apply Pod Security Standards to all critical namespaces:

```bash
# Create a namespace with restricted PSS
kubectl create namespace iron-bank-prod
kubectl label namespace iron-bank-prod \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit-version=latest

# View the labels
kubectl get namespace iron-bank-prod --show-labels
```

---

## Gate 6: Falco Runtime Security Monitoring

**Threat Model Connection:** Detecting if an attacker has compromised a container at runtime — suspicious syscalls, unexpected network connections, file access patterns that indicate lateral movement or data exfiltration.

Falco is a runtime security engine that monitors Linux syscalls in real-time. Unlike static scanning (Trivy) or deployment-time enforcement (PSS), Falco watches LIVE container behavior and detects anomalies:

- An app suddenly reading `/etc/passwd` (reconnaissance)
- A process spawning a shell (container breakout attempt)
- Unexpected outbound connections (data exfiltration)
- Non-root process changing to root (privilege escalation)

### Install Falco on Your Cluster

The `falco-k8s-setup.sh` script (in the `scripts/` folder) installs Falco with custom detection rules. Here's the abbreviated version:

```bash
# Add Falco Helm repository
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Create Falco namespace
kubectl create namespace falco

# Install Falco with custom rules
cat > /tmp/falco-values.yaml << 'EOF'
falco:
  ebpf:
    enabled: true            # Use eBPF (efficient, no kernel modules)
  jsonOutput: true           # Output JSON for parsing

daemonset:
  enabled: true              # Run on every node

serviceAccount:
  create: true
  name: falco

rbac:
  create: true

resources:
  requests:
    memory: "256Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m"

# Custom detection rules
customRules:
  rules.yaml: |
    - rule: Unauthorized Root Access
      desc: Detect when non-root process runs as root (privilege escalation)
      condition: >
        spawned_process and
        user.name != "root" and
        container
      output: >
        Privilege escalation attempt
        (user=%user.name command=%proc.name container=%container.name)
      priority: CRITICAL

    - rule: Suspicious Network Activity
      desc: Detect unexpected outbound connections from container
      condition: >
        outbound and
        container and
        not fd.snet = "127.0.0.1"
      output: >
        Suspicious network connection
        (container=%container.name destination=%fd.sip:%fd.sport)
      priority: WARNING

    - rule: File Access Anomaly
      desc: Detect unauthorized /etc file access
      condition: >
        read and
        container and
        fd.name glob "/etc/*"
      output: >
        Container accessing sensitive file
        (file=%fd.name container=%container.name user=%user.name)
      priority: WARNING
EOF

helm install falco falcosecurity/falco \
  --namespace falco \
  --values /tmp/falco-values.yaml \
  --wait \
  --timeout 5m

# Verify Falco is running
kubectl rollout status daemonset/falco -n falco --timeout=5m
kubectl get pods -n falco
```

### Monitor Falco Alerts in Real-Time

```bash
# Stream Falco logs from all pods
kubectl logs -n falco -l app.kubernetes.io/name=falco -f

# Or, get recent alerts from a specific pod
FALCO_POD=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')
kubectl logs -n falco "$FALCO_POD" --tail=50 | grep -i "CRITICAL\|WARNING"
```

### Test Falco with a Privilege Escalation Attempt

```bash
# Create a test pod in the iron-bank-prod namespace
kubectl run falco-test \
  --namespace iron-bank-prod \
  --image=alpine \
  -- sleep 3600

# Wait for pod to be ready
kubectl wait pod falco-test --namespace iron-bank-prod --for=condition=Ready --timeout=30s

# Inside the pod, try to trigger an alert: attempt to read /etc/shadow
kubectl exec -it falco-test -n iron-bank-prod -- cat /etc/shadow

# Check Falco logs — you should see:
#   WARNING File Access Anomaly
#   Container accessing sensitive file (/etc/shadow)
```

### Integrate Falco with Security Hub (Optional)

For production, send Falco alerts to AWS Security Hub via EventBridge:

```bash
# This requires setting up CloudWatch → EventBridge → Security Hub integration
# For now, reviewing Falco logs directly is sufficient

# Future enhancement: pipe Falco alerts to a gRPC/HTTP endpoint that posts to Security Hub
```

### Understanding Falco Alert Priority Levels

Falco alerts use standard severity levels:

| Priority | Meaning | Action |
|----------|---------|--------|
| EMERGENCY, ALERT, CRITICAL | Immediate threat — block/kill the container | Investigate within minutes, possibly kill the pod |
| WARNING, NOTICE | Suspicious behavior worth reviewing | Review logs, look for patterns, may be false positive |
| INFO, DEBUG | Informational — can safely ignore | Only use for troubleshooting or baselining normal behavior |

---

## The 3-Layer Container Security Model

You now have container security at three stages:

```
Build Time (Gate 4 — Trivy)
  ↓
  Container image scanned for vulnerable dependencies
  ↓
  Only clean images pushed to ECR

Deployment Time (Gate 5 — Pod Security Standards)
  ↓
  Kubernetes rejects unsafe pod configurations
  ↓
  No privileged containers, no root, no dangerous capabilities

Runtime (Gate 6 — Falco)
  ↓
  Live monitoring of syscalls and process behavior
  ↓
  Alerts on suspicious activity (privilege escalation, breakout attempts, data exfil)
```

This is **defense in depth**: if Trivy misses a CVE, PSS prevents privilege escalation. If an attacker breaches the application, Falco detects anomalous syscalls before they escape the container.

---

## Gate 7: OWASP ZAP DAST Scan

This gate runs after the application is deployed to a staging environment (or a temporary container). ZAP performs an automated baseline scan — the same scan you ran manually in Month 8, now automated on every deployment.

```bash
cat > .github/workflows/gate5-dast.yml << 'EOF'
# ─────────────────────────────────────────────────────────────────────────────
# Gate 5: Dynamic Application Security Testing (DAST) with OWASP ZAP
# Triggers: after a staging deployment (or on-demand via workflow_dispatch)
# What it does:
#   1. Starts the application in Docker (simulating staging)
#   2. Runs ZAP Baseline Scan against the running app
#   3. Fails if HIGH risk findings are detected
#   4. Uploads HTML report as a workflow artifact
# ─────────────────────────────────────────────────────────────────────────────
name: Gate 5 — DAST (OWASP ZAP)

on:
  workflow_dispatch:    # Manual trigger — you click "Run workflow" in the Actions tab
                        # This is useful for DAST since you control when it runs
  push:
    branches: [main]
    paths:
      - 'src/**'        # Run DAST when application code changes

jobs:
  dast:
    name: ZAP DAST Baseline Scan
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    # ── Step 1: Start the application ─────────────────────────────────────────
    - name: Start application in Docker
      run: |
        docker build -t iron-bank-app:dast-test .

        docker run -d \
          --name iron-bank-target \
          --network host \
          iron-bank-app:dast-test

        # Wait for the app to be ready before ZAP tries to scan it
        echo "Waiting for app to start..."
        for i in {1..30}; do
          if curl -s http://localhost:3000 > /dev/null 2>&1; then
            echo "✅ App is up at http://localhost:3000"
            break
          fi
          echo "  Attempt $i/30 — waiting..."
          sleep 2
        done
        # --network host = the container shares the runner's network
        # This lets ZAP (also on the runner) reach localhost:3000

    # ── Step 2: Run ZAP Baseline Scan ─────────────────────────────────────────
    - name: Run ZAP Baseline Scan
      uses: zaproxy/action-baseline@v0.12.0
      # Official OWASP ZAP GitHub Action
      with:
        target: 'http://localhost:3000'   # The app ZAP will scan
        rules_file_name: '.zap/rules.tsv' # Optional: custom alert thresholds
        cmd_options: '-a'                  # -a = include alpha-quality passive scan rules
        fail_action: true                  # fail_action: true = gate fails if HIGH findings found
        allow_issue_writing: false         # Don't create GitHub Issues for findings (use report instead)

    # ── Step 3: Upload the HTML report ────────────────────────────────────────
    - name: Upload ZAP report
      if: always()    # Always upload the report — we want to see findings even when gate fails
      uses: actions/upload-artifact@v4
      with:
        name: zap-baseline-report-${{ github.run_number }}
        path: report_html.html
        retention-days: 14    # Keep reports for 2 weeks

    # ── Step 4: Clean up the test container ───────────────────────────────────
    - name: Stop test application
      if: always()
      run: |
        docker stop iron-bank-target 2>/dev/null || true
        docker rm iron-bank-target 2>/dev/null || true
EOF
```

### Configuring ZAP Alert Thresholds

ZAP has hundreds of rules. You can tune which alerts fail the gate using a rules file:

```bash
mkdir -p .zap
cat > .zap/rules.tsv << 'EOF'
# Format: rule_id TAB threshold
# Threshold: FAIL (fail gate), WARN (report only), IGNORE (suppress)
10202	WARN    # Absence of Anti-CSRF Tokens — warn but don't fail (many apps use SameSite cookies instead)
10011	WARN    # Cookie Without Secure Flag — warn (localhost doesn't use HTTPS)
10096	IGNORE  # Timestamp Disclosure — suppress (not a real risk)
EOF
# Rule IDs are found in ZAP's documentation or in the HTML report
```

Push both files:

```bash
git add .github/workflows/gate5-dast.yml .zap/rules.tsv
git commit -m "feat: add Gate 5 DAST scan"
git push
```

### Running Gate 5 Manually

```
GitHub repo → Actions → "Gate 5 — DAST (OWASP ZAP)" → Run workflow → Run workflow
```

ZAP takes about 2–5 minutes. When done, go to the workflow run → Artifacts → download `zap-baseline-report-N.html` and open it in your browser.

---

## The 7-Gate Pipeline Summary

You now have a complete security pipeline with defense in depth:

```
Developer opens PR:
  Gate 1 (Semgrep)    → scans code for injection/auth bugs
  Gate 2 (Gitleaks)   → scans git history for secrets
  Gate 3 (Checkov)    → scans Terraform for misconfigurations

PR merged to main:
  Gate 4 (Trivy)      → scans Docker image for CVEs → only pushes clean images to ECR
  Gate 5 (PSS)        → enforces pod security at deployment (no privileged, no root)
  Gate 6 (Falco)      → monitors runtime behavior (syscalls, process anomalies)
  Gate 7 (ZAP)        → scans running app for web vulnerabilities (DAST)
```

This is a complete "shift left + shift right" security strategy:
- **Shift Left:** Find issues in code before merge (Gates 1-3)
- **Shift Right:** Catch runtime breaches after deployment (Gates 4-7)
- **Defense in Depth:** If one gate fails, the next catches the attacker

---

## 🧹 Cleanup

```bash
# Stop any locally running containers from testing
docker stop iron-bank-target 2>/dev/null || true
docker rm iron-bank-target 2>/dev/null || true
docker image rm iron-bank-app:dast-test iron-bank-app:latest 2>/dev/null || true

# No AWS resources were created this week
# ECR push only happens on main branch with AWS credentials configured
echo "✅ Week 3 complete — all containers cleaned up"
```

---

## Checklist

**Trivy Container Scanning (Gate 4)**
- [ ] Dockerfile created with non-root user
- [ ] Gate 4 workflow YAML created — builds image and runs Trivy
- [ ] Trivy output visible in Actions tab (CRITICAL, HIGH, MEDIUM)
- [ ] ECR push only happens when `success()` gate passes
- [ ] AWS credentials added as GitHub Secrets (not in code)
- [ ] OIDC token exchange understood (production best practice)

**Pod Security Standards (Gate 5)**
- [ ] Kubernetes cluster running (EKS, minikube, or local cluster)
- [ ] Pod Security Standards applied to default namespace
- [ ] Privileged pod rejected (Forbidden error observed)
- [ ] Compliant pod deployed successfully with `restricted` standard
- [ ] Can explain: why `runAsNonRoot`, `readOnlyRootFilesystem`, `drop: ALL` matter
- [ ] PSS labels applied to critical namespaces (iron-bank-prod, iron-bank-staging)

**Falco Runtime Monitoring (Gate 6)**
- [ ] Falco Helm chart added and repo updated
- [ ] Falco daemonset deployed to cluster (all nodes running Falco pods)
- [ ] Custom rules configured (privilege escalation, suspicious network, file access)
- [ ] Test alert triggered: pod reading /etc/shadow detected by Falco
- [ ] Falco logs monitored in real-time (`kubectl logs -f`)
- [ ] Can explain: syscall monitoring vs static scanning vs deployment-time enforcement
- [ ] Falco pod logs show at least one WARNING or CRITICAL alert

**DAST with ZAP (Gate 7)**
- [ ] Gate 7 YAML created — ZAP baseline scan runs against app in Docker
- [ ] `.zap/rules.tsv` created — at least one rule set to WARN instead of FAIL
- [ ] Gate 7 triggered manually via `workflow_dispatch`
- [ ] ZAP HTML report downloaded and reviewed — understand finding categories
- [ ] Report uploaded as workflow artifact

**Defense in Depth Understanding**
- [ ] All 7 gates can be explained in one sentence each
- [ ] Can draw the 3-layer container security model (build, deploy, runtime)
- [ ] Understand that Falco catches runtime threats that static scanning misses
- [ ] No AWS resources running — bill $0
- [ ] No containers left running locally — cleanup complete

