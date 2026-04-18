# Month 10 — Special: Container Image Hardening & Supply Chain Integrity

!!! abstract "💰 Cost: $0-10/month — ECR image scanning ($0.005/image), Cosign (free), OPA (free)"

!!! danger "Why Container Hardening Matters"
    Phase 4 m10-week3 covers container scanning (Trivy). This expansion teaches **supply chain integrity**: building images with zero known vulnerabilities, signing images so you know they haven't been tampered with, and enforcing policies that only allow signed, minimal images in production. SolarWinds attack happened because an attacker compromised a build artifact. Your containers should be minimal (no unnecessary tools), signed (provenance verified), and scanned (no CVEs). Together, these prevent supply chain attacks.

!!! info "Background Context"
    Phase 3 covered container basics (Docker, ECS, K8s). This expansion teaches how to build **production-grade** containers: distroless images (reduce attack surface 90%), image signing (prove you built it), and runtime enforcement (only signed images allowed). This is how Google, AWS, and Netflix deploy containers.

---

## Part 1: Minimal Base Images (Distroless, Alpine)

Smaller image = fewer vulnerabilities = smaller attack surface.

### Traditional Docker Image (Large)

```dockerfile
FROM ubuntu:22.04  # 77 MB

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    git \
    vim \
    openssh-client \
    # ... 20+ packages most apps don't use

COPY app.py /app/
RUN pip install flask

ENTRYPOINT ["python3", "/app/app.py"]
```

**Image size: 500 MB+**  
**Packages included: 100+ (including tools attackers can use)**

### Distroless Image (Minimal)

```dockerfile
# Distroless: Only app + minimal runtime (NO shell, NO package manager)
FROM python:3.11-slim as builder

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Multi-stage: copy only artifacts, discard builder
FROM gcr.io/distroless/python3-nonroot:nonroot

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY app.py /app/app.py

ENTRYPOINT ["python3", "/app/app.py"]
```

**Image size: 100-150 MB**  
**Packages included: Only Python + libc (nothing else)**

### Alpine Image (Lightweight)

```dockerfile
FROM alpine:latest  # 7 MB (smallest)

RUN apk add --no-cache python3 py3-pip

COPY app.py /app/
RUN pip install flask

ENTRYPOINT ["python3", "/app/app.py"]
```

**Image size: 50-100 MB**  
**Pros: Tiny, fast to pull**  
**Cons: Alpine uses musl libc (different from standard glibc, can break some apps)**

### Comparison

| Image | Size | CVEs | Shell | Package Mgr | Use Case |
|---|---|---|---|---|---|
| **Ubuntu** | 500+ MB | 50-200 | ✅ bash | ✅ apt-get | Development, debugging |
| **Debian** | 300-400 MB | 30-100 | ✅ bash | ✅ apt-get | Traditional deployments |
| **Alpine** | 50-150 MB | 5-20 | ✅ sh | ✅ apk | Minimal production |
| **Distroless** | 100-150 MB | 0-10 | ❌ None | ❌ None | Secure production |

### Lab: Build & Compare Distroless

```bash
# Build distroless image
cat > Dockerfile.distroless << 'EOF'
FROM golang:1.21 as builder

WORKDIR /app
COPY main.go .
RUN CGO_ENABLED=0 go build -o myapp main.go

# Distroless: only binary + minimal runtime
FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=builder /app/myapp /myapp
ENTRYPOINT ["/myapp"]
EOF

# Build and scan
docker build -f Dockerfile.distroless -t myapp:distroless .
docker scan myapp:distroless  # Check for CVEs

# Compare sizes
docker images | grep myapp
# myapp  distroless  50MB   ← Minimal
# myapp  ubuntu      500MB  ← Bloated

# Verify: distroless has NO shell
docker run --rm -it myapp:distroless sh
# Error: executable file not found in $PATH ✅
# (Attacker can't get shell access)
```

---

## Part 2: ECR Image Scanning & Vulnerability Management

Amazon ECR scans images for CVEs automatically.

### Setup ECR Scanning

```bash
# Enable image scan on push
aws ecr put-image-scanning-configuration \
  --repository-name iron-bank-app \
  --image-scan-config scanOnPush=true

# Scan an image manually
aws ecr start-image-scan \
  --repository-name iron-bank-app \
  --image-id imageTag=v1.0.0

# Get scan results
aws ecr describe-image-scan-findings \
  --repository-name iron-bank-app \
  --image-id imageTag=v1.0.0 \
  --query 'imageScanFindings.findingSeverityCounts' \
  --output table

# Output:
# ────────────────────
# CRITICAL  30
# HIGH      50
# MEDIUM    100
# LOW       200
# ────────────────────
```

### Vulnerability Lifecycle Management

```bash
# Only push images with ZERO critical vulnerabilities

# Policy: Prevent images with CVEs from reaching prod
cat > ecr-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PreventCVEDeployment",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:BatchDownloadImage"
      ],
      "Condition": {
        "StringEquals": {
          "aws:PrincipalArn": "arn:aws:iam::ACCOUNT:role/KubernetesRole"
        }
      },
      "Resource": "arn:aws:ecr:*:ACCOUNT:repository/iron-bank-app"
    }
  ]
}
EOF

# Lambda: Auto-scan on image push and fail if CVEs found
cat > lambda/ecr-scan-enforce.py << 'LAMBDA'
import boto3
import json

ecr = boto3.client('ecr')

def lambda_handler(event, context):
    """Enforce: images with CVEs cannot be pulled"""
    
    detail = event['detail']
    image_tag = detail.get('image-tag')
    repository = detail.get('repository-name')
    
    # Get scan results
    findings = ecr.describe_image_scan_findings(
        repositoryName=repository,
        imageId={'imageTag': image_tag}
    )
    
    critical_count = findings['imageScanFindings']['findingSeverityCounts'].get('CRITICAL', 0)
    high_count = findings['imageScanFindings']['findingSeverityCounts'].get('HIGH', 0)
    
    if critical_count > 0:
        print(f"❌ BLOCKED: {repository}:{image_tag} has {critical_count} CRITICAL CVEs")
        return {
            'statusCode': 403,
            'body': 'Image blocked: Critical vulnerabilities detected'
        }
    
    if high_count > 10:
        print(f"⚠️ WARNING: {repository}:{image_tag} has {high_count} HIGH severity CVEs")
        # Could also block, or require manual approval
    
    print(f"✅ ALLOWED: {repository}:{image_tag} passed scan")
    return {
        'statusCode': 200,
        'body': 'Image passed security scan'
    }

LAMBDA
```

### Remediation: Patch Vulnerabilities

```bash
# When CVE found in image, create remediation plan:

# 1. Identify affected package
# Example: Image has OpenSSL 1.0.2 (CVE-2022-0001)

# 2. Patch base image
# Change: FROM ubuntu:22.04
# To:     FROM ubuntu:22.04
# Then:   RUN apt-get update && apt-get upgrade -y openssl

# 3. Re-build and re-scan
docker build -t myapp:v1.0.1 .
aws ecr push myapp:v1.0.1  # Auto-scans on push

# 4. Validate fix
aws ecr describe-image-scan-findings \
  --repository-name iron-bank-app \
  --image-id imageTag=v1.0.1

# 5. Deploy patched image
kubectl set image deployment/myapp myapp=myapp:v1.0.1
```

---

## Part 3: Image Signing with Cosign/Sigstore

**Signing** proves you built the image and it hasn't been tampered with.

### Lab: Sign a Container Image

```bash
# Install cosign
wget https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x cosign-linux-amd64

# Generate keypair (stored securely)
./cosign-linux-amd64 generate-key-pair

# Sign an image in ECR
./cosign-linux-amd64 sign \
  --key cosign.key \
  ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/iron-bank-app:v1.0.0

# Output:
# ✅ Signature created: ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/iron-bank-app:v1.0.0@sha256:abc123...
# Signature stored in OCI Image Index

# Verify signature
./cosign-linux-amd64 verify \
  --key cosign.pub \
  ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/iron-bank-app:v1.0.0

# Output:
# ✅ Verification successful
# Certificates:
#   URI: https://token.actions.githubusercontent.com
#   SANs: https://github.com/myorg/iron-bank/.github/workflows/build.yml@refs/tags/v1.0.0
```

### Image Attestation (Proof of Build)

```bash
# Store build metadata with image signature
cat > attestation.json << 'EOF'
{
  "builder": "GitHub Actions",
  "workflow": "build.yml",
  "trigger": "push to main",
  "commit": "abc123def456",
  "timestamp": "2024-01-15T14:30:00Z",
  "scans": {
    "cve_scan": "passed (0 critical)",
    "sast_scan": "passed",
    "dependency_check": "passed"
  }
}
EOF

# Attach attestation to image
./cosign-linux-amd64 attest \
  --key cosign.key \
  --attestation attestation.json \
  ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/iron-bank-app:v1.0.0
```

### CI/CD Integration: Sign in Pipeline

```yaml
# .github/workflows/build-and-sign.yml
name: Build & Sign Container

on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      packages: write
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Build image
        run: docker build -t myapp:${{ github.ref_name }} .
      
      - name: Push to ECR
        run: |
          aws ecr get-login-password | docker login --username AWS --password-stdin ACCOUNT.dkr.ecr.us-east-1.amazonaws.com
          docker push ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/iron-bank-app:${{ github.ref_name }}
      
      - name: Install cosign
        uses: sigstore/cosign-installer@v3
      
      - name: Sign image (Keyless via OIDC)
        run: |
          cosign sign --yes \
            ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/iron-bank-app:${{ github.ref_name }}
        env:
          COSIGN_EXPERIMENTAL: 1  # Use OIDC token, not key file
```

---

## Part 4: Binary Authorization (Enforce Signed Images)

Kubernetes policy: only pull images that are signed and scanned.

```yaml
# Kubernetes Binary Authorization (GKE)
apiVersion: binaryauthorization.grafeas.io/v1beta1
kind: Policy
metadata:
  name: binary-authorization-policy
spec:
  globalPolicyEvaluationMode: ENFORCE
  
  admissionWhitelistPatterns:
  - namePattern: gcr.io/gke-release/*  # Allow GKE system images
  - namePattern: gke.gcr.io/*
  
  kubernetesNamespaceAdmissionRules:
    prod:
      evaluationMode: ALWAYS_REQUIRE
      requireAttestationsBy:
      - projects/PROJECT_ID/attestors/prod-attestor
      
      # Images MUST be signed AND scanned
      # Only allow from our registry
      allowedImages:
      - allowedData:
        - allowedByteValues: "ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/*"
    
    dev:
      evaluationMode: DRYRUN_AUDIT_LOG_ONLY  # Dev: audit only
      requireAttestationsBy: []
```

### Alternative: OPA/Gatekeeper Policy

```rego
# OPA policy: Block unsigned images

package admission

deny[msg] {
    input.request.kind.kind == "Pod"
    image := input_images[_]
    
    # Must be from approved registry
    not startswith(image, "gcr.io/myproject/")
    not startswith(image, "docker.io/myorg/")
    
    msg := sprintf("Image '%s' from unapproved registry", [image])
}

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    image := container.image
    
    # No latest tag (unpredictable)
    endswith(image, ":latest")
    
    msg := sprintf("Image '%s' uses :latest tag (use specific version)", [image])
}

input_images[image] {
    image := input.request.object.spec.containers[_].image
}
```

---

## Part 5: OCI Image Spec & Runtime Security

OCIImage standard defines immutable image metadata.

```bash
# Inspect OCI image config
skopeo inspect docker://myapp:v1.0.0 --format='{{json .}}'

# Output shows:
# {
#   "Digest": "sha256:abc123...",
#   "RepoTags": ["myapp:v1.0.0"],
#   "Created": "2024-01-15T14:30:00Z",
#   "Author": "GitHub Actions CI",
#   "Architecture": "amd64",
#   "Layers": [
#     {
#       "Digest": "sha256:layer1...",
#       "Size": "50000000"
#     }
#   ]
# }

# Runtime validation: ensure image matches OCI spec
podman run \
  --rm \
  --security-opt=no-new-privileges:true \
  --cap-drop=ALL \
  myapp:v1.0.0
```

---

## Part 6: Write a Container Security Finding

```bash
cat > ~/container-finding.md << 'EOF'
# Finding: Unsigned Container Images — Supply Chain Compromise Risk

**Severity:** Critical  
**Component:** Container Supply Chain (Image Integrity)  

## Description
Container images pushed to production are unsigned and unscanned.
An attacker can push malicious images; no way to detect compromise.

## Risk Scenario
1. Attacker compromises CI/CD credentials
2. Attacker builds malicious image containing backdoor
3. Attacker pushes to ECR with legitimate version tag (v2.0.0)
4. K8s pulls and runs unsigned image
5. Backdoor executes in production (undetected)

## Remediation
1. **Sign all images:** Cosign + private key (stored in Secrets Manager)
2. **Scan on push:** ECR image scanning (automated)
3. **Enforce policy:** Binary Authorization or OPA/Gatekeeper
4. **Minimal images:** Distroless/Alpine (reduce attack surface)
5. **Attestation:** Store build metadata with signature

## Compliance
- NIST: "Verify software integrity before deployment"
- SLSA Framework: Level 2+ requires provenance
- Supply Chain Risk Management (SCRM): Essential practice

## Effort
- Initial: 16 hours (setup Cosign, binary auth, CI/CD integration)
- Ongoing: 1 hour/month (key rotation, policy updates)

## Result
- Image tampering: Possible → Impossible (cryptographically verified)
- Unknown provenance: Yes → No (full audit trail)
- Compliance gap: Critical → Closed
EOF

cat ~/container-finding.md
```

---

## 🧹 Cleanup

```bash
rm -f ~/container-finding.md
rm -f attestation.json

echo "✅ Container Hardening lab cleaned up"
```

---

## Checklist

**Minimal Base Images**
- [ ] Know difference between distroless, Alpine, Debian
- [ ] Can write multi-stage Dockerfile with distroless
- [ ] Understand trade-offs (size vs. compatibility)
- [ ] Scanned own images for CVEs

**ECR Image Scanning**
- [ ] Enabled image scanning on push
- [ ] Can interpret scan results (critical, high, medium)
- [ ] Know vulnerability lifecycle (patch, re-scan, re-deploy)
- [ ] Can set policies to block vulnerable images

**Cosign & Image Signing**
- [ ] Generated Cosign keypair securely
- [ ] Signed images in ECR
- [ ] Verified signatures
- [ ] Understand keyless signing (OIDC)
- [ ] Integrated signing into CI/CD

**Binary Authorization**
- [ ] Can write Binary Authorization or OPA policies
- [ ] Know enforcement modes (ALWAYS_REQUIRE vs. DRYRUN)
- [ ] Tested policy (signatures required, latest tag blocked)
- [ ] Documented image approval process

**Production Readiness**
- [ ] All images minimal (distroless or Alpine)
- [ ] All images scanned (0 critical CVEs before deploy)
- [ ] All images signed with verified key
- [ ] Binary authorization enforced on all K8s clusters
- [ ] Image registry locked down (only approved orgs can push)
- [ ] Monitoring in place for unsigned image attempts

---

## Integration with Phase 4

This container hardening expansion strengthens:
- **Phase 4 m10-week3:** Trivy scanning now integrated with ECR
- **Phase 3 kubernetes-security:** K8s security now has provenance verification
- **Phase 4 m11-week1:** Compliance evidence includes image signatures
- **Phase 4 m12-week3:** IR investigations prove image integrity

---

## Supply Chain Defense Layers

After this expansion, you have:

| Layer | Defense | Tool |
|---|---|---|
| **Build** | SAST finds code bugs | Semgrep |
| **Package** | Dependency scanning | Grype |
| **Image** | Vulnerability scanning | ECR, Trivy |
| **Signing** | Tamper detection | Cosign |
| **Registry** | Access control | ECR permissions |
| **Deployment** | Policy enforcement | Binary Auth, OPA |
| **Runtime** | Behavior monitoring | Falco |

You now have **production-grade container supply chain**. 🐳
