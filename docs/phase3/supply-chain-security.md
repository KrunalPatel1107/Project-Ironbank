# Month 8 — Special: Supply Chain Security

!!! abstract "💰 Cost: $0-10/month — Free tools (syft, grype, sigstore)"

!!! danger "Why Supply Chain Security Matters"
    Software supply chain attacks are skyrocketing. SolarWinds (2020), Log4j (2021), 3CX (2023) — attackers compromise the *build process* rather than the runtime. You can't trust a library just because "everyone uses it." This week teaches you to verify integrity and provenance of every artifact: base images, dependencies, compiled binaries.

!!! info "Background Context"
    From a Microsoft/Azure perspective: Software supply chain security is a core pillar of the Zero Trust model (Secure Development Lifecycle in the Microsoft Security Stack). This week bridges Months 7-8 (OWASP, SAST/DAST) with Phase 4 (DevSecOps) — you verify that dependencies are safe, container images are signed, and artifacts are from trusted sources before deployment.

---

## Part 1: SBOM (Software Bill of Materials)

An **SBOM** is a complete inventory of components, dependencies, and versions used in your software. It answers: "What's inside this container image?"

### Why SBOM Matters

When a vulnerability is announced (e.g., "Log4j RCE in versions 2.0-2.14"), you need to:
1. Know if your software uses Log4j
2. Know which version you're using
3. Know where that version came from

Without an SBOM, you're flying blind.

### Generate an SBOM with Syft

```bash
# Install Syft (free, CNCF project)
pip install syft --break-system-packages

# Verify
syft --version

# Generate SBOM for a container image
syft ghcr.io/aquasecurity/trivy:latest -o cyclonedx-json > sbom-trivy.json
# Output: JSON with all components, versions, licenses

# Generate SBOM from a local Dockerfile
cd ~/projects/myapp
syft dir:.  # Analyzes current directory
# Finds: Python packages from requirements.txt, Go modules, npm dependencies, etc.

# View the SBOM
cat sbom-trivy.json | jq '.components[] | {name, version, type}' | head -20
```

### SBOM Formats

| Format | Use Case | Example |
|--------|----------|---------|
| **CycloneDX** | Industry standard, XML/JSON | `<component><name>log4j</name><version>2.14.1</version></component>` |
| **SPDX** | US regulatory standard (NTIA) | Machine-readable document of all dependencies |
| **SLSA** | Supply chain security levels (1-4) | Provenance metadata (who built it, on what toolchain) |

### Lab: Scan a Real Container Image

```bash
# Scan a public image
syft alpine:latest -o cyclonedx-json > sbom-alpine.json

# Find vulnerable packages in the SBOM
cat sbom-alpine.json | jq '.components[] | select(.purl | contains("openssl")) | {name, version}'

# Note version numbers — check NIST NVD for vulnerabilities
# https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX
```

---

## Part 2: Dependency Scanning with Grype

**Grype** compares your SBOM against known vulnerability databases (NVD, GitHub, Snyk).

```bash
# Install Grype
pip install grype --break-system-packages

# Scan an image's dependencies for vulnerabilities
grype ghcr.io/aquasecurity/trivy:latest

# Output:
# NAME        INSTALLED   FIXED-IN   TYPE   VULNERABILITY
# openssl     1.1.1k      1.1.1l     apk    CVE-2021-3711 (HIGH)
# curl        7.79.1      7.80.0     apk    CVE-2021-22922 (MEDIUM)

# Format output for CI/CD
grype ghcr.io/aquasecurity/trivy:latest -o json > vulns.json
grype ghcr.io/aquasecurity/trivy:latest -o table > vulns.txt

# Exit with non-zero if HIGH/CRITICAL found (good for gating builds)
grype ghcr.io/aquasecurity/trivy:latest --fail-on high
# Exit code: 1 if high-severity vulns found
```

### Integration into Your Pipeline

```bash
# In your GitHub Actions or CI/CD:
- name: Generate SBOM
  run: syft . -o cyclonedx-json > sbom.json

- name: Scan for vulnerabilities
  run: grype sbom.json --fail-on high
  # If high-severity found, gate fails

- name: Upload SBOM
  run: |
    # Upload to artifact repository or compliance system
    curl -H "Authorization: Bearer $SBOM_TOKEN" \
      -F sbom=@sbom.json \
      https://compliance.yourcompany.com/sbom
```

---

## Part 3: Container Image Provenance & Signing with Cosign

**Threat Model:** An attacker could push a malicious image to your registry with the same tag as a legitimate image. How do you know the image you're pulling is the one YOU built?

**Solution:** Sign images with a private key. Verify the signature before running.

### How Cosign Works

```
Build Phase:
  Docker build → image pushed to registry → sign with private key
  Registry now has:
    - image:latest (the binary)
    - image:latest.sig (the cryptographic signature)

Deploy Phase:
  kubectl run image:latest → K8s checks signature
  If signature is invalid → reject the image → pod fails to start
```

### Lab: Sign & Verify a Container Image

```bash
# Install Cosign (part of Sigstore project — free, open-source)
wget https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign

# Generate a keypair (keep private key VERY secret)
cosign generate-key-pair
# Prompts for a password — use a strong passphrase
# Creates: cosign.key (private), cosign.pub (public)

# Sign a container image (requires authentication to registry)
cosign sign --key cosign.key ghcr.io/youruser/myapp:v1.0
# Pushes signature to registry

# Verify the signature (anyone with the public key can verify)
cosign verify --key cosign.pub ghcr.io/youruser/myapp:v1.0
# Output: verified successfully

# Attempt to verify with wrong key (fails)
cosign verify --key wrong-key.pub ghcr.io/youruser/myapp:v1.0
# Error: signature verification failed
```

### Use Cosign in Kubernetes (with Admission Controller)

```bash
# Deploy Sigstore Policy Controller (enforces signature verification)
kubectl apply -f https://github.com/sigstore/policy-controller/releases/latest/download/release.yaml

# Create a policy: only allow signed images
cat > /tmp/signed-only-policy.yaml << 'EOF'
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: require-signed-images
webhooks:
  - name: require-image-signature
    # This webhook calls Policy Controller
    # If image is not signed → reject pod creation
    rules:
      - operations: ["CREATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    failurePolicy: Fail
EOF

# Now try to deploy an unsigned image
kubectl run unsigned-app --image=nginx:latest
# Error: image signature verification failed

# Deploy a signed image (succeeds)
kubectl run signed-app --image=ghcr.io/youruser/myapp:v1.0
# Success (if image is properly signed)
```

---

## Part 4: Minimize Base Images (Distroless & Alpine)

**Threat Model:** A large base image (e.g., Ubuntu 22 GB) includes unnecessary tools an attacker could use (curl, wget, bash, nc). Minimize the attack surface.

### Distroless Images

Distroless images contain ONLY your application + minimal runtime (libc, timezone data). No package manager, no shell, no utilities.

```dockerfile
# BAD: 1.2 GB image with full Ubuntu including build tools
FROM ubuntu:22.04
RUN apt-get install -y build-essential python3
COPY app.py .
CMD ["python3", "app.py"]

# GOOD: 100 MB distroless image with only Python runtime
FROM python:3.11-slim as builder
COPY app.py .
RUN pip install -r requirements.txt

FROM gcr.io/distroless/python3:nonroot
COPY --from=builder /app /app
ENTRYPOINT ["/app/app.py"]
# No shell, no bash, no curl — attacker can't break out
```

### Alpine Linux (Lightweight Alternative)

```dockerfile
# 50 MB image with essentials + shell
FROM python:3.11-alpine
COPY app.py .
RUN pip install -r requirements.txt
USER 1001  # Non-root
CMD ["python3", "app.py"]
```

### Scan for Vulnerabilities by Image Size

```bash
# Distroless image: smaller = fewer CVEs
grype gcr.io/distroless/python3 --quiet
# Output: 0-2 critical vulnerabilities (just base OS)

# Ubuntu base image: larger = more CVEs
grype ubuntu:22.04 --quiet
# Output: 50+ vulnerabilities
```

---

## Part 5: Vendor Risk Assessment

Not all dependencies are created equal. Evaluate third-party libraries before using:

```bash
cat > ~/vendor-assessment-template.md << 'EOF'
# Vendor Risk Assessment Checklist

## For Every Third-Party Library:

### Maintenance Status
- [ ] Project is actively maintained (commits in last 3 months)
- [ ] Issues are triaged and closed (not ignored)
- [ ] Security vulnerabilities are disclosed responsibly
- [ ] Average time-to-patch for CVEs is < 2 weeks

### Code Quality
- [ ] Source code is publicly available (on GitHub, GitLab, etc.)
- [ ] Project has CI/CD pipeline (automated testing)
- [ ] Code is regularly reviewed (pull request process, not solo commits)
- [ ] Dependencies are pinned/vendored (not relying on floating versions)

### Security Practices
- [ ] Has a published security policy (SECURITY.md)
- [ ] Has SBOM or provenance metadata
- [ ] Is signed (Sigstore/cosign or GPG)
- [ ] Publishes vulnerability reports (CVE list)

### Community & Support
- [ ] Project has > 100 GitHub stars (established, not abandoned)
- [ ] Backing organization (Apache, CNCF, Mozilla, etc.) or active maintainers
- [ ] Documentation is complete and updated
- [ ] Issues/discussions are responsive

### Red Flags (Don't Use)
- [ ] Last commit > 1 year ago
- [ ] > 20 open security vulnerabilities unfixed
- [ ] Anonymous author (can't verify identity)
- [ ] Single maintainer with no backup
- [ ] No tests or CI pipeline
- [ ] Vendor requested cryptocurrency payment for "faster support"

## Example: Evaluating log4j After CVE-2021-44228
- ✅ Apache Logging Services (maintained by Apache Foundation)
- ✅ Public GitHub, active contributors
- ✅ Security policy exists (disclosures@logging.apache.org)
- ✅ Vulnerability fixed within 48 hours
- ✅ SBOM/provenance metadata available
- Result: OK to use with rapid patching
EOF

cat ~/vendor-assessment-template.md
```

---

## Part 6: Artifact Repository Security

Where do you store your built images, SBOM,signatures? A secure artifact repository is critical.

### Options

| Repository | Security | When to Use |
|---|---|---|
| **ECR (AWS)** | Native encryption, IAM, private by default | Production AWS workloads |
| **GCR (Google)** | Distroless images, native Sigstore support | GKE clusters |
| **Artifactory** | RBAC, audit logs, SBOM support | On-premise or multi-cloud |
| **Docker Hub Public** | No security | Demo/OSS only |

### ECR Scanning Configuration

```bash
# Enable image scanning on push (ECS/ECR)
aws ecr create-repository --repository-name myapp --image-scanning-configuration scanOnPush=true

# Policy: Reject images with CRITICAL CVEs
cat > ~/ecr-scan-policy.json << 'EOF'
{
  "imageScanningConfiguration": {
    "scanOnPush": true
  },
  "encryptionConfiguration": {
    "encryptionType": "KMS"
  }
}
EOF

aws ecr put-image-scan-findings-for-image-policy \
  --repository-name myapp \
  --policy file://~/ecr-scan-policy.json
```

---

## Part 7: Write a Supply Chain Security Finding

```bash
cat > ~/supply-chain-finding.md << 'EOF'
# Finding: Unverified Third-Party Dependencies — Supply Chain Risk

**Severity:** High  
**Component:** Python requirements.txt / npm package.json  

## Description
The application uses 127 third-party Python packages, but:
1. No SBOM is generated (we don't know what's inside each package)
2. No dependency verification (packages could be substituted with malicious clones)
3. Packages are pinned to major versions only (1.2.*), allowing patch updates without review
4. No automated vulnerability scanning (grype)

## Risk Scenario
- Attacker compromises a popular library (e.g., requests library)
- Pushes malicious code to PyPI
- Your build pulls the compromised version
- Compromised code runs in production

## Remediation
1. Generate SBOM on every build: `syft . -o cyclonedx-json > sbom.json`
2. Scan for vulnerabilities: `grype sbom.json --fail-on high`
3. Pin dependencies to exact versions: `requests==2.28.1` (not `2.28.*`)
4. Review dependency updates manually (use GitHub Dependabot with required reviews)
5. Scan vendor ecosystem: document why each library is trusted
EOF

cat ~/supply-chain-finding.md
```

---

## 🧹 Cleanup

```bash
# Remove test images and SBOM files
rm -f sbom*.json vulns.* cosign.* supply-chain-finding.md

# If you have ECR repos created for testing
aws ecr delete-repository --repository-name myapp --force 2>/dev/null || true

echo "✅ Supply chain security lab cleaned up"
```

---

## Checklist

**SBOM Generation & Understanding**
- [ ] Can define SBOM in one sentence
- [ ] Generated SBOM for a container image using Syft
- [ ] Examined SBOM JSON — can identify components and versions
- [ ] Can name 3 SBOM formats (CycloneDX, SPDX, SLSA)
- [ ] Know why SBOM matters post-CVE announcement

**Vulnerability Scanning (Grype)**
- [ ] Installed and ran Grype on a public image
- [ ] Can interpret Grype output (CVE ID, severity, component)
- [ ] Understand `--fail-on high` flag for CI/CD gating
- [ ] Know where vulnerability data comes from (NVD, GitHub, Snyk)

**Image Signing & Verification (Cosign)**
- [ ] Installed Cosign
- [ ] Generated a public/private keypair
- [ ] Signed a container image (or understood the command)
- [ ] Verified image signature with public key
- [ ] Know that signatures prevent tampering/substitution attacks
- [ ] Can explain: Policy Controller enforces signature verification in K8s

**Base Image Hardening**
- [ ] Can compare image sizes: distroless vs Alpine vs Ubuntu
- [ ] Know why minimal images reduce CVE surface area
- [ ] Understand distroless (no shell, no package manager)
- [ ] Can write a multi-stage Dockerfile using distroless base

**Vendor Risk Assessment**
- [ ] Completed vendor assessment template for 1 library you use
- [ ] Can identify 5 red flags in project maintenance (stale commits, etc.)
- [ ] Know what to check: maintenance status, code quality, security practices
- [ ] Can explain: why a 10-year-old library with 1 commit/year is risky

**Artifact Repository Security**
- [ ] Can compare ECR, GCR, Artifactory (when to use each)
- [ ] Know that artifact repos should have: encryption, IAM, audit logs, SBOM support
- [ ] Understand scanning policies (reject images with CRITICAL CVEs)

**Supply Chain Findings Documentation**
- [ ] Wrote 1 supply chain security finding (unverified deps, unsigned images, etc.)
- [ ] Can explain real-world supply chain attacks (SolarWinds, Log4j, 3CX)
- [ ] Know the difference between source attack (code) and supply chain attack (build process)

**Integration into DevSecOps Pipeline**
- [ ] Can write the steps for SBOM generation in CI/CD
- [ ] Can write the steps for vulnerability scanning in CI/CD
- [ ] Know where SBOMs should be stored (artifact repo, compliance system)
- [ ] Understand that supply chain security is part of the overall 7-gate pipeline
