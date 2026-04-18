# Month 9 — Week 3: Kubernetes Security (Extended)

!!! abstract "💰 Cost: $0 — minikube runs locally (or $50-150/mo for EKS if using managed K8s)"

!!! danger "This Week: Production Kubernetes Security Architecture"
    Week 3 now covers the complete K8s security picture:
    1. **Core security controls** (RBAC, Network Policies, Security Contexts — already in place)
    2. **Service Mesh** (Istio/Linkerd for mTLS and advanced networking — NEW)
    3. **Admission Controllers** (ValidatingWebhook, MutatingWebhook for policy enforcement — NEW)
    4. **Cluster hardening & audit logging** (NEW)

!!! info "Why Kubernetes for a Cloud Security role?"
    K8s is the orchestration layer that runs containers at scale. It appears in 80%+ of senior DevSecOps job descriptions. You don't need to be a K8s admin — you need to understand the security model: identity (RBAC), network segmentation (Network Policies), runtime enforcement (Security Contexts), certificate-based auth (mTLS via Service Mesh), and policy as code (Admission Controllers). This week gives you the complete picture.

---

## Part 1: Install minikube (Local K8s)

minikube runs a single-node Kubernetes cluster on your laptop — free, no cloud needed.

```bash
# ─── Ubuntu/WSL ───────────────────────────────────────────────────────────────
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# Install kubectl (the CLI to talk to K8s)
curl -LO "https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install kubectl /usr/local/bin/kubectl

# macOS
# brew install minikube kubectl

# Start the cluster
minikube start --driver=docker
# Uses Docker as the VM driver — needs Docker running

# Verify
kubectl get nodes
# NAME       STATUS   ROLES           AGE   VERSION
# minikube   Ready    control-plane   1m    v1.29.x
```

---

## Part 2: Core K8s Concepts (Security-Relevant Only)

```
Kubernetes objects you need to know:

Pod          → one or more containers running together (smallest deployable unit)
Deployment   → manages a set of identical Pods, handles restarts/rolling updates
Service      → stable DNS name + IP for a set of Pods (like an internal load balancer)
Namespace    → isolation boundary — like a folder for K8s objects
ServiceAccount → identity for a Pod (like an IAM Role for containers)
Secret       → K8s object for sensitive data (base64 encoded — NOT encrypted by default)
ConfigMap    → non-sensitive configuration data
NetworkPolicy → firewall rules between Pods
```

```bash
# K8s uses YAML manifest files to describe desired state (like Terraform HCL)
# Create a namespace for your lab work — keeps it isolated
kubectl create namespace iron-bank
kubectl config set-context --current --namespace=iron-bank
# Now all kubectl commands default to the iron-bank namespace
```

---

## Part 3: Security Contexts — Run Containers Safely

A **SecurityContext** in K8s enforces the same principles you applied to Docker in Week 1, but declaratively in YAML.

```bash
cat > ~/projects/k8s-lab/secure-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  namespace: iron-bank
  labels:
    app: secure-app
spec:
  # Pod-level security context applies to all containers
  securityContext:
    runAsNonRoot: true       # K8s will reject the pod if the image runs as root
    runAsUser: 1001          # Must match the USER set in your Dockerfile
    runAsGroup: 1001
    fsGroup: 1001            # Files written to volumes owned by this group
    seccompProfile:
      type: RuntimeDefault   # Apply the container runtime's default seccomp profile
                             # Blocks 300+ dangerous syscalls

  containers:
  - name: app
    image: nginx:alpine      # Using nginx for a quick lab — replace with your image

    # Container-level security context (more specific, overrides pod-level)
    securityContext:
      allowPrivilegeEscalation: false   # Process can't gain more privileges than its parent
      readOnlyRootFilesystem: true      # No writes to container filesystem
      capabilities:
        drop:
          - ALL              # Drop all Linux capabilities
        add:
          - NET_BIND_SERVICE # Only add back what's needed (e.g. bind ports < 1024)

    resources:
      limits:
        cpu: "500m"          # 500 millicores = 0.5 vCPU
        memory: "128Mi"      # 128 Megabytes
      requests:
        cpu: "100m"
        memory: "64Mi"

    # Writable tmpfs for /tmp since root filesystem is read-only
    volumeMounts:
    - name: tmp
      mountPath: /tmp

  volumes:
  - name: tmp
    emptyDir: {}    # In-memory temporary storage
EOF

mkdir -p ~/projects/k8s-lab
kubectl apply -f ~/projects/k8s-lab/secure-pod.yaml

# Verify it's running and check the effective user
kubectl get pod secure-app -n iron-bank
kubectl exec -n iron-bank secure-app -- id
# Should show: uid=1001 gid=1001 — NOT root
```

---

## Part 4: RBAC — Role-Based Access Control

K8s RBAC works like IAM: you define *what* is allowed (Role), then *bind* it to a subject (RoleBinding).

```bash
# ─── Create a ServiceAccount (identity for your Pod) ──────────────────────────
kubectl create serviceaccount iron-bank-app -n iron-bank

# ─── Create a Role (what this identity can do in this namespace) ───────────────
cat > ~/projects/k8s-lab/app-role.yaml << 'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-reader
  namespace: iron-bank
rules:
  # Allow the app to read ConfigMaps (for configuration)
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
  # Allow reading its own pod status (for health checks)
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get"]
  # NOT allowed: create/delete pods, access secrets, access other namespaces
EOF

kubectl apply -f ~/projects/k8s-lab/app-role.yaml

# ─── Bind the Role to the ServiceAccount ──────────────────────────────────────
kubectl create rolebinding app-reader-binding \
  --role=app-reader \
  --serviceaccount=iron-bank:iron-bank-app \
  -n iron-bank

# ─── Verify: test what the ServiceAccount can do ──────────────────────────────
kubectl auth can-i get configmaps \
  --as=system:serviceaccount:iron-bank:iron-bank-app \
  -n iron-bank
# → yes

kubectl auth can-i delete pods \
  --as=system:serviceaccount:iron-bank:iron-bank-app \
  -n iron-bank
# → no

kubectl auth can-i get secrets \
  --as=system:serviceaccount:iron-bank:iron-bank-app \
  -n iron-bank
# → no
```

??? note "ClusterRole vs Role"
    `Role` applies within a single namespace. `ClusterRole` applies across all namespaces (or to cluster-level resources like Nodes). For application workloads, always use `Role` + `RoleBinding` — not `ClusterRole`. Granting cluster-wide permissions to an app is a common over-permissioning mistake.

---

## Part 5: Network Policies

By default, all Pods in K8s can talk to all other Pods — there's no firewall. **NetworkPolicy** adds one.

```bash
cat > ~/projects/k8s-lab/network-policy.yaml << 'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-then-allow-specific
  namespace: iron-bank
spec:
  # Apply this policy to pods with label app=secure-app
  podSelector:
    matchLabels:
      app: secure-app

  policyTypes:
    - Ingress   # Control inbound connections TO this pod
    - Egress    # Control outbound connections FROM this pod

  ingress:
    # Only allow inbound from pods labelled "role: frontend" in the same namespace
    - from:
        - podSelector:
            matchLabels:
              role: frontend
      ports:
        - protocol: TCP
          port: 3000

  egress:
    # Allow DNS (every pod needs this to resolve service names)
    - ports:
        - protocol: UDP
          port: 53
    # Allow outbound to the database pods only
    - to:
        - podSelector:
            matchLabels:
              role: database
      ports:
        - protocol: TCP
          port: 5432
EOF

kubectl apply -f ~/projects/k8s-lab/network-policy.yaml

# List all network policies
kubectl get networkpolicies -n iron-bank
```

!!! tip "Default-deny pattern"
    Apply a catch-all NetworkPolicy that selects all pods (`podSelector: {}`) with empty `ingress` and `egress` rules to deny all traffic by default, then add permissive policies for only the paths you need. This is zero-trust at the pod level.

---

## Part 6: K8s Secrets — What to Know

```bash
# ─── Create a K8s Secret ──────────────────────────────────────────────────────
kubectl create secret generic db-creds \
  --from-literal=DB_USER=ironbank \
  --from-literal=DB_PASS=secretpassword \
  -n iron-bank

# ─── Inspect the secret ───────────────────────────────────────────────────────
kubectl get secret db-creds -n iron-bank -o yaml
# You'll see: data.DB_PASS: c2VjcmV0cGFzc3dvcmQ=
# This is just base64 — decode it:
echo "c2VjcmV0cGFzc3dvcmQ=" | base64 -d
# → secretpassword   ← NOT encrypted, just encoded
```

!!! warning "K8s Secrets are NOT encrypted by default"
    K8s Secrets are stored in etcd (the cluster database) as base64 — which is easily decoded. For a production cluster you must:

    1. Enable **etcd encryption at rest** in the API server config
    2. Use an **external secrets manager** (AWS Secrets Manager via External Secrets Operator, or HashiCorp Vault)

    In EKS (AWS managed K8s), use the **AWS Secrets and Configuration Provider (ASCP)** — it pulls secrets from Secrets Manager directly into your pod as files or env vars, without storing them in etcd at all.

---

## Part 7: Scan K8s Manifests with Trivy

```bash
# Trivy can scan your YAML manifests for security misconfigurations
trivy config ~/projects/k8s-lab/

# It checks for:
#   - runAsRoot: true (or missing runAsNonRoot)
#   - allowPrivilegeEscalation: true
#   - Missing resource limits
#   - Containers with NET_ADMIN or SYS_ADMIN capabilities
#   - Privileged containers

# Example output:
# secure-pod.yaml (kubernetes)
#   PASS (kubernetes-no-privilege-escalation)
#   PASS (kubernetes-non-root-user)
#   WARN (kubernetes-seccomp-profile) — add seccompProfile to suppress
```

---

## Part 8: Service Mesh for mTLS & Advanced Networking

**Threat Model Connection:** A compromised pod could eavesdrop on unencrypted traffic between services. A Service Mesh enforces encryption (mTLS) and authorization between every service automatically, without app code changes.

A **Service Mesh** (Istio, Linkerd, AWS App Mesh) is a sidecar proxy deployed alongside every Pod. It intercepts and controls all network traffic — providing:
- **mTLS:** Every pod-to-pod connection is encrypted with automatically-rotated certificates
- **Authorization policies:** Fine-grained rules for which services can call which
- **Traffic shaping:** Retries, timeouts, circuit breakers
- **Observability:** Metrics, logging, tracing without app instrumentation

### Lightweight Option: Linkerd (Easy for Learning)

```bash
# Linkerd is simpler and lighter than Istio (good for learning)
# Install Linkerd on minikube

curl --proto '=https' --tlsv1.2 -sSfL https://run.linkerd.io/install | sh
# This downloads and installs linkerd CLI

linkerd install | kubectl apply -f -
# Deploys Linkerd control plane (3-5 minutes)

# Verify
linkerd check
# Should show all checks passing

# Inject Linkerd sidecars into your app namespace
kubectl annotate namespace iron-bank linkerd.io/inject=enabled

# Redeploy pods — Linkerd automatically injects mTLS sidecars
kubectl rollout restart deployment -n iron-bank
# (if you have deployments; for pods, recreate them)

# Verify sidecar injection
kubectl describe pod secure-app -n iron-bank | grep "linkerd-proxy"
# Should show the proxy container
```

### Verify mTLS is Working

```bash
# Linkerd provides a dashboard
linkerd viz install | kubectl apply -f -
linkerd viz dashboard &
# Opens http://localhost:50750 — shows traffic visualization with encryption status
```

**Key Points:**
- mTLS is **automatic** — services don't need code changes
- Certificates are **rotated automatically** (Linkerd handles it)
- **Zero-trust at the service level** — every connection is verified and encrypted
- **Observability** — Linkerd shows you golden signals (latency, errors, throughput) per service pair

---

## Part 9: Admission Controllers — Policy as Code

**Threat Model Connection:** A developer could accidentally deploy an insecure image, or bypass security policies. **Admission Controllers** are webhooks that enforce policies — they accept or reject resources before they're stored in etcd.

There are two types:
- **ValidatingAdmissionWebhook:** Checks if a resource is valid (reject if it violates policy)
- **MutatingAdmissionWebhook:** Modifies a resource (e.g., add labels, inject sidecars)

### Example: Enforce a Pod Security Policy

```bash
# Create a ValidatingAdmissionWebhook that rejects privileged containers

cat > ~/projects/k8s-lab/validating-webhook.yaml << 'EOF'
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: reject-privileged-pods
webhooks:
  - name: reject-privileged.ironbank.internal
    clientConfig:
      # In production, point to your validation service endpoint
      # For learning, use a public example
      url: "https://example.com/validate"  # Placeholder
    rules:
      - operations: ["CREATE", "UPDATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail  # Reject if validation fails
    timeoutSeconds: 5
EOF

# In production, you'd implement a validation service that:
# 1. Receives a Pod definition
# 2. Checks if securityContext.privileged = true
# 3. Returns denied: true if so
# 4. K8s rejects the Pod from being created
```

### Real-World Example: OPA/Gatekeeper

**OPA (Open Policy Agent)** is a general-purpose policy engine. **Gatekeeper** is the K8s-specific version.

```bash
# Install Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# Define a policy: "All pods must have CPU/memory limits"
cat > ~/projects/k8s-lab/require-limits.yaml << 'EOF'
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredResources
metadata:
  name: pod-must-have-limits
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    cpu: "100m"
    memory: "128Mi"
EOF

kubectl apply -f ~/projects/k8s-lab/require-limits.yaml

# Now try to deploy a pod without limits — it will be rejected
kubectl run no-limits --image=nginx
# → Error: pod rejected by constraint pod-must-have-limits
```

This is **policy as code** — your security policies are versioned, reviewed, and enforced automatically.

---

## Part 10: Cluster Hardening & Audit Logging

### Enable Audit Logging

K8s audit logs record all API requests — who did what, when, and with what result. Essential for forensics and compliance.

```bash
# In minikube, audit logging is disabled by default
# For EKS, enable it via AWS Console:
# EKS Cluster → Logging → enable "API server logs" → destination (CloudWatch)

# For minikube (advanced lab):
# Create an audit policy file
cat > /tmp/audit-policy.yaml << 'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all requests at RequestResponse level
  - level: RequestResponse
    omitStages:
      - RequestReceived
EOF

# Then start minikube with audit enabled:
# minikube start --extra-config=apiserver.audit-policy-file=/tmp/audit-policy.yaml
# (This requires additional setup, skip if complex)
```

### Cluster Hardening Checklist

```bash
cat > ~/k8s-hardening-checklist.md << 'EOF'
# Kubernetes Cluster Hardening Checklist

## API Server Security
- [ ] RBAC enabled (not `--authorization-mode=AlwaysAllow`)
- [ ] Network policies enabled (`--enable-network-policy`)
- [ ] Audit logging enabled (log all API requests)
- [ ] Secure port only (443, not 8080 unencrypted)

## Node Security
- [ ] kubelet authorization enabled (`--authorization-mode=Webhook`)
- [ ] kubelet anonymous auth disabled (`--anonymous-auth=false`)
- [ ] Read-only port disabled (`--read-only-port=0`)

## Pod Security
- [ ] Pod Security Standards or PSP enforced (no privileged containers)
- [ ] NetworkPolicy default-deny applied to all namespaces
- [ ] Resource limits set on all workloads (prevent DOS)
- [ ] Image pull policy set to `IfNotPresent` (not `Always` — use digests)

## Secrets & Configuration
- [ ] etcd encryption at rest enabled
- [ ] RBAC restricts who can read secrets
- [ ] Secrets use external provider (not K8s default base64)

## Monitoring & Observability
- [ ] Audit logging enabled
- [ ] Prometheus/monitoring scrapes kubelet metrics
- [ ] Pod logs ingested into centralized logging (Loki, ELK, etc.)
- [ ] Network policy violations logged & alerted
EOF

cat ~/k8s-hardening-checklist.md
```

---

## Part 11: Supply Chain Security in K8s

Link to Phase 3 Supply Chain Expansion (once created). In K8s context, this means:
- **Image signing:** Verify container image provenance before deployment
- **Binary Authorization:** Only run signed images (GKE feature, similar in EKS)
- **Artifact attestation:** Prove that the image passed security scans before deployment

```bash
# Example with Sigstore (open-source image signing)
# Sign a container image
cosign sign --key cosign.key image:tag

# Deploy only signed images (would be enforced by AdmissionController)
# kubectl run app --image=image:tag  # Would be rejected if not signed
```

---

## Part 12: Write a K8s Security Finding

Document a misconfiguration you found:

```bash
cat > ~/k8s-finding.md << 'EOF'
# Finding: Pod Without Resource Limits — Denial of Service Risk

**Severity:** Medium  
**Component:** Kubernetes Deployments  

## Description
A production deployment is missing CPU and memory limits.
An uncontrolled pod can consume all available cluster resources,
causing other workloads to be evicted (DOS).

## Example Misconfiguration
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:latest
        # ❌ NO resource limits defined
```

## Impact
A single misbehaving or compromised pod can starve the entire cluster,
causing cascading failures across all applications.

## Remediation
Add resource limits:
```yaml
resources:
  requests:
    cpu: "100m"
    memory: "128Mi"
  limits:
    cpu: "500m"
    memory: "512Mi"
```
EOF
```

---

## 🧹 Cleanup

```bash
kubectl delete namespace iron-bank
minikube stop
# minikube delete  # Uncomment to fully remove the cluster

echo "✅ K8s lab cleaned up — no cloud resources used"
```

---

## Checklist

**Core K8s Security (Basics)**
- [ ] minikube and kubectl installed — `kubectl get nodes` shows minikube Ready
- [ ] `iron-bank` namespace created and set as default context
- [ ] Secure pod deployed with: `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, resource limits
- [ ] Verified pod runs as UID 1001 — not root
- [ ] ServiceAccount created with a least-privilege Role (not ClusterRole)
- [ ] `kubectl auth can-i` confirms correct permissions
- [ ] NetworkPolicy applied — understand default-deny pattern
- [ ] K8s Secret created — decoded it to confirm base64 is NOT encryption
- [ ] Trivy scanned K8s manifests — findings reviewed
- [ ] Can explain RBAC Role vs ClusterRole in one sentence

**Service Mesh (mTLS & Advanced Networking)**
- [ ] Linkerd CLI installed
- [ ] Linkerd control plane deployed on minikube
- [ ] `linkerd check` shows all checks passing
- [ ] Linkerd sidecars injected into iron-bank namespace
- [ ] Verified mTLS: sidecar proxies are running on pods
- [ ] Opened Linkerd dashboard and saw traffic visualization
- [ ] Can explain: what mTLS is, why sidecars, how cert rotation works

**Admission Controllers & Policy as Code**
- [ ] Understand ValidatingAdmissionWebhook vs MutatingAdmissionWebhook
- [ ] Know that admission controllers run before etcd storage
- [ ] Deployed a ValidatingAdmissionWebhook YAML (or reviewed example)
- [ ] Can explain: how Gatekeeper/OPA enforces "all pods must have limits"
- [ ] Attempted to deploy a pod without limits — verified rejection

**Cluster Hardening**
- [ ] Can list 5 API server hardening options (RBAC, audit logging, secure port, etc.)
- [ ] Can list 3 node hardening options (kubelet auth, read-only port, etc.)
- [ ] Understand etcd encryption at rest and why it matters
- [ ] Know the difference between Pod Security Policy (deprecated) and Pod Security Standards
- [ ] Completed K8s hardening checklist — understand each item

**Supply Chain Security in K8s**
- [ ] Understand image signing (Sigstore/cosign concept)
- [ ] Know what Binary Authorization means (only run signed images)
- [ ] Can explain: attestation, provenance verification, supply chain risk

**Audit Logging & Forensics**
- [ ] Understand K8s audit logging (logs all API requests)
- [ ] Know where audit logs go (CloudWatch for EKS, local files for minikube)
- [ ] Can explain: what information is captured, why it's needed for compliance

**K8s Security Findings Documentation**
- [ ] Wrote at least 1 K8s security finding (e.g., missing resource limits, insecure pod)
- [ ] Can explain real-world K8s breaches (e.g., Tesla/Kubernetes-exposed-to-internet)

**Cleanup**
- [ ] `kubectl delete namespace iron-bank` — cluster cleaned up
- [ ] minikube stopped (or fully deleted)

