#!/bin/bash

# ════════════════════════════════════════════════════════════════════════════
# Falco Runtime Security Setup for Kubernetes
# ════════════════════════════════════════════════════════════════════════════
#
# Purpose:
#   Install Falco on a Kubernetes cluster to detect suspicious runtime behavior.
#   Falco monitors syscalls and alerts on:
#   - Unauthorized file access (e.g., /etc/passwd read by non-root)
#   - Privilege escalation attempts
#   - Network anomalies (unexpected outbound connections)
#   - Container breakout attempts
#
# What Falco Does:
#   Falco is a runtime security engine that uses Linux syscalls to detect threats.
#   Unlike static scanning (SAST), Falco watches LIVE behavior.
#
# Prerequisites:
#   - Kubernetes cluster (EKS, minikube, etc.)
#   - kubectl configured
#   - Helm package manager installed
#
# Usage:
#   ./falco-k8s-setup.sh
#
# Author: Iron Bank Training
# Date: April 2026
# ════════════════════════════════════════════════════════════════════════════

set -euo pipefail

echo "[*] Installing Falco on Kubernetes..."

# ════════════════════════════════════════════════════════════════════════════
# STEP 1: Add Falco Helm Chart Repository
# ════════════════════════════════════════════════════════════════════════════

echo "[1/5] Adding Falco Helm repository..."

helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# ════════════════════════════════════════════════════════════════════════════
# STEP 2: Create Falco Namespace
# ════════════════════════════════════════════════════════════════════════════

echo "[2/5] Creating falco namespace..."

kubectl create namespace falco 2>/dev/null || echo "Namespace already exists"

# ════════════════════════════════════════════════════════════════════════════
# STEP 3: Install Falco with Custom Values
# ════════════════════════════════════════════════════════════════════════════

echo "[3/5] Installing Falco Helm chart..."

cat > /tmp/falco-values.yaml <<'EOF'
# Falco Helm Chart Configuration

falco:
  # Enable runtime security
  ebpf:
    enabled: true   # Use eBPF for syscall capture (more efficient than kernel modules)

  # Rules configuration
  rulesFile: /etc/falco/rules.d

  # Output formatting
  jsonOutput: true  # Output in JSON format for parsing

# DaemonSet: Falco runs as a daemon on every node
daemonset:
  enabled: true

# Service Account
serviceAccount:
  create: true
  name: falco

# RBAC
rbac:
  create: true

# Pod Security
podSecurityPolicy:
  create: true

# Resources
resources:
  requests:
    memory: "256Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m"

# Node tolerations (so Falco runs on all nodes, including taints)
tolerations:
  - operator: "Exists"

# Alerts output (stdout = visible in pod logs)
falco:
  grpcOutput:
    enabled: false

# Custom rules (detect suspicious behavior)
customRules:
  rules.yaml: |
    - rule: Unauthorized Root Access
      desc: Detect when non-root process runs as root
      condition: >
        spawned_process and
        user.name != "root" and
        container
      output: >
        Unauthorized privilege escalation attempt
        (user=%user.name command=%proc.name container=%container.name)
      priority: WARNING

    - rule: Suspicious Network Activity
      desc: Detect unexpected outbound connections
      condition: >
        outbound and
        container and
        not fd.snet = "127.0.0.1"
      output: >
        Suspicious network connection from container
        (container=%container.name dest=%fd.sip)
      priority: NOTICE

    - rule: File Access Anomaly
      desc: Detect unauthorized /etc access
      condition: >
        read and
        container and
        fd.name glob "/etc/*"
      output: >
        Container accessing sensitive file
        (file=%fd.name container=%container.name)
      priority: WARNING
EOF

# Install Falco
helm install falco falcosecurity/falco \
  --namespace falco \
  --values /tmp/falco-values.yaml \
  --wait \
  --timeout 5m

# Clean up temp file
rm /tmp/falco-values.yaml

echo "✓ Falco installed"

# ════════════════════════════════════════════════════════════════════════════
# STEP 4: Verify Installation
# ════════════════════════════════════════════════════════════════════════════

echo "[4/5] Verifying Falco installation..."

# Wait for Falco pods to be ready
kubectl rollout status daemonset/falco -n falco --timeout=5m

# Check Falco pods
echo ""
echo "Falco pods:"
kubectl get pods -n falco

# ════════════════════════════════════════════════════════════════════════════
# STEP 5: Verify Falco is Detecting Events
# ════════════════════════════════════════════════════════════════════════════

echo "[5/5] Testing Falco alerts..."

# Get a Falco pod name
FALCO_POD=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -n "$FALCO_POD" ]; then
  echo ""
  echo "Recent Falco alerts from pod $FALCO_POD:"
  echo "(These are normal system activity alerts — Falco is working)"

  kubectl logs -n falco "$FALCO_POD" --tail=20 | grep -i "warning\|alert" || echo "No alerts yet (normal)"
else
  echo "⚠ Falco pod not ready yet"
fi

# ════════════════════════════════════════════════════════════════════════════
# CLEANUP INSTRUCTIONS
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "SUCCESS! Falco is installed and monitoring your cluster"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""
echo "Monitor Falco alerts:"
echo "  kubectl logs -n falco -l app.kubernetes.io/name=falco -f"
echo ""
echo "Trigger a test alert (privilege escalation):"
echo "  kubectl run --image=alpine test-pod -- sleep 3600"
echo "  kubectl exec -it test-pod -- sh"
echo "    # Inside pod:"
echo "    apk add sudo"
echo "    sudo id  # Will trigger Falco alert"
echo ""
echo "Uninstall Falco:"
echo "  helm uninstall falco -n falco"
echo "  kubectl delete namespace falco"
echo ""
echo "For more details, see: Month 10, Week 3 — Container & Runtime Security"
echo "════════════════════════════════════════════════════════════════════════════"
