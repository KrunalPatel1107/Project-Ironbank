# Month 9 — Week 1: Docker Security

!!! abstract "💰 Cost: $0 — All local Docker"

!!! info "Background Context"
    Containers are now the default deployment unit for cloud workloads. A misconfigured container can give an attacker root on the host. This week you learn to harden containers — skills that appear in every CloudSecOps, DevSecOps, and Platform Security job description.

---

## The Container Security Threat Model

Before hardening, understand what can go wrong:

| Threat | Example | Defence |
|---|---|---|
| Running as root | Container process has UID 0 → if it escapes, owns the host | Non-root USER in Dockerfile |
| Secrets in image layers | `ENV DB_PASS=secret123` baked into image | Secrets Manager at runtime |
| Writable filesystem | Malware can modify binaries | `--read-only` + tmpfs for writable dirs |
| Privileged container | `--privileged` = full host access | Never use privileged |
| Vulnerable base image | Old Ubuntu with unpatched CVEs | Minimal base + Trivy scanning |
| Exposed Docker socket | Mounting `/var/run/docker.sock` = container escape | Never mount the socket |

---

## Part 1: Write a Secure Dockerfile

!!! info "These examples use Node.js — but the Docker concepts are language-universal"
    The Dockerfile examples below containerize a Node.js app (the same `src/app.js` test file from Month 10). You don't need to understand Node.js. The security principles shown — non-root users, multi-stage builds, pinned base images, no secrets in layers — apply identically to Python, Java, or any other language. If you ever containerize a Python app, just change `FROM node:20-alpine` to `FROM python:3.11-alpine` and `CMD ["node", "app.js"]` to `CMD ["python3", "app.py"]`. Everything else stays the same.

**❌ Insecure Dockerfile (common mistakes):**

```dockerfile
FROM ubuntu:latest          # Huge image, always latest = unpinned
RUN apt-get install -y curl python3 nodejs npm git vim wget  # Unnecessary tools
ENV DB_PASSWORD=supersecret123   # Secret baked into image layer permanently
COPY . /app                 # Copies everything including .git, .env files
WORKDIR /app
RUN npm install
# No USER directive = runs as root
CMD ["node", "server.js"]
```

**✅ Secure Dockerfile (best practices):**

```dockerfile
# ── Stage 1: Builder ─────────────────────────────────────────────────────────
# Multi-stage build: build in a fat image, copy only the result to a slim image
FROM node:20-alpine AS builder
# Pin to a specific minor version in production: node:20.11-alpine3.19

WORKDIR /app

# Copy dependency files FIRST (Docker layer caching — only re-installs if these change)
COPY package.json package-lock.json ./
RUN npm ci --only=production   # ci = clean install, exactly matches lock file

COPY src/ ./src/

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM node:20-alpine AS runtime
# alpine = minimal base image (~5MB vs ~900MB for ubuntu) — fewer CVEs, smaller attack surface

WORKDIR /app

# Create a non-root user and group
# -r = system user (no login), -u 1001 = specific UID
RUN addgroup -r appgroup -g 1001 && \
    adduser  -r -u 1001 -G appgroup -s /sbin/nologin appuser

# Copy only the production dependencies and built code from the builder stage
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/src          ./src

# Switch to the non-root user — everything after this runs as appuser
USER appuser

# Expose only the port the app needs
EXPOSE 3000

# HEALTHCHECK tells Docker (and ECS) how to verify the container is healthy
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', r => process.exit(r.statusCode===200?0:1))"

# Use exec form (not shell form) so signals are handled correctly
CMD ["node", "src/server.js"]
```

```bash
# Build the secure image
mkdir -p ~/projects/secure-app
cat > ~/projects/secure-app/Dockerfile << 'DOCKERFILE'
FROM node:20-alpine AS runtime
RUN addgroup -r appgroup -g 1001 && \
    adduser  -r -u 1001 -G appgroup -s /sbin/nologin appuser
WORKDIR /app
RUN echo '{"name":"test","version":"1.0.0"}' > package.json
USER appuser
CMD ["node", "-e", "console.log('Secure container running'); setInterval(()=>{},1000)"]
DOCKERFILE

docker build -t iron-bank-secure:v1 ~/projects/secure-app/

# Verify it runs as non-root
docker run --rm iron-bank-secure:v1 id
# Should show: uid=1001(appuser) gid=1001(appgroup)

# Compare image sizes
docker images | grep -E "iron-bank|node|ubuntu"
```

---

## Part 2: Run Containers Securely

```bash
# ─── Run with read-only filesystem ────────────────────────────────────────────
# --read-only = container can't write to its own filesystem
# --tmpfs = create a writable in-memory filesystem for /tmp only
docker run --rm \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  iron-bank-secure:v1

# ─── Drop all capabilities ────────────────────────────────────────────────────
# Linux capabilities are fine-grained privileges (bind port <1024, raw sockets, etc.)
# --cap-drop ALL removes everything, then add back only what's needed
docker run --rm \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  iron-bank-secure:v1

# ─── Limit resources ──────────────────────────────────────────────────────────
# Prevent one container from consuming all host resources (DoS / cryptominer defence)
docker run --rm \
  --memory 256m \      # Max 256MB RAM
  --cpus 0.5 \         # Max 50% of one CPU core
  --pids-limit 50 \    # Max 50 processes (prevents fork bombs)
  iron-bank-secure:v1

# ─── NEVER do these ───────────────────────────────────────────────────────────
# docker run --privileged ...                         # Full host access
# docker run -v /var/run/docker.sock:/var/run/docker.sock ...  # Container escape
# docker run --user root ...                          # Force root even if Dockerfile sets USER
```

---

## Part 3: Scan Your Secure Image with Trivy

```bash
# Scan the image you just built
trivy image iron-bank-secure:v1

# Compare with a vulnerable base image
trivy image ubuntu:latest | grep -c CRITICAL || true

# Scan for misconfigurations in your Dockerfile
trivy config ~/projects/secure-app/

# Expected: far fewer CVEs in alpine vs ubuntu
# Goal: zero CRITICAL CVEs in your production images
```

---

## Part 4: Docker Bench for Security

Docker Bench is an automated script that checks your Docker host configuration against CIS Docker Benchmark.

```bash
docker run --rm -it \
  --net host \
  --pid host \
  --userns host \
  --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -v /etc:/etc:ro \
  --label docker_bench_security \
  docker/docker-bench-security

# Output: PASS / WARN / INFO for each CIS check
# Focus on WARN items — each has a remediation suggestion
```

!!! tip "What Docker Bench checks"
    Host configuration (separate partition for Docker), daemon configuration (no remote TCP without TLS), image practices (non-root, no unnecessary packages), container runtime (no privileged, resource limits), security operations (AppArmor/SELinux enabled).

---

## Part 5: .dockerignore

Like `.gitignore` — tells Docker what NOT to copy into the image.

```bash
cat > ~/projects/secure-app/.dockerignore << 'EOF'
# Never copy these into an image
.git/
.env
.env.*
*.pem
*.key
*.p12
secrets/
node_modules/        # Re-installed in Dockerfile — don't copy host version
.DS_Store
*.log
coverage/
.nyc_output/
test/
*.test.js
README.md
Dockerfile*
.dockerignore
EOF
```

---

## 🧹 Cleanup

```bash
docker image rm iron-bank-secure:v1 2>/dev/null
rm -rf ~/projects/secure-app
echo "✅ Week 1 complete — no cloud resources"
```

---

## Checklist

- [ ] Can list 6 Docker security threats from memory
- [ ] Secure Dockerfile written with: non-root USER, multi-stage build, alpine base, HEALTHCHECK
- [ ] Image built and verified running as UID 1001 (not root)
- [ ] Container launched with `--read-only`, `--cap-drop ALL`, `--no-new-privileges`
- [ ] Trivy scan run on your secure image — CRITICAL count lower than ubuntu base
- [ ] Trivy config scan run on your Dockerfile
- [ ] Docker Bench run — WARN items read and understood
- [ ] `.dockerignore` created — no secrets or `.git` would enter the image
- [ ] All containers stopped — no cloud resources used

