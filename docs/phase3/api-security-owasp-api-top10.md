# Month 7 — Week 3: API Security Deep Dive

!!! abstract "💰 Cost: $0-5 — Local Docker + free Postman/Burp Suite CE"

!!! danger "This Week: From API Basics to Production Defense"
    Week 3 now covers the complete API security picture:
    1. **API vulnerabilities** (OWASP API Top 10 — already in place)
    2. **API authentication mechanisms** (OAuth 2.0, JWT, mTLS — NEW)
    3. **Rate limiting & abuse prevention** (NEW)
    4. **API versioning strategies** (NEW)
    5. **Advanced API testing** (Burp Suite, Postman — NEW)

!!! info "Background Context"
    APIs are the attack surface of the cloud era — every mobile app, SaaS product, and microservice exposes one. The AWS services you've been using (S3, IAM, EC2) are themselves REST APIs. Understanding how APIs break AND how to defend them is essential for both AppSec and Cloud Security roles. This week bridges theory (OWASP) with practical authentication & defense mechanisms.

---

## OWASP API Security Top 10

The OWASP API Security Top 10 (2023) is separate from the web app Top 10. APIs have distinct attack patterns because they expose raw data operations rather than rendered pages.

| # | Category | What It Means | Example |
|---|---|---|---|
| API1 | Broken Object Level Auth | Missing per-object ownership check | GET /users/456/orders works even when you're user 123 |
| API2 | Broken Authentication | Weak or missing auth on endpoints | Admin endpoints return data without a token |
| API3 | Broken Object Property Level Auth | Returns more fields than needed | User profile returns password hash, SSN, internal flags |
| API4 | Unrestricted Resource Consumption | No rate limiting | Enumerate all user IDs in a loop |
| API5 | Broken Function Level Auth | Non-admin can call admin actions | DELETE /users/123 works with a regular token |
| API6 | Unrestricted Access to Sensitive Business Flows | Business logic abuse | Checkout API lets you set price to $0 |
| API7 | SSRF | Server fetches attacker-controlled URL | POST /fetch?url=http://169.254.169.254 |
| API8 | Security Misconfiguration | Default settings, exposed debug endpoints | Swagger UI exposed publicly in production |
| API9 | Improper Inventory Management | Old API versions still live | /api/v1/ deprecated but still functional |
| API10 | Unsafe Consumption of APIs | Trusting third-party API responses | Injecting content via a third-party data feed |

---

## Part 1: Tools Setup

```bash
# Juice Shop is your API target (it has a full REST API behind the UI)
docker run --rm -p 3000:3000 bkimminich/juice-shop

# Install HTTPie — a friendlier curl for API testing
pip install httpie --break-system-packages
# Verify
http --version

# Install jq — JSON pretty-printer and query tool (essential for API work)
sudo apt install jq -y   # Ubuntu/WSL
# brew install jq          # macOS
echo '{"name":"test"}' | jq .name   # Should print "test"
```

---

## Part 2: Explore the Juice Shop API

Before attacking, understand what the API exposes. Real-world API recon uses the same approach.

```bash
# ─── Step 1: Discover the API documentation ────────────────────────────────
# Juice Shop exposes its own Swagger UI
# Open in browser: http://localhost:3000/api-docs
# This lists every endpoint, HTTP method, parameters, and response schema

# ─── Step 2: Get an auth token ─────────────────────────────────────────────
# First create a test account via the UI, then log in via API:
TOKEN=$(http POST http://localhost:3000/rest/user/login \
  email="test@test.com" \
  password="Test1234!" \
  --print=b | jq -r '.authentication.token')
echo "Token: $TOKEN"

# ─── Step 3: List all products (no auth required — note this) ───────────────
http GET http://localhost:3000/rest/products/search q==juice | jq '.data[] | {id,name,price}'

# ─── Step 4: Inspect your own user profile ──────────────────────────────────
http GET http://localhost:3000/rest/user/whoami \
  "Authorization: Bearer $TOKEN" | jq .
# Note what fields come back — more than you'd expect for a "current user" endpoint
```

---

## Part 3: API1 — Broken Object Level Auth

This is the most common API vulnerability. You already saw a version of it (basket IDOR) in Week 2 — now you'll go deeper.

```bash
# ─── Access another user's profile by ID ────────────────────────────────────
# Juice Shop has a /rest/user endpoint that returns user details

# Try to access user ID 1 (admin) while authenticated as a regular user
http GET http://localhost:3000/api/Users/1 \
  "Authorization: Bearer $TOKEN"
# If it returns admin's data — BOLA confirmed

# ─── Enumerate users in a loop ──────────────────────────────────────────────
# This simulates an attacker harvesting the entire user database
for ID in 1 2 3 4 5 6 7 8 9 10; do
  RESULT=$(http GET http://localhost:3000/api/Users/$ID \
    "Authorization: Bearer $TOKEN" --print=b 2>/dev/null)
  EMAIL=$(echo $RESULT | jq -r '.data.email // "not found"')
  echo "User $ID: $EMAIL"
done
# No rate limiting = full enumeration possible
```

??? note "Why sequential IDs are dangerous"
    If your API uses auto-incrementing integers as resource IDs (1, 2, 3...) and doesn't check ownership, an attacker can iterate through every ID to harvest all data. Use **UUIDs** (e.g. `550e8400-e29b-41d4-a716-446655440000`) to make guessing practically impossible, *and* enforce server-side ownership checks — UUIDs alone are not sufficient.

---

## Part 4: API3 — Excessive Data Exposure

APIs often return full database objects when they should return only what the client needs. This is both a privacy issue and an information disclosure risk.

```bash
# ─── Inspect what the product search endpoint returns ────────────────────────
http GET "http://localhost:3000/rest/products/search?q=apple" | jq '.data[0]'
# Look carefully at the response — it returns fields like:
#   "deletedAt": null     (internal soft-delete status — clients don't need this)
#   "createdAt"           (internal timestamp)
#   "updatedAt"           (internal timestamp)

# ─── User endpoint over-exposure ─────────────────────────────────────────────
http GET http://localhost:3000/rest/user/whoami \
  "Authorization: Bearer $TOKEN" | jq .
# Returns: id, email, lastLoginIp, profileImage, totpSecret, isActive, role...
# A /whoami endpoint should return: email, name, role — nothing more
```

**The fix — API response shaping:**

!!! info "This is a code example for context, not something you write"
    As the security reviewer, you identify *that* the API returns too much data. The developer then writes the fix. The Python below shows the concept — your job is to understand and explain the difference, not to implement it.

```python
# BAD — returns entire database object (every field, including sensitive internal ones)
# user.__dict__ = all the object's data, including deletedAt, totpSecret, passwordHash etc.
return jsonify(user.__dict__)

# GOOD — explicitly select only the fields the client actually needs
# This is the "principle of least privilege" applied to API responses
return jsonify({
    "email": user.email,       # What the client needs
    "name":  user.username,    # What the client needs
    "role":  user.role,        # What the client needs
    # Everything else stays server-side
})
```

---

## Part 5: API7 — Server-Side Request Forgery (SSRF)

SSRF tricks the server into making HTTP requests on your behalf — to internal services, or to the AWS metadata endpoint.

```bash
# ─── Conceptual test: does the app fetch URLs? ───────────────────────────────
# Juice Shop has a profile image upload that accepts a URL
# Log in via the browser, go to your account → profile photo → paste a URL

# In a real AWS deployment, try:
# http://169.254.169.254/latest/meta-data/
# This is the EC2 Instance Metadata Service (IMDS) — if the server fetches this
# it returns the instance's IAM role credentials

# ─── Why AWS IMDS is the critical target ────────────────────────────────────
# On any EC2 instance, this URL returns credentials:
# GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# Response contains: AccessKeyId, SecretAccessKey, Token (valid for hours)
# An attacker who can trigger SSRF can steal AWS credentials and pivot to S3, IAM, etc.

# ─── IMDSv2 — the defence ────────────────────────────────────────────────────
# AWS now defaults to IMDSv2 which requires a PUT request to get a session token first
# Simple GET requests to the metadata endpoint are rejected
# Always enforce IMDSv2 on your EC2 instances:
echo "Terraform to enforce IMDSv2:"
cat << 'EOF'
resource "aws_instance" "secure" {
  ...
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # Forces IMDSv2 — rejects unauthenticated GET
    http_put_response_hop_limit = 1            # Prevents containers from reaching IMDS
  }
}
EOF
```

!!! warning "SSRF + AWS IMDS = Critical severity"
    This exact attack vector was used in the **Capital One breach (2019)**. The attacker found an SSRF vulnerability in a WAF misconfiguration, used it to call the EC2 metadata endpoint, received IAM role credentials, and then exfiltrated 100 million credit card applications from S3. IMDSv2 and least-privilege IAM roles are the primary mitigations.

---

## Part 6: API Security Headers

Security headers tell browsers and clients how to behave — they're a cheap, high-value defence.

```bash
# ─── Inspect Juice Shop's response headers ────────────────────────────────────
http --headers GET http://localhost:3000/rest/products/search q==test | grep -i \
  -e "content-security" \
  -e "x-frame" \
  -e "strict-transport" \
  -e "x-content-type" \
  -e "permissions-policy"

# Missing headers = findings you'd report in a real assessment
```

**The headers that matter:**

| Header | Value | What It Does |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'` | Blocks XSS by restricting which scripts can run |
| `Strict-Transport-Security` | `max-age=31536000` | Forces HTTPS — prevents downgrade attacks |
| `X-Frame-Options` | `DENY` | Prevents clickjacking via iframes |
| `X-Content-Type-Options` | `nosniff` | Stops browsers guessing content type |
| `Permissions-Policy` | `camera=(), microphone=()` | Restricts browser feature access |

```bash
# Test any website's security headers
curl -sI https://amazon.com | grep -i "strict-transport\|content-security\|x-frame"

# Or use the free online scanner:
# https://securityheaders.com  — paste any URL, get a grade A-F
```

---

## Part 7: API Authentication Deep Dive (OAuth 2.0, JWT, mTLS)

**Threat Model Connection:** Weak or missing authentication = API2 (Broken Authentication) and API5 (Broken Function Level Auth). An attacker can masquerade as another user or escalate to admin privileges.

APIs must prove "you are who you claim to be" (authentication) and "you're allowed to do this" (authorization). There are multiple mechanisms — each with trade-offs.

### Mechanism 1: JWT (JSON Web Tokens) — Stateless Authentication

JWTs encode user identity into a cryptographically signed token. The server doesn't store session state.

**How JWT works:**
1. Client logs in with credentials → Server returns a signed JWT token
2. Client includes JWT in Authorization header: `Authorization: Bearer eyJhbGc...`
3. Server verifies the signature (proves the token wasn't tampered with) and reads claims (`sub: user_id`, `role: admin`)
4. No server-side session storage needed → scales horizontally

**JWT structure:** `header.payload.signature`
- **Header:** `{"alg": "HS256", "typ": "JWT"}` (base64url encoded)
- **Payload:** `{"sub": "user123", "role": "user", "exp": 1700000000}` (base64url encoded)
- **Signature:** HMAC-SHA256(header + "." + payload, secret_key) — proves the token wasn't modified

**Lab: Decode and understand a JWT**

```bash
# Use jwt.io (web) or a command-line tool
pip install PyJWT --break-system-packages

# Create a JWT (use this to understand the structure)
cat > ~/test-jwt.py << 'EOF'
import jwt
from datetime import datetime, timedelta

# The secret key — this is what the server uses to sign tokens
SECRET = "my-secret-key-keep-this-safe"

# Create a token
payload = {
    "sub": "user123",           # Subject (user ID)
    "name": "Alice",            # User's name
    "role": "user",             # Authorization role
    "exp": datetime.utcnow() + timedelta(hours=1)  # Expiration time
}

token = jwt.encode(payload, SECRET, algorithm="HS256")
print(f"Token: {token}\n")

# Decode and verify (this is what the server does)
decoded = jwt.decode(token, SECRET, algorithms=["HS256"])
print(f"Decoded: {decoded}\n")

# Tamper attempt: change the payload
parts = token.split('.')
# If attacker tries to change payload[1] without knowing SECRET:
fake_token = parts[0] + ".eyJzdWIiOiJ1c2VyNDU2Iiwicm9sZSI6ImFkbWluIn0." + parts[2]
try:
    jwt.decode(fake_token, SECRET, algorithms=["HS256"])
except jwt.InvalidSignatureError:
    print("❌ Tampering detected! Signature doesn't match.")
EOF

python3 ~/test-jwt.py
```

**JWT Vulnerabilities & Defense:**

| Vulnerability | What Happens | Defense |
|---|---|---|
| Weak secret key | Attacker brute-forces the signing key | Use strong, random secret (32+ bytes) |
| Algorithm confusion | Attacker changes `alg: "RS256"` to `alg: "none"` | Verify algorithm matches server expectations |
| Expired token not checked | Old token still accepted | Always check `exp` claim |
| Token stored in localStorage | XSS steals token | Store in httpOnly, secure cookies instead |

### Mechanism 2: OAuth 2.0 — Delegated Authorization

OAuth 2.0 is used when you want to let users log in via a third party (Google, GitHub, AWS) without sharing their password with your app.

**Flow:**
1. User clicks "Login with GitHub"
2. App redirects to GitHub: `https://github.com/login/oauth/authorize?client_id=xxx&redirect_uri=your-app.com/callback`
3. User logs in with GitHub credentials (your app never sees the password)
4. GitHub redirects back with an authorization code: `redirect_uri?code=xyz`
5. Your app exchanges the code for a JWT or session token: `POST https://github.com/login/oauth/access_token`
6. Your app now has proof the user is authenticated via GitHub

**Key security points:**
- Client secret must never be exposed (keep on backend only)
- Always validate the redirect_uri (prevent open redirect attacks)
- Use state parameter to prevent CSRF: `&state=random_nonce`

### Mechanism 3: mTLS (Mutual TLS) — Certificate-Based Auth

mTLS is used for machine-to-machine API authentication (service-to-service, not user-to-service). Both client and server present X.509 certificates.

**When to use mTLS:**
- Kubernetes: service-to-service communication (service mesh like Istio handles this)
- Microservices: secure inter-service calls
- AWS: S3 can be called via mTLS, or Lambda can call another service via mTLS

**Simple mTLS example (conceptual):**

```bash
# Server presents: "I'm service-api.internal, signed by corporate CA"
# Client presents: "I'm client-webapp.internal, signed by corporate CA"
# Both verify each other's cert → mutual trust established
# No passwords, no tokens — just cryptographic proof of identity
```

---

## Part 8: Rate Limiting & Abuse Prevention

**Threat Model Connection:** API4 (Unrestricted Resource Consumption) — without rate limiting, attackers can:
- Enumerate all user IDs in a loop
- Brute-force passwords
- Scrape sensitive data
- Cause denial of service by flooding the API

**Defense mechanisms:**

### Token Bucket Algorithm (Most Common)

```
Each user gets a "bucket" with N tokens.
Every request costs 1 token.
Tokens refill at rate R per second.

Example: 100 tokens, 10/sec refill rate
  → User can do 100 requests immediately
  → Then 10 requests/sec forever
```

### Implementation Example (Conceptual):

```python
# Pseudo-code for rate limiting
class RateLimiter:
    def __init__(self, max_requests=100, refill_rate=10):
        self.max = max_requests
        self.rate = refill_rate
        self.tokens = max_requests
        self.last_refill = time.time()
    
    def is_allowed(self):
        # Refill tokens based on time elapsed
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.max, self.tokens + elapsed * self.rate)
        self.last_refill = now
        
        # Check if user has tokens
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

# When client makes a request:
limiter = RateLimiter()
if limiter.is_allowed():
    return process_request()
else:
    return 429_TOO_MANY_REQUESTS
```

### HTTP Response Headers for Rate Limiting

When a client hits the limit, return 429 with headers:

```
HTTP/1.1 429 Too Many Requests
RateLimit-Limit: 100
RateLimit-Remaining: 0
RateLimit-Reset: 1700000000
Retry-After: 60

{"error": "Rate limit exceeded. Retry after 60 seconds."}
```

**Rate Limiting Per What?**
- **Per IP address:** `GET /api/users/enum` limited to 10/sec per IP
- **Per user ID:** `GET /api/orders/{id}` limited to 100/sec per authenticated user
- **Per endpoint:** `POST /api/login` limited to 5/min per IP (brute-force protection)
- **Global:** API overall limited to 10,000 req/sec (protect backend from overwhelm)

---

## Part 9: API Versioning Strategies

**Threat Model Connection:** API9 (Improper Inventory Management) — old API versions with vulnerabilities still exposed and exploitable.

Old APIs never die — clients depend on them. But you need a migration path to deprecate them without breaking existing users.

### Strategy 1: URL Path Versioning (Most Common)

```
/api/v1/users      ← Version 1 (old, deprecated)
/api/v2/users      ← Version 2 (current)
/api/v3/users      ← Version 3 (future)
```

**Pros:** Clear, easy to understand  
**Cons:** Maintenance burden (run multiple code paths)

### Strategy 2: Header-Based Versioning

```
GET /api/users
Accept: application/vnd.myapi.v2+json
```

**Pros:** Same URL, cleaner  
**Cons:** Clients must know to set the header

### Strategy 3: Query Parameter Versioning

```
GET /api/users?version=2
```

**Best Practice for Deprecation:**

```bash
# In your API documentation
GET /api/v1/users
  DEPRECATED since 2024-01-01
  Use GET /api/v2/users instead
  Sunset-Date: 2024-07-01
  Migration-Link: https://docs.yourapi.com/v1-to-v2-migration
```

Return headers to warn clients:

```
Deprecation: true
Sunset: Sun, 01 Jul 2024 00:00:00 GMT
Link: </api/v2/users>; rel="successor-version"
```

---

## Part 10: Advanced API Testing with Burp Suite & Postman

### Setup

```bash
# Install Burp Suite CE (community edition, free)
# Download from: https://portswigger.net/burp/communitydownload
# (It's Java, runs on any OS)

# Or use Postman (free tier is sufficient)
# Download from: https://www.postman.com/downloads/

# For this lab, we'll use both
```

### Lab: Test Juice Shop API with Postman

```bash
# Step 1: Create a Postman collection for Juice Shop
# File → New → Collection → name it "Juice Shop API"

# Step 2: Create requests
# POST http://localhost:3000/rest/user/login
#   Body (JSON): {"email": "test@test.com", "password": "Test1234!"}
#   → Copy the token from response

# Step 3: Use the token in subsequent requests
# GET http://localhost:3000/rest/user/whoami
#   Header: Authorization: Bearer {{token}}
#   → Right-click token in response, "Set as variable"

# Step 4: Test BOLA
# GET http://localhost:3000/api/Users/1
#   Header: Authorization: Bearer {{token}}
#   → Does it return user 1's data? (vulnerability confirmed)

# Step 5: Test rate limiting
# Create a "Runner" in Postman
# Run the same request 100 times in 10 seconds
# Watch for 429 responses
```

### Lab: Test with Burp Suite Intruder

Burp Suite is more powerful for attack simulation (Postman is better for API design).

```bash
# Step 1: Launch Burp and proxy traffic through it
# Browser → Burp settings → set HTTP proxy to localhost:8080

# Step 2: Visit Juice Shop, log in (Burp captures all traffic)

# Step 3: Go to Burp Intruder
# Intercept the API request
# Highlight the user ID: /api/Users/[1]
# Click "Send to Intruder"

# Step 4: Configure attack
# Positions: /api/Users/§1§ (mark the ID as variable)
# Payload: Numbers from 1 to 20
# Start attack

# Step 5: Analyze results
# Look for status 200 (successful BOLA)
# vs 403 (properly rejected)
# Burp highlights which IDs succeeded
```

---

## Part 11: API Security Checklist Template

Create a reusable checklist for API reviews:

```bash
cat > ~/api-security-checklist.md << 'EOF'
# API Security Assessment Checklist

## Authentication & Authorization
- [ ] All endpoints require authentication (except public ones explicitly marked)
- [ ] JWT tokens are signed with a strong secret (32+ bytes)
- [ ] JWT signature algorithm is verified (not "none")
- [ ] Tokens include expiration (`exp` claim), checked on every request
- [ ] No sensitive data in JWT payload (tokens can be decoded by anyone)
- [ ] Credentials are not logged or exposed in error messages
- [ ] CORS headers are restrictive (`Access-Control-Allow-Origin` not `*`)

## Authorization (Who can do what)
- [ ] Ownership check on user-specific endpoints (can't access other users' data)
- [ ] Role-based access control enforced on admin endpoints
- [ ] No privilege escalation (can't self-promote from user to admin)

## Data Protection
- [ ] All data in transit is encrypted (HTTPS only, no HTTP)
- [ ] Sensitive fields are not returned (passwords, API keys, internal IDs)
- [ ] PII is properly scoped (only return what the client needs)
- [ ] Secrets (API keys, credentials) are not logged

## Rate Limiting & Abuse Prevention
- [ ] Rate limiting is enforced per IP and/or per user
- [ ] Brute-force targets (login, password reset) have strict limits
- [ ] 429 responses include Retry-After header
- [ ] Resource enumeration attacks are limited (e.g., /api/users/1, /api/users/2...)

## API Versioning & Deprecation
- [ ] Old API versions have documented sunset dates
- [ ] Deprecation headers are returned (Deprecation, Sunset, Link)
- [ ] Migration guide provided for v1 → v2 users

## Error Handling
- [ ] Errors don't leak system information (no stack traces, DB schema details)
- [ ] 401 vs 403 properly distinguished (not found vs unauthorized vs forbidden)
- [ ] No directory listing (404, not 200 with directory contents)

## Security Headers
- [ ] Content-Security-Policy set (limits XSS)
- [ ] Strict-Transport-Security set (forces HTTPS)
- [ ] X-Frame-Options: DENY (prevents clickjacking)
- [ ] X-Content-Type-Options: nosniff (stops MIME sniffing)

## Business Logic
- [ ] Prices/amounts can't be set by clients (POST /checkout with price=$0)
- [ ] Operations are idempotent where needed (duplicate requests OK)
- [ ] State transitions are validated (can't jump from pending → shipped → pending)
EOF

cat ~/api-security-checklist.md
```

---

## Part 12: Write Advanced API Finding

Add to your GitHub writeup collection:

```bash
cat > ~/projects/juice-shop-writeups/02-bola-user-enumeration.md << 'EOF'
# Finding: Broken Object Level Authorization — User Enumeration

**Severity:** High
**OWASP API:** API1 — Broken Object Level Authorization
**Affected Endpoint:** GET /api/Users/{id}

## Description
The /api/Users/{id} endpoint returns user profile data for any user ID when a valid
authentication token is supplied. No ownership check is performed — any authenticated
user can retrieve any other user's data by incrementing the ID parameter.

## Steps to Reproduce
1. Log in as any user and obtain a JWT token
2. Send: `GET /api/Users/1` with Authorization header
3. Response contains admin user's email, hashed password, and internal flags

## Impact
Full user database enumeration. An attacker can harvest all email addresses,
identify admin accounts, and access sensitive profile data for all users.

## Remediation
The development team should add a server-side ownership check before returning user data.
In pseudo-code (language doesn't matter — this is the logic to enforce):
`if (requestedUser.id !== authenticatedUser.id AND user is not admin) → return 403 Forbidden`

As a security advisor, your job is to identify the missing check and describe the logic.
The developers write the actual code fix in whatever language the app uses.

Use UUIDs instead of sequential integers for resource IDs.
Log and alert on sequential ID enumeration patterns.
EOF

git -C ~/projects/juice-shop-writeups add .
git -C ~/projects/juice-shop-writeups commit -m "feat: add BOLA finding writeup — Week 3"
git -C ~/projects/juice-shop-writeups push
```

---

## 🧹 Cleanup

```bash
docker stop $(docker ps -q --filter ancestor=bkimminich/juice-shop) 2>/dev/null
docker image rm bkimminich/juice-shop
echo "✅ All containers stopped and images removed"
```

---

## Checklist

**OWASP API Top 10 & Vulnerability Testing**
- [ ] Can name all 10 OWASP API Security categories from memory
- [ ] Explored Juice Shop's Swagger UI at `/api-docs`
- [ ] Confirmed API1 (BOLA) — accessed another user's data via ID manipulation
- [ ] Identified API3 (excessive data exposure) — noted over-exposed fields in responses
- [ ] Understand API7 (SSRF) → AWS IMDS attack chain (can explain the Capital One breach)
- [ ] Know what IMDSv2 is and the Terraform config that enforces it
- [ ] Inspected Juice Shop security headers — noted what's missing

**API Authentication (JWT, OAuth 2.0, mTLS)**
- [ ] Can explain JWT structure (header.payload.signature)
- [ ] Decoded a JWT and identified claims (sub, role, exp)
- [ ] Understand JWT vulnerabilities: weak secret, algorithm confusion, missing expiration check
- [ ] Can explain OAuth 2.0 flow (user, app, authorization server, token)
- [ ] Know when to use mTLS (service-to-service, Kubernetes)
- [ ] Created a JWT test script and verified signature validation

**Rate Limiting & Abuse Prevention**
- [ ] Understand token bucket algorithm (refill rate, max tokens)
- [ ] Can explain rate limiting strategies (per IP, per user, per endpoint, global)
- [ ] Know the HTTP 429 response and Retry-After header
- [ ] Tested rate limit bypass with Postman Runner (flooded API, watched for 429s)
- [ ] Can explain why sequential ID enumeration is dangerous without rate limiting

**API Versioning & Deprecation**
- [ ] Can compare 3 versioning strategies (URL path, header, query parameter)
- [ ] Know how to deprecate an API version (Sunset header, deprecation notice)
- [ ] Can explain migration path for breaking changes

**Advanced API Testing Tools**
- [ ] Downloaded and installed Burp Suite CE and/or Postman
- [ ] Created a Postman collection for Juice Shop API
- [ ] Used Postman to chain requests (login → get token → use token in subsequent requests)
- [ ] Used Postman Runner to test rate limiting (batch requests)
- [ ] Intercepted API traffic in Burp Suite
- [ ] Used Burp Intruder to enumerate user IDs (BOLA confirmation)

**API Security Assessment**
- [ ] Created an API security checklist (authentication, authorization, data protection, rate limiting, etc.)
- [ ] Wrote at least 2 API finding documents (BOLA, JWT misconfiguration, or rate limit bypass)
- [ ] Can explain real-world API breaches: Facebook BOLA, Uber JWT bypass, Slack rate limit bypass
- [ ] Obtained a JWT token via httpie: `http POST`
- [ ] Completed 10+ PortSwigger API labs (running total: 20+)

**Cleanup**
- [ ] Docker containers stopped and images removed
- [ ] Postman collection saved to git
- [ ] API findings documented in GitHub repository
