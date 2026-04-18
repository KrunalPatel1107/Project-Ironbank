# Month 7 — Special: Secure Software Development Lifecycle (SDLC)

!!! abstract "💰 Cost: $0-5/month — GitHub (free), Jira (self-hosted free), templates (free)"

!!! danger "Why Secure SDLC Matters"
    You can deploy WAF, SAST, DAST, and container scanning (Phase 3-4), but if developers never learn to build securely, you're treating symptoms, not the root cause. Secure SDLC embeds security into every phase: **design → code → review → test → deploy → monitor**. Microsoft, Google, and Amazon mandate secure SDLC for all engineers. This week teaches you to operationalize security as a developer responsibility, not a security-team-only function.

!!! info "Background Context"
    You've learned OWASP attacks (owasp-top10-theory), exploitation labs (owasp-exploitation-labs), API security (api-security-owasp-api-top10), and threat modeling (threat-modeling-bootcamp). This week ties it together: threat models → secure design → code review → security testing → incident response. It's the **process** that prevents Equifax, Solar Winds, and Log4j from happening on *your* team.

---

## Part 1: Threat Modeling in Development

**Threat modeling at design time** catches security flaws before code is written.

### STRIDE Framework (Threat Categorization)

```
S = Spoofing (forged identity)
T = Tampering (modifying data)
R = Repudiation (denying action)
I = Information Disclosure (leaking data)
D = Denial of Service (crashing app)
E = Elevation of Privilege (unauthorized access)
```

### Example: Threat Model for a Login API

```
API Endpoint: POST /api/v1/login
  Input: { username, password }
  Output: { jwt_token }

Threats:
1. SPOOFING: Attacker forges JWT token to impersonate user
   - Mitigation: Sign JWT with strong key, verify signature on backend
   
2. TAMPERING: Attacker modifies JWT in transit (man-in-the-middle)
   - Mitigation: Use HTTPS/TLS for all traffic
   
3. INFORMATION DISCLOSURE: Password sent in plaintext
   - Mitigation: Hash password with Argon2, never log passwords
   
4. DENIAL OF SERVICE: Brute-force attack (1000s of login attempts/sec)
   - Mitigation: Rate limit (max 5 attempts per minute), lock account after 10 failures
   
5. ELEVATION OF PRIVILEGE: User modifies JWT to change user_id
   - Mitigation: Sign JWT, verify expiration, store user_id in token, validate on each request
```

### Lab: Document a Threat Model for YOUR App

```bash
cat > ~/threat-model-login.md << 'EOF'
# Threat Model: User Registration & Authentication

## Component Diagram
```
[User Client] → HTTPS → [API Server] → [PostgreSQL]
                                      ↓
                               [Email Service]
```

## Data Flow Analysis

### 1. User Registration Flow
Threat: Attacker registers with weak password
- Mitigation: Enforce password policy (min 12 chars, uppercase, symbols, no common patterns)

Threat: Attacker registers multiple accounts (spam)
- Mitigation: Email verification (send code to email), CAPTCHA on signup

### 2. Login Flow
Threat: Brute-force attack on login
- Mitigation: Rate limit (5 attempts/min), progressive delays, account lockout

Threat: Session hijacking (attacker steals JWT)
- Mitigation: Short JWT expiration (15 min), refresh token rotation, secure cookie flags (HttpOnly, Secure, SameSite)

### 3. Password Reset Flow
Threat: Attacker resets another user's password
- Mitigation: Email verification before reset, token expires in 1 hour, reset link is one-time use

## Risk Assessment Matrix

| Threat | Likelihood | Impact | Risk | Mitigation |
|--------|-----------|--------|------|-----------|
| Brute-force | High | High | CRITICAL | Rate limit + MFA |
| SQL Injection | Low | Critical | CRITICAL | Parameterized queries |
| JWT Theft | Medium | High | HIGH | HTTPS + short expiry |
| Weak Password | High | Medium | HIGH | Policy enforcement |

EOF

cat ~/threat-model-login.md
```

---

## Part 2: Secure Coding Standards

Security should be a non-functional requirement, like performance or availability.

### Security Requirements Checklist

```yaml
# Before coding, developers should answer:

Authentication:
  - [ ] How do users prove identity? (password, MFA, OAuth)
  - [ ] Are passwords hashed with Argon2? (not MD5, SHA1)
  - [ ] Is password reset secure? (email token, 1-hour expiry)
  - [ ] Is session timeout configured? (15-30 min for sensitive apps)

Authorization:
  - [ ] Does every API endpoint check user permissions?
  - [ ] Are there default deny policies? (no blanket "allow all")
  - [ ] Can users access only their own data?
  - [ ] Is role-based access control (RBAC) implemented?

Data Protection:
  - [ ] Is sensitive data encrypted at rest? (AES-256)
  - [ ] Is data encrypted in transit? (HTTPS, TLS 1.2+)
  - [ ] Are API responses logged? (avoid logging passwords, tokens, PII)
  - [ ] Is database encryption enabled? (RDS, KMS)

Input Validation:
  - [ ] Are all inputs validated before use?
  - [ ] Are SQL queries parameterized? (no string concatenation)
  - [ ] Are file uploads scanned for malware?
  - [ ] Are JSON/XML inputs size-limited? (prevent DoS)

Error Handling:
  - [ ] Are error messages generic? (don't leak system info)
  - [ ] Are exceptions logged with context?
  - [ ] Are credentials never logged?
  - [ ] Is logging output checked for PII?

Dependencies:
  - [ ] Are third-party libraries pinned to versions?
  - [ ] Are security advisories checked? (npm audit, pip-audit)
  - [ ] Is an SBOM generated for each build?
  - [ ] Are container images scanned for CVEs?
```

---

## Part 3: Code Review Security Checklist

Code review is YOUR defense against vulnerabilities. Here's what to check:

### Security Code Review Template

```bash
cat > ~/code-review-security-checklist.md << 'EOF'
# Security Code Review Checklist

## Authentication & Authorization
- [ ] User identity is verified before sensitive operations
- [ ] Passwords are hashed with Argon2 (or bcrypt/scrypt), NOT MD5/SHA1
- [ ] JWT tokens are signed and signature is verified on each request
- [ ] OAuth/SAML integration correctly validates issuer and audience
- [ ] Tokens have short expiration times (15-60 min)
- [ ] Authorization checks pass at API level (not just frontend)
- [ ] No hardcoded credentials in code (API keys, DB passwords, SSH keys)

## Input Validation
- [ ] All user inputs are validated for type, length, format
- [ ] SQL queries use parameterized statements (no string concat)
- [ ] File uploads are validated (type, size, extension)
- [ ] Regular expressions are not vulnerable to ReDoS (catastrophic backtracking)
- [ ] XML/JSON parsing has limits (prevent billion laughs attack, zip bomb)
- [ ] API rate limits are enforced (prevent brute-force, DoS)

## Data Protection
- [ ] Sensitive data is not logged (passwords, tokens, credit cards, PII)
- [ ] Database connections use SSL/TLS (not plain TCP)
- [ ] Encryption keys are not hardcoded (use KMS, Secrets Manager)
- [ ] Data is encrypted at rest (S3, database) and in transit (HTTPS)
- [ ] PII (personally identifiable info) is minimized (collect only what's needed)
- [ ] Data deletion is implemented (GDPR, CCPAssistant compliance)

## Error Handling & Logging
- [ ] Error messages don't leak system details (stack traces, paths, versions)
- [ ] Exceptions are logged with context (request ID, user, timestamp)
- [ ] Secrets are never logged (check all log statements)
- [ ] Sensitive data is masked in logs (credit card → ****-****-****-1234)
- [ ] Log aggregation is secure (encrypted in transit, access controlled)

## Dependencies & Supply Chain
- [ ] Third-party libraries are from official sources (npm, PyPI, Maven)
- [ ] Dependencies are pinned to specific versions (no floating ~X.Y.Z)
- [ ] Security advisories are checked (npm audit, pip-audit, Dependabot)
- [ ] Outdated libraries are updated (especially critical vulnerabilities)
- [ ] New dependencies have minimum GitHub stars/activity (avoid abandoned projects)

## Cryptography
- [ ] AES-256-GCM is used for symmetric encryption (not ECB, CBC without auth)
- [ ] RSA-2048+ or ECDSA is used for signatures (not MD5, SHA1)
- [ ] Key derivation uses Argon2/PBKDF2 (not plain hashing)
- [ ] IV (initialization vector) is random for each encryption
- [ ] Key rotation is planned (annual for long-term keys)

## Common Vulnerabilities (OWASP Top 10)
- [ ] No SQL Injection (use parameterized queries)
- [ ] No XSS (sanitize user input, use templating engines)
- [ ] No CSRF (use anti-CSRF tokens, SameSite cookies)
- [ ] No Broken Auth (strong password policy, MFA, secure session handling)
- [ ] No Insecure Deserialization (validate data before deserializing)
- [ ] No SSRF (validate URLs, use IP allowlists for internal services)
- [ ] No XXE (disable XML external entities)
- [ ] No Weak Crypto (use approved algorithms, not custom crypto)

## API Security
- [ ] API endpoints require authentication (no public access)
- [ ] API rate limits are enforced (prevent abuse)
- [ ] API versioning is documented (v1, v2 deprecation path)
- [ ] Sensitive data is not exposed in API responses (only necessary fields)
- [ ] API keys are rotated regularly (if used)

## Testing & Release
- [ ] Unit tests include security tests (invalid input, edge cases)
- [ ] SAST tools are run (Semgrep, eslint security plugins)
- [ ] DAST is performed before production (ZAP, Burp)
- [ ] Dependency scan is run (Grype, Snyk)
- [ ] Container image is scanned for CVEs (Trivy)

---

## Approval Criteria

**Do not approve PR if:**
- Hardcoded credentials present
- No input validation on user inputs
- SQL concatenation (string interpolation)
- Passwords not hashed (plain text or weak hash)
- Security tests are missing
- SAST/DAST findings not resolved

**Red flags requiring escalation:**
- Disabling CORS, CSP, or security headers
- Changes to authentication/authorization logic
- Cryptographic algorithm changes
- Bypass of security checks
EOF

cat ~/code-review-security-checklist.md
```

---

## Part 4: Security Training for Developers

Engineers are your first line of defense. Invest in their security knowledge.

### Mandatory Security Training Topics

```
Frequency: All developers should complete annually

1. OWASP Top 10 (4 hours)
   - SQL Injection, XSS, CSRF, Broken Auth, Sensitive Data Exposure
   - Lab: Write exploits, then fix them

2. Secure Coding (4 hours)
   - Input validation, output encoding, crypto basics
   - Lab: Code review real vulnerabilities

3. API Security (2 hours)
   - OAuth 2.0, JWT, rate limiting, API versioning
   - Lab: Test APIs with Postman

4. Secrets Management (2 hours)
   - Why not to hardcode credentials, how to use Secrets Manager
   - Lab: Deploy app with Secrets Manager

5. Threat Modeling (2 hours)
   - STRIDE framework, risk assessment, mitigation
   - Lab: Model your team's architecture

6. Incident Response (1 hour)
   - What to do if you discover a vulnerability
   - Lab: Simulated incident response
```

### Internal Security Champion Program

```
Goal: Develop security experts within engineering teams

Requirements:
- Attend monthly security workshops (1 hour)
- Review security findings in code reviews (lead role)
- Mentor other engineers on security practices
- Participate in threat modeling sessions
- Stay updated on CVEs in team's dependencies

Benefits:
- Recognition (title, compensation bonus)
- Paid time for security work
- First look at new security tools
- Input on security priorities
```

---

## Part 5: Bug Bounty Programs

A bug bounty incentivizes external security researchers to find (and report) vulnerabilities before attackers do.

### Bug Bounty Platforms

| Platform | Cost | Coverage | When to Use |
|---|---|---|---|
| **HackerOne** | $25K-$100K+ annual | Private + public | Large companies, mature programs |
| **Bugcrowd** | $20K-$50K+ annual | Private + public | Enterprises, compliance-driven |
| **Intigriti** | $10K-$25K+ annual | Private + public | Mid-market, European focus |
| **YesWeHack** | $5K-$15K+ annual | Private + public | Startups, cost-conscious |

### Setting Up a Basic Bug Bounty

```bash
# 1. Define Scope
cat > ~/bug-bounty-policy.md << 'EOF'
# Bug Bounty Policy

## Eligible Targets
- ✅ api.myapp.com (all endpoints)
- ✅ myapp.com (main website)
- ❌ internal.myapp.com (no access)
- ❌ security.txt (not in scope)

## Eligible Vulnerabilities
**CRITICAL/HIGH:**
- Remote Code Execution (RCE)
- SQL Injection leading to data breach
- Broken Authentication (account takeover)
- Sensitive Data Exposure (PII leak)
- XXE, SSRF, CSRF on sensitive actions

**MEDIUM:**
- Reflected XSS
- Weak Cryptography
- Rate limit bypass
- API key exposure

**OUT OF SCOPE:**
- Self-XSS (attacker-only)
- Physical vulnerabilities
- Social engineering
- DoS attacks (unless novel)
- Already known vulnerabilities

## Reward Structure
| Severity | Reward | Example |
|----------|--------|---------|
| CRITICAL | $500-$2000 | RCE, auth bypass |
| HIGH | $200-$500 | SQL injection, XXE |
| MEDIUM | $50-$200 | XSS, weak crypto |
| LOW | $10-$50 | Security header missing |

## Submission Process
1. Report via HackerOne.com/mycompany
2. Provide: vulnerability description, steps to reproduce, impact
3. Do NOT publicly disclose (honor embargo period: 90 days)
4. We'll triage within 7 days, fix within 30 days
EOF

cat ~/bug-bounty-policy.md
```

### Responsible Disclosure Process

```
Day 0: Researcher finds vulnerability, reports via HackerOne
Day 1: Your team triages (reproduce, assess severity)
Day 3: Confirm receipt, provide timeline for fix
Day 14: Send fix for internal testing
Day 30: Deploy fix to production
Day 45: Researcher can publicly disclose (if they choose)
Day 60: Bounty payment processed

(Adjust timeline based on severity — critical vulns faster)
```

---

## Part 6: Vulnerability Disclosure

When your researchers (internal or external) find a vulnerability, communicate responsibly.

### Security.txt File

```bash
# Create /.well-known/security.txt
cat > /var/www/html/.well-known/security.txt << 'EOF'
Contact: security@mycompany.com
Expires: 2025-04-16T00:00:00.000Z
Preferred-Languages: en
Canonical: https://mycompany.com/.well-known/security.txt
Policy: https://mycompany.com/security/bug-bounty-policy

# Include if you have a bug bounty program
Bug-Bounty: https://hackerone.com/mycompany
EOF

# Verify it's accessible
curl https://mycompany.com/.well-known/security.txt
```

### Vulnerability Disclosure Communication

```bash
cat > ~/vuln-disclosure-template.md << 'EOF'
# Subject: [SECURITY] Critical Vulnerability Fixed - User Action Required

Dear Customer,

On [DATE], we discovered a critical vulnerability in our service that could allow [BRIEF DESCRIPTION OF IMPACT].

**What happened:**
[Explain in clear terms, avoid technical jargon]

**What we've done:**
1. Immediately took [ACTION] to prevent further exploitation
2. Deployed a fix on [DATE]
3. Reviewed logs to identify affected users
4. [SPECIFIC ACTION] to remediate

**What you should do:**
1. Change your password
2. Enable multi-factor authentication (MFA)
3. Review your account activity at [LINK]

**Questions?**
Contact: security@mycompany.com

We take security seriously and apologize for this incident.

[Your Security Team]
EOF

cat ~/vuln-disclosure-template.md
```

---

## Part 7: Write a Secure SDLC Finding

```bash
cat > ~/sdlc-finding.md << 'EOF'
# Finding: No Secure Code Review Process — Vulnerabilities Slip to Production

**Severity:** High  
**Component:** Development Process (SDLC)  

## Description
Code reviews lack a security checklist. Reviewers focus on functionality, not security. Vulnerabilities like SQL injection, hardcoded credentials, and weak crypto regularly reach production.

## Evidence
- Code review comments: 0 security findings in last 50 reviews
- Production incidents: 3 security bugs in last 6 months (SQL injection, XSS, weak auth)
- Dependency scanning: 15+ known CVEs in current dependencies, unpatched
- Secret scanning: 2 AWS keys found in git history (require rotation)

## Risk
- Attackers exploit vulnerabilities in production
- Breach detection delayed (no secure logging)
- Compliance violations (PCI-DSS, HIPAA)
- Incident response costs escalate

## Remediation
1. **Create security code review checklist** (input validation, crypto, auth, dependencies)
2. **Assign security champion** per team (reviews all PRs with security angle)
3. **Mandatory security training** for all developers (OWASP Top 10, secure coding)
4. **Run SAST on every PR** (Semgrep, enforce before merge)
5. **Dependency scanning** (Dependabot, fail PR if critical CVE found)
6. **Secret scanning** (gitleaks, prevent credential commits)

## Effort
- Initial: 40 hours (create checklist, train team)
- Ongoing: 5 hours/week per team (security reviews)

## Benefits
- Fewer production vulnerabilities
- Faster incident response (better logging, cleaner code)
- Compliance coverage (audit trail of security reviews)
- Team confidence (developers know best practices)
EOF

cat ~/sdlc-finding.md
```

---

## 🧹 Cleanup

```bash
rm -f ~/threat-model-login.md ~/code-review-security-checklist.md
rm -f ~/bug-bounty-policy.md ~/vuln-disclosure-template.md ~/sdlc-finding.md

echo "✅ Secure SDLC lab cleaned up"
```

---

## Checklist

**Threat Modeling**
- [ ] Can apply STRIDE framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- [ ] Created a threat model for an API or application
- [ ] Can identify threats and propose mitigations
- [ ] Understand threat modeling happens BEFORE coding

**Secure Coding Standards**
- [ ] Know the 10 security requirements checklist (auth, authz, data protection, input validation, error handling, dependencies)
- [ ] Can explain why certain practices matter (e.g., Argon2 for passwords, parameterized queries)
- [ ] Understand that security is non-functional requirement (like performance)
- [ ] Can document security requirements for a feature

**Code Review Security Checklist**
- [ ] Know what to look for in security code reviews (auth, authz, input validation, crypto, logging)
- [ ] Can spot common vulnerabilities (SQL injection, XSS, CSRF, hardcoded secrets)
- [ ] Understand red flags that require escalation (auth/authz changes, crypto changes)
- [ ] Can use a code review checklist in real reviews

**Security Training**
- [ ] Understand mandatory training topics (OWASP, secure coding, API security, secrets, threat modeling, IR)
- [ ] Can design training for a team (tailored to their tech stack)
- [ ] Know how to establish security champions within engineering
- [ ] Understand that security training is ongoing (at least annual refresh)

**Bug Bounty Programs**
- [ ] Can choose appropriate bug bounty platform (HackerOne, Bugcrowd, etc.)
- [ ] Understand scope definition (eligible targets, eligible vulns, out of scope)
- [ ] Know reward structure (CRITICAL $500-$2000, HIGH $200-$500, etc.)
- [ ] Can write a bug bounty policy
- [ ] Understand responsible disclosure (90-day embargo, coordinated release)

**Vulnerability Disclosure**
- [ ] Can create security.txt file with correct metadata
- [ ] Understand how to communicate a vulnerability (clear language, recommended actions)
- [ ] Know timeline for disclosure (immediate patch, then public disclosure)
- [ ] Can draft a customer notification

**Real-World Scenarios**
- [ ] Can explain: threat model → secure design → code review → testing → deployment
- [ ] Can explain: why Equifax happened (no threat model, weak input validation, unpatched dependencies)
- [ ] Can explain: why SolarWinds happened (supply chain — compromised build process)
- [ ] Understand: secure SDLC prevents incidents; incident response treats them after the fact

---

## Integration with Phase 3

Secure SDLC ties together the entire Phase 3:

- **owasp-top10-theory:** Learn OWASP attacks (theory)
- **owasp-exploitation-labs:** Lab exploitation (hands-on attacks)
- **api-security-owasp-api-top10:** API security (specific attack surface)
- **aws-saa-exam-prep:** Threat modeling (design security)
- **semgrep-sast:** SAST (find vulns in code)
- **owasp-zap-dast:** DAST (find vulns in running app)
- **waf-ddos-protection:** Deploy WAF (defense in production)
- **secure-sdlc:** Prevent vulns via secure development ← **This Week**

You now have the complete **shift-left security** model: find vulns early (SAST) → prevent them via secure coding → defend against exploits (WAF, DAST) → respond to incidents quickly.
