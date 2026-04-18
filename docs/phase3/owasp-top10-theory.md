# Month 7 — Week 1: OWASP Top 10 Theory

!!! abstract "💰 Cost: $0 — All local Docker containers"

!!! info "OWASP Top 10 (2021)"
    The industry standard list of the most critical web application security risks.

## The 10 Categories

| # | Category | Plain English | Example |
|---|---|---|---|
| A01 | Broken Access Control | Users can do things they shouldn't | Viewing other users' data by changing a URL ID |
| A02 | Cryptographic Failures | Sensitive data exposed | Passwords stored in plain text |
| A03 | Injection | Attacker inserts malicious commands | SQL injection on a login form |
| A04 | Insecure Design | Security wasn't considered in design | No rate limiting on password reset |
| A05 | Security Misconfiguration | Default settings left unchanged | Debug mode enabled in production |
| A06 | Vulnerable Components | Using libraries with known CVEs | Old version of Log4j |
| A07 | Auth Failures | Weak authentication | No MFA, weak passwords allowed |
| A08 | Data Integrity Failures | Trusting untrusted data | Accepting unsigned software updates |
| A09 | Logging Failures | Can't detect or investigate attacks | No audit trail of admin actions |
| A10 | SSRF | Server makes requests to attacker-controlled URLs | Accessing AWS metadata endpoint |

## Launch Juice Shop (Vulnerable Practice App)

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
# --rm   = auto-delete container when stopped
# -p 3000:3000 = map port 3000 on your machine to container
# Open http://localhost:3000 in your browser
```

## Try SQL Injection (A03)

1. Go to the **Login** page
2. In the Email field, type exactly: `' OR 1=1 --`
3. In Password, type anything (e.g., `test`)
4. Click **Log In** → You're logged in as admin!

??? note "Why this works"
    The app builds SQL like:
    ```sql
    SELECT * FROM users WHERE email='INPUT' AND password='INPUT'
    ```
    Your input `' OR 1=1 --` makes it:
    ```sql
    SELECT * FROM users WHERE email='' OR 1=1 --' AND password='test'
    ```
    - The `'` closes the email string early
    - `OR 1=1` is always true → returns ALL users
    - `--` comments out the rest of the query
    - Result: logs you in as the first user (admin)

## Study Resources

- [OWASP Top 10 Official](https://owasp.org/www-project-top-ten/)
- [Kontra Interactive OWASP](https://application.security/free/owasp-top-10) (FREE)
- [Snyk Learn](https://snyk.io/learn/) (FREE)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

## 🧹 Cleanup

```bash
# Press Ctrl+C in the terminal running Docker to stop Juice Shop
# --rm flag auto-deletes the container

# Verify nothing is running
docker ps                # Should show nothing

# Remove the downloaded image (saves ~500MB disk)
docker image rm bkimminich/juice-shop
```

## Checklist

- [ ] Can name all 10 OWASP categories
- [ ] Juice Shop running at localhost:3000
- [ ] Successfully exploited SQL injection on login
- [ ] Read [Kontra OWASP Top 10](https://application.security/free/owasp-top-10) interactive lessons
- [ ] Docker container stopped and cleaned up
