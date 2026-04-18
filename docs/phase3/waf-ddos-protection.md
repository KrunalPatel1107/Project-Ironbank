# Month 8 — Special: Web Application Firewalls & DDoS Protection

!!! abstract "💰 Cost: $5-20/month — AWS WAF on ALB/CloudFront (or free: ModSecurity on self-hosted)"

!!! danger "Why WAF & DDoS Matter"
    Your app passes SAST (static analysis) and DAST (dynamic testing), but attackers still find zero-days. A WAF (Web Application Firewall) acts as a second line of defense: it detects and blocks malicious HTTP requests *before* they reach your application. DDoS attacks overwhelm your infrastructure with junk traffic — a DDoS shield lets legitimate users through while dropping attacker traffic. Together, WAF + DDoS protection detect/block OWASP Top 10 attacks in production.

!!! info "Background Context"
    From Months 7-8 (OWASP, SAST/DAST), you've learned how to find vulnerabilities. This week you'll learn how to *defend* against them in production. You'll configure AWS WAF to block SQL injection (owasp-top10-theory), XSS (owasp-exploitation-labs), broken API authentication (api-security-owasp-api-top10), and SSRF attacks. You'll understand DDoS mitigation strategies (rate limiting, geo-blocking, IP reputation) and integrate them into your pipeline.

---

## Part 1: WAF Fundamentals & Rule Types

A **WAF** inspects HTTP/HTTPS requests and decides: allow, block, or challenge.

### Types of WAF Deployments

| Deployment | Coverage | Latency | Use Case |
|---|---|---|---|
| **Cloud WAF (AWS WAF)** | CloudFront, ALB, API Gateway | <10ms | Production web apps |
| **ModSecurity (OSS)** | nginx, Apache | <5ms | Self-hosted, on-premise |
| **WAF Appliance** | F5, Palo Alto | Inline | High-security, compliance |
| **API Gateway WAF** | API endpoints only | Low | Microservices, APIs |

### Common WAF Rules

```
Rule Type        | Example Attack          | Action
─────────────────┼─────────────────────────┼──────────────
SQL Injection    | SELECT * FROM users...  | BLOCK
XSS              | <script>alert(1)</script> | BLOCK
Path Traversal   | ../../../etc/passwd     | BLOCK
Command Injection| ; rm -rf /              | BLOCK
XXE              | <!DOCTYPE foo [...]>    | BLOCK
SSRF             | http://169.254.169.254  | BLOCK
Rate Limit       | >100 req/sec from IP    | CHALLENGE (captcha)
Geo-Block        | Request from denied country | BLOCK
IP Reputation    | Known botnet IP         | BLOCK
```

### WAF vs. Network Firewall

```
Network Firewall (Layer 3-4):
  - Inspects: IP, TCP, UDP
  - Can't see: HTTP headers, request body
  - Blocks: Port scans, network-level attacks

WAF (Layer 7):
  - Inspects: HTTP method, URI, headers, body
  - Can see: SQL queries, JavaScript payloads
  - Blocks: Application-level attacks (OWASP Top 10)
```

---

## Part 2: AWS WAF on ALB (Application Load Balancer)

AWS WAF protects ALBs, CloudFront distributions, and API Gateways.

### Lab: Deploy WAF on ALB

```bash
# Prerequisites: ALB already running with a web app
# https://docs.aws.amazon.com/elasticloadbalancing/

# Step 1: Create WAF Web ACL (Access Control List)
aws wafv2 create-web-acl \
  --name MyAppWAF \
  --region us-east-1 \
  --scope REGIONAL \  # REGIONAL = ALB/API Gateway; CLOUDFRONT = CloudFront
  --default-action Block={} \  # Default = block everything
  --rules file://waf-rules.json \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=MyAppWAF

# Output: WebACL ARN = arn:aws:wafv2:us-east-1:ACCOUNT:regional/webacl/MyAppWAF/...

# Step 2: Create WAF rules (OWASP Core Rule Set)
cat > waf-rules.json << 'EOF'
[
  {
    "Name": "AWSManagedRulesCommonRuleSet",
    "Priority": 0,
    "Statement": {
      "ManagedRuleGroupStatement": {
        "Name": "AWSManagedRulesCommonRuleSet",
        "VendorName": "AWS",
        "ExcludedRules": []  # Don't exclude any rules
      }
    },
    "OverrideAction": {
      "None": {}  # Apply rules as-is
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "AWSManagedRulesCommonRuleSetMetric"
    }
  },
  {
    "Name": "RateLimitRule",
    "Priority": 1,
    "Statement": {
      "RateBasedStatement": {
        "Limit": 2000,  # 2000 requests per 5 minutes per IP
        "AggregateKeyType": "IP"
      }
    },
    "Action": {
      "Block": {
        "CustomResponse": {
          "ResponseCode": 429  # HTTP 429 = Too Many Requests
        }
      }
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "RateLimitRuleMetric"
    }
  },
  {
    "Name": "GeoBlockRule",
    "Priority": 2,
    "Statement": {
      "GeoMatchStatement": {
        "CountryCodes": ["CN", "RU", "KP"]  # Block China, Russia, North Korea
      }
    },
    "Action": {
      "Block": {}
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "GeoBlockRuleMetric"
    }
  }
]
EOF

# Step 3: Associate WAF with ALB
ALB_ARN="arn:aws:elasticloadbalancing:us-east-1:ACCOUNT:loadbalancer/app/my-alb/..."
WAF_ARN="arn:aws:wafv2:us-east-1:ACCOUNT:regional/webacl/MyAppWAF/..."

aws wafv2 associate-web-acl \
  --web-acl-arn $WAF_ARN \
  --resource-arn $ALB_ARN \
  --region us-east-1

# Step 4: Test WAF (should be blocked)
curl "http://ALB-IP/?id=1' OR '1'='1"  # SQL injection
# Response: 403 Forbidden (or custom WAF block page)

curl "http://ALB-IP/?search=<script>alert(1)</script>"  # XSS
# Response: 403 Forbidden

# Legitimate request (should pass)
curl "http://ALB-IP/?search=cat"
# Response: 200 OK (passed through)
```

### WAF Rule Tuning

After deploying WAF, monitor false positives (legitimate requests blocked):

```bash
# View blocked requests
aws wafv2 get-sampled-requests \
  --web-acl-arn $WAF_ARN \
  --rule-metric-name AWSManagedRulesCommonRuleSet \
  --scope REGIONAL \
  --time-window StartTime=$(date -u -d '1 hour ago' +%s),EndTime=$(date +%s) \
  --max-items 100 \
  --region us-east-1

# Output shows:
# - Request URI that was blocked
# - Rule that triggered
# - Timestamp
```

---

## Part 3: ModSecurity (Open-Source WAF)

ModSecurity is a free, open-source WAF that runs on nginx/Apache.

### Lab: Deploy ModSecurity on nginx

```bash
# Install ModSecurity on Ubuntu
sudo apt update
sudo apt install -y modsecurity modsecurity-doc
sudo apt install -y libapache2-mod-security2  # For Apache
# OR
sudo apt install -y libnginx-mod-modsecurity  # For nginx

# Enable ModSecurity
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

# Edit config to enable rule engine
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# Install OWASP ModSecurity Core Rule Set (CRS)
git clone https://github.com/coreruleset/coreruleset.git
sudo cp -r coreruleset/rules/* /etc/modsecurity/

# Configure nginx to use ModSecurity
cat > /etc/nginx/modsecurity-rules.conf << 'EOF'
# Enable ModSecurity
modsecurity on;
modsecurity_rules_file /etc/modsecurity/modsecurity.conf;

# Include OWASP CRS
include /etc/modsecurity/rules/*.conf;
EOF

# Add to nginx site config
sudo nano /etc/nginx/sites-available/default
# Add inside server block:
# include /etc/nginx/modsecurity-rules.conf;

sudo systemctl restart nginx

# Test ModSecurity
curl "http://localhost/?id=1' OR '1'='1"  # SQL injection
# Response: 403 Forbidden (ModSecurity blocked it)

# Check logs
sudo tail -f /var/log/modsecurity.log
# Output: Rule 942251 (SQL Injection) triggered for request /...
```

### Custom ModSecurity Rules

```bash
cat > /etc/modsecurity/custom-rules.conf << 'EOF'
# Block API key in query string
SecRule ARGS:api_key "@match [a-z0-9]{32}" \
  "id:9001,phase:2,block,msg:'API key exposure in query string'"

# Block admin panel unless from internal IP
SecRule REQUEST_URI "@contains /admin" \
  "id:9002,phase:2,block,msg:'Admin access denied',skipAfter:AdminWhitelist"
SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8" \
  "id:9003,phase:2,allow,msg:'Internal IP allowed'"
SecMarker AdminWhitelist

# Rate limit: max 100 requests per minute per IP
SecRule IP:@collection_size "@gt 100" \
  "id:9004,phase:1,block,msg:'Rate limit exceeded'"
EOF

# Reload nginx
sudo systemctl reload nginx
```

---

## Part 4: Rate Limiting & Token Bucket Algorithm

**Rate Limiting** caps the number of requests an IP address (or user) can make in a time window.

### Token Bucket Algorithm

```
Token Bucket:
1. Bucket capacity: 100 tokens (requests allowed per minute)
2. Refill rate: 100 tokens/minute
3. Each request costs 1 token
4. Request denied if bucket empty

Visualization:
  [Bucket: 100 tokens]
  Client 1 makes 50 requests → [Bucket: 50 tokens] ✅
  Client 2 makes 60 requests → [Bucket: 0 tokens] ❌ Denied (exceeded limit)
  Wait 1 minute → Refill → [Bucket: 100 tokens]
```

### Lab: Token Bucket Rate Limiting in Python

```bash
cat > ~/rate-limit-demo.py << 'EOF'
import time
from collections import defaultdict

class RateLimiter:
    def __init__(self, capacity=100, refill_rate=100):
        """
        capacity: max tokens in bucket (e.g., 100 requests)
        refill_rate: tokens added per minute
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.buckets = defaultdict(lambda: {"tokens": capacity, "last_refill": time.time()})

    def allow_request(self, client_ip):
        """Returns True if request allowed, False if rate limited"""
        bucket = self.buckets[client_ip]
        now = time.time()
        
        # Refill tokens based on elapsed time
        elapsed = (now - bucket["last_refill"]) / 60  # Convert to minutes
        bucket["tokens"] = min(
            self.capacity,
            bucket["tokens"] + (elapsed * self.refill_rate)
        )
        bucket["last_refill"] = now
        
        # Check if token available
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return True
        else:
            return False

# Demo
limiter = RateLimiter(capacity=5, refill_rate=5)  # 5 requests per minute

print("=== Rate Limiting Demo ===")
client_ip = "192.168.1.100"

# Make 6 requests in quick succession
for i in range(6):
    if limiter.allow_request(client_ip):
        print(f"Request {i+1}: ✅ ALLOWED")
    else:
        print(f"Request {i+1}: ❌ RATE LIMITED (HTTP 429)")

# Wait and try again
print("\nWaiting 30 seconds (bucket refills)...")
time.sleep(30)

if limiter.allow_request(client_ip):
    print("Request 7 (after wait): ✅ ALLOWED")
EOF

python3 ~/rate-limit-demo.py
```

### HTTP 429 Response

When rate limited, return HTTP 429 with `Retry-After` header:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 60
Content-Type: application/json

{
  "error": "Rate limit exceeded",
  "retry_after": 60,
  "limit": 100,
  "remaining": 0
}
```

---

## Part 5: DDoS Mitigation Strategies

**DDoS (Distributed Denial of Service):** Attacker floods your app with junk traffic to overwhelm it.

### Attack Types & Mitigations

| Attack Type | Example | Mitigation |
|---|---|---|
| **Volume** | 1 Gbps of junk traffic | AWS Shield (DDoS protection), Cloudflare |
| **Protocol** | SYN floods, UDP floods | Router-level rate limiting, WAF |
| **Application** | Slowloris (slow requests) | HTTP request timeout, rate limiting |
| **Amplification** | Attacker sends 1 byte, reflector sends 100 bytes | ISP filtering, source IP validation |

### AWS Shield & DDoS Protection

```bash
# AWS Shield Standard (free)
# - Automatic protection against common DDoS attacks
# - Absorbs up to ~50 Gbps
# - Included with CloudFront, Route 53, ELB

# AWS Shield Advanced (paid, ~$3000/month)
# - Enhanced protection against larger attacks
# - DDoS Cost Protection (shields you from costs during attack)
# - 24/7 DDoS Response Team (DRT)

# Enable Shield Advanced
aws shield subscribe-to-drt
# Requires Shield Advanced subscription

# Monitor attacks
aws shield list-attacks --start-time 2024-01-01 --end-time 2024-12-31
```

### Geo-Blocking & IP Reputation

```bash
# AWS WAF: Block traffic from high-risk countries
cat > geo-block-rules.json << 'EOF'
{
  "Name": "GeoBlockHighRisk",
  "Priority": 0,
  "Statement": {
    "GeoMatchStatement": {
      "CountryCodes": ["CN", "RU", "IR", "KP"]  # Adjust as needed
    }
  },
  "Action": {
    "Block": {
      "CustomResponse": {
        "ResponseCode": 403,
        "CustomResponseBodyKey": "geo-blocked"
      }
    }
  }
}
EOF

# CloudFront: Block by geography natively
aws cloudfront create-distribution \
  --distribution-config file://distribution-config.json \
  # Include: RestrictionType=geo, Locations=[...countries to block...]
```

---

## Part 6: Write a WAF/DDoS Security Finding

```bash
cat > ~/waf-finding.md << 'EOF'
# Finding: Missing Web Application Firewall (WAF) on Production ALB

**Severity:** High  
**Component:** Infrastructure (AWS ALB)  

## Description
The production ALB lacks WAF protection. HTTP requests are NOT scanned for OWASP Top 10 attacks (SQL injection, XSS, path traversal). An attacker can exploit known vulnerabilities directly without triggering any detection.

## Risk Scenario
1. Attacker finds SQL injection in login form (DAST found it in owasp-zap-dast)
2. Attacker sends: `POST /login?user=admin' OR '1'='1`
3. ALB forwards request directly to backend
4. Backend executes malicious SQL, attacker gains access
5. No WAF rule triggered = no detection = incident response delayed

## Compliance Impact
- PCI-DSS 6.6: Requires WAF on internet-facing applications
- NIST 800-53: SI-4 (Intrusion detection systems) includes WAF
- ISO 27001: A.13.1.3 (Network segregation) recommends WAF

## Remediation
1. Deploy AWS WAF on ALB with OWASP CRS rules
2. Enable logging to CloudWatch (all blocked requests)
3. Set initial mode to COUNT (monitor) for 1 week
4. Review false positives, then switch to BLOCK mode
5. Monitor WAF metrics in CloudWatch

## Effort
- Deployment: 30 minutes
- Rule tuning: 1-2 hours (based on traffic patterns)
EOF

cat ~/waf-finding.md
```

---

## Part 7: Integration into DevSecOps Pipeline

WAF deployment should be part of your CI/CD pipeline:

```yaml
# GitHub Actions: WAF Rules as Code
name: Deploy WAF Rules

on:
  push:
    branches: [main]
    paths:
      - 'waf-rules/**'

jobs:
  deploy-waf:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # Validate WAF rules syntax
      - name: Validate WAF Rules
        run: |
          python3 -m json.tool waf-rules/rules.json > /dev/null
          echo "✅ WAF rules valid JSON"
      
      # Deploy to AWS
      - name: Deploy WAF to ALB
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_KEY }}
        run: |
          aws wafv2 update-web-acl \
            --name MyAppWAF \
            --region us-east-1 \
            --scope REGIONAL \
            --rules file://waf-rules/rules.json \
            --default-action Block={} \
            --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=MyAppWAF
      
      # Verify WAF is blocking attacks
      - name: Test WAF (should block SQL injection)
        run: |
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            "https://${{ env.ALB_DNS }}/?id=1' OR '1'='1")
          if [ "$STATUS" = "403" ]; then
            echo "✅ WAF successfully blocked SQL injection"
          else
            echo "❌ WAF failed to block attack"
            exit 1
          fi
```

---

## 🧹 Cleanup

```bash
# Remove test files
rm -f ~/rate-limit-demo.py ~/waf-finding.md waf-rules.json geo-block-rules.json

# Remove WAF from ALB (if testing in AWS)
aws wafv2 disassociate-web-acl \
  --resource-arn arn:aws:elasticloadbalancing:us-east-1:ACCOUNT:loadbalancer/... \
  --region us-east-1

# Delete WAF Web ACL (if testing in AWS)
# Note: Must delete all associated resources first
aws wafv2 delete-web-acl \
  --name MyAppWAF \
  --id <WEB_ACL_ID> \
  --scope REGIONAL \
  --region us-east-1 2>/dev/null || true

echo "✅ WAF & DDoS lab cleaned up"
```

---

## Checklist

**WAF Fundamentals**
- [ ] Can define WAF and explain Layer 7 inspection
- [ ] Know the difference between WAF (Layer 7) and network firewall (Layer 3-4)
- [ ] Can list 5 common WAF rule types (SQL injection, XSS, path traversal, etc.)
- [ ] Understand WAF rule actions: allow, block, challenge (CAPTCHA)

**AWS WAF on ALB**
- [ ] Deployed AWS WAF on an ALB (or understood the commands)
- [ ] Can configure OWASP Core Rule Set (CRS) in WAF
- [ ] Know how to view blocked requests in AWS WAF Sampled Requests
- [ ] Understand WAF pricing (per rule + per request)
- [ ] Can associate/disassociate WAF with ALB

**ModSecurity (Open-Source WAF)**
- [ ] Installed ModSecurity on nginx or Apache
- [ ] Enabled OWASP CRS rules
- [ ] Tested ModSecurity by triggering a rule (SQL injection, XSS)
- [ ] Can write a custom ModSecurity rule
- [ ] Know when to use self-hosted WAF vs. cloud WAF

**Rate Limiting**
- [ ] Can explain token bucket algorithm
- [ ] Implemented or understood rate limiting in code
- [ ] Know HTTP 429 response and Retry-After header
- [ ] Understand rate limiting prevents both DDoS and brute-force attacks
- [ ] Can configure rate limiting in AWS WAF or nginx

**DDoS Mitigation**
- [ ] Can name 4 types of DDoS attacks (volume, protocol, application, amplification)
- [ ] Know AWS Shield Standard (free) vs. Advanced (paid)
- [ ] Can configure geo-blocking in CloudFront or WAF
- [ ] Understand IP reputation filtering
- [ ] Know when to escalate to AWS DRT (DDoS Response Team)

**Integration into DevSecOps**
- [ ] Can write WAF rules as JSON/YAML in version control
- [ ] Understand WAF deployment pipeline (validate → deploy → test)
- [ ] Know how to test WAF rules in COUNT mode before BLOCK
- [ ] Can monitor WAF metrics in CloudWatch
- [ ] Understand WAF logging for incident response

**Real-World Scenarios**
- [ ] Can explain: WAF blocks SQL injection before it reaches backend
- [ ] Can explain: rate limiting stops brute-force attempts on login
- [ ] Can explain: DDoS protection keeps legitimate users online
- [ ] Understand: WAF + DAST = defense in depth
- [ ] Know compliance requirements (PCI-DSS, NIST, ISO 27001) for WAF

---

## Integration with Phase 3

This WAF & DDoS topic completes the **defense-in-depth** model:

- **owasp-top10-theory:** OWASP vulnerabilities (theory)
- **owasp-exploitation-labs:** OWASP exploitation labs (hands-on attacks)
- **semgrep-sast:** SAST (Semgrep) — find vulns in code
- **owasp-zap-dast:** DAST (ZAP) — find vulns in running app
- **waf-ddos-protection:** WAF & DDoS — block vulns in production ✅

You now understand the complete appsec lifecycle: **Find → Test → Defend → Monitor**.
