# Application Security

**Months 7–9 · OWASP, SAST/DAST/SCA, Containers**

!!! info "The shift from infrastructure to applications"
    80% of real-world breaches happen at the application layer. This phase teaches you to find and fix those vulnerabilities.

## What You'll Build

| Month | Focus | Deliverable | Cert |
|---|---|---|---|
| 7 | OWASP Top 10 | Juice Shop exploit writeups + threat model | **AWS SAA** |
| 8 | SAST/DAST/SCA | Security Testing Toolkit → GitHub | — |
| 9 | Container Security | Secure Docker deployment + ECR/ECS | **AWS Security Specialty** |

!!! abstract "💰 Cost: Nearly $0"
    Almost everything this phase runs locally on Docker. No cloud costs except during Month 9 ECS deployment (use `terraform destroy` daily).

## Background Context

!!! info "If you're coming from a defensive security background"
    - **SOC / incident response experience** → you've written playbooks *after* attacks. This phase teaches you what those attacks look like from the attacker's side — so your defensive recommendations are grounded in how exploits actually work.
    - **WAF / firewall experience** → you'll understand exactly what managed rule groups block and why
    - **SIEM / detection engineering** → translates directly to writing remediation guidance after finding vulnerabilities with SAST/DAST tools
