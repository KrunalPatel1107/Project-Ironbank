# Cloud Security

**Months 4–6 · VPC Networking, Terraform, AWS Detection**

!!! info "Iron Bank Volumes 1–6"
    This phase follows the Iron Bank Field Manual directly. Each lab has exact beginner steps, expected outputs, and cleanup instructions.

## What You'll Build

| Month | Focus | Deliverable | Cert |
|---|---|---|---|
| 4 | VPC Networking | 3-Tier VPC + Flow Log Analyzer → GitHub | — |
| 5 | Terraform IaC | Terraform Module Library → GitHub | — |
| 6 | AWS Detective Controls | Security Dashboard Script → GitHub | **Terraform Associate** |

## Background Context

!!! info "If you're coming from a Microsoft / Azure background"
    - **VPC Security Groups** = Azure NSGs — same concept, different console
    - **CloudTrail** = Azure Activity Log — you may already know KQL analytics on top of these
    - **GuardDuty** = Defender for Cloud threat alerts — same detection philosophy
    - **Security Hub** = Microsoft Secure Score / Defender for Cloud CSPM dashboard
    - **AWS Config** = Azure Policy — continuous compliance evaluation, same concept

!!! danger "💰 Cost Warning for This Phase"
    Months 4–6 involve AWS resources that **cost money**:

    - NAT Gateway: **$32/month** if left running!
    - ALB: **$16/month**
    - Elastic IPs (unattached): **$3.60/month**

    **Always run cleanup after each session.** Terraform makes this easy: `terraform destroy`.
