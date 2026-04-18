# Month 3 — Week 4: CCP Exam & Final Cleanup

!!! abstract "💰 Exam cost: $100"

## Exam Day Tips

1. Schedule at a testing center or online via [aws.training](https://www.aws.training/certification)
2. Bring government ID
3. Budget 2 min per question — flag hard ones and come back
4. Eliminate obviously wrong answers first
5. "Most secure" and "least privilege" are usually correct in security questions

## After the Exam: Build IAM Policy Analyzer

Your Month 3 project — Python tool that flags overly permissive IAM policies:

```python
# iam_analyzer.py — Find dangerous IAM policies
import boto3, json

session = boto3.Session(profile_name='iron-bank')
iam = session.client('iam')

policies = iam.list_policies(Scope='Local')['Policies']
print(f"Analyzing {len(policies)} custom policies...\n")

for policy in policies:
    name = policy['PolicyName']
    arn = policy['Arn']
    version = policy['DefaultVersionId']

    doc = iam.get_policy_version(PolicyArn=arn, VersionId=version)
    statements = doc['PolicyVersion']['Document']['Statement']

    for stmt in statements:
        actions = stmt.get('Action', [])
        resources = stmt.get('Resource', [])
        if isinstance(actions, str): actions = [actions]
        if isinstance(resources, str): resources = [resources]

        # Flag: Action=* + Resource=* (God mode)
        if '*' in actions and '*' in resources:
            print(f"  🔴 CRITICAL: {name} has Action:* + Resource:* (God mode)")

        # Flag: iam:* (can create backdoor users)
        if 'iam:*' in actions:
            print(f"  🟡 HIGH: {name} has iam:* (can modify identity)")
```

## 🧹 FINAL Phase 1 Cleanup

```bash
# Delete ALL practice AWS resources
aws s3 ls --profile iron-bank    # Should show no practice buckets
aws iam list-users --profile iron-bank    # Only terraform-admin should exist
aws ec2 describe-instances --profile iron-bank \
  --query "Reservations[].Instances[?State.Name=='running'].[InstanceId]" \
  --output text    # Should be empty

# Check your bill
# AWS Console → Billing → should be $0 or near-zero
```

!!! danger "💰 Verify your bill!"
    Go to AWS Console → Billing → check current month. Should be $0. If not, find and delete the resource that's charging you.

## ✅ Phase 1 Complete Checklist

- [ ] **PASSED AWS Cloud Practitioner (CLF-C02)** 🎉
- [ ] IAM Policy Analyzer built and pushed to GitHub
- [ ] flAWS.cloud and flAWS2.cloud completed
- [ ] ALL AWS practice resources deleted
- [ ] AWS bill verified: $0 or minimal
- [ ] 3 GitHub repositories: cis-audit, aws-security-scanner, iam-analyzer

!!! success "🎉 Phase 1 Complete!"
    You now have Linux CLI fluency, Python automation skills, and AWS fundamentals. Plus 1 certification and 3 GitHub portfolio projects. Proceed to **Phase 2: Cloud Security**.
