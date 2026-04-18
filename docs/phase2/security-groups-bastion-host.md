# Month 4 — Week 3: Security Groups & Bastion Host

!!! danger "💰 Cost Warning"
    This week you launch an **EC2 instance** (t2.micro = free tier, ~$0 if stopped when done).
    An **Elastic IP** costs **$3.60/month if left unattached** — always release it after the lab.
    **No NAT Gateway this week.** That stays off until the Flow Logs project in Week 4.

!!! info "If you know Azure networking"
    Security Groups = Azure NSGs at the NIC level — same concept, different console.
    A Bastion Host = Azure Bastion. This week you build the open-source equivalent from scratch using a plain EC2 + SSH, so you understand exactly what's happening under the hood.

---

## Security Group Deep Dive

Security Groups are **stateful** virtual firewalls attached to individual EC2 instances (technically to the Elastic Network Interface, or ENI). Stateful means: if you allow inbound SSH on port 22, the return traffic is automatically allowed — you don't need a separate outbound rule.

??? note "Stateful vs Stateless — the full explanation"
    **Stateful (Security Groups):** The firewall tracks connection state. If you open a connection inbound, the response is automatically permitted outbound.

    **Stateless (NACLs from Week 2):** The firewall treats every packet independently. You must explicitly allow both directions.

    **Real-world analogy:** A stateful firewall is like a receptionist who remembers you came in — so they let you leave without checking your ID again. A stateless firewall checks your ID both coming in AND going out, every time.

### Security Group Rules: How They Work

- Rules are **allow-only** — there is no "deny" rule in a Security Group
- AWS implicitly denies everything not explicitly allowed
- Rules are evaluated **all at once** (not in order like NACLs)
- You can reference **another Security Group** as a source (very powerful for tiered architectures)

---

## Part 1: Create Layered Security Groups

You'll build two Security Groups: one for the Bastion (internet-facing) and one for private instances (only accessible from the Bastion).

```bash
# ─── Setup: Re-use or recreate your VPC infrastructure from Week 2 ───────────
# (Skip this block if your Week 2 VPC is still running)
VPC_ID=$(aws ec2 describe-vpcs \
  --filters "Name=tag:Name,Values=Iron-Bank-VPC" \
  --profile iron-bank \
  --query 'Vpcs[0].VpcId' --output text)
echo "Using VPC: $VPC_ID"

# Get your public subnet ID
PUB_1A=$(aws ec2 describe-subnets \
  --filters "Name=tag:Name,Values=Public-1a" "Name=vpc-id,Values=$VPC_ID" \
  --profile iron-bank \
  --query 'Subnets[0].SubnetId' --output text)
echo "Public Subnet: $PUB_1A"

# ─── Step 1: Get your current public IP ──────────────────────────────────────
# This ensures only YOUR machine can SSH to the Bastion — not the entire internet
MY_IP=$(curl -s https://checkip.amazonaws.com)
echo "Your IP: $MY_IP"

# ─── Step 2: Bastion Security Group ──────────────────────────────────────────
# Allows SSH only from your IP — everything else blocked
SG_BASTION=$(aws ec2 create-security-group \
  --group-name "Iron-Bank-Bastion-SG" \
  --description "SSH access to Bastion from admin IP only" \
  --vpc-id $VPC_ID \
  --tag-specifications 'ResourceType=security-group,Tags=[{Key=Name,Value=Bastion-SG}]' \
  --profile iron-bank \
  --query GroupId --output text)
echo "Bastion SG: $SG_BASTION"

# Allow SSH (port 22) inbound from your IP only
# /32 means "exactly this one IP address" — the most restrictive CIDR possible
aws ec2 authorize-security-group-ingress \
  --group-id $SG_BASTION \
  --protocol tcp \
  --port 22 \
  --cidr ${MY_IP}/32 \
  --profile iron-bank

# ─── Step 3: Private Instance Security Group ─────────────────────────────────
# References the Bastion SG — only EC2 instances IN the Bastion SG can reach this
SG_PRIVATE=$(aws ec2 create-security-group \
  --group-name "Iron-Bank-Private-SG" \
  --description "Allow SSH only from Bastion SG" \
  --vpc-id $VPC_ID \
  --tag-specifications 'ResourceType=security-group,Tags=[{Key=Name,Value=Private-SG}]' \
  --profile iron-bank \
  --query GroupId --output text)
echo "Private SG: $SG_PRIVATE"

# SOURCE is the Bastion SG ID — not an IP address
# This means: "only traffic from an EC2 instance attached to SG_BASTION is allowed"
aws ec2 authorize-security-group-ingress \
  --group-id $SG_PRIVATE \
  --protocol tcp \
  --port 22 \
  --source-group $SG_BASTION \
  --profile iron-bank

echo "✅ Security Groups created"
echo "SAVE THESE: SG_BASTION=$SG_BASTION  SG_PRIVATE=$SG_PRIVATE"
```

??? note "Why reference a Security Group instead of an IP?"
    If you hard-code the Bastion's IP as the source, you'd need to update the rule every time the Bastion's IP changes (e.g. after a reboot). By referencing the Bastion's *Security Group*, you're saying "I trust any EC2 instance that has this SG attached" — the IP is irrelevant. This is the standard AWS pattern for multi-tier architectures.

---

## Part 2: Create a Key Pair

SSH into EC2 requires a key pair — like an SSH certificate. AWS holds the public key; you hold the private key (`.pem` file).

```bash
# ─── Step 4: Generate an SSH key pair ────────────────────────────────────────
aws ec2 create-key-pair \
  --key-name iron-bank-key \
  --profile iron-bank \
  --query KeyMaterial \
  --output text > ~/.ssh/iron-bank-key.pem

# Set strict permissions — SSH will refuse to use a key that's too open
chmod 400 ~/.ssh/iron-bank-key.pem

echo "Key saved to ~/.ssh/iron-bank-key.pem"
ls -la ~/.ssh/iron-bank-key.pem
# Should show: -r-------- (read-only for owner, nothing for others)
```

!!! warning "Never commit .pem files to Git"
    Add `*.pem` to your `.gitignore`. If you accidentally push a private key to GitHub, rotate it immediately — scanners find exposed keys within minutes.

---

## Part 3: Launch the Bastion Host

```bash
# ─── Step 5: Find the latest Amazon Linux 2023 AMI ───────────────────────────
# AMI = Amazon Machine Image (the OS template). IDs change per region and update regularly.
AMI=$(aws ec2 describe-images \
  --owners amazon \
  --filters \
    "Name=name,Values=al2023-ami-2023*-x86_64" \
    "Name=state,Values=available" \
  --profile iron-bank \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
  --output text)
echo "Using AMI: $AMI"

# ─── Step 6: Launch the Bastion EC2 instance ─────────────────────────────────
BASTION_ID=$(aws ec2 run-instances \
  --image-id $AMI \
  --instance-type t2.micro \          # Free tier eligible
  --key-name iron-bank-key \          # The key pair we just created
  --security-group-ids $SG_BASTION \  # Attach the Bastion SG
  --subnet-id $PUB_1A \              # Launch in a PUBLIC subnet
  --associate-public-ip-address \     # Give it a public IP so we can SSH in
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=Iron-Bank-Bastion}]' \
  --profile iron-bank \
  --query 'Instances[0].InstanceId' --output text)
echo "Bastion Instance: $BASTION_ID"

# ─── Step 7: Wait for the instance to be running ─────────────────────────────
echo "Waiting for instance to start (usually 30–60 seconds)..."
aws ec2 wait instance-running --instance-ids $BASTION_ID --profile iron-bank
echo "✅ Bastion is running"

# ─── Step 8: Get the public IP ───────────────────────────────────────────────
BASTION_IP=$(aws ec2 describe-instances \
  --instance-ids $BASTION_ID \
  --profile iron-bank \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)
echo "Bastion Public IP: $BASTION_IP"
```

---

## Part 4: SSH into the Bastion

```bash
# ─── Step 9: Connect via SSH ─────────────────────────────────────────────────
# -i = identity file (your private key)
# ec2-user = default username for Amazon Linux
ssh -i ~/.ssh/iron-bank-key.pem ec2-user@$BASTION_IP

# You should see a prompt like:
#    ,     #_
#    ~\_  ####_        Amazon Linux 2023
#   ~~  \_#####\
#   ~~     \###|       https://aws.amazon.com/linux/amazon-linux-2023
#   ~~       \#/ ___
#    ~~       V~' '->
#     ~~~         /
#       ~~._.   _/
#          _/ _/
#        _/m/'
# [ec2-user@ip-10-0-1-x ~]$

# Once inside, run a few checks:
whoami          # → ec2-user
hostname        # → ip-10-0-1-x.ec2.internal
curl -s https://checkip.amazonaws.com  # → Shows the Bastion's public IP
cat /etc/os-release  # → Amazon Linux 2023 details

# Exit the SSH session
exit
```

!!! tip "Connection refused?"
    The most common causes: (1) the instance isn't fully started yet — wait 60 more seconds; (2) your IP changed since you created the Security Group rule — run `curl checkip.amazonaws.com` and update the inbound rule.

---

## Part 5: Inspect Your Security Group Rules

```bash
# ─── View all SG rules in your VPC ───────────────────────────────────────────
aws ec2 describe-security-groups \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --profile iron-bank \
  --query 'SecurityGroups[*].{Name:GroupName,ID:GroupId,Inbound:IpPermissions}' \
  --output table

# Check specifically what's allowed INTO the Bastion SG:
aws ec2 describe-security-group-rules \
  --filters "Name=group-id,Values=$SG_BASTION" \
  --profile iron-bank \
  --query 'SecurityGroupRules[?!IsEgress].{Port:FromPort,CIDR:CidrIpv4,SrcSG:ReferencedGroupInfo.GroupId}' \
  --output table
```

Expected output: you should see port 22 allowed from your `/32` IP only.

---

## 🧹 Cleanup

!!! abstract "🧹 Cleanup — Run this before ending your session"

```bash
# Terminate the EC2 instance first (must be terminated before deleting SGs)
aws ec2 terminate-instances --instance-ids $BASTION_ID --profile iron-bank
echo "Waiting for termination..."
aws ec2 wait instance-terminated --instance-ids $BASTION_ID --profile iron-bank

# Delete the Security Groups (order matters — delete Private SG first, it references Bastion SG)
aws ec2 delete-security-group --group-id $SG_PRIVATE --profile iron-bank
aws ec2 delete-security-group --group-id $SG_BASTION --profile iron-bank

# Delete the key pair from AWS (keep the .pem file locally if you want)
aws ec2 delete-key-pair --key-name iron-bank-key --profile iron-bank

# Remove local key file
rm ~/.ssh/iron-bank-key.pem

echo "✅ All Week 3 resources deleted"
```

!!! warning "Also clean up the VPC resources from Week 2 if you're done with them"
    Week 4 (Flow Logs) rebuilds the VPC as part of the project — so you can safely tear everything down now.

---

## Checklist

- [ ] Created a Bastion Security Group (SSH from your IP only)
- [ ] Created a Private Security Group (SSH from Bastion SG only)
- [ ] Understand SG referencing (source = another SG, not an IP)
- [ ] Generated a key pair and set correct `chmod 400` permissions
- [ ] Launched a t2.micro Bastion in a public subnet
- [ ] Successfully SSH'd into the Bastion
- [ ] Can explain the difference between Bastion SG and Private SG rules
- [ ] **All resources terminated and deleted — no Elastic IPs left unattached**
- [ ] **Bill verified $0**
