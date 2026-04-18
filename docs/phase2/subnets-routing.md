# Month 4 — Week 2: Subnets & Routing

!!! danger "💰 Cost"
    Everything this week is **FREE** — subnets, route tables, and NACLs have no cost.
    NAT Gateway ($32/mo) is introduced in Week 3 — **do not create it yet**.

!!! info "If you know Azure networking"
    Route tables = Azure User Defined Routes (UDRs). NACLs = Azure NSGs at the subnet level.
    If you've configured UDRs to force-tunnel traffic through a firewall, this is the same concept — just built with AWS route tables instead.

---

## Why Subnets Matter

A VPC gives you a big block of IP addresses (e.g. `10.0.0.0/16` = 65,536 IPs). Subnets carve that block into smaller, isolated networks. The key distinction:

| Subnet Type | Internet Access | Use Case |
|---|---|---|
| **Public** | Yes (via IGW + route) | Web servers, Bastion hosts, Load balancers |
| **Private** | No (by default) | Databases, App servers, Lambda functions |

!!! tip "Security Principle"
    Always put sensitive resources in private subnets. If they need to reach the internet (e.g. to pull updates), you add a NAT Gateway later — they can call *out*, but nothing can reach *in*.

---

## Part 1: Build a Multi-AZ Subnet Architecture

Real production VPCs use **at least 2 Availability Zones** so if one AWS data centre has a problem, your app keeps running. This week you'll build 4 subnets across 2 AZs.

```bash
# ─── Step 1: Re-use (or recreate) your VPC from Week 1 ───────────────────────
# If you cleaned up Week 1, recreate the VPC first:
VPC_ID=$(aws ec2 create-vpc \
  --cidr-block 10.0.0.0/16 \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=Iron-Bank-VPC}]' \
  --profile iron-bank \
  --query Vpc.VpcId --output text)
echo "VPC: $VPC_ID"

# Enable DNS so EC2 instances get hostnames like ec2-1-2-3-4.compute-1.amazonaws.com
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames --profile iron-bank
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-support    --profile iron-bank

# ─── Step 2: Create 4 subnets across 2 AZs ───────────────────────────────────
# Public subnet in us-east-1a  (10.0.1.0/24 = 256 IPs, first 5 reserved by AWS)
PUB_1A=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block 10.0.1.0/24 \
  --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=Public-1a}]' \
  --profile iron-bank \
  --query Subnet.SubnetId --output text)

# Public subnet in us-east-1b  (different AZ = different physical data centre)
PUB_1B=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block 10.0.2.0/24 \
  --availability-zone us-east-1b \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=Public-1b}]' \
  --profile iron-bank \
  --query Subnet.SubnetId --output text)

# Private subnet in us-east-1a  (no route to internet)
PRIV_1A=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block 10.0.3.0/24 \
  --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=Private-1a}]' \
  --profile iron-bank \
  --query Subnet.SubnetId --output text)

# Private subnet in us-east-1b
PRIV_1B=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block 10.0.4.0/24 \
  --availability-zone us-east-1b \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=Private-1b}]' \
  --profile iron-bank \
  --query Subnet.SubnetId --output text)

echo "Public:  $PUB_1A  $PUB_1B"
echo "Private: $PRIV_1A $PRIV_1B"
```

??? note "Why /24? How does CIDR work?"
    CIDR (Classless Inter-Domain Routing) notation is just a shorthand for "how many IPs are in this block":

    | CIDR | Total IPs | Usable IPs | Use Case |
    |---|---|---|---|
    | /16 | 65,536 | 65,531 | Entire VPC |
    | /24 | 256 | 251 | One subnet |
    | /28 | 16 | 11 | Very small subnet |

    AWS always reserves the first 4 and last 1 IP in every subnet.
    A `/24` gives you 251 usable IPs — plenty for a lab.
    Use [cidr.xyz](https://cidr.xyz/) to visualize this.

---

## Part 2: Internet Gateway & Route Tables

A **route table** is exactly like a UDR in Azure — it tells traffic *where to go* based on destination IP.

```bash
# ─── Step 3: Create and attach an Internet Gateway ───────────────────────────
# IGW = the door between your VPC and the public internet
IGW=$(aws ec2 create-internet-gateway \
  --profile iron-bank \
  --query InternetGateway.InternetGatewayId --output text)

# Attach it to our VPC — one IGW per VPC maximum
aws ec2 attach-internet-gateway \
  --internet-gateway-id $IGW \
  --vpc-id $VPC_ID \
  --profile iron-bank

echo "IGW: $IGW"

# ─── Step 4: Create a PUBLIC route table ─────────────────────────────────────
# This route table will say: "anything going to 0.0.0.0/0 (internet) → use the IGW"
PUB_RT=$(aws ec2 create-route-table \
  --vpc-id $VPC_ID \
  --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=Public-RT}]' \
  --profile iron-bank \
  --query RouteTable.RouteTableId --output text)

# Add the default route: destination 0.0.0.0/0 (all internet traffic) → IGW
aws ec2 create-route \
  --route-table-id $PUB_RT \
  --destination-cidr-block 0.0.0.0/0 \
  --gateway-id $IGW \
  --profile iron-bank

# Associate BOTH public subnets with this route table
aws ec2 associate-route-table --route-table-id $PUB_RT --subnet-id $PUB_1A --profile iron-bank
aws ec2 associate-route-table --route-table-id $PUB_RT --subnet-id $PUB_1B --profile iron-bank

echo "Public Route Table: $PUB_RT"

# ─── Step 5: Create a PRIVATE route table ────────────────────────────────────
# Private subnets get their own route table with NO route to the internet
PRIV_RT=$(aws ec2 create-route-table \
  --vpc-id $VPC_ID \
  --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=Private-RT}]' \
  --profile iron-bank \
  --query RouteTable.RouteTableId --output text)

# Associate both private subnets (no internet route added — that's intentional)
aws ec2 associate-route-table --route-table-id $PRIV_RT --subnet-id $PRIV_1A --profile iron-bank
aws ec2 associate-route-table --route-table-id $PRIV_RT --subnet-id $PRIV_1B --profile iron-bank

echo "Private Route Table: $PRIV_RT"
```

??? note "Why two separate route tables?"
    If both subnets shared one route table that had `0.0.0.0/0 → IGW`, then your "private" subnet would actually have internet access — defeating the entire purpose. Separate route tables enforce the boundary.

    Think of it like:
    - Public RT = "you have a door to the street"
    - Private RT = "you're in an interior room — no street door"

---

## Part 3: Network ACLs (Subnet-Level Firewall)

NACLs are **stateless** firewall rules at the subnet boundary. Unlike Security Groups (which you'll deepen in Week 3), NACLs evaluate *both* inbound and outbound traffic independently.

!!! warning "NACLs vs Security Groups"
    | | NACL | Security Group |
    |---|---|---|
    | Level | Subnet | Instance (ENI) |
    | Stateful? | ❌ No — must allow return traffic explicitly | ✅ Yes — return traffic auto-allowed |
    | Rules | Allow AND Deny | Allow only |
    | Evaluation | Numbered order (lowest first) | All rules evaluated |

```bash
# ─── Step 6: Create a custom NACL for private subnets ────────────────────────
NACL=$(aws ec2 create-network-acl \
  --vpc-id $VPC_ID \
  --tag-specifications 'ResourceType=network-acl,Tags=[{Key=Name,Value=Private-NACL}]' \
  --profile iron-bank \
  --query NetworkAcl.NetworkAclId --output text)
echo "NACL: $NACL"

# Allow inbound traffic from within the VPC only (10.0.0.0/16)
# Rule 100: allow all TCP from VPC CIDR
aws ec2 create-network-acl-entry \
  --network-acl-id $NACL \
  --rule-number 100 \
  --protocol tcp \
  --rule-action allow \
  --ingress \
  --cidr-block 10.0.0.0/16 \
  --port-range From=0,To=65535

# Rule 200: deny everything else inbound (redundant — default is deny — but explicit is better)
aws ec2 create-network-acl-entry \
  --network-acl-id $NACL \
  --rule-number 200 \
  --protocol -1 \
  --rule-action deny \
  --ingress \
  --cidr-block 0.0.0.0/0

# Allow outbound back to VPC (stateless = must explicitly allow return traffic)
aws ec2 create-network-acl-entry \
  --network-acl-id $NACL \
  --rule-number 100 \
  --protocol tcp \
  --rule-action allow \
  --egress \
  --cidr-block 10.0.0.0/16 \
  --port-range From=0,To=65535

# Associate private subnets with this NACL
aws ec2 describe-network-acls \
  --filters "Name=association.subnet-id,Values=$PRIV_1A" \
  --profile iron-bank \
  --query 'NetworkAcls[0].Associations[0].NetworkAclAssociationId' \
  --output text
# Note: Use the association ID returned above to replace the default NACL association:
# aws ec2 replace-network-acl-association --association-id <ID> --network-acl-id $NACL --profile iron-bank
```

---

## Part 4: Verify Your Architecture

```bash
# ─── Verify everything looks right ───────────────────────────────────────────
echo "=== VPC ==="
aws ec2 describe-vpcs --vpc-ids $VPC_ID \
  --profile iron-bank \
  --query 'Vpcs[0].{ID:VpcId,CIDR:CidrBlock,DNS:EnableDnsHostnames}' \
  --output table

echo "=== Subnets ==="
aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --profile iron-bank \
  --query 'Subnets[*].{Name:Tags[?Key==`Name`]|[0].Value,ID:SubnetId,AZ:AvailabilityZone,CIDR:CidrBlock}' \
  --output table

echo "=== Route Tables ==="
aws ec2 describe-route-tables \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --profile iron-bank \
  --query 'RouteTables[*].{Name:Tags[?Key==`Name`]|[0].Value,ID:RouteTableId,Routes:Routes[*].DestinationCidrBlock}' \
  --output table
```

Expected output — you should see 4 subnets with the right CIDRs, 2 route tables, and the public one showing `0.0.0.0/0` as a route.

---

## 🧹 Cleanup

!!! abstract "🧹 Cleanup — Run this before ending your session"

```bash
# Delete NACLs (must disassociate first — easier via console if stuck)
# aws ec2 delete-network-acl --network-acl-id $NACL --profile iron-bank

# Delete route tables (must remove associations first)
aws ec2 disassociate-route-table --association-id <assoc-id-pub-1a> --profile iron-bank
aws ec2 disassociate-route-table --association-id <assoc-id-pub-1b> --profile iron-bank
aws ec2 delete-route-table --route-table-id $PUB_RT --profile iron-bank
aws ec2 delete-route-table --route-table-id $PRIV_RT --profile iron-bank

# Detach and delete IGW
aws ec2 detach-internet-gateway --internet-gateway-id $IGW --vpc-id $VPC_ID --profile iron-bank
aws ec2 delete-internet-gateway --internet-gateway-id $IGW --profile iron-bank

# Delete subnets
aws ec2 delete-subnet --subnet-id $PUB_1A --profile iron-bank
aws ec2 delete-subnet --subnet-id $PUB_1B --profile iron-bank
aws ec2 delete-subnet --subnet-id $PRIV_1A --profile iron-bank
aws ec2 delete-subnet --subnet-id $PRIV_1B --profile iron-bank

# Delete VPC last (must delete everything inside it first)
aws ec2 delete-vpc --vpc-id $VPC_ID --profile iron-bank

echo "✅ All Week 2 resources deleted"
```

!!! tip "Cleanup tip"
    If any delete command fails with a dependency error, go to **AWS Console → VPC → Your VPCs → select Iron-Bank-VPC → Actions → Delete VPC**. The console handles deletion order automatically.

---

## Checklist

- [ ] Built 4 subnets across 2 Availability Zones
- [ ] Created separate Public and Private route tables
- [ ] Public route table has `0.0.0.0/0 → IGW`
- [ ] Private route table has no internet route
- [ ] Created and reviewed a custom NACL
- [ ] Can explain the difference between NACLs and Security Groups
- [ ] Ran `describe-subnets` and read the output
- [ ] **All resources cleaned up — bill verified $0**
