#!/usr/bin/env python3
"""
CloudTrail Log Analyzer for Forensics
======================================

Purpose:
  Parses CloudTrail logs from S3 and extracts key forensic indicators
  including suspicious API calls, lateral movement, and credential abuse.

Why this script matters:
  - CloudTrail logs thousands of events per hour in production
  - Each event is a JSON object with 20+ fields
  - Manual analysis is impossible at scale
  - This script automates detection of "what went wrong" patterns

How to use:
  1. Download CloudTrail logs from S3: aws s3 sync s3://bucket-name ./logs/
  2. Decompress: find logs -name "*.gz" -exec gunzip {} \;
  3. Run this script: python3 analyze-cloudtrail.py ./logs/
  4. Review output for suspicious events

Author: Iron Bank Training
Date: April 2026
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG: Suspicious API Calls to Flag
# ═══════════════════════════════════════════════════════════════════════════════

# These actions are red flags and should trigger investigation
SUSPICIOUS_ACTIONS = {
    # Credential attacks
    "CreateAccessKey": "Attacker creating backdoor credential",
    "CreateUser": "Creating new administrative user",
    "AttachUserPolicy": "Granting permissions to user",
    "PutUserPolicy": "Creating inline privilege-escalation policy",

    # Privilege escalation
    "AssumeRole": "Lateral movement to higher-privilege role",
    "UpdateAssumeRolePolicy": "Modifying role trust relationship",

    # Network security bypass
    "ModifySecurityGroupIngress": "Opening inbound network access",
    "ModifySecurityGroupEgress": "Opening outbound network access (exfiltration risk)",
    "AuthorizeSecurityGroupIngress": "Alternative: adding ingress rule",
    "RevokeSecurityGroupEgress": "Removing egress restrictions",

    # Data exfiltration
    "GetObject": "Reading from S3 (high volume = suspicious)",
    "PutBucketPolicy": "Modifying S3 bucket access",
    "DeleteBucketPolicy": "Removing S3 access controls",

    # Database tampering
    "ModifyDBInstance": "Modifying database configuration (encryption, backups, etc)",
    "ModifyDBCluster": "Modifying database cluster settings",
    "CreateDBSnapshot": "Exfiltration preparation (snapshot copy-out)",

    # Covering tracks
    "DeleteTrail": "CRITICAL: Attacker destroying audit logs",
    "StopLogging": "CRITICAL: Disabling CloudTrail logging",
    "DisableLogging": "CRITICAL: Disabling service logging",
    "PutEventSelectors": "Modifying what CloudTrail logs (reduce visibility)",

    # Secrets theft
    "GetSecretValue": "Accessing encrypted secrets/credentials",
    "CreateSecret": "Creating new secret (preparation for exfil)",
}

# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def print_section(title: str) -> None:
    """Print a formatted section header."""
    print(f"\n{'='*70}")
    print(f"{title:^70}")
    print(f"{'='*70}")

def print_suspicious_event(event: Dict[str, Any]) -> None:
    """Print a suspicious event in a readable format."""
    event_name = event.get("eventName", "UNKNOWN")
    event_time = event.get("eventTime", "UNKNOWN")
    user_identity = event.get("userIdentity", {})
    principal = user_identity.get("principalId", "UNKNOWN")
    source_ip = event.get("sourceIPAddress", "UNKNOWN")

    print(f"\n⚠️  {event_name}")
    print(f"    Principal:  {principal}")
    print(f"    Time:       {event_time}")
    print(f"    Source IP:  {source_ip}")

    # Event-specific details
    if event_name == "CreateAccessKey":
        response = event.get("responseElements", {})
        access_key = response.get("accessKey", {})
        key_id = access_key.get("accessKeyId", "UNKNOWN")
        print(f"    ⚠️  NEW ACCESS KEY CREATED: {key_id}")
        print(f"        → Check if this user should have new credentials")
        print(f"        → Monitor if this key is used from unusual locations")

    elif event_name == "CreateUser":
        request = event.get("requestParameters", {})
        new_user = request.get("userName", "UNKNOWN")
        print(f"    ⚠️  NEW USER CREATED: {new_user}")
        print(f"        → Verify this user was authorized")
        print(f"        → Check what permissions are attached")

    elif event_name == "AssumeRole":
        request = event.get("requestParameters", {})
        target_role = request.get("roleArn", "UNKNOWN")
        print(f"    ⚠️  ROLE ASSUMPTION (Lateral Movement)")
        print(f"        → From: {principal}")
        print(f"        → To:   {target_role}")
        print(f"        → Risk: Attacker escalating from one role to higher-privilege role")

    elif event_name in ["ModifySecurityGroupIngress", "AuthorizeSecurityGroupIngress"]:
        request = event.get("requestParameters", {})
        sg_id = request.get("groupId", "UNKNOWN")
        ip_perms = request.get("ipPermissions", [])
        print(f"    ⚠️  NETWORK ACCESS MODIFIED")
        print(f"        → Security Group: {sg_id}")
        for perm in ip_perms:
            protocol = perm.get("ipProtocol", "unknown")
            from_port = perm.get("fromPort", "?")
            to_port = perm.get("toPort", "?")
            cidr_ranges = [r.get("cidrIp", "?") for r in perm.get("ipRanges", [])]
            print(f"        → {protocol} ports {from_port}-{to_port} from {', '.join(cidr_ranges)}")
            if "0.0.0.0/0" in cidr_ranges or "::/0" in cidr_ranges:
                print(f"        → ⚠️  CRITICAL: Opened to the entire internet!")

    elif event_name in ["DeleteTrail", "StopLogging", "DisableLogging"]:
        print(f"    🚨 CRITICAL: AUDIT LOG TAMPERING")
        print(f"        → Attacker is destroying evidence")
        print(f"        → This is the highest-priority incident")

    elif event_name == "GetSecretValue":
        request = event.get("requestParameters", {})
        secret_id = request.get("secretId", "UNKNOWN")
        print(f"    ⚠️  SECRET ACCESSED: {secret_id}")
        print(f"        → Verify if this access was authorized")
        print(f"        → Consider rotating this secret if compromised")

def analyze_cloudtrail_logs(log_dir: str) -> None:
    """
    Main analysis function.

    Scans all JSON files in the directory and extracts forensic indicators.
    Prints a detailed report of suspicious activity.

    Args:
        log_dir (str): Path to directory containing CloudTrail logs

    Returns:
        None (prints to stdout)
    """

    # Statistics tracking
    stats = {
        "total_events": 0,
        "suspicious_count": 0,
        "parse_errors": 0,
        "events_by_principal": {},
        "suspicious_by_type": {},
        "access_keys_created": [],
        "access_keys_used": [],
    }

    log_path = Path(log_dir)

    # ═══════════════════════════════════════════════════════════════════════════
    # PASS 1: Scan all files and extract events
    # ═══════════════════════════════════════════════════════════════════════════

    print_section("PHASE 1: Scanning CloudTrail Logs")

    json_files = list(log_path.glob("**/*.json"))
    print(f"Found {len(json_files)} CloudTrail log file(s)")

    all_events = []  # Collect events from all files

    for json_file in json_files:
        print(f"\n  Reading {json_file.name}...", end=" ")

        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            # CloudTrail format: { "Records": [ {...}, {...}, ... ] }
            events = data.get("Records", [])
            all_events.extend(events)
            print(f"✓ ({len(events)} events)")

        except json.JSONDecodeError as e:
            print(f"❌ JSON error: {e}")
            stats["parse_errors"] += 1
        except Exception as e:
            print(f"❌ Error: {e}")
            stats["parse_errors"] += 1

    print(f"\nTotal events extracted: {len(all_events)}")

    # ═══════════════════════════════════════════════════════════════════════════
    # PASS 2: Detect suspicious activity
    # ═══════════════════════════════════════════════════════════════════════════

    print_section("PHASE 2: Detecting Suspicious Activity")

    suspicious_events = []

    for event in all_events:
        stats["total_events"] += 1
        event_name = event.get("eventName", "UNKNOWN")
        principal = event.get("userIdentity", {}).get("principalId", "UNKNOWN")

        # Track events by principal
        if principal not in stats["events_by_principal"]:
            stats["events_by_principal"][principal] = 0
        stats["events_by_principal"][principal] += 1

        # Check if event is suspicious
        if event_name in SUSPICIOUS_ACTIONS:
            stats["suspicious_count"] += 1

            # Track suspicious events by type
            if event_name not in stats["suspicious_by_type"]:
                stats["suspicious_by_type"][event_name] = 0
            stats["suspicious_by_type"][event_name] += 1

            suspicious_events.append(event)
            print_suspicious_event(event)

        # Track access key creation and usage
        if event_name == "CreateAccessKey":
            response = event.get("responseElements", {})
            access_key = response.get("accessKey", {})
            stats["access_keys_created"].append({
                "AccessKeyId": access_key.get("accessKeyId"),
                "Principal": principal,
                "Time": event.get("eventTime"),
            })

        # Track access key usage (used by IAM roles that assume credentials)
        # This is a heuristic: if principalId ends with the access key, it's that key
        if len(principal) > 20 and principal[-20:].startswith("AKIA"):
            stats["access_keys_used"].append({
                "AccessKeyId": principal[-20:],
                "Time": event.get("eventTime"),
                "SourceIP": event.get("sourceIPAddress"),
                "Action": event_name,
            })

    # ═══════════════════════════════════════════════════════════════════════════
    # PASS 3: Timeline analysis (access key creation → usage from different IP)
    # ═══════════════════════════════════════════════════════════════════════════

    if stats["access_keys_created"] and stats["access_keys_used"]:
        print_section("PHASE 3: Access Key Timeline Analysis")
        print("\n⚠️  Checking for access keys created then used from different IPs...")

        for created_key in stats["access_keys_created"]:
            key_id = created_key["AccessKeyId"]

            # Find usages of this key
            usages = [u for u in stats["access_keys_used"] if u["AccessKeyId"] == key_id]

            if usages:
                print(f"\nAccess Key {key_id}:")
                print(f"  Created by: {created_key['Principal']} at {created_key['Time']}")

                for usage in usages:
                    print(f"  Used from: {usage['SourceIP']} at {usage['Time']} ({usage['Action']})")

                    # Check if IPs are different (suspicious)
                    if len(set(u["SourceIP"] for u in usages)) > 1:
                        print(f"  ⚠️  SUSPICIOUS: Key used from MULTIPLE IPs")
                        print(f"      → Possible credential theft/exfiltration")

    # ═══════════════════════════════════════════════════════════════════════════
    # SUMMARY & RECOMMENDATIONS
    # ═══════════════════════════════════════════════════════════════════════════

    print_section("FORENSICS SUMMARY")

    print(f"\nTotal events analyzed:       {stats['total_events']}")
    print(f"Suspicious events detected:  {stats['suspicious_count']}")
    print(f"Parse errors:                {stats['parse_errors']}")

    if stats["suspicious_by_type"]:
        print(f"\nSuspicious events by type:")
        for event_type, count in sorted(stats["suspicious_by_type"].items(), key=lambda x: x[1], reverse=True):
            risk = "🚨 CRITICAL" if event_type in ["DeleteTrail", "StopLogging", "DisableLogging"] else "⚠️  WARNING"
            print(f"  {risk:15} {event_type:30} ({count}x)")

    print(f"\nActivity by principal (top 5):")
    for principal, count in sorted(stats["events_by_principal"].items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {principal:40} ({count} events)")

    print_section("INCIDENT RESPONSE RECOMMENDATIONS")

    if stats["suspicious_count"] == 0:
        print("\n✅ No suspicious events detected in this time window")
        print("   Continue monitoring for threats (enable GuardDuty in Month 6)")
    else:
        print("\n⚠️  SUSPICIOUS ACTIVITY DETECTED")
        print("\nImmediate actions:")
        print("  1. Review each flagged event in AWS CloudTrail Console")
        print("  2. Verify authorization with the principal's manager")
        print("  3. Check if credentials were compromised (check other unusual activity)")
        print("  4. Revoke unauthorized credentials:")
        print("     aws iam delete-access-key --access-key-id AKIA... --user-name <user>")
        print("  5. Detach unauthorized policies:")
        print("     aws iam detach-user-policy --user-name <user> --policy-arn <arn>")
        print("\nLonger-term fixes:")
        print("  - Implement SCPs to deny dangerous actions (Month 6, Week 3)")
        print("  - Enable GuardDuty for real-time threat detection (Month 6, Week 1)")
        print("  - Enable CloudTrail with immutable logging (S3 Object Lock)")
        print("  - Configure CloudWatch alarms for suspicious actions")
        print("  - Implement MFA for sensitive operations")

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("CloudTrail Log Analyzer")
        print("=======================")
        print("Usage: python3 analyze-cloudtrail.py <log_directory>")
        print("\nExample:")
        print("  1. aws s3 sync s3://my-cloudtrail-bucket ./logs/")
        print("  2. find logs -name '*.gz' -exec gunzip {} \\;")
        print("  3. python3 analyze-cloudtrail.py ./logs/")
        sys.exit(1)

    log_dir = sys.argv[1]

    if not os.path.isdir(log_dir):
        print(f"❌ Error: Directory '{log_dir}' not found")
        sys.exit(1)

    print("\n" + "="*70)
    print("CloudTrail Forensics Analyzer".center(70))
    print("="*70)
    print(f"Analyzing logs from: {log_dir}\n")

    analyze_cloudtrail_logs(log_dir)

    print("\n" + "="*70)
    print("Analysis complete".center(70))
    print("="*70 + "\n")
