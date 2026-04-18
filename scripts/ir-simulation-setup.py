#!/usr/bin/env python3

"""
ir-simulation-setup.py — Automated Incident Response Simulation

Purpose:
  This script creates a realistic incident scenario for IR training:
  1. Creates a mock "attacker" IAM user with limited privileges
  2. Injects suspicious API calls to CloudTrail
  3. Generates evidence for forensic investigation
  4. Provides step-by-step labs for detection and response
  5. Cleanup removes all test artifacts

Threat Scenarios:
  - Reconnaissance: ListBuckets, DescribeInstances, GetSecretValue
  - Data Exfiltration: CopyObject to attacker-controlled bucket
  - Privilege Escalation: Attempt to create new IAM user
  - Persistence: Create new access key for backdoor
  - Lateral Movement: AssumeRole to access other accounts

Usage:
  python3 ir-simulation-setup.py --create --scenario reconnaissance
  python3 ir-simulation-setup.py --investigate  (analyze CloudTrail)
  python3 ir-simulation-setup.py --cleanup

Author: Iron Bank Training
Date: 2026-04-15
"""

import boto3
import argparse
import json
import time
from datetime import datetime, timedelta
import random
import string

class IRSimulation:
    def __init__(self, profile='iron-bank', region='us-east-1'):
        """Initialize AWS clients for IR simulation."""
        self.profile = profile
        self.region = region
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.iam = self.session.client('iam')
        self.s3 = self.session.client('s3')
        self.ec2 = self.session.client('ec2')
        self.cloudtrail = self.session.client('cloudtrail')
        self.account_id = boto3.client('sts', region_name=region).get_caller_identity()['Account']
        self.attacker_user = 'iron-bank-attacker-sim'
        self.attacker_access_key = None
        self.attacker_secret_key = None

    def create_attacker_user(self):
        """
        Create a mock "attacker" IAM user with basic S3 and EC2 read permissions.
        This simulates an attacker who has compromised a legitimate user's credentials.
        """
        print(f"\n[*] Creating attacker IAM user: {self.attacker_user}")

        try:
            # Create the user
            response = self.iam.create_user(UserName=self.attacker_user)
            print(f"    ✅ User created: {self.attacker_user}")
        except self.iam.exceptions.EntityAlreadyExistsException:
            print(f"    ⚠  User already exists, skipping creation")

        # Attach a policy that allows S3 and EC2 reads
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListBucket",
                        "s3:GetObject",
                        "s3:ListAllMyBuckets"
                    ],
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeInstances",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeSnapshots"
                    ],
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:ListSecrets",
                        "secretsmanager:GetSecretValue"
                    ],
                    "Resource": "*"
                }
            ]
        }

        policy_name = f"{self.attacker_user}-policy"
        try:
            self.iam.put_user_policy(
                UserName=self.attacker_user,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
            print(f"    ✅ Policy attached: {policy_name}")
        except Exception as e:
            print(f"    ⚠  Policy already exists: {e}")

        # Create access keys for the attacker user
        try:
            key_response = self.iam.create_access_key(UserName=self.attacker_user)
            self.attacker_access_key = key_response['AccessKey']['AccessKeyId']
            self.attacker_secret_key = key_response['AccessKey']['SecretAccessKey']
            print(f"    ✅ Access key created: {self.attacker_access_key[:8]}...")
            return True
        except self.iam.exceptions.LimitExceededException:
            # If already 2 keys, list them
            keys = self.iam.list_access_keys(UserName=self.attacker_user)
            if keys['AccessKeyMetadata']:
                self.attacker_access_key = keys['AccessKeyMetadata'][0]['AccessKeyId']
                print(f"    ⚠  Using existing key: {self.attacker_access_key[:8]}...")
                return True
            raise

    def simulate_reconnaissance(self):
        """
        Simulate attacker reconnaissance phase:
        - ListBuckets to find sensitive S3 buckets
        - DescribeInstances to map infrastructure
        - ListSecrets to identify secrets

        These calls are logged in CloudTrail and appear suspicious
        when clustered together from the same IP/user.
        """
        print(f"\n[*] Simulating reconnaissance phase...")

        if not self.attacker_access_key:
            print("    ❌ Attacker user not created. Run --create first.")
            return False

        # Create attacker session
        attacker_session = boto3.Session(
            aws_access_key_id=self.attacker_access_key,
            aws_secret_access_key=self.attacker_secret_key,
            region_name=self.region
        )

        try:
            # Reconnaissance call 1: List all buckets
            print(f"    [1/4] ListBuckets (reconnaissance)")
            s3_attacker = attacker_session.client('s3')
            buckets = s3_attacker.list_buckets()
            bucket_count = len(buckets['Buckets'])
            print(f"          Found {bucket_count} buckets")

            # Reconnaissance call 2: Describe EC2 instances
            print(f"    [2/4] DescribeInstances (infrastructure mapping)")
            ec2_attacker = attacker_session.client('ec2')
            instances = ec2_attacker.describe_instances()
            instance_count = sum(len(r['Instances']) for r in instances['Reservations'])
            print(f"          Found {instance_count} instances")

            # Reconnaissance call 3: List secrets (attempt to find credentials)
            print(f"    [3/4] ListSecrets (identify sensitive data)")
            sm_attacker = attacker_session.client('secretsmanager')
            try:
                secrets = sm_attacker.list_secrets()
                secret_count = len(secrets.get('SecretList', []))
                print(f"          Found {secret_count} secrets")
            except Exception as e:
                print(f"          (No Secrets Manager access or no secrets)")

            # Reconnaissance call 4: Try to get a specific secret (will likely fail due to permissions)
            print(f"    [4/4] GetSecretValue attempt (credential theft)")
            try:
                secret = sm_attacker.get_secret_value(SecretId='iron-bank-db-password')
                print(f"          ❌ CRITICAL: Successfully retrieved secret!")
            except sm_attacker.exceptions.ResourceNotFoundException:
                print(f"          (Secret not found or permission denied — expected)")
            except Exception as e:
                print(f"          (Access denied — expected)")

            print(f"    ✅ Reconnaissance phase complete")
            print(f"    📝 These API calls are now in CloudTrail with timestamp {datetime.utcnow().isoformat()}Z")
            return True

        except Exception as e:
            print(f"    ❌ Error during reconnaissance: {e}")
            return False

    def simulate_data_exfiltration(self):
        """
        Simulate attacker attempting to exfiltrate data:
        - Get an object from a sensitive S3 bucket
        - Copy it to attacker-controlled location
        - Delete evidence (delete logs)

        This simulates the eradication/covering-tracks phase.
        """
        print(f"\n[*] Simulating data exfiltration phase...")

        if not self.attacker_access_key:
            print("    ❌ Attacker user not created. Run --create first.")
            return False

        attacker_session = boto3.Session(
            aws_access_key_id=self.attacker_access_key,
            aws_secret_access_key=self.attacker_secret_key,
            region_name=self.region
        )

        try:
            s3_attacker = attacker_session.client('s3')

            # Step 1: Create an "exfiltration bucket" (attacker-controlled)
            exfil_bucket = f"iron-bank-exfil-{datetime.utcnow().strftime('%s')}"
            print(f"    [1/3] Creating exfiltration bucket: {exfil_bucket}")
            try:
                s3_attacker.create_bucket(Bucket=exfil_bucket)
                print(f"          ✅ Bucket created")
            except Exception as e:
                print(f"          (Bucket creation failed — permissions issue, expected)")
                return False

            # Step 2: Try to copy a sensitive file
            print(f"    [2/3] Attempting to copy data to exfiltration bucket")
            print(f"          (This would copy sensitive data — simulated)")

            # Step 3: Try to delete CloudTrail logs (cover tracks)
            print(f"    [3/3] Attempting to delete CloudTrail logs (cover tracks)")
            try:
                trails = self.cloudtrail.describe_trails()
                if trails['trailList']:
                    trail_name = trails['trailList'][0]['Name']
                    print(f"          Attempting to delete {trail_name}...")
                    self.cloudtrail.delete_trail(Name=trail_name)
                    print(f"          ✅ Trail deleted (if permitted)")
            except Exception as e:
                print(f"          (Trail deletion denied — SCP protection active, good!)")

            print(f"    ✅ Exfiltration phase complete")
            return True

        except Exception as e:
            print(f"    ❌ Error during exfiltration: {e}")
            return False

    def simulate_privilege_escalation(self):
        """
        Simulate attacker attempting privilege escalation:
        - Create new IAM user (will likely fail due to permissions)
        - Create new access key (might succeed if inline policy allows)
        - Assume role (will fail without trust relationship)
        """
        print(f"\n[*] Simulating privilege escalation phase...")

        if not self.attacker_access_key:
            print("    ❌ Attacker user not created. Run --create first.")
            return False

        attacker_session = boto3.Session(
            aws_access_key_id=self.attacker_access_key,
            aws_secret_access_key=self.attacker_secret_key,
            region_name=self.region
        )

        try:
            iam_attacker = attacker_session.client('iam')

            # Attempt 1: Create new IAM user (will fail due to permissions)
            print(f"    [1/3] Attempting CreateUser (privilege escalation)")
            try:
                new_user = f"iron-bank-backdoor-{random.randint(1000, 9999)}"
                iam_attacker.create_user(UserName=new_user)
                print(f"          ❌ CRITICAL: User creation succeeded!")
            except iam_attacker.exceptions.AccessDenied:
                print(f"          (Access denied — permission boundary active, good!)")
            except Exception as e:
                print(f"          (Failed: {str(e)[:50]}...)")

            # Attempt 2: Create access key
            print(f"    [2/3] Attempting CreateAccessKey (backdoor creation)")
            try:
                current_user = attacker_session.client('sts').get_caller_identity()
                username = current_user['Arn'].split('/')[-1]
                key = iam_attacker.create_access_key(UserName=username)
                print(f"          ❌ CRITICAL: Access key created: {key['AccessKey']['AccessKeyId']}")
            except Exception as e:
                print(f"          (Failed: {str(e)[:50]}...)")

            # Attempt 3: Assume role (will fail without trust relationship)
            print(f"    [3/3] Attempting AssumeRole (lateral movement)")
            try:
                sts_attacker = attacker_session.client('sts')
                sts_attacker.assume_role(
                    RoleArn=f"arn:aws:iam::{self.account_id}:role/AdminRole",
                    RoleSessionName="attacker-session"
                )
                print(f"          ❌ CRITICAL: Role assumption succeeded!")
            except sts_attacker.exceptions.AccessDenied:
                print(f"          (Access denied — trust policy protecting role)")
            except Exception as e:
                print(f"          (Failed: {str(e)[:50]}...)")

            print(f"    ✅ Privilege escalation phase complete")
            return True

        except Exception as e:
            print(f"    ❌ Error during escalation: {e}")
            return False

    def investigate_cloudtrail(self):
        """
        Analyze CloudTrail logs to find suspicious activity.
        This demonstrates forensic investigation techniques.
        """
        print(f"\n[*] Investigating CloudTrail logs...")

        try:
            # Get CloudTrail logs from the last hour
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)

            print(f"    Searching CloudTrail for events from {self.attacker_user}...")

            events = self.cloudtrail.lookup_events(
                LookupAttributes=[
                    {'AttributeKey': 'Username', 'AttributeValue': self.attacker_user}
                ],
                StartTime=start_time,
                MaxResults=50
            )

            if events['Events']:
                print(f"    ✅ Found {len(events['Events'])} suspicious events:\n")

                # Timeline reconstruction
                for event in sorted(events['Events'], key=lambda x: x['EventTime']):
                    event_time = event['EventTime'].strftime('%H:%M:%S')
                    event_name = event['EventName']
                    event_source = event.get('EventSource', 'unknown')
                    print(f"       [{event_time}] {event_name} ({event_source})")

                print(f"\n    📊 Attack Timeline Summary:")
                print(f"       Phase 1: Reconnaissance (ListBuckets, DescribeInstances)")
                print(f"       Phase 2: Persistence (CreateAccessKey)")
                print(f"       Phase 3: Lateral Movement (AssumeRole attempts)")
                print(f"       Phase 4: Data Exfiltration (CopyObject to external bucket)")
                print(f"       Phase 5: Cover Tracks (DeleteTrail, DeleteLog events)")

            else:
                print(f"    ℹ️  No events found for {self.attacker_user}")
                print(f"       (CloudTrail may not yet show the events)")
                print(f"       (Try running this investigation 5-10 minutes after --create)")

        except Exception as e:
            print(f"    ❌ Error investigating CloudTrail: {e}")

    def cleanup(self):
        """
        Remove all test artifacts:
        - Delete attacker IAM user and keys
        - Remove inline policies
        - Delete exfiltration bucket (if created)
        """
        print(f"\n[*] Cleaning up incident simulation...")

        try:
            # Delete access keys
            keys = self.iam.list_access_keys(UserName=self.attacker_user)
            for key in keys['AccessKeyMetadata']:
                self.iam.delete_access_key(
                    UserName=self.attacker_user,
                    AccessKeyId=key['AccessKeyId']
                )
                print(f"    ✅ Deleted access key: {key['AccessKeyId'][:8]}...")

            # Delete inline policies
            policies = self.iam.list_user_policies(UserName=self.attacker_user)
            for policy_name in policies['PolicyNames']:
                self.iam.delete_user_policy(
                    UserName=self.attacker_user,
                    PolicyName=policy_name
                )
                print(f"    ✅ Deleted policy: {policy_name}")

            # Delete user
            self.iam.delete_user(UserName=self.attacker_user)
            print(f"    ✅ Deleted user: {self.attacker_user}")

            print(f"\n    ✅ Cleanup complete — all test artifacts removed")

        except self.iam.exceptions.NoSuchEntityException:
            print(f"    ℹ️  User does not exist — nothing to cleanup")
        except Exception as e:
            print(f"    ❌ Error during cleanup: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Incident Response Simulation for IR Training',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create attacker and run all scenarios
  python3 ir-simulation-setup.py --profile iron-bank --create --scenario all

  # Run just reconnaissance
  python3 ir-simulation-setup.py --profile iron-bank --create --scenario reconnaissance

  # Investigate CloudTrail (run 5-10 mins after --create)
  python3 ir-simulation-setup.py --profile iron-bank --investigate

  # Clean up when done
  python3 ir-simulation-setup.py --profile iron-bank --cleanup
        """
    )

    parser.add_argument('--profile', default='iron-bank', help='AWS profile (default: iron-bank)')
    parser.add_argument('--region', default='us-east-1', help='AWS region (default: us-east-1)')
    parser.add_argument('--create', action='store_true', help='Create attacker user and inject events')
    parser.add_argument('--scenario', choices=['reconnaissance', 'exfiltration', 'escalation', 'all'],
                       default='all', help='Which scenario to simulate (default: all)')
    parser.add_argument('--investigate', action='store_true', help='Analyze CloudTrail for attack evidence')
    parser.add_argument('--cleanup', action='store_true', help='Remove all test artifacts')

    args = parser.parse_args()

    # Validate arguments
    if not any([args.create, args.investigate, args.cleanup]):
        print("Error: Specify one of --create, --investigate, or --cleanup")
        parser.print_help()
        return 1

    # Initialize simulation
    sim = IRSimulation(profile=args.profile, region=args.region)

    if args.create:
        print(f"\n{'='*65}")
        print(f"  Iron Bank — Incident Response Simulation")
        print(f"  Creating attack scenario: {args.scenario}")
        print(f"{'='*65}")

        # Step 1: Create attacker user
        if not sim.create_attacker_user():
            return 1

        # Step 2: Run scenarios
        time.sleep(2)  # Wait for IAM propagation

        if args.scenario in ['reconnaissance', 'all']:
            sim.simulate_reconnaissance()
            time.sleep(2)

        if args.scenario in ['exfiltration', 'all']:
            sim.simulate_data_exfiltration()
            time.sleep(2)

        if args.scenario in ['escalation', 'all']:
            sim.simulate_privilege_escalation()

        print(f"\n{'='*65}")
        print(f"  ✅ Incident simulation created!")
        print(f"  📝 Attacker User: {sim.attacker_user}")
        print(f"  📝 Access Key: {sim.attacker_access_key}")
        print(f"\n  Next Steps:")
        print(f"  1. Wait 5-10 minutes for CloudTrail to process events")
        print(f"  2. Run: python3 ir-simulation-setup.py --investigate")
        print(f"  3. Check CloudTrail console for attack evidence")
        print(f"  4. Run: python3 ir-simulation-setup.py --cleanup")
        print(f"{'='*65}\n")

    elif args.investigate:
        sim.investigate_cloudtrail()

    elif args.cleanup:
        sim.cleanup()

    return 0

if __name__ == '__main__':
    exit(main())
