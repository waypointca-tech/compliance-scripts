#!/usr/bin/env python3
"""
IAM User Auditor
Waypoint Compliance Advisory - waypointca.com

Purpose: Compares AWS IAM users against an approved access list
         Maps to NIST 800-171 AC-2 (Account Management)

Prerequisites:
    1. Install AWS CLI: https://aws.amazon.com/cli/
    2. Configure credentials: aws configure
    3. Install boto3: pip install boto3
    4. Create approved_users.json (see example below)
    
Usage:
    python 05_iam_auditor.py approved_users.json
    
    Or schedule weekly via cron:
    0 9 * * 1 python /path/to/05_iam_auditor.py /path/to/approved_users.json

approved_users.json format:
{
    "users": ["admin", "developer1", "developer2", "ci-service-account"],
    "last_reviewed": "2025-01-08",
    "reviewed_by": "security-team"
}
"""

import boto3
import json
import sys
import os
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Set, Dict, Tuple


def load_approved_users(filepath: str) -> Tuple[Set[str], Dict]:
    """
    Load the approved users list from JSON file.
    
    Args:
        filepath: Path to approved_users.json
        
    Returns:
        Tuple of (set of usernames, full config dict)
    """
    if not os.path.exists(filepath):
        print(f"Error: Approved users file not found: {filepath}")
        print("\nCreate a file with this format:")
        print(json.dumps({
            "users": ["admin", "developer1", "service-account"],
            "last_reviewed": "2025-01-08",
            "reviewed_by": "security-team"
        }, indent=2))
        sys.exit(1)
    
    with open(filepath, 'r') as f:
        config = json.load(f)
    
    return set(config.get('users', [])), config


def get_iam_users() -> Set[str]:
    """
    Fetch all IAM users from AWS account.
    
    Returns:
        Set of IAM usernames
    """
    try:
        iam = boto3.client('iam')
        users = set()
        
        # Handle pagination for accounts with many users
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                users.add(user['UserName'])
        
        return users
        
    except NoCredentialsError:
        print("Error: AWS credentials not configured.")
        print("Run 'aws configure' to set up your credentials.")
        sys.exit(1)
    except ClientError as e:
        print(f"Error: AWS API call failed - {e}")
        sys.exit(1)


def audit_iam_users(approved_file: str) -> Dict:
    """
    Compare actual IAM users against approved list.
    
    Args:
        approved_file: Path to approved users JSON
        
    Returns:
        Audit results dictionary
    """
    approved, config = load_approved_users(approved_file)
    actual = get_iam_users()
    
    unauthorized = actual - approved
    missing = approved - actual
    valid = actual & approved
    
    results = {
        "audit_timestamp": datetime.utcnow().isoformat() + "Z",
        "approved_list_reviewed": config.get("last_reviewed", "unknown"),
        "approved_list_reviewed_by": config.get("reviewed_by", "unknown"),
        "total_iam_users": len(actual),
        "total_approved": len(approved),
        "authorized_users": sorted(list(valid)),
        "unauthorized_users": sorted(list(unauthorized)),
        "missing_users": sorted(list(missing)),
        "compliant": len(unauthorized) == 0
    }
    
    return results


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: python iam_auditor.py <approved_users.json>")
        print("Example: python iam_auditor.py ./approved_users.json")
        sys.exit(1)
    
    approved_file = sys.argv[1]
    
    print("IAM User Audit")
    print("=" * 50)
    print(f"Running at: {datetime.utcnow().isoformat()}Z\n")
    
    results = audit_iam_users(approved_file)
    
    # Summary
    print(f"Total IAM users in AWS: {results['total_iam_users']}")
    print(f"Approved users in list: {results['total_approved']}")
    print(f"Approved list last reviewed: {results['approved_list_reviewed']}")
    print()
    
    # Findings
    if results['unauthorized_users']:
        print("⚠️  UNAUTHORIZED USERS DETECTED:")
        for user in results['unauthorized_users']:
            print(f"    - {user}")
        print()
    
    if results['missing_users']:
        print("ℹ️  EXPECTED USERS NOT FOUND:")
        for user in results['missing_users']:
            print(f"    - {user}")
        print()
    
    # Compliance status
    if results['compliant']:
        print("✅ COMPLIANT: All IAM users are in the approved list.")
        exit_code = 0
    else:
        print("❌ NON-COMPLIANT: Unauthorized users exist in the account.")
        print("\nAction required: Review and either remove unauthorized users")
        print("or add them to the approved list with proper authorization.")
        exit_code = 1
    
    # Save detailed results
    output_file = f"iam_audit_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nDetailed results saved to: {output_file}")
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
