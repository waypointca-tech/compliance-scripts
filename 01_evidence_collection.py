#!/usr/bin/env python3
"""
AWS Security Group Evidence Collector
Waypoint Compliance Advisory - waypointca.com

Purpose: Automates collection of AWS security group configurations
         for compliance evidence (maps to NIST AC-4 Information Flow)

Prerequisites:
    1. Install AWS CLI: https://aws.amazon.com/cli/
    2. Configure credentials: aws configure
    3. Install boto3: pip install boto3
    
Usage:
    python 01_evidence_collection.py
    
Output:
    JSON file with timestamped security group configurations
"""

import boto3
import json
import os
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError


def collect_security_group_evidence(output_dir: str = "./evidence") -> str:
    """
    Collects AWS security group configurations and saves as timestamped JSON.
    
    Args:
        output_dir: Directory to save evidence files
        
    Returns:
        Path to the created evidence file
        
    Raises:
        NoCredentialsError: If AWS credentials not configured
        ClientError: If AWS API call fails
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        ec2 = boto3.client('ec2')
        groups = ec2.describe_security_groups()
        
    except NoCredentialsError:
        print("ERROR: AWS credentials not configured.")
        print("Run 'aws configure' to set up your credentials.")
        raise
    except ClientError as e:
        print(f"ERROR: AWS API call failed - {e}")
        raise
    
    # Build evidence record
    evidence = {
        "metadata": {
            "collected_at": datetime.utcnow().isoformat() + "Z",
            "collector": "evidence_collection.py",
            "control_mapping": "NIST 800-171 AC-4 (Information Flow)",
            "aws_region": boto3.session.Session().region_name
        },
        "security_groups": groups['SecurityGroups']
    }
    
    # Save with timestamp in filename
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"evidence_ac4_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w') as f:
        json.dump(evidence, f, indent=2, default=str)
    
    print(f"Evidence collected: {filepath}")
    return filepath


if __name__ == "__main__":
    collect_security_group_evidence()
