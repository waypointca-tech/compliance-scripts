#!/usr/bin/env python3
"""
Secrets Scanner
Waypoint Compliance Advisory - waypointca.com

Purpose: Scans codebase for hardcoded secrets before deployment
         Helps prevent common CMMC/NIST findings

Prerequisites:
    None - uses Python standard library only
    
Usage:
    python 04_secrets_scanner.py /path/to/your/code
    
    Or as a module:
    from secrets_scanner import scan_for_secrets
    findings = scan_for_secrets("./src")

Security Notes:
    - Run this in CI/CD pipelines before deployment
    - Add to pre-commit hooks for automatic checking
    - Does not detect all secrets - use alongside tools like git-secrets or trufflehog
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple


# Patterns that may indicate hardcoded secrets
SECRET_PATTERNS = [
    (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password"),
    (r'api_key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key"),
    (r'apikey\s*=\s*["\'][^"\']+["\']', "Hardcoded API key"),
    (r'secret\s*=\s*["\'][^"\']+["\']', "Hardcoded secret"),
    (r'token\s*=\s*["\'][^"\']+["\']', "Hardcoded token"),
    (r'aws_access_key_id\s*=\s*["\'][A-Z0-9]+["\']', "AWS Access Key"),
    (r'aws_secret_access_key\s*=\s*["\'][^"\']+["\']', "AWS Secret Key"),
    (r'private_key\s*=\s*["\'][^"\']+["\']', "Private key"),
    (r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----', "Private key block"),
    (r'-----BEGIN OPENSSH PRIVATE KEY-----', "SSH private key"),
]

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.java', '.go', '.rb', '.php',
    '.yaml', '.yml', '.json', '.xml', '.env', '.conf',
    '.sh', '.bash', '.ps1', '.config'
}

# Directories to skip
SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', 'venv', 'env',
    '.venv', 'vendor', 'dist', 'build', '.tox'
}


def should_scan_file(filepath: Path) -> bool:
    """Check if file should be scanned based on extension."""
    return filepath.suffix.lower() in SCANNABLE_EXTENSIONS


def scan_file(filepath: Path) -> List[Dict]:
    """
    Scan a single file for potential secrets.
    
    Args:
        filepath: Path to the file to scan
        
    Returns:
        List of findings with file, line, pattern type
    """
    findings = []
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                # Skip comments (basic check)
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('//'):
                    continue
                    
                for pattern, description in SECRET_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "file": str(filepath),
                            "line": line_num,
                            "type": description,
                            "preview": line.strip()[:60] + "..." if len(line.strip()) > 60 else line.strip()
                        })
    except Exception as e:
        print(f"Warning: Could not scan {filepath}: {e}")
    
    return findings


def scan_for_secrets(directory: str) -> Tuple[List[Dict], int]:
    """
    Scan a directory recursively for hardcoded secrets.
    
    Args:
        directory: Root directory to scan
        
    Returns:
        Tuple of (findings list, files scanned count)
    """
    all_findings = []
    files_scanned = 0
    
    root_path = Path(directory)
    
    for filepath in root_path.rglob('*'):
        # Skip directories in ignore list
        if any(skip_dir in filepath.parts for skip_dir in SKIP_DIRS):
            continue
            
        if filepath.is_file() and should_scan_file(filepath):
            files_scanned += 1
            findings = scan_file(filepath)
            all_findings.extend(findings)
    
    return all_findings, files_scanned


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: python secrets_scanner.py <directory>")
        print("Example: python secrets_scanner.py ./src")
        sys.exit(1)
    
    target_dir = sys.argv[1]
    
    if not os.path.isdir(target_dir):
        print(f"Error: {target_dir} is not a valid directory")
        sys.exit(1)
    
    print(f"Scanning {target_dir} for hardcoded secrets...\n")
    
    findings, files_scanned = scan_for_secrets(target_dir)
    
    print(f"Files scanned: {files_scanned}")
    print(f"Potential secrets found: {len(findings)}\n")
    
    if findings:
        print("=" * 60)
        print("FINDINGS (Review these before committing)")
        print("=" * 60)
        
        for finding in findings:
            print(f"\n[{finding['type']}]")
            print(f"  File: {finding['file']}")
            print(f"  Line: {finding['line']}")
            print(f"  Preview: {finding['preview']}")
        
        print("\n" + "=" * 60)
        print("RECOMMENDED FIX: Use environment variables")
        print("=" * 60)
        print("""
# Instead of:
API_KEY = "sk-1234567890abcdef"

# Use:
import os
API_KEY = os.environ.get('API_KEY')
""")
        sys.exit(1)  # Exit with error for CI/CD
    else:
        print("No hardcoded secrets detected.")
        sys.exit(0)


if __name__ == "__main__":
    main()
