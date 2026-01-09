# Compliance Automation Scripts

**Waypoint Compliance Advisory** | [waypointca.com](https://waypointca.com)

Practical Python scripts for automating federal compliance evidence collection and security controls. Designed for defense contractors and organizations pursuing CMMC, FedRAMP, or NIST 800-171 compliance.

## Scripts

| Script | Purpose | NIST Control |
|--------|---------|--------------|
| `01_evidence_collection.py` | Collect AWS security group configs | AC-4 (Information Flow) |
| `02_ai_decision_logger.py` | Log AI model decisions for audit | AU-2, AU-3 (Audit Events) |
| `03_audit_decorator.py` | Auto-log who did what when | AU-2, AU-3 (Audit Events) |
| `04_secrets_scanner.py` | Find hardcoded secrets in code | SC-28 (Protection at Rest) |
| `05_iam_auditor.py` | Audit IAM users against approved list | AC-2 (Account Management) |

## Prerequisites

### For AWS Scripts (01, 05)

1. Install AWS CLI:
   ```bash
   # macOS
   brew install awscli
   
   # Windows
   choco install awscli
   
   # Linux
   curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
   unzip awscliv2.zip && sudo ./aws/install
   ```

2. Configure credentials:
   ```bash
   aws configure
   # Enter your Access Key ID, Secret Access Key, region, and output format
   ```

3. Install boto3:
   ```bash
   pip install boto3
   ```

### For Other Scripts (02, 03, 04)

No external dependencies - uses Python standard library only.

## Usage

### Evidence Collection (AWS)
```bash
python 01_evidence_collection.py
# Creates: ./evidence/evidence_ac4_YYYYMMDD_HHMMSS.json
```

### AI Decision Logger
```python
from 02_ai_decision_logger import AIDecisionLogger

logger = AIDecisionLogger("./logs")
logger.log_decision(
    model_name="my_model",
    input_data={"user": "123"},
    output="approved",
    confidence=0.95
)
```

### Audit Decorator
```python
from 03_audit_decorator import audit_log

@audit_log("accessed_sensitive_data")
def my_function():
    # Your code here
    pass
```

### Secrets Scanner
```bash
python 04_secrets_scanner.py ./your-code-directory
```

### IAM Auditor (AWS)
```bash
# First, create approved_users.json:
{
    "users": ["admin", "developer1", "ci-service"],
    "last_reviewed": "2025-01-08",
    "reviewed_by": "security-team"
}

# Then run:
python 05_iam_auditor.py approved_users.json
```

## CI/CD Integration

Add the secrets scanner to your pipeline:

```yaml
# GitHub Actions example
- name: Scan for secrets
  run: python scripts/04_secrets_scanner.py ./src
```

## Security Notes

- **Evidence collection** - Files contain configuration data; store securely
- **AI logger** - Hashes input data by default to protect sensitive information  
- **Audit decorator** - Does not log function arguments to avoid capturing sensitive data
- **Secrets scanner** - Basic pattern matching; use alongside dedicated tools like trufflehog or git-secrets
- **IAM auditor** - Requires read-only IAM permissions; use least-privilege credentials

## License

MIT License - Use freely, attribution appreciated.

GitHub: [github.com/waypointca-tech/compliance-scripts](https://github.com/waypointca-tech/compliance-scripts)

## About

Built by [Waypoint Compliance Advisory](https://waypointca.com), a Service-Disabled Veteran-Owned Small Business providing cybersecurity compliance consulting for federal contractors.

- CMMC 2.0 Assessments
- FedRAMP Consulting
- Security Assessments
- Fractional CISO Services

Questions? [Book a free consultation](https://calendly.com/tech-waypointca/30min)
