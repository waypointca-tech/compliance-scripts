#!/usr/bin/env python3
"""
AI Decision Logger
Waypoint Compliance Advisory - waypointca.com

Purpose: Logs AI model decisions for audit trails and explainability
         Supports federal AI governance requirements

Prerequisites:
    pip install hashlib (standard library, no install needed)
    
Usage:
    from ai_decision_logger import AIDecisionLogger
    
    logger = AIDecisionLogger("./ai_audit_logs")
    logger.log_decision(
        model_name="fraud_detector_v2",
        input_data={"transaction_id": "12345"},
        output="approved",
        confidence=0.94
    )

Security Notes:
    - Input data is hashed by default to avoid logging sensitive information
    - Set hash_inputs=False only for non-sensitive data
    - Logs are append-only for integrity
"""

import json
import hashlib
import logging
import os
from datetime import datetime
from typing import Any, Optional


class AIDecisionLogger:
    """
    Secure logger for AI model decisions.
    Designed for compliance with federal AI governance requirements.
    """
    
    def __init__(self, log_dir: str = "./ai_audit_logs"):
        """
        Initialize the AI decision logger.
        
        Args:
            log_dir: Directory for audit log files
        """
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Configure logging with append mode for integrity
        log_file = os.path.join(log_dir, "ai_decisions.log")
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(message)s'  # JSON only, no extra formatting
        )
        self.logger = logging.getLogger("ai_audit")
        
    def _hash_sensitive_data(self, data: Any) -> str:
        """Create SHA-256 hash of input data for audit without exposing values."""
        data_string = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(data_string.encode()).hexdigest()[:16]
    
    def log_decision(
        self,
        model_name: str,
        input_data: Any,
        output: Any,
        confidence: float,
        hash_inputs: bool = True,
        additional_context: Optional[dict] = None
    ) -> dict:
        """
        Log an AI model decision.
        
        Args:
            model_name: Identifier for the AI model
            input_data: Data passed to the model
            output: Model's decision/output
            confidence: Confidence score (0-1)
            hash_inputs: If True, hash input data for privacy
            additional_context: Optional metadata
            
        Returns:
            The logged record
        """
        record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "model": model_name,
            "input_reference": self._hash_sensitive_data(input_data) if hash_inputs else input_data,
            "input_hashed": hash_inputs,
            "decision": output,
            "confidence": round(confidence, 4),
            "reviewable": True,
            "context": additional_context or {}
        }
        
        self.logger.info(json.dumps(record))
        return record


# Example usage
if __name__ == "__main__":
    logger = AIDecisionLogger("./ai_audit_logs")
    
    # Example: Log a fraud detection decision
    result = logger.log_decision(
        model_name="fraud_detector_v2",
        input_data={"user_id": "user123", "amount": 5000},
        output="flagged_for_review",
        confidence=0.87,
        additional_context={"rule_triggered": "high_value_transaction"}
    )
    
    print("Decision logged:")
    print(json.dumps(result, indent=2))
