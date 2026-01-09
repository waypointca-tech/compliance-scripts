#!/usr/bin/env python3
"""
Audit Log Decorator
Waypoint Compliance Advisory - waypointca.com

Purpose: Automatically logs who did what and when for any function
         Maps to NIST 800-171 AU-2 (Audit Events) and AU-3 (Content of Audit Records)

Prerequisites:
    None - uses Python standard library only
    
Usage:
    from audit_decorator import audit_log
    
    @audit_log("accessed_sensitive_report")
    def get_sensitive_report(report_id):
        # your code here
        pass

Security Notes:
    - Logs user, timestamp, action, and success/failure
    - Does NOT log function arguments (may contain sensitive data)
    - Configure log file permissions appropriately (e.g., 640)
"""

import logging
import os
import getpass
from functools import wraps
from datetime import datetime
from typing import Callable, Any


def setup_audit_logger(log_file: str = "./audit.log") -> logging.Logger:
    """
    Configure a secure audit logger.
    
    Args:
        log_file: Path to the audit log file
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("security_audit")
    logger.setLevel(logging.INFO)
    
    # Prevent duplicate handlers
    if not logger.handlers:
        handler = logging.FileHandler(log_file, mode='a')
        handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(handler)
        
        # Also log to console for visibility
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(console)
    
    return logger


# Global audit logger
_audit_logger = setup_audit_logger()


def audit_log(action_name: str) -> Callable:
    """
    Decorator that logs function execution for audit compliance.
    
    Args:
        action_name: Human-readable name for the action being logged
        
    Returns:
        Decorated function with audit logging
        
    Example:
        @audit_log("exported_customer_data")
        def export_data(customer_id):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Collect audit information
            timestamp = datetime.utcnow().isoformat() + "Z"
            
            try:
                user = getpass.getuser()
            except Exception:
                user = "unknown"
            
            # Log the attempt
            audit_record = {
                "timestamp": timestamp,
                "user": user,
                "action": action_name,
                "function": func.__name__,
                "status": "started"
            }
            
            try:
                result = func(*args, **kwargs)
                audit_record["status"] = "success"
                _audit_logger.info(str(audit_record))
                return result
                
            except Exception as e:
                audit_record["status"] = "failed"
                audit_record["error_type"] = type(e).__name__
                _audit_logger.warning(str(audit_record))
                raise
                
        return wrapper
    return decorator


# Example usage
if __name__ == "__main__":
    
    @audit_log("accessed_cui_data")
    def get_sensitive_report(report_id: str) -> dict:
        """Example function that accesses sensitive data."""
        return {"report_id": report_id, "data": "sensitive content"}
    
    @audit_log("modified_user_permissions")
    def change_permissions(user_id: str, new_role: str) -> bool:
        """Example function that modifies access."""
        return True
    
    @audit_log("failed_operation")
    def risky_operation():
        """Example function that fails."""
        raise ValueError("Something went wrong")
    
    # Test successful operations
    print("Testing audit logging...\n")
    
    get_sensitive_report("RPT-001")
    change_permissions("user123", "admin")
    
    # Test failed operation
    try:
        risky_operation()
    except ValueError:
        pass
    
    print("\nCheck audit.log for records.")
