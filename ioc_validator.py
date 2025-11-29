"""
IOC Validation Module
Handles detection and validation of IOCs (IPs, domains, file hashes)
"""

import re
import ipaddress
import pandas as pd


def detect_ioc_type(ioc):
    """
    Detect the type of IOC (IP, domain, or file hash)
    
    Args:
        ioc: String containing the IOC to analyze
        
    Returns:
        str: "ip", "domain", "file", or None if invalid
    """
    if not ioc or not isinstance(ioc, str):
        return None
        
    ioc = ioc.strip()
    
    # Patterns for different IOC types
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    hash_pattern = r"^[a-fA-F0-9]{32,64}$"  # Support both MD5 (32) and SHA-256 (64)

    if re.match(ip_pattern, ioc):
        return "ip"
    elif re.match(hash_pattern, ioc):
        return "file"
    elif re.match(domain_pattern, ioc):
        return "domain"
    else:
        return None


def is_valid_ip(ip_address):
    """
    Validate if a string is a valid IPv4 address
    
    Args:
        ip_address: String to validate
        
    Returns:
        bool: True if valid IPv4, False otherwise
    """
    try:
        ipaddress.IPv4Address(ip_address)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_ioc(ioc):
    """
    Validate an IOC entry
    
    Args:
        ioc: IOC string to validate
        
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    if pd.isna(ioc) or ioc == "" or str(ioc).strip().lower() == "nan":
        return False, "Empty IOC"
    
    ioc_str = str(ioc).strip()
    
    # Check for wildcard entries
    if '*' in ioc_str:
        return False, "Wildcard entry"
    
    # Check if valid IOC type
    ioc_type = detect_ioc_type(ioc_str)
    if not ioc_type:
        return False, "Invalid IOC type"
    
    return True, None

