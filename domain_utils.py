import re
import ipaddress
import logging
from typing import Optional, List, Dict
from urllib.parse import urlparse
from config import WHITELISTED_DOMAINS

def is_valid_ip(ip: str) -> bool:
    """
    Validates if the given text is a valid IP address (IPv4 or IPv6) and checks for special ranges.
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if IP is valid and not in special ranges, False otherwise
    """
    # IPv4 validation
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$', ip):
        try:
            ip_obj = ipaddress.ip_address(ip.split(':')[0])
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                return False
            return True
        except ValueError:
            return False
            
    # IPv6 validation
    try:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
        return False
    except ValueError:
        return False
            
    return False

def is_ip_address(domain: str) -> bool:
    """
    Check if a domain is actually an IP address.
    
    Args:
        domain (str): Domain to check
        
    Returns:
        bool: True if domain is an IP address, False otherwise
    """
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

def clean_domain(domain: str) -> str:
    """
    Cleans domain by removing comments and path information.
    
    Args:
        domain (str): Domain to clean
        
    Returns:
        str: Cleaned domain
    """
    # Clean domain by removing comments if any
    if '#' in domain:
        domain = domain.split('#')[0].strip()
        
    # Remove path after '/' if exists
    if '/' in domain:
        domain = domain.split('/')[0].strip()
    
    # Handle other common patterns
    if domain.startswith('0.0.0.0 '):
        domain = domain.replace('0.0.0.0 ', '').strip()
    elif domain.startswith('127.0.0.1 '):
        domain = domain.replace('127.0.0.1 ', '').strip()
    
    # Remove trailing dot (representing root domain in DNS notation)
    if domain.endswith('.'):
        domain = domain[:-1]
        
    # Remove trailing backslash that might appear in some records
    if domain.endswith('\\'):
        domain = domain[:-1]
        
    return domain

def is_valid_domain_format(domain: str) -> bool:
    """
    Validates domain string format against RFC standards.
    Accepts special characters like '/', '*', '_' that can be valid in DNS records.
    Removes any comments or path information before validation.
    
    Args:
        domain (str): Domain to validate
        
    Returns:
        bool: True if domain format is valid, False otherwise
    """
    try:
        original_domain = domain
        domain = clean_domain(domain)
        
        # Log the cleaning transformation for debugging
        if original_domain != domain:
            logging.debug(f"Domain cleaned: '{original_domain}' -> '{domain}'")
            
        # Domain must contain at least one dot
        if '.' not in domain:
            logging.debug(f"Domain rejected - no dot: '{domain}'")
            return False
        
        # Reject email addresses
        if '@' in domain:
            logging.debug(f"Domain rejected - contains @ symbol: '{domain}'")
            return False
            
        # Domain parts check
        parts = domain.split('.')
        if len(parts) < 2:
            logging.debug(f"Domain rejected - less than 2 parts: '{domain}'")
            return False
            
        # Each part must contain at least one character
        if any(len(part) == 0 for part in parts):
            logging.debug(f"Domain rejected - contains empty part: '{domain}'")
            return False
        
        # Check for invalid characters in each part
        for part in parts:
            # Reject empty parts
            if not part:
                logging.debug(f"Domain rejected - empty part in: '{domain}'")
                return False
                
            # Check for incorrect use of punctuation
            if '..' in domain:
                logging.debug(f"Domain rejected - double dots in: '{domain}'")
                return False
                
            # Subdomains should not start or end with -
            if part.startswith('-') or part.endswith('-'):
                logging.debug(f"Domain rejected - part starts or ends with dash: '{part}' in '{domain}'")
                return False
            
            # Accept only valid characters for DNS:
            # a-z, 0-9, -, *, _ (for wildcard and service records)
            if not re.match(r'^[a-zA-Z0-9\-\*\_]+$', part):
                logging.debug(f"Domain rejected - invalid characters in part: '{part}' in '{domain}'")
                return False
            
        return True
    except Exception as e:
        logging.debug(f"Domain validation exception: '{domain}' - {str(e)}")
        return False

def is_whitelisted_domain(domain: str) -> bool:
    """
    Check if a domain is in the whitelist.
    
    Args:
        domain (str): Domain to check
        
    Returns:
        bool: True if domain is whitelisted, False otherwise
    """
    for white_domain in WHITELISTED_DOMAINS:
        if domain == white_domain or domain.endswith(f".{white_domain}"):
            return True
    
    return False

def is_valid_domain(domain: str) -> bool:
    """
    Validates domain string against RFC standards and checks against whitelist.
    Excludes IP addresses, IP:Port formats, and popular/trusted domains.
    
    Args:
        domain (str): Domain to validate
        
    Returns:
        bool: True if domain is valid and not whitelisted, False otherwise
    """
    try:
        original_domain = domain
        
        # Handle trailing dots in domains (RFC valid)
        if domain.endswith('.'):
            domain = domain[:-1]
            
        # Reject email addresses
        if '@' in domain:
            logging.debug(f"Domain rejected - contains @ symbol: {original_domain}")
            return False
            
        # IP address validation
        if is_ip_address(domain):
            logging.debug(f"Domain rejected - is IP address: {original_domain}")
            return False
            
        # IP:Port format validation
        if ':' in domain:
            ip_part = domain.split(':')[0]
            if is_valid_ip(ip_part):
                logging.debug(f"Domain rejected - is IP:port format: {original_domain}")
                return False
        
        # Domain format validation
        if not is_valid_domain_format(domain):
            logging.debug(f"Domain rejected - invalid format: {original_domain}")
            return False
            
        # Whitelist check
        if is_whitelisted_domain(domain):
            logging.debug(f"Domain rejected - whitelisted: {original_domain}")
            return False
            
        return True
    except Exception as e:
        logging.debug(f"Domain validation exception for {domain}: {str(e)}")
        return False

def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extracts and validates domain from URL.
    Excludes IP addresses and IP:Port formats from being considered as valid domains.
    
    Args:
        url (str): URL to extract domain from
        
    Returns:
        Optional[str]: Validated domain or None if invalid/not found
    """
    try:
        # Parse URL
        parsed = urlparse(url)
        
        # Use netloc if available, otherwise use path
        domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
            
        # Convert to lowercase
        domain = domain.lower()
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
            
        # Remove port information
        if ':' in domain:
            domain = domain.split(':')[0]
            
        # Reject IP addresses and IP:Port formats
        if is_valid_ip(domain) or (':' in url and is_valid_ip(domain.split(':')[0])):
            return None
            
        # Validate domain format
        if is_valid_domain(domain):
            return domain
            
        return None
    except Exception:
        return None

def get_filter_reason(domain: str) -> str:
    """
    Get the reason why a domain was filtered.
    
    Args:
        domain (str): The domain name
        
    Returns:
        str: The reason for filtering
    """
    if not domain:
        return "EMPTY_DOMAIN"
    
    if is_ip_address(domain):
        return "IP_ADDRESS"
    
    if not "." in domain:
        return "INVALID_DOMAIN_FORMAT"
    
    if domain in ["example.com", "example.org", "example.net"]:
        return "EXAMPLE_DOMAIN"
        
    if is_whitelisted_domain(domain):
        return "WHITELISTED_DOMAIN"
        
    if len(domain) > 253:
        return "DOMAIN_TOO_LONG"
    
    # Check domain parts
    parts = domain.split('.')
    
    for part in parts:
        # Sections starting or ending with - are invalid
        if part.startswith('-') or part.endswith('-'):
            return "INVALID_DOMAIN_FORMAT"
        
        # Character check for each part
        if not re.match(r'^[a-zA-Z0-9\-\*\_]+$', part):
            return "SPECIAL_DNS_RECORD"
    
    # Check for double dots
    if '..' in domain:
        return "INVALID_DOMAIN_FORMAT"
        
    return "VALID"

def debug_domain_validation(domain: str) -> Dict[str, bool]:
    """
    Debug function to trace domain validation steps.
    
    Args:
        domain (str): Domain to validate
        
    Returns:
        Dict[str, bool]: Dictionary with validation step results
    """
    results = {
        "original": domain,
        "cleaned": clean_domain(domain),
        "is_ip_address": False,
        "is_ip_port": False,
        "valid_format": False,
        "whitelisted": False,
        "final_result": False
    }
    
    # Clean the domain
    cleaned_domain = clean_domain(domain)
    results["cleaned"] = cleaned_domain
    
    # Check if it's an IP address
    results["is_ip_address"] = is_ip_address(cleaned_domain)
    
    # Check if it's IP:Port format
    if ':' in cleaned_domain:
        ip_part = cleaned_domain.split(':')[0]
        try:
            results["is_ip_port"] = is_valid_ip(ip_part)
        except:
            results["is_ip_port"] = False
    
    # Check domain format
    results["valid_format"] = is_valid_domain_format(cleaned_domain)
    
    # Check whitelist
    results["whitelisted"] = is_whitelisted_domain(cleaned_domain)
    
    # Final result
    results["final_result"] = (not results["is_ip_address"] and 
                              not results["is_ip_port"] and 
                              results["valid_format"] and 
                              not results["whitelisted"])
    
    return results 