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

def is_ip_address(text: str) -> bool:
    """
    Check if text is an IP address.
    
    Args:
        text (str): Text to check
        
    Returns:
        bool: True if text is an IP address, False otherwise
    """
    try:
        ipaddress.ip_address(text)
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
    # Convert to string if not already
    domain = str(domain).strip()
    
    # Clean domain by removing comments if any
    if '#' in domain:
        domain = domain.split('#')[0].strip()
        
    # Remove path after '/' if exists
    if '/' in domain:
        domain = domain.split('/')[0].strip()
    
    # Handle hostfile format patterns
    if domain.startswith('0.0.0.0 '):
        domain = domain.split('0.0.0.0')[-1].strip()
    elif domain.startswith('127.0.0.1 '):
        domain = domain.split('127.0.0.1')[-1].strip()
    elif domain.startswith('::1 '):
        domain = domain.split('::1')[-1].strip()
    
    # Handle tab separators that might appear in hostfiles
    if '\t' in domain:
        domain = domain.split('\t')[-1].strip()
    
    # Remove trailing dot (representing root domain in DNS notation)
    if domain.endswith('.'):
        domain = domain[:-1]
        
    # Remove trailing backslash that might appear in some records
    if domain.endswith('\\'):
        domain = domain[:-1]
        
    # Convert to lowercase
    domain = domain.lower()
    
    return domain

def is_whitelisted_domain(domain: str) -> bool:
    """
    Check if domain is in whitelist.
    
    Args:
        domain (str): Domain to check
        
    Returns:
        bool: True if domain is whitelisted, False otherwise
    """
    # Direct match
    if domain in WHITELISTED_DOMAINS:
        return True
        
    # Check if domain is a subdomain of any whitelisted domain
    for whitelisted in WHITELISTED_DOMAINS:
        if domain.endswith('.' + whitelisted):
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
        
        # Domain must contain at least one dot
        if '.' not in domain:
            logging.debug(f"Domain rejected - no dot: {original_domain}")
            return False
            
        # Domain parts check
        parts = domain.split('.')
        if len(parts) < 2:
            logging.debug(f"Domain rejected - less than 2 parts: {original_domain}")
            return False
            
        # Each part must contain at least one character
        if any(len(part) == 0 for part in parts):
            logging.debug(f"Domain rejected - contains empty part: {original_domain}")
            return False
            
        # Check for double dots
        if '..' in domain:
            logging.debug(f"Domain rejected - contains double dots: {original_domain}")
            return False
            
        # Check each part for valid characters and length
        for part in parts:
            # Sections starting or ending with - are invalid
            if part.startswith('-') or part.endswith('-'):
                logging.debug(f"Domain rejected - part starts/ends with hyphen: {original_domain}")
                return False
                
            # Character check for each part
            if not re.match(r'^[a-zA-Z0-9\-\*\_]+$', part):
                logging.debug(f"Domain rejected - contains invalid characters: {original_domain}")
                return False
                
            # Length check for each part
            if len(part) > 63:
                logging.debug(f"Domain rejected - part too long: {original_domain}")
                return False
                
        # Total length check
        if len(domain) > 253:
            logging.debug(f"Domain rejected - total length too long: {original_domain}")
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
        
    if '@' in domain:
        return "CONTAINS_AT_SYMBOL"
        
    if is_ip_address(domain):
        return "IS_IP_ADDRESS"
        
    if ':' in domain:
        ip_part = domain.split(':')[0]
        if is_valid_ip(ip_part):
            return "IS_IP_PORT_FORMAT"
            
    if '.' not in domain:
        return "NO_DOT"
        
    parts = domain.split('.')
    if len(parts) < 2:
        return "LESS_THAN_2_PARTS"
        
    if any(len(part) == 0 for part in parts):
        return "EMPTY_PART"
        
    if '..' in domain:
        return "DOUBLE_DOTS"
        
    for part in parts:
        if part.startswith('-') or part.endswith('-'):
            return "STARTS_ENDS_WITH_HYPHEN"
            
        if not re.match(r'^[a-zA-Z0-9\-\*\_]+$', part):
            return "INVALID_CHARACTERS"
            
        if len(part) > 63:
            return "PART_TOO_LONG"
            
    if len(domain) > 253:
        return "TOTAL_LENGTH_TOO_LONG"
        
    if is_whitelisted_domain(domain):
        return "WHITELISTED"
        
    return "VALID" 