import csv
import os
import time
import datetime
import requests
import logging
import json
import re
import random
import sys
from colorama import Fore, Style
from typing import List, Dict, Tuple, Any
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from domain_utils import extract_domain_from_url, is_valid_domain, get_filter_reason, is_valid_ip
from config import HTTP_TIMEOUT, HTTP_MAX_RETRIES, HTTP_BACKOFF_FACTOR, HTTP_RETRY_CODES, WHITELISTED_DOMAINS

# Add URLScan specific settings
URLSCAN_TIMEOUT = 60  # Longer timeout for URLScan API
URLSCAN_RETRY_DELAY = 10  # Seconds to wait between retries
URLSCAN_MAX_RETRIES = 3  # Maximum number of retries for URLScan

def get_intelligence_sources() -> Dict[str, Dict[str, Any]]:
    """
    Returns a dictionary of threat intelligence sources with their URLs and metadata.
    
    Returns:
        Dict[str, Dict[str, Any]]: Dictionary mapping source names to their metadata
    """
    return {
        # Active sources with improved descriptions
        "ThreatFox": {
            "url": "https://threatfox.abuse.ch/downloads/hostfile/",
            "format": "hostfile",
            "description": "Malicious domains - collected by abuse.ch",
            "enabled": True
        },
        "URLhaus": {
            "url": "https://urlhaus.abuse.ch/downloads/text_online/",
            "format": "url",
            "description": "URLs distributing malware - by abuse.ch",
            "enabled": True
        },
        "OpenPhish": {
            "url": "https://openphish.com/feed.txt",
            "format": "url",
            "description": "Active common phishing sites",
            "enabled": True
        },
        "CyberCrime": {
            "url": "https://cybercrime-tracker.net/all.php",
            "format": "url",
            "description": "Cybercrime and malware panels",
            "enabled": True
        },
        "Botvrij": {
            "url": "https://www.botvrij.eu/data/ioclist.domain",
            "format": "domain",
            "description": "Botvrij.eu IOC domain list",
            "enabled": True
        },
        "StopForumSpam": {
            "url": "https://www.stopforumspam.com/downloads/toxic_domains_whole.txt",
            "format": "domain",
            "description": "Toxicological domains associated with spammers",
            "enabled": True
        },
        # URLScan rate limiting fixed with backoff mechanism
        "URLScan": {
            "url": "https://urlscan.io/api/v1/search/?q=task.tags:malicious&size=1000",
            "format": "urlscan",
            "description": "Malicious domains detected by URLScan.io",
            "enabled": True,
            "use_special_handler": True  # Flag to use special handling for this source
        },
        "PhishStats": {
            "url": "https://phishstats.info/phish_score.csv",
            "format": "phishstats",
            "description": "Phishing sites collected by PhishStats",
            "enabled": True
        },
        # More reliable new sources
        "URLhaus_Database": {
            "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "format": "csv", 
            "description": "Latest URLs in URLhaus database",
            "enabled": True
        },
        "PhishingArmy": {
            "url": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
            "format": "domain",
            "description": "PhishingArmy phishing domains",
            "enabled": True
        }
    }

def create_resilient_session() -> requests.Session:
    """
    Creates a requests Session with retry logic and timeouts.
    
    Returns:
        requests.Session: Configured session object
    """
    session = requests.Session()
    
    # Configure retries using config values
    retry_strategy = Retry(
        total=HTTP_MAX_RETRIES,
        backoff_factor=HTTP_BACKOFF_FACTOR,
        status_forcelist=HTTP_RETRY_CODES,
        allowed_methods=["GET"]  # Only retry for GET requests
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Simpler timeout solution
    old_request = session.request
    
    def new_request(method, url, **kwargs):
        if 'timeout' not in kwargs:
            kwargs['timeout'] = HTTP_TIMEOUT
        return old_request(method, url, **kwargs)
    
    session.request = new_request
    
    # Set user agent to avoid being blocked - more realistic user agents
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.51'
    ]
    session.headers.update({
        'User-Agent': random.choice(user_agents),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'cross-site'
    })
    
    return session

# Add a special handler for URLScan to avoid rate limiting
def fetch_urlscan_data(url: str, session: requests.Session) -> str:
    """
    Special handler for URLScan API to avoid rate limiting.
    Implements additional delays and retry logic.
    
    Args:
        url (str): URLScan API URL
        session (requests.Session): Existing session object
        
    Returns:
        str: Response content or empty string on failure
    """
    max_retries = URLSCAN_MAX_RETRIES
    retry_count = 0
    
    while retry_count <= max_retries:
        try:
            # Add significant delay between requests to respect rate limits
            if retry_count > 0:
                # Exponential backoff
                sleep_time = URLSCAN_RETRY_DELAY * (2 ** (retry_count - 1))
                logging.info(f"URLScan API retry {retry_count}/{max_retries}. Waiting {sleep_time} seconds...")
                time.sleep(sleep_time)
            
            # Make the request with extended timeout
            response = session.get(url, timeout=URLSCAN_TIMEOUT)
            
            # Check if we hit rate limit
            if response.status_code == 429:
                retry_count += 1
                continue
                
            response.raise_for_status()
            return response.text
            
        except requests.exceptions.RequestException as e:
            if "429" in str(e) and retry_count < max_retries:
                retry_count += 1
                continue
            else:
                logging.error(f"Error fetching URLScan data: {str(e)}")
                return ""
    
    logging.error(f"Max retries exceeded for URLScan API")
    return ""

def clean_domain_entry(domain_entry: str) -> str:
    """
    Cleans a domain entry by removing comments and whitespace.
    
    Args:
        domain_entry (str): Raw domain entry possibly containing comments
    
    Returns:
        str: Cleaned domain entry
    """
    # Remove comments (# and anything after it)
    if '#' in domain_entry:
        domain_entry = domain_entry.split('#')[0]
    
    # Remove any leading/trailing whitespace
    domain_entry = domain_entry.strip()
    
    # Handle other common patterns
    if domain_entry.startswith('0.0.0.0 '):
        domain_entry = domain_entry.replace('0.0.0.0 ', '')
    elif domain_entry.startswith('127.0.0.1 '):
        domain_entry = domain_entry.replace('127.0.0.1 ', '')
    
    # Remove trailing backslashes that shouldn't be part of domain names
    if domain_entry.endswith('\\'):
        domain_entry = domain_entry[:-1]
    
    return domain_entry

def process_url_format(content: str) -> List[str]:
    """
    Process data in URL format (one URL per line).
    
    Args:
        content (str): Raw URL content
    
    Returns:
        List[str]: List of processed domain strings
    """
    domains = []
    
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Check each line, could be URL or domain
        cleaned_line = clean_domain_entry(line)
        if not cleaned_line:
            continue
        
        # Is it in URL format?
        if cleaned_line.startswith('http://') or cleaned_line.startswith('https://'):
            domain = extract_domain_from_url(cleaned_line)
            if domain and is_valid_domain(domain):
                domains.append(domain)
        # Is it in IP and domain format? (IP domain)
        elif ' ' in cleaned_line and is_valid_ip(cleaned_line.split(' ')[0]):
            domain_part = cleaned_line.split(' ')[1].strip()
            if is_valid_domain(domain_part):
                domains.append(domain_part)
        # Direct domain
        elif is_valid_domain(cleaned_line):
            domains.append(cleaned_line)
    
    return domains

def process_domain_format(content: str) -> List[str]:
    """
    Process data in domain format (one domain per line).
    
    Args:
        content (str): Raw domain content
    
    Returns:
        List[str]: List of processed domain strings
    """
    domains = []
    for line in content.split('\n'):
        # Skip if line is empty or starts with comment
        if not line.strip() or line.strip().startswith('#'):
            continue
            
        # Clean the domain entry
        domain = clean_domain_entry(line)
        
        # Add if not empty
        if domain:
            domains.append(domain)
            
    return domains

def process_hostfile_format(content: str) -> List[str]:
    """
    Process data in hostfile format (typically 0.0.0.0 or 127.0.0.1 followed by domain).
    
    Args:
        content (str): Raw hostfile content
    
    Returns:
        List[str]: List of processed domain strings
    """
    domains = []
    for line in content.split('\n'):
        # Skip if line is empty or starts with comment
        if not line.strip() or line.strip().startswith('#'):
            continue
            
        # Clean line from comments
        cleaned_line = clean_domain_entry(line)
        
        if not cleaned_line:
            continue
        
        # Process lines with IP addresses followed by domain
        parts = cleaned_line.strip().split()
        
        # Get the last part as domain (after IP address)
        if len(parts) >= 2:
            domains.append(parts[-1].strip())
            
    return domains

def process_special_format(content: str) -> List[str]:
    """
    Process data in special format cases (like MalwarePatrol).
    
    Args:
        content (str): Raw content
    
    Returns:
        List[str]: List of processed domain strings
    """
    domains = []
    
    # Check each line for URL or domain
    for line in content.split('\n'):
        # Skip if line is empty or starts with comment
        if not line.strip() or line.strip().startswith('#'):
            continue
            
        # Clean line from comments
        cleaned_line = clean_domain_entry(line)
        
        if not cleaned_line:
            continue
        
        # Is it a URL format?
        if "://" in cleaned_line:
            domain = extract_domain_from_url(cleaned_line)
            if domain:
                domains.append(domain)
        # Is it in IP and domain format? (IP domain)
        elif len(cleaned_line.split()) >= 2:
            try:
                ip_part = cleaned_line.split()[0]
                domain_part = cleaned_line.split()[-1]
                
                # Clean domain part further to handle edge cases like trailing backslashes
                domain_part = clean_domain_entry(domain_part)
                
                # Validate if first part is an IP
                if is_valid_ip(ip_part):
                    domains.append(domain_part)
                else:
                    # If not an IP, treat as domain directly
                    if is_valid_domain(cleaned_line):
                        domains.append(cleaned_line)
            except Exception as e:
                logging.debug(f"Error in process_special_format: {str(e)} for line: {cleaned_line}")
                # If IP validation fails, just try to use as domain
                if is_valid_domain(cleaned_line):
                    domains.append(cleaned_line)
        # Direct domain?
        else:
            if is_valid_domain(cleaned_line):
                domains.append(cleaned_line)
                
    return domains

def process_blocklist_format(content: str) -> List[str]:
    """
    Process data in blocklist.site format.
    
    Args:
        content (str): Raw blocklist content
    
    Returns:
        List[str]: List of processed domain strings
    """
    domains = []
    for line in content.split('\n'):
        # Skip if line is empty or starts with comment
        if not line.strip() or line.strip().startswith('#'):
            continue
            
        # Clean the entry
        cleaned_line = clean_domain_entry(line)
        
        if not cleaned_line or "." not in cleaned_line:
            continue
            
        # Common format variations have been handled by clean_domain_entry
        domains.append(cleaned_line)
            
    return domains

def process_urlscan_format(content: str) -> List[str]:
    """
    Process data in URLScan.io API format.
    
    Args:
        content (str): Raw URLScan API JSON content
    
    Returns:
        List[str]: List of processed domain strings
    """
    domains = []
    
    # Return empty list if content is empty
    if not content:
        return domains
        
    try:
        data = json.loads(content)
        results = data.get("results", [])
        
        for result in results:
            page = result.get("page", {})
            domain = page.get("domain")
            if domain:
                domains.append(domain)
    except (json.JSONDecodeError, AttributeError) as e:
        logging.error(f"URLScan format parsing error: {str(e)}")
    
    return domains

def process_phishstats_format(content: str) -> List[str]:
    """
    Process data in PhishStats CSV format.
    
    Args:
        content (str): Raw CSV content
    
    Returns:
        List[str]: List of processed domain strings
    """
    domains = []
    
    # Process CSV lines
    lines = content.splitlines()
    if len(lines) > 1:  # Skip header row
        for i, line in enumerate(lines):
            if i == 0:  # Header row
                continue
                
            # Parse CSV row
            parts = line.split(',')
            if len(parts) >= 2:
                url = parts[1].strip('"').strip()
                
                # Extract domain from URL
                domain = extract_domain_from_url(url)
                if domain and is_valid_domain(domain):
                    domains.append(domain)
    
    return domains

def process_csv_format(content: str) -> List[str]:
    """
    Process CSV format data (specifically for URLhaus).
    
    Args:
        content (str): Raw CSV content
    
    Returns:
        List[str]: List of processed domain strings
    """
    domains = []
    
    # Process CSV rows
    rows = content.splitlines()
    if len(rows) > 1:  # Skip header row
        for i, row in enumerate(rows):
            if i == 0 or row.startswith('#'):
                continue  # Skip header row
                
            # Handle escaped values in CSV
            try:
                parts = []
                # Simple CSV parsing with handling for escaped quotes
                in_quotes = False
                current_part = ""
                for char in row:
                    if char == ',' and not in_quotes:
                        parts.append(current_part)
                        current_part = ""
                    elif char == '"':
                        in_quotes = not in_quotes
                    else:
                        current_part += char
                if current_part:
                    parts.append(current_part)
                
                if len(parts) < 2:
                    continue
                
                # URLhaus CSV format: ID, URL, ...
                url_part = parts[1].strip('"').strip()
                
                # Clean URL part
                domain = extract_domain_from_url(url_part)
                if domain and is_valid_domain(domain):
                    domains.append(domain)
            except Exception as e:
                logging.debug(f"Error processing CSV row: {str(e)} for row: {row}")
    
    return domains

def process_archive_format(content: bytes, url: str) -> List[str]:
    """
    Process archive files (tar.gz, zip) to extract domains.
    
    Args:
        content (bytes): Raw archive content
        url (str): Source URL for determining archive type
        
    Returns:
        List[str]: List of processed domain strings
    """
    domains = []
    
    try:
        import io
        import tarfile
        import zipfile
        import tempfile
        
        content_stream = io.BytesIO(content)
        
        # Determine archive type from URL
        if url.endswith('.tar.gz') or url.endswith('.tgz'):
            with tarfile.open(fileobj=content_stream, mode='r:gz') as tar:
                # File count for progress indicator
                file_count = 0
                for member in tar.getmembers():
                    file_count += 1
                
                # Process only a few files, not all of them
                processed_files = 0
                for member in tar.getmembers():
                    if not member.isfile() or member.size > 10 * 1024 * 1024:  # Skip files larger than 10MB
                        continue
                        
                    # Extract and process file content
                    extracted = tar.extractfile(member)
                    if extracted:
                        content = extracted.read().decode('utf-8', errors='ignore')
                        
                        # Process line by line to find domains
                        for line in content.splitlines():
                            line = line.strip()
                            if line and not line.startswith('#'):
                                domain = extract_domain_from_url(line) or line
                                if domain and is_valid_domain(domain):
                                    domains.append(domain)
                        
                    processed_files += 1
                    if processed_files >= 100:  # Process max 100 files
                        break
                
                print(f"\r\t{Fore.GREEN}✓ Archive processing complete. Found {len(domains)} domains.{Style.RESET_ALL}", flush=True)
                
        elif url.endswith('.zip'):
            with zipfile.ZipFile(content_stream) as zip_file:
                # İlerleme göstergesi için dosya sayısı
                info_list = zip_file.infolist()
                print(f"\r\t{Fore.YELLOW}✓ Extracting {len(info_list)} files from archive...{Style.RESET_ALL}", flush=True)
                
                # En fazla birkaç dosyayı işle, tümünü işleme
                processed_files = 0
                for info in info_list:
                    if info.is_dir() or info.file_size > 10 * 1024 * 1024:  # 10MB'den büyük dosyaları atla
                        continue
                        
                    with zip_file.open(info) as f:
                        content_str = f.read().decode('utf-8', errors='ignore')
                        # Satır satır işleyerek domain ara
                        for line in content_str.split('\n'):
                            line = line.strip()
                            if line and not line.startswith('#') and '.' in line:
                                domains.append(line)
                        
                        processed_files += 1
                        if processed_files % 10 == 0:
                            print(f"\r\t{Fore.YELLOW}✓ Processed {processed_files}/{len(info_list)} files, found {len(domains)} domains...{Style.RESET_ALL}", end='', flush=True)
                        
                        # Max 100 dosya işle
                        if processed_files >= 100:
                            break
                
                print(f"\r\t{Fore.GREEN}✓ Archive processing complete. Found {len(domains)} domains.{Style.RESET_ALL}", flush=True)
    
    except Exception as e:
        logging.warning(f"Archive format parsing warning: {str(e)}")
    
    return domains

def fetch_domain_list(source_name: str, source_info: Dict[str, Any]) -> Tuple[Dict[str, List[str]], int]:
    """
    Fetches domain list from a single source with improved reliability.
    
    Args:
        source_name (str): Name of the intelligence source
        source_info (Dict[str, Any]): Source metadata including URL and format
        
    Returns:
        Tuple[Dict[str, List[str]], int]: Tuple containing domains dictionary and count
    """
    domains: Dict[str, List[str]] = {}
    domain_count = 0
    comment_count = 0  # Track how many entries had comments
    
    if not source_info.get("enabled", True):
        notes = source_info.get("notes", "")
        note_text = f" ({notes})" if notes else ""
        print(f"{source_name:<15} {Fore.YELLOW}⊘ Disabled{note_text}{Style.RESET_ALL}")
        return domains, domain_count
        
    url = source_info.get("url", "")
    data_format = source_info.get("format", "url")
    use_special_handler = source_info.get("use_special_handler", False)
    
    try:
        # Display source name only without spinner
        print(f"{source_name:<15}", end='', flush=True)
        
        # Create a session with retry logic
        session = create_resilient_session()
        
        # Handle URLScan specially to avoid rate limiting
        if use_special_handler and source_name == "URLScan":
            content = fetch_urlscan_data(url, session)
        elif data_format == "archive":
            # Binary mode for archives
            response = session.get(url, stream=True, verify=False)
            response.raise_for_status()
            content = response.content  # Binary mode
        else:
            # Normal text mode download
            response = session.get(url, stream=True, verify=False)
            response.raise_for_status()
            content = response.text
        
        # Process based on format
        raw_domains = []
        if data_format == "url":
            raw_domains = process_url_format(content)
        elif data_format == "domain":
            raw_domains = process_domain_format(content)
        elif data_format == "hostfile":
            raw_domains = process_hostfile_format(content)
        elif data_format == "special":
            raw_domains = process_special_format(content)
        elif data_format == "blocklist":
            raw_domains = process_blocklist_format(content)
        elif data_format == "urlscan":
            raw_domains = process_urlscan_format(content)
        elif data_format == "phishstats":
            raw_domains = process_phishstats_format(content)
        elif data_format == "csv":
            raw_domains = process_csv_format(content)
        elif data_format == "archive":
            raw_domains = process_archive_format(content, url)
            
        # Extract domains from URLs or process raw domains
        processed_count = 0
        for item in raw_domains:
            if item:
                # Check if this item had a comment that was cleaned
                if '#' in item:
                    comment_count += 1
                    item = clean_domain_entry(item)  # Clean again just to be sure
                
                if data_format == "url":
                    domain = extract_domain_from_url(item)
                else:
                    domain = item.lower()
                
                if domain:
                    if domain not in domains:
                        domains[domain] = []
                    domains[domain].append(source_name)
                    domain_count += 1
        
        # Display completion with domain count and comment info
        comment_info = f" (cleaned {comment_count} comments)" if comment_count > 0 else ""
        print(f"{Fore.GREEN}✓ {domain_count} domains{comment_info}{Style.RESET_ALL}")
            
    except requests.exceptions.HTTPError as e:
        print(f"{Fore.RED}✗ HTTP Error: {e.response.status_code}{Style.RESET_ALL}")
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}✗ Request Timeout{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}✗ {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}✗ {str(e)}{Style.RESET_ALL}")
    
    return domains, domain_count

def merge_domain_lists(domain_lists: List[Dict[str, List[str]]]) -> Dict[str, List[str]]:
    """
    Merges multiple domain lists into a single dictionary.
    
    Args:
        domain_lists (List[Dict[str, List[str]]]): List of domain dictionaries to merge
        
    Returns:
        Dict[str, List[str]]: Merged domain dictionary
    """
    merged_domains: Dict[str, List[str]] = {}
    
    for domain_list in domain_lists:
        for domain, sources in domain_list.items():
            if domain not in merged_domains:
                merged_domains[domain] = []
            merged_domains[domain].extend(sources)
            merged_domains[domain] = list(set(merged_domains[domain]))
    
    return merged_domains

def save_filtered_domains(filtered_domains: Dict[str, List[str]], timestamp: str) -> str:
    """
    Saves filtered domains and their reasons to a CSV file.
    
    Args:
        filtered_domains (Dict[str, List[str]]): Dictionary of filtered domains and their sources
        timestamp (str): Timestamp for the filename
        
    Returns:
        str: Path to the created CSV file
    """
    results_dir = "test-results/filtered-domains"
    os.makedirs(results_dir, exist_ok=True)
    
    output_file = f'{results_dir}/filtered_domains_{timestamp}.csv'
    
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['Domain', 'Filter Reason', 'Sources', 'Timestamp']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for domain, sources in filtered_domains.items():
            filter_reason = get_filter_reason(domain)
            writer.writerow({
                'Domain': domain,
                'Filter Reason': filter_reason,
                'Sources': ', '.join(sources),
                'Timestamp': timestamp
            })
    
    return output_file

def fetch_malicious_domains(terminal_width: int) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    """
    Fetches malicious domains from various threat intelligence sources.
    
    Args:
        terminal_width (int): Width of the terminal for formatting
        
    Returns:
        Tuple[Dict[str, List[str]], Dict[str, List[str]]]: Tuple containing valid domains and filtered domains
    """
    print(f"\n{Fore.YELLOW}Collecting Malicious Domain Lists:{Style.RESET_ALL}\n")
    
    intelligence_sources = get_intelligence_sources()
    
    # Get only active sources
    active_sources = {name: info for name, info in intelligence_sources.items() 
                     if info.get("enabled", True)}
    
    # Show user which sources will be used
    source_count = len(active_sources)
    
    print(f"{Fore.CYAN}Total {source_count} active sources detected{Style.RESET_ALL}")
    print(f"{'-' * terminal_width}")
    print(f"{'Source':<15} | {'Type':<10} | {'Description':<50}")
    print(f"{'-' * terminal_width}")
    
    # Only show active sources
    for source_name, source_info in active_sources.items():
        print(f"{source_name:<15} | {source_info.get('format', 'url'):<10} | {source_info.get('description', ''):<50}")
    
    print(f"{'-' * terminal_width}\n")
    
    # Progress message
    print(f"{Fore.CYAN}Starting data collection from {source_count} active sources...{Style.RESET_ALL}\n")
    
    domain_lists = []
    total_domains_before_dedup = 0
    
    # Collect domains from each source
    for source_name, source_info in active_sources.items():
        domains, count = fetch_domain_list(source_name, source_info)
        domain_lists.append(domains)
        total_domains_before_dedup += count
    
    print(f"\n{Fore.CYAN}Collection completed: {total_domains_before_dedup} total domains from {source_count} sources{Style.RESET_ALL}")
    
    # Merge all domain lists
    all_domains = merge_domain_lists(domain_lists)
    
    # Separate valid and filtered domains
    valid_domains = {}
    filtered_domains = {}
    
    for domain, sources in all_domains.items():
        if is_valid_domain(domain):
            valid_domains[domain] = sources
        else:
            filtered_domains[domain] = sources
    
    total_domains_after_dedup = len(valid_domains) + len(filtered_domains)
    duplicate_count = total_domains_before_dedup - total_domains_after_dedup
    
    print(f"\n{Fore.YELLOW}Domain Analysis:{Style.RESET_ALL}")
    print(f"{'-' * terminal_width}")
    print(f"{'Metric':<40} | {'Count':>10}")
    print(f"{'-' * terminal_width}")
    print(f"{'Total Domains (Including Duplicates)':<40} | {total_domains_before_dedup:>10}")
    print(f"{'Duplicate Domains':<40} | {Fore.RED}{duplicate_count:>10}{Style.RESET_ALL}")
    print(f"{'Valid Domains':<40} | {Fore.GREEN}{len(valid_domains):>10}{Style.RESET_ALL}")
    print(f"{'Filtered Domains':<40} | {len(filtered_domains):>10}")
    print(f"{'-' * terminal_width}")
    
    # Print filter reasons statistics
    filter_reasons = {}
    for domain in filtered_domains:
        reason = get_filter_reason(domain)
        if reason not in filter_reasons:
            filter_reasons[reason] = 0
        filter_reasons[reason] += 1
    
    if filter_reasons:
        print(f"\n{Fore.YELLOW}Filter Reasons:{Style.RESET_ALL}")
        print(f"{'-' * terminal_width}")
        print(f"{'Reason':<40} | {'Count':>10}")
        print(f"{'-' * terminal_width}")
        for reason, count in filter_reasons.items():
            print(f"{reason:<40} | {count:>10}")
        print(f"{'-' * terminal_width}")
    
    if not valid_domains:
        logging.error("No valid domains found. Terminating execution.")
        print(f"\n{Fore.RED}No valid domains found! Please check your internet connection and source URLs.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Domain counts by source
    print(f"\n{Fore.YELLOW}Domain Counts by Source:{Style.RESET_ALL}")
    print(f"{'-' * terminal_width}")
    print(f"{'Source':<20} | {'Valid':<10} | {'Filtered':<10} | {'Total':>10}")
    print(f"{'-' * terminal_width}")
    
    source_stats = {}
    for domain, sources in valid_domains.items():
        for source in sources:
            if source not in source_stats:
                source_stats[source] = {"valid": 0, "filtered": 0}
            source_stats[source]["valid"] += 1
            
    for domain, sources in filtered_domains.items():
        for source in sources:
            if source not in source_stats:
                source_stats[source] = {"valid": 0, "filtered": 0}
            source_stats[source]["filtered"] += 1
    
    for source, stats in sorted(source_stats.items()):
        total = stats["valid"] + stats["filtered"]
        print(f"{source:<20} | {stats['valid']:<10} | {stats['filtered']:<10} | {total:>10}")
    
    print(f"{'-' * terminal_width}")
    
    logging.info(f"Starting analysis with {len(valid_domains)} domains.")
    return valid_domains, filtered_domains 