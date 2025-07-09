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

from domain_utils import extract_domain_from_url, is_valid_domain, get_filter_reason, is_valid_ip, clean_domain
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
        cleaned_line = clean_domain(line)
        if not cleaned_line:
            continue
        
        # Is it in URL format?
        if cleaned_line.startswith('http://') or cleaned_line.startswith('https://'):
            domain = extract_domain_from_url(cleaned_line)
            if domain and is_valid_domain(domain):
                domains.append(domain)
        else:
            # Common format variations have been handled by clean_domain
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
        domain = clean_domain(line)
        
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
            
        # Split line into parts (IP and domain)
        parts = line.strip().split()
        
        # Get domain part (last part after IP)
        if len(parts) >= 2:
            # Get the last part as domain
            domain = parts[-1].strip()
            
            # Clean the domain
            domain = clean_domain(domain)
            
            # Add if not empty and valid
            if domain:
                domains.append(domain)
            
    return domains

def process_csv_format(content: str) -> List[str]:
    """
    Process data in CSV format.
    
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
                # File count for progress indicator
                info_list = zip_file.infolist()
                print(f"\r\t{Fore.YELLOW}✓ Extracting {len(info_list)} files from archive...{Style.RESET_ALL}", flush=True)
                
                # Process only a few files, not all of them
                processed_files = 0
                for info in info_list:
                    if info.is_dir() or info.file_size > 10 * 1024 * 1024:  # Skip files larger than 10MB
                        continue
                        
                    # Process domains line by line
                    with zip_file.open(info) as f:
                        for line in f:
                            domain = extract_domain_from_url(line.strip().decode('utf-8', errors='ignore'))
                            if domain:
                                domains.append(domain)
                                
                    processed_files += 1
                    if processed_files % 10 == 0:
                        print(f"\r\t{Fore.YELLOW}✓ Processed {processed_files}/{len(info_list)} files, found {len(domains)} domains...{Style.RESET_ALL}", end='', flush=True)
                        
                    # Process max 100 files
                    if processed_files >= 100:
                        break
                
                print(f"\r\t{Fore.GREEN}✓ Archive processing complete. Found {len(domains)} domains.{Style.RESET_ALL}", flush=True)
    
    except Exception as e:
        logging.warning(f"Archive format parsing warning: {str(e)}")
    
    return domains

def fetch_domain_list(source_name: str, source_info: Dict[str, Any]) -> Tuple[Dict[str, List[str]], int]:
    """
    Fetches domain list from a specific source.
    
    Args:
        source_name (str): Name of the source
        source_info (Dict[str, Any]): Source metadata
        
    Returns:
        Tuple[Dict[str, List[str]], int]: Dictionary mapping domains to their sources and count of domains
    """
    url = source_info.get("url", "")
    data_format = source_info.get("format", "")
    use_special_handler = source_info.get("use_special_handler", False)
    
    if not url or not data_format:
        return {}, 0
    
    session = create_resilient_session()
    raw_domains = []
    
    try:
        # Handle URLScan specially to avoid rate limiting
        if use_special_handler and source_name == "URLScan":
            print(f"{Fore.YELLOW}⊘ URLScan disabled{Style.RESET_ALL}")
            pass # Removed URLScan specific handling
        elif data_format == "archive":
            # Binary mode for archives
            response = session.get(url, stream=True)
            response.raise_for_status()
            raw_domains = process_archive_format(response.content, url)
        else:
            # Text mode for other formats
            response = session.get(url)
            response.raise_for_status()
            content = response.text
            
            # Process according to format
            if data_format == "url":
                raw_domains = process_url_format(content)
            elif data_format == "domain":
                raw_domains = process_domain_format(content)
            elif data_format == "hostfile":
                raw_domains = process_hostfile_format(content)
            elif data_format == "csv":
                raw_domains = process_csv_format(content)
            else:
                logging.error(f"Unknown format: {data_format}")
                return {}, 0
                
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching {source_name}: {str(e)}")
        return {}, 0
    except Exception as e:
        logging.error(f"Unexpected error processing {source_name}: {str(e)}")
        return {}, 0
        
    # Process domains and track sources
    domain_sources = {}
    for domain in raw_domains:
        if domain not in domain_sources:
            domain_sources[domain] = []
        domain_sources[domain].append(source_name)
    
    return domain_sources, len(raw_domains)

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
    intelligence_sources = get_intelligence_sources()
    
    # Get only active sources
    active_sources = {name: info for name, info in intelligence_sources.items() 
                     if info.get("enabled", True)}
    
    # Show user which sources will be used
    source_count = len(active_sources)
    
    logging.info(f"{Fore.CYAN}[PHASE] DATA COLLECTION{Style.RESET_ALL}")
    logging.info(f"Starting data collection from {source_count} active sources")
    
    domain_lists = []
    total_domains_before_dedup = 0
    
    # Collect domains from each source
    for source_name, source_info in active_sources.items():
        domains, count = fetch_domain_list(source_name, source_info)
        domain_lists.append(domains)
        total_domains_before_dedup += count
        logging.info(f"Collected {count} domains from {source_name} ({source_info.get('description', '')})")
    
    logging.info(f"Collection completed: {total_domains_before_dedup} total domains from {source_count} sources")
    
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
    
    logging.info(f"{Fore.CYAN}[PHASE] DOMAIN ANALYSIS{Style.RESET_ALL}")
    logging.info(f"Total Domains (Including Duplicates): {total_domains_before_dedup}")
    logging.info(f"Duplicate Domains: {duplicate_count}")
    logging.info(f"Valid Domains: {len(valid_domains) + len(filtered_domains)}")
    
    # Calculate and log filter reasons
    filter_reasons = {}
    for domain in filtered_domains:
        reason = get_filter_reason(domain)
        if reason not in filter_reasons:
            filter_reasons[reason] = 0
        filter_reasons[reason] += 1
    
    logging.info(f"{Fore.CYAN}[PHASE] FILTERING STATISTICS{Style.RESET_ALL}")
    # Print filter reasons as logs
    if filter_reasons:
        for reason, count in filter_reasons.items():
            logging.info(f"Filter Reason - {reason}: {count} domains")
    
    if not valid_domains:
        logging.error("No valid domains found. Terminating execution.")
        print(f"\n{Fore.RED}No valid domains found! Please check your internet connection and source URLs.{Style.RESET_ALL}")
        sys.exit(1)
    
    logging.info(f"{Fore.CYAN}[PHASE] SOURCE STATISTICS{Style.RESET_ALL}")
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
        logging.info(f"Source {source}: Valid={stats['valid']}, Filtered={stats['filtered']}, Total={total}")
    
    logging.info(f"{Fore.CYAN}[PHASE] STARTING ANALYSIS{Style.RESET_ALL}")
    logging.info(f"Starting analysis with {len(valid_domains)} domains.")
    return valid_domains, filtered_domains 