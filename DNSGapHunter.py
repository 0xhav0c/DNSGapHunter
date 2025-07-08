import csv
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import time
import datetime
from colorama import Fore, Style, init
import requests
import json
from typing import List, Set, Optional, Dict, Tuple, Any
from tqdm import tqdm
import ipaddress
from urllib.parse import urlparse
import re
import urllib3
import signal
import sys
import os
import io

# Import modules from project files
from domain_utils import is_valid_ip, extract_domain_from_url, is_valid_domain, get_filter_reason, debug_domain_validation
from dns_checker import check_dns, get_security_configuration, resolve_domain
from data_collector import get_intelligence_sources, fetch_domain_list, merge_domain_lists, save_filtered_domains, fetch_malicious_domains
from reporting import format_duration, generate_html_report
from ui_utils import show_banner
from config import MAX_DOMAINS, MAX_WORKERS, REPORT_DIR, DNSFW_REPORT_SUBDIR, SINKHOLE_REPORT_SUBDIR

class DNSGapHunter:
    def __init__(self):
        self.is_running = True
        self.results = []
        self.no_dns_records = []
        self.total_domains = 0
        self.completed_domains = 0
        self.terminal_width = 100
        
        # Try to get terminal size
        try:
            self.terminal_width = os.get_terminal_size().columns
        except:
            self.terminal_width = 100  # Default width if terminal size cannot be determined
        
    def signal_handler(self, sig, frame):
        """
        Handles Ctrl+C signal and safely terminates the script.
        """
        print(f"\n\n{Fore.RED}Terminating script...{Style.RESET_ALL}")
        
        # Set flag to stop processing
        self.is_running = False
        
        try:
            # Save current results
            if self.results or self.no_dns_records:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
                
                # Save successful results
                if self.results:
                    output_file = f'dnsfw_results_{timestamp}.csv'
                    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                        fieldnames = ['Domain', 'Status', 'Security Status', 'IP', 'Sources']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        
                        for domain, status, security_status, resolved_ip, sources in self.results:
                            writer.writerow({
                                'Domain': domain,
                                'Status': status,
                                'Security Status': security_status,
                                'IP': resolved_ip,
                                'Sources': ', '.join(sources)
                            })
                    print(f"{Fore.GREEN}Current analysis results saved: {output_file}{Style.RESET_ALL}")
                
                # Save results with no DNS records
                if self.no_dns_records:
                    no_dns_file = f'dnsfw_no_records_{timestamp}.csv'
                    with open(no_dns_file, 'w', newline='', encoding='utf-8') as csvfile:
                        fieldnames = ['Domain', 'Status', 'Security Status', 'IP', 'Sources']
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        
                        for domain, status, security_status, resolved_ip, sources in self.no_dns_records:
                            writer.writerow({
                                'Domain': domain,
                                'Status': status,
                                'Security Status': security_status,
                                'IP': resolved_ip,
                                'Sources': ', '.join(sources)
                            })
                    print(f"{Fore.RED}Current results with no DNS records saved: {no_dns_file}{Style.RESET_ALL}")
            
            # Show statistics
            print(f"\n{Fore.YELLOW}Process Status:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Completed Domains:{Style.RESET_ALL} {self.completed_domains}/{self.total_domains}")
            print(f"{Fore.CYAN}Progress:{Style.RESET_ALL} %{(self.completed_domains/self.total_domains)*100:.2f}")
            
            # Use sys.exit instead of os._exit for cleaner termination
            sys.exit(0)
        except Exception as e:
            print(f"{Fore.RED}Error while terminating: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)
    
    def limit_domains(self, domains: Dict[str, List[str]], limit: int = MAX_DOMAINS) -> Dict[str, List[str]]:
        """
        Limits the domain list to analyze a limited number of domains.
        
        Args:
            domains (Dict[str, List[str]]): Dictionary of domains to analyze
            limit (int): Maximum number of domains (default from config)
            
        Returns:
            Dict[str, List[str]]: Limited domain dictionary
        """
        if len(domains) <= limit:
            return domains
        
        limited_domains = {}
        count = 0
        
        for domain, sources in domains.items():
            limited_domains[domain] = sources
            count += 1
            if count >= limit:
                break
        
        print(f"\n{Fore.YELLOW}Warning: Domain list limited to {limit} entries. Total {len(domains)} domains found.{Style.RESET_ALL}")
        return limited_domains
        
    def run(self):
        # Show banner
        show_banner()
        
        # Register signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        
        title = ' DNS SECURITY ANALYSIS TOOL '
        print(f"\n{'█' * ((self.terminal_width - len(title)) // 2)}{title}{'█' * ((self.terminal_width - len(title)) // 2)}")
        
        title = ' SECURITY CONFIGURATION '
        print(f"\n{'█' * ((self.terminal_width - len(title)) // 2)}{title}{'█' * ((self.terminal_width - len(title)) // 2)}")
        security_ips, test_type = get_security_configuration()
        
        title = ' MALICIOUS DOMAIN COLLECTION '
        print(f"\n{'█' * ((self.terminal_width - len(title)) // 2)}{title}{'█' * ((self.terminal_width - len(title)) // 2)}")
        valid_domains, filtered_domains = fetch_malicious_domains(self.terminal_width)
        
        # Limit domains to MAX_DOMAINS (from config)
        valid_domains = self.limit_domains(valid_domains, MAX_DOMAINS)
        
        # Save filtered domains
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
        filtered_domains_file = save_filtered_domains(filtered_domains, timestamp)
        
        self.results = []
        self.no_dns_records = []
        
        security_bypassed_count = 0
        security_blocked_count = 0
        
        security_block_counts = {ip: 0 for ip in security_ips}
        
        self.total_domains = len(valid_domains)
        self.completed_domains = 0
        
        start_time = time.time()
        
        title = ' DNS QUERY AND ANALYSIS '
        print(f"\n{'█' * ((self.terminal_width - len(title)) // 2)}{title}{'█' * ((self.terminal_width - len(title)) // 2)}")
        print("\n\n")  # Two line breaks added
        
        # Square progress bar characters
        square_chars = "□▣▤▥▦▧▨▩■"
        
        pbar = tqdm(total=self.total_domains, desc="DNS Queries", 
                    bar_format='{l_bar}█{bar}█ {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]',
                    ascii=square_chars)
        
        stats_pbar = tqdm(total=0, desc="Blocking Statistics", 
                         bar_format='{desc}: {postfix}', position=1, leave=True)
        
        # Use MAX_WORKERS from config
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(check_dns, domain, security_ips, test_type): domain 
                      for domain in valid_domains.keys()}
            
            for future in as_completed(futures):
                if not self.is_running:
                    break
                    
                domain = futures[future]
                try:
                    result = future.result()
                    domain, status, security_status, resolved_ip = result
                    
                    sources = valid_domains[domain]
                    
                    if status in ['no_dns_record', 'no_nameserver', 'timeout']:
                        self.no_dns_records.append((domain, status, security_status, resolved_ip, sources))
                    else:
                        self.results.append((domain, status, security_status, resolved_ip, sources))
                        if security_status == 'DNSFW Bypassed' or security_status == 'Sinkhole Bypassed':
                            security_bypassed_count += 1
                        elif security_status == 'DNSFW Blocked' or security_status == 'Sinkhole Address Blocked':
                            security_blocked_count += 1
                            if resolved_ip in security_block_counts:
                                security_block_counts[resolved_ip] += 1
                        
                    self.completed_domains += 1
                    
                    current_time = time.time()
                    elapsed_time = current_time - start_time
                    domains_per_second = self.completed_domains / elapsed_time
                    estimated_remaining = (self.total_domains - self.completed_domains) / domains_per_second
                    
                    postfix = f'| Valid: {len(self.results)} | {Fore.RED}Bypassed{Style.RESET_ALL}: {security_bypassed_count} | {Fore.GREEN}Blocked{Style.RESET_ALL}: {security_blocked_count} | {Fore.YELLOW}No DNS{Style.RESET_ALL}: {len(self.no_dns_records)}'
                    pbar.set_postfix_str(postfix)
                    pbar.update(1)
                    
                    block_stats = []
                    sorted_blocks = sorted(security_block_counts.items(), key=lambda x: x[1], reverse=True)
                    for ip, count in sorted_blocks:
                        if count > 0:
                            block_stats.append(f"{ip}:{count}")
                    
                    stats_postfix = f"{' '.join(block_stats)}" if block_stats else "No blocking yet"
                    stats_pbar.set_postfix_str(stats_postfix)
                    
                except Exception as exc:
                    logging.error(f'%{(self.completed_domains / self.total_domains) * 100:.2f} | Error querying {domain}: {exc}')
                    self.no_dns_records.append((domain, 'error', f'Unexpected error: {str(exc)}', None, valid_domains[domain]))
                    pbar.update(1)
        
        pbar.close()
        stats_pbar.close()
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
        
        if test_type == "sinkhole":
            results_dir = f"{REPORT_DIR}/{SINKHOLE_REPORT_SUBDIR}"
        else:
            results_dir = f"{REPORT_DIR}/{DNSFW_REPORT_SUBDIR}"
        
        os.makedirs(results_dir, exist_ok=True)
        
        output_file = f'{results_dir}/dnsfw_results_{timestamp}.csv'
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Domain', 'Status', 'Security Status', 'IP', 'Sources']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for domain, status, security_status, resolved_ip, sources in self.results:
                writer.writerow({
                    'Domain': domain,
                    'Status': status,
                    'Security Status': security_status,
                    'IP': resolved_ip,
                    'Sources': ', '.join(sources)
                })
        
        no_dns_file = f'{results_dir}/dnsfw_no_records_{timestamp}.csv'
        with open(no_dns_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Domain', 'Status', 'Security Status', 'IP', 'Sources']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for domain, status, security_status, resolved_ip, sources in self.no_dns_records:
                writer.writerow({
                    'Domain': domain,
                    'Status': status,
                    'Security Status': security_status,
                    'IP': resolved_ip,
                    'Sources': ', '.join(sources)
                })
        
        html_report_path = generate_html_report(self.results, self.no_dns_records, security_bypassed_count, security_blocked_count, security_block_counts, test_type, timestamp)
        
        title = ' ANALYSIS RESULTS '
        print(f"\n{'█' * ((self.terminal_width - len(title)) // 2)}{title}{'█' * ((self.terminal_width - len(title)) // 2)}")
        print("\n\n")  # Two line breaks added
        print(f"{'File Type':<40} | {'Path':<60}")
        print(f"{'-' * self.terminal_width}")
        print(f"{'Analysis Results':<40} | {output_file:<60}")
        print(f"{'Domains with no DNS records':<40} | {no_dns_file:<60}")
        print(f"{'Filtered Domains':<40} | {filtered_domains_file:<60}")
        print(f"{'HTML Report':<40} | {html_report_path:<60}")
        print(f"{'-' * self.terminal_width}")
        
        title = ' SUMMARY STATISTICS '
        print(f"\n{'█' * ((self.terminal_width - len(title)) // 2)}{title}{'█' * ((self.terminal_width - len(title)) // 2)}")
        print("\n\n")  # Two line breaks added
        print(f"{'Metric':<40} | {'Count':>10}")
        print(f"{'-' * self.terminal_width}")
        print(f"{'Total domains':<40} | {len(valid_domains):>10}")
        print(f"{'Valid domains':<40} | {len(self.results):>10}")
        print(f"{'Bypassed':<40} | {security_bypassed_count:>10}")
        print(f"{'Blocked':<40} | {security_blocked_count:>10}")
        print(f"{'Domains with no DNS records':<40} | {len(self.no_dns_records):>10}")
        print(f"{'-' * self.terminal_width}")
        
        title = ' SECURITY IP BLOCKING STATISTICS '
        print(f"\n{'█' * ((self.terminal_width - len(title)) // 2)}{title}{'█' * ((self.terminal_width - len(title)) // 2)}")
        print("\n\n")  # Two line breaks added
        print(f"{'IP Address':<20} | {'Blocked Count':>15}")
        print(f"{'-' * self.terminal_width}")
        sorted_blocks = sorted(security_block_counts.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_blocks:
            if count > 0:
                print(f"{ip:<20} | {count:>15}")
        print(f"{'-' * self.terminal_width}")
        
        title = ' ANALYSIS COMPLETED '
        print(f"\n{'█' * ((self.terminal_width - len(title)) // 2)}{title}{'█' * ((self.terminal_width - len(title)) // 2)}\n")

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
    
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
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

def main():
    # Suppress SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Initialize colorama
    init(autoreset=True)
    
    # Configure logging - improved with DEBUG level
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    
    # Check for debug mode
    debug_mode = '--debug' in sys.argv
    debug_validation = '--debug-validation' in sys.argv
    
    if debug_mode:
        logging.basicConfig(level=logging.DEBUG, format=log_format)
        print(f"{Fore.YELLOW}Debug mode enabled - detailed logs will be shown{Style.RESET_ALL}")
    elif debug_validation:
        # Set up logging to file for validation debugging
        logging.basicConfig(
            level=logging.DEBUG,
            format=log_format,
            filename='domain_validation_debug.log',
            filemode='w'
        )
        # Also print to console
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        logging.getLogger().addHandler(console)
        print(f"{Fore.YELLOW}Domain validation debugging enabled - detailed logs will be saved to domain_validation_debug.log{Style.RESET_ALL}")
    else:
        logging.basicConfig(level=logging.INFO, format=log_format)
    
    # Display AbuseIPDB removal info - only show once during program startup
    logging.info(f"{Fore.CYAN}Info: AbuseIPDB source has been removed from intelligence sources{Style.RESET_ALL}")
    
    # Process test domain if provided
    if '--test-domain' in sys.argv:
        try:
            idx = sys.argv.index('--test-domain')
            if idx + 1 < len(sys.argv):
                test_domain = sys.argv[idx + 1]
                result = debug_domain_validation(test_domain)
                print(f"\n{Fore.CYAN}Domain validation debug for: {test_domain}{Style.RESET_ALL}")
                for key, value in result.items():
                    print(f"{key:<15}: {value}")
                sys.exit(0)
        except Exception as e:
            print(f"{Fore.RED}Error testing domain: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)
    
    # Create and run DNSGapHunter
    hunter = DNSGapHunter()
    hunter.run()

if __name__ == "__main__":
    main()
