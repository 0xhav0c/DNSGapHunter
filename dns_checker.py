import dns.resolver
import logging
import requests
from typing import List, Tuple, Optional
from colorama import Fore, Style

from domain_utils import is_valid_ip
from config import DNS_TIMEOUT, DNS_RETRY_COUNT, SINKHOLE_IPS

def check_dns(domain: str, security_ips: List[str], test_type: str = "dnsfw") -> Tuple[str, str, str, Optional[str]]:
    """
    Performs DNS resolution and security checks for a domain.
    
    Args:
        domain (str): Domain to check
        security_ips (List[str]): List of security appliance IPs/domains
        test_type (str): Type of security test ("dnsfw" or "sinkhole")
        
    Returns:
        Tuple[str, str, str, Optional[str]]: Domain, status, security status, and resolved IP/domain
    """
    original_domain = domain
    
    if not domain.endswith('.'):
        query_domain = domain
    else:
        query_domain = domain
        domain = domain[:-1]
        
    # Initialize resolver with timeout
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    
    # Try to resolve domain
    resolved_ip = None
    status = "valid"
    security_status = "DNSFW Bypassed" if test_type == "dnsfw" else "Sinkhole Bypassed"
    
    for attempt in range(DNS_RETRY_COUNT + 1):
        try:
            # Try A record first
            answers = resolver.resolve(query_domain, 'A')
            
            # Get first IP from answers
            for answer in answers:
                resolved_ip = answer.address
                
                # Check if resolved IP is a terminated domain IP
                if resolved_ip in ['0.0.0.0', '127.0.0.1', '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4']:
                    status = 'valid'
                    security_status = 'Post-Attack Terminated Domain'
                    return domain, status, security_status, resolved_ip
                
                # Check if resolved IP is in security IPs
                if test_type == "dnsfw":
                    if resolved_ip in security_ips:
                        security_status = "DNSFW Blocked"
                else:  # sinkhole
                    if resolved_ip in SINKHOLE_IPS:
                        security_status = "Sinkhole Address Blocked"
                break
                
            break  # If we get here, resolution succeeded
            
        except dns.resolver.NXDOMAIN:
            status = "no_dns_record"
            security_status = "No DNS Record"
            break
        except dns.resolver.NoAnswer:
            # Try CNAME if A record fails
            try:
                cname_answers = resolver.resolve(query_domain, 'CNAME')
                resolved_ip = str(cname_answers[0].target).rstrip('.')
                break
            except:
                status = "no_dns_record"
                security_status = "No DNS Record"
                break
        except dns.resolver.NoNameservers:
            if attempt < DNS_RETRY_COUNT:
                continue
            status = "no_nameserver"
            security_status = "No DNS Record"
            break
        except dns.resolver.Timeout:
            if attempt < DNS_RETRY_COUNT:
                continue
            status = "timeout"
            security_status = "No DNS Record"
            break
        except Exception as e:
            if attempt < DNS_RETRY_COUNT:
                continue
            logging.error(f"Unexpected error resolving {domain}: {str(e)}")
            status = "error"
            security_status = "Error"
            break
            
    return domain, status, security_status, resolved_ip

def get_security_configuration() -> Tuple[List[str], str]:
    """
    Gets security appliance configuration from user.
    
    Returns:
        Tuple[List[str], str]: List of security IPs/domains and test type
    """
    while True:
        print("\nSelect security configuration type:")
        print("1. DNS Firewall (Infoblox Threat Defense)")
        print("2. DNS Firewall (Manual IP entry)")
        print("3. DNS Firewall (IP list file)")
        print("4. Sinkhole DNS Security")
        
        choice = input("\nEnter choice (1-4): ").strip()
        
        if choice not in ["1", "2", "3", "4"]:
            print(f"{Fore.RED}Invalid choice. Please enter 1-4.{Style.RESET_ALL}")
            continue
            
        if choice == "1":
            try:
                url = "https://infoblox-whitelist.s3.amazonaws.com/infoblox-ip-whitelist.json"
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                
                data = response.json()
                security_ips = data.get("IP", [])
                security_ips.extend(data.get("IPv6", []))
                
                if not security_ips:
                    print(f"Empty DNSFW IP list received. Please try another option.")
                    continue
                    
                color = Fore.GREEN if len(security_ips) > 0 else Fore.RED
                print(f"Successfully retrieved DNSFW IP list. Total {color}{len(security_ips)}{Style.RESET_ALL} IPs.")
                return security_ips, "dnsfw"
                
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}Error: Failed to fetch IP list. Please try another option.{Style.RESET_ALL}")
                continue
                
        elif choice == "2":
            print("\nEnter DNS Firewall IP addresses (one per line, empty line to finish):")
            security_ips = []
            
            while True:
                ip = input().strip()
                if not ip:
                    break
                    
                if is_valid_ip(ip):
                    security_ips.append(ip)
                else:
                    print(f"{Fore.RED}Invalid IP address: {ip}{Style.RESET_ALL}")
                    
            if not security_ips:
                print(f"{Fore.RED}No valid IPs entered. Please try again.{Style.RESET_ALL}")
                continue
                
            print(f"\nConfigured {Fore.GREEN}{len(security_ips)}{Style.RESET_ALL} DNS Firewall IPs")
            return security_ips, "dnsfw"
            
        elif choice == "3":
            file_path = input("\nEnter path to IP list file: ").strip()
            
            try:
                with open(file_path, 'r') as f:
                    security_ips = []
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith('#') and is_valid_ip(ip):
                            security_ips.append(ip)
                            
                if not security_ips:
                    print(f"{Fore.RED}No valid IPs found in file. Please try again.{Style.RESET_ALL}")
                    continue
                    
                print(f"\nLoaded {Fore.GREEN}{len(security_ips)}{Style.RESET_ALL} DNS Firewall IPs from file")
                return security_ips, "dnsfw"
                
            except Exception as e:
                print(f"{Fore.RED}Error reading file: {str(e)}{Style.RESET_ALL}")
                continue
                
        else:  # choice == "4"
            print("\nSelect sinkhole configuration:")
            print("1. Palo Alto Networks (default: sinkhole.paloaltonetworks.com)")
            print("2. Cisco Umbrella (default: hit-nxdomain.opendns.com)")
            print("3. Fortinet (default: block.fortinet.com)")
            print("4. Custom sinkhole domain")
            
            sinkhole_choice = input("\nEnter choice (1-4): ").strip()
            
            if sinkhole_choice == "1":
                return ["sinkhole.paloaltonetworks.com"], "sinkhole"
            elif sinkhole_choice == "2":
                return ["hit-nxdomain.opendns.com"], "sinkhole"
            elif sinkhole_choice == "3":
                return ["block.fortinet.com"], "sinkhole"
            elif sinkhole_choice == "4":
                domain = input("\nEnter custom sinkhole domain: ").strip()
                if domain:
                    return [domain], "sinkhole"
            
            print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")
            continue 