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
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        
        if test_type == "dnsfw":
            answers = resolver.resolve(query_domain, 'A')
            security_status = 'DNSFW Bypassed'
            resolved_address = None
            valid_ip_found = False
            
            for answer in answers:
                ip = answer.address
                if ip in SINKHOLE_IPS:
                    status = 'valid'
                    security_status = 'Post-Attack Terminated Domain'
                    resolved_address = ip
                    return domain, status, security_status, resolved_address
            
            for answer in answers:
                ip = answer.address
                if is_valid_ip(ip):
                    valid_ip_found = True
                    if ip in security_ips:
                        security_status = 'DNSFW Blocked'
                    resolved_address = ip
                    break
            
            if not valid_ip_found:
                status = 'invalid_ip'
                security_status = 'Invalid IP Detected'
                resolved_address = None
            else:
                status = 'valid'
                
        elif test_type == "sinkhole":
            try:
                answers = resolver.resolve(query_domain, 'CNAME')
                security_status = 'Sinkhole Bypassed'
                resolved_address = None
                
                for answer in answers:
                    cname = str(answer.target).rstrip('.')
                    if cname in security_ips:
                        security_status = 'Sinkhole Address Blocked'
                        resolved_address = cname
                        break
                
                status = 'valid'
                
            except dns.resolver.NoAnswer:
                answers = resolver.resolve(query_domain, 'A')
                security_status = 'Sinkhole Bypassed'
                resolved_address = None
                
                for answer in answers:
                    ip = answer.address
                    if ip in SINKHOLE_IPS:
                        status = 'valid'
                        security_status = 'Post-Attack Terminated Domain'
                        resolved_address = ip
                        return domain, status, security_status, resolved_address
                
                for answer in answers:
                    ip = answer.address
                    if is_valid_ip(ip):
                        resolved_address = ip
                        break
                
                status = 'valid'
                
    except dns.resolver.NoAnswer:
        status = 'no_dns_record'
        security_status = 'No DNS Record Available'
        resolved_address = None
        logging.debug(f"No DNS record for {original_domain}")
    except dns.resolver.NXDOMAIN:
        status = 'no_dns_record'
        security_status = 'No DNS Record Available'
        resolved_address = None
        logging.debug(f"NXDOMAIN for {original_domain}")
    except dns.resolver.NoNameservers:
        status = 'no_nameserver'
        security_status = 'No Nameserver Available'
        resolved_address = None
        logging.debug(f"No nameservers for {original_domain}")
    except dns.resolver.Timeout:
        status = 'timeout'
        security_status = 'DNS Query Timeout'
        resolved_address = None
        logging.debug(f"DNS query timeout for {original_domain}")
    except Exception as e:
        status = 'error'
        security_status = f'Unexpected Error: {str(e)}'
        resolved_address = None
        logging.debug(f"DNS query error for {original_domain}: {str(e)}")

    return domain, status, security_status, resolved_address

def get_security_configuration() -> Tuple[List[str], str]:
    """
    Gets security appliance configuration from user.
    
    Returns:
        Tuple[List[str], str]: List of security IPs/domains and test type
    """
    print(f"\n{Fore.CYAN}Security Test Selection:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}1.{Style.RESET_ALL} DNS Firewall Test (Infoblox Threat Defense IP List)")
    print(f"{Fore.YELLOW}2.{Style.RESET_ALL} DNS Firewall Test (Manual IP Entry)")
    print(f"{Fore.YELLOW}3.{Style.RESET_ALL} DNS Firewall Test (IP List File)")
    print(f"{Fore.YELLOW}4.{Style.RESET_ALL} Sinkhole DNS Security Test (Sinkhole Domain List)")
    
    while True:
        try:
            choice = input(f"\n{Fore.YELLOW}Select Option (1-4):{Style.RESET_ALL} ").strip()
            
            if choice in ["1", "2", "3"]:
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
                    ip_input = input(f"\n{Fore.YELLOW}Enter IP addresses (comma-separated):{Style.RESET_ALL} ").strip()
                    ip_list = [ip.strip() for ip in ip_input.split(',')]
                    
                    valid_ips = []
                    for ip in ip_list:
                        if is_valid_ip(ip):
                            valid_ips.append(ip)
                        else:
                            print(f"{Fore.RED}Invalid IP address: {ip}{Style.RESET_ALL}")
                    
                    if not valid_ips:
                        print(f"{Fore.RED}No valid IP addresses found. Please try again.{Style.RESET_ALL}")
                        continue
                        
                    print(f"{Fore.GREEN}Validated {len(valid_ips)} IP addresses.{Style.RESET_ALL}")
                    return valid_ips, "dnsfw"
                    
                elif choice == "3":
                    file_path = input(f"\n{Fore.YELLOW}Enter IP list file path (.txt):{Style.RESET_ALL} ").strip()
                    
                    try:
                        with open(file_path, 'r') as file:
                            ip_list = [line.strip() for line in file if line.strip()]
                        
                        valid_ips = []
                        for ip in ip_list:
                            if is_valid_ip(ip):
                                valid_ips.append(ip)
                            else:
                                print(f"{Fore.RED}Invalid IP address: {ip}{Style.RESET_ALL}")
                        
                        if not valid_ips:
                            print(f"{Fore.RED}No valid IP addresses found. Please try again.{Style.RESET_ALL}")
                            continue
                            
                        print(f"{Fore.GREEN}Validated {len(valid_ips)} IP addresses.{Style.RESET_ALL}")
                        return valid_ips, "dnsfw"
                        
                    except FileNotFoundError:
                        print(f"{Fore.RED}File not found: {file_path}{Style.RESET_ALL}")
                        continue
                    except Exception as e:
                        print(f"{Fore.RED}File reading error: {str(e)}{Style.RESET_ALL}")
                        continue
                        
            elif choice == "4":
                print(f"\n{Fore.CYAN}Select Sinkhole Domain for Sinkhole DNS Security Test:{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}1.{Style.RESET_ALL} Palo Alto Networks Sinkhole")
                print(f"{Fore.YELLOW}2.{Style.RESET_ALL} Cisco Umbrella Sinkhole")
                print(f"{Fore.YELLOW}3.{Style.RESET_ALL} Fortinet Sinkhole")
                print(f"{Fore.YELLOW}4.{Style.RESET_ALL} Custom Sinkhole Domain")
                
                sinkhole_choice = input(f"\n{Fore.YELLOW}Select Option (1-4):{Style.RESET_ALL} ").strip()
                
                if sinkhole_choice == "1":
                    return ["sinkhole.paloaltonetworks.com"], "sinkhole"
                elif sinkhole_choice == "2":
                    return ["sinkhole.umbrella.com"], "sinkhole"
                elif sinkhole_choice == "3":
                    return ["sinkhole.fortinet.com"], "sinkhole"
                elif sinkhole_choice == "4":
                    custom_domain = input(f"\n{Fore.YELLOW}Enter custom sinkhole domain:{Style.RESET_ALL} ").strip()
                    return [custom_domain], "sinkhole"
                else:
                    print(f"{Fore.RED}Invalid selection. Please enter 1-4.{Style.RESET_ALL}")
                    continue
                    
            else:
                print(f"{Fore.RED}Invalid selection. Please enter 1-4.{Style.RESET_ALL}")
                continue
                
        except Exception as e:
            print(f"{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")
            continue

def resolve_domain(domain: str, record_type: str = 'A', timeout: int = DNS_TIMEOUT) -> List[str]:
    """
    General purpose domain resolution function. Performs DNS query for the specified record type.
    
    Args:
        domain (str): Domain to resolve
        record_type (str): DNS record type (A, AAAA, MX, TXT, NS, etc.)
        timeout (int): DNS query timeout in seconds (from config)
        
    Returns:
        List[str]: List of resolved records
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        answers = resolver.resolve(domain, record_type)
        
        results = []
        for answer in answers:
            if record_type == 'A' or record_type == 'AAAA':
                results.append(answer.address)
            elif record_type == 'MX':
                results.append(f"{answer.preference} {answer.exchange}")
            elif record_type == 'CNAME':
                results.append(str(answer.target).rstrip('.'))
            elif record_type == 'NS':
                results.append(str(answer.target).rstrip('.'))
            elif record_type == 'TXT':
                results.append(str(answer).strip('"'))
            else:
                results.append(str(answer))
        
        return results
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.resolver.Timeout:
        logging.warning(f"DNS timeout resolving {domain} ({record_type})")
        return []
    except Exception as e:
        logging.error(f"Error resolving {domain} ({record_type}): {e}")
        return [] 