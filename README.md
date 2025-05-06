# DNS Gap Hunter

A comprehensive tool for detecting malicious domains that bypass DNS security controls.

## Overview

DNS Gap Hunter is a security tool designed to evaluate the effectiveness of DNS security solutions by testing them against known malicious domains. It retrieves domains from various threat intelligence sources, checks whether they are properly blocked by DNS security solutions, and provides detailed reports.

## For Network Administrators and Blue Team Members

DNS Gap Hunter has been specifically developed for network administrators and blue team security personnel who need to validate the effectiveness of their DNS security infrastructure. This tool enables precise measurement of how many malicious domains are properly detected and blocked by DNS Firewalls or security solutions utilizing sinkhole mechanisms, and critically, identifies which malicious domains are evading detection. Organizations invest significantly in DNS security controls, yet without proper validation, unknown gaps in protection persist. By leveraging multiple authoritative threat intelligence sources and performing comprehensive DNS resolution testing against your security infrastructure, DNS Gap Hunter provides detailed metrics and actionable intelligence on protection coverage, helping teams identify and remediate security gaps, validate vendor claims about protection efficacy, and demonstrate compliance with security requirements through quantifiable evidence. The detailed reporting helps justify security investments and supports continuous improvement of defensive capabilities.

## Core Components and Workflow

1. `DNSGapHunter.py`: Main application interface and orchestration engine
2. `data_collector.py`: Threat intelligence data collection engine
3. `dns_checker.py`: Module performing DNS queries and security checks for domains
4. `domain_utils.py`: Domain validation and processing helper functions
5. `reporting.py`: Module generating CSV and HTML format outputs for reporting results
6. `ui_utils.py`: User interface components and visual helpers
7. `config.py`: Application configuration settings

## Features

- **Multiple Threat Intelligence Sources**:
  - ThreatFox: Malicious domains collected by abuse.ch
  - URLhaus: URLs distributing malware by abuse.ch
  - OpenPhish: Active phishing sites
  - CyberCrime: Cybercrime and malware panels
  - Botvrij: Botvrij.eu IOC domain list
  - StopForumSpam: Toxic domains associated with spammers
  - URLScan: Malicious domains detected by URLScan.io
  - PhishStats: Phishing sites collected by PhishStats
  - URLhaus Database: Latest URLs in URLhaus database
  - PhishingArmy: PhishingArmy phishing domains

- **Supported Security Configurations**:
  - **DNS Firewall Testing**:
    - Infoblox Threat Defense IP list
    - Manual IP entry
    - IP list file
  - **Sinkhole DNS Security Testing**:
    - Palo Alto Networks Sinkhole
    - Cisco Umbrella Sinkhole
    - Fortinet Sinkhole
    - Custom Sinkhole domain

- **Technical Features**:
  - Multi-threaded architecture for fast processing (configurable thread count)
  - Scalable HTTP requests and retry mechanism
  - Intelligent DNS resolution and error handling
  - Special rate limiting control for URLScan API
  - IP validation and verification mechanisms
  - Comprehensive status monitoring and progress indicators

- **Reporting Features**:
  - CSV output for domains with valid DNS records
  - CSV output for domains with no DNS records
  - CSV output for domains filtered during validation
  - Detailed HTML reports with interactive charts and statistics
  - Domain analysis by threat intelligence source
  - Security blocking statistics and distribution

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/DNSGapHunter.git
cd DNSGapHunter

# Install dependencies
pip install -r requirements.txt
```

### Requirements

```
colorama>=0.4.6
dnspython>=2.3.0
requests>=2.28.2
tqdm>=4.64.1
urllib3>=1.26.15
ipaddress>=1.0.23
```

## Usage

```bash
python DNSGapHunter.py
```

Follow the interactive prompts to select your security solution and test configuration.

### Running DNS Firewall Test

1. Run the script: `python DNSGapHunter.py`
2. Select option 1 for "DNS Firewall Test"
3. Choose between Infoblox, manual IP entry, or IP list file
4. Wait for domains to be collected and tested
5. Review the results in the terminal and generated reports

### Running Sinkhole DNS Security Test

1. Run the script: `python DNSGapHunter.py`
2. Select option 4 for "Sinkhole DNS Security Test"
3. Choose between Palo Alto, Cisco Umbrella, Fortinet, or custom sinkhole
4. Wait for domains to be collected and tested
5. Review the results in the terminal and generated reports

### Important Note on Vendor Sinkhole Configurations

**Sinkhole Address Verification Status**: The current implementation includes predefined configurations for Cisco Umbrella, Fortinet, and Palo Alto Networks sinkholes; however, these have not been extensively validated in production environments. If you test against these vendor sinkholes, please consider sharing your results with the developer to improve the accuracy of the built-in configurations.

For enterprise deployments, you have three options:
1. **Share Test Results**: After testing with your vendor's sinkhole implementation, share your findings to help improve the tool for all users.
2. **Customize the Implementation**: You can modify the relevant functions in the `dns_checker.py` file to accurately reflect your security vendor's sinkhole configurations.
3. **Use Manual Configuration**: If you prefer not to modify the code, you can select the "Custom Sinkhole" option and manually enter your security solution's sinkhole address when prompted.

## Technical Details

### Domain Collection and Processing

1. `get_intelligence_sources()`: Gets the list and configurations of supported threat intelligence sources.
2. `create_resilient_session()`: Creates a session configured with retry logic and timeouts for HTTP requests.
3. `fetch_domain_list()`: Fetches and processes domain list from the specified source.
4. `merge_domain_lists()`: Merges domain lists collected from various sources.
5. Filtering: Domains are filtered for invalid reasons (syntax, whitelist, etc.).

### DNS Resolution and Security Checking

1. `check_dns()`: Performs DNS resolution and security checks for a domain.
2. `get_security_configuration()`: Gets security appliance configuration from user.
3. Resolution processes: Different record types (A, CNAME) are checked and tested according to protocol.
4. Error handling: Various DNS error conditions (NoAnswer, NXDOMAIN, NoNameservers, Timeout) are handled.

### Parallel Processing and Performance

1. `ThreadPoolExecutor`: Used for running DNS queries in parallel.
2. MAX_WORKERS in `config.py`: Configures the number of threads (defaults to 2x CPU cores, max 16).
3. Smart HTTP request management: Retries, exponential backoff, and rate limiting are considered.

### Output and Reporting

The tool generates the following output files:

- `dnsfw_results_[timestamp].csv`: Domains with valid DNS records
- `dnsfw_no_records_[timestamp].csv`: Domains with no DNS records
- `filtered_domains_[timestamp].csv`: Domains filtered out during validation
- HTML reports in the `test-results/dns-fw/reports/` or `test-results/sinkhole-dns-security/reports/` directories

## Configuration

You can customize the tool's behavior by modifying the `config.py` file:

```python
# DNS resolution settings
DNS_TIMEOUT = 5  # Seconds
DNS_RETRY_COUNT = 2

# Domain processing settings
MAX_DOMAINS = 1000  # Maximum domains to process
SKIP_WHITELISTED = True  # Skip well-known domains

# HTTP request settings
HTTP_TIMEOUT = 45  # Seconds
HTTP_MAX_RETRIES = 5
HTTP_BACKOFF_FACTOR = 2
HTTP_RETRY_CODES = [429, 500, 502, 503, 504]

# URLScan API settings
URLSCAN_TIMEOUT = 60  # Seconds for URLScan requests
URLSCAN_RETRY_DELAY = 10  # Seconds between retries
URLSCAN_MAX_RETRIES = 3  # Maximum number of retry attempts

# Thread pool settings
# Default is 2x CPU cores, but no more than 16 threads
MAX_WORKERS = min(16, CPU_COUNT * 2)

# Special IPs for sinkhole detection
SINKHOLE_IPS = ['0.0.0.0', '127.0.0.1']

# Report generation settings
REPORT_DIR = "test-results"
DNSFW_REPORT_SUBDIR = "dns-fw"
SINKHOLE_REPORT_SUBDIR = "sinkhole-dns-security"

# Whitelisted domains
WHITELISTED_DOMAINS = [
    "google.com", "googleapis.com", "gstatic.com", "youtube.com", "youtu.be",
    "microsoft.com", "live.com", "office.com", "office365.com", "microsoftonline.com",
    # More domains are listed in config.py
]
```

## Extending the Application

The project can be extended with new features thanks to its modular structure:

1. New threat intelligence sources can be added to `data_collector.py`.
2. Support for new DNS security solutions can be added to `dns_checker.py`.
3. New report formats can be added to `reporting.py`.
4. Domain processing algorithms can be improved in `domain_utils.py`.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Thanks to all the threat intelligence sources that make their data available.
- Built with [dnspython](https://github.com/rthalley/dnspython) and other excellent open-source libraries.