"""
Configuration module for DNS Gap Hunter.
Contains default settings and constants used throughout the application.
"""

# DNS resolution settings
DNS_TIMEOUT = 5  # Seconds
DNS_RETRY_COUNT = 2

# Domain processing settings
MAX_DOMAINS = 1000  # Maximum domains to process in one run
SKIP_WHITELISTED = True  # Skip well-known domains

# HTTP request settings
HTTP_TIMEOUT = 45  # Seconds for HTTP requests
HTTP_MAX_RETRIES = 5
HTTP_BACKOFF_FACTOR = 2
HTTP_RETRY_CODES = [429, 500, 502, 503, 504]

# Thread pool settings
# Default is 2x CPU cores, but no more than 16 threads
import os
CPU_COUNT = os.cpu_count() or 1
MAX_WORKERS = min(16, CPU_COUNT * 2)

# Special IPs for sinkhole detection
SINKHOLE_IPS = ['0.0.0.0', '127.0.0.1']

# Report generation settings
REPORT_DIR = "test-results"
DNSFW_REPORT_SUBDIR = "dns-fw"
SINKHOLE_REPORT_SUBDIR = "sinkhole-dns-security"

# Domain sources
WHITELISTED_DOMAINS = [
    "google.com", "googleapis.com", "gstatic.com", "youtube.com", "youtu.be",
    "microsoft.com", "live.com", "office.com", "office365.com", "microsoftonline.com",
    "amazon.com", "apple.com", "icloud.com", "facebook.com",
    "fb.com", "instagram.com", "whatsapp.com", "twitter.com", "linkedin.com",
    "github.com", "cloudflare.com", "akamai.com", "akamaitech.net",
    "akamaiedge.net", "adobe.com", "dropbox.com", "yahoo.com", "bing.com",
    "wikimedia.org", "wikipedia.org", "zoom.us"
] 