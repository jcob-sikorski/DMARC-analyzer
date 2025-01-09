# Standard library imports for core functionality
import logging
from typing import Dict, Any, List, Tuple, Optional
import socket  # For DNS lookups
import requests  # For making HTTP requests
from collections import defaultdict  # For automatic dictionary initialization
import datetime  # For timestamp handling
import os  # For file operations
import json  # For JSON processing
import traceback  # For detailed error tracking

# Set up logging configuration
# - Logs will be written to both a file and console
# - Debug level enables detailed tracking
# - Format includes timestamp, log level, and message
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dmarc_analyzer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Dictionary mappings for categorizing different types of email servers
# These help identify the source and legitimacy of emails

# Known legitimate email service providers
LEGITIMATE_SERVERS = {
    'outlook.com': 'Microsoft 365',
    'microsoft.com': 'Microsoft 365',
    'googlemail.com': 'Google Workspace',
    'google.com': 'Google Workspace',
    'amazonses.com': 'Amazon SES',
    'sendgrid.net': 'SendGrid',
    'mailgun.org': 'Mailgun',
    'mailchimp.com': 'Mailchimp',
    'postmarkapp.com': 'Postmark',
    'mandrill': 'Mandrill',
    'mailjet.com': 'Mailjet'
}

# Known email forwarding services
FORWARDER_SERVERS = {
    'protonmail': 'ProtonMail',
    'fastmail.com': 'FastMail',
    'forwardemail.net': 'Forward Email',
    'improvmx.com': 'ImprovMX',
    'zoho.com': 'Zoho Mail',
    'pobox.com': 'Pobox'
}

# Known email security gateway providers
SECURITY_GATEWAYS = {
    'mimecast.com': 'Mimecast',
    'barracuda.com': 'Barracuda',
    'proofpoint.com': 'Proofpoint',
    'trustwave.com': 'Trustwave SEG',
    'symantec': 'Symantec Email Security',
    'trendmicro.com': 'Trend Micro',
    'cisco.com': 'Cisco Email Security',
    'sophos': 'Sophos Email'
}

# Cache class to store DNS and geolocation lookups
# This reduces API calls and improves performance
class Cache:
    def __init__(self, cache_file: str):
        """Initialize cache with specified file path"""
        logger.info(f"Initializing cache with file: {cache_file}")
        self.cache_file = cache_file
        self.cache = {}
        self.load()
    
    def load(self) -> None:
        """Load cached data from disk
        If file doesn't exist or has errors, starts with empty cache"""
        logger.debug(f"Loading cache from {self.cache_file}")
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
                logger.info(f"Successfully loaded {len(self.cache)} items from cache")
            else:
                logger.warning(f"Cache file {self.cache_file} does not exist")
        except Exception as e:
            logger.error(f"Error loading cache {self.cache_file}: {str(e)}")
            logger.debug(traceback.format_exc())
    
    def save(self) -> None:
        """Save current cache to disk
        Creates directories if they don't exist"""
        logger.debug(f"Saving cache to {self.cache_file}")
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
            logger.info(f"Successfully saved {len(self.cache)} items to cache")
        except Exception as e:
            logger.error(f"Error saving cache {self.cache_file}: {str(e)}")
            logger.debug(traceback.format_exc())
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve value from cache by key"""
        value = self.cache.get(key)
        logger.debug(f"Cache get: {key} -> {value}")
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Store value in cache and persist to disk"""
        logger.debug(f"Cache set: {key} = {value}")
        self.cache[key] = value
        self.save()

# Main DMARC analysis class
class DMARCAnalyzer:
    def __init__(self):
        """Initialize analyzer with separate caches for DNS and geolocation data"""
        logger.info("Initializing DMARCAnalyzer")
        self.dns_cache = Cache('cache/dns_cache.json')
        self.geo_cache = Cache('cache/geo_cache.json')
        self.reset()

    def reset(self):
        """Reset all analysis results to initial state
        Called at initialization and between analysis runs"""
        logger.info("Resetting analyzer state")
        self.combined_results = {
            'total_emails': 0,
            'legitimate_systems': defaultdict(int),
            'forwarded': 0,
            'suspicious_forwards': 0,
            'potential_phishing': 0,
            'security_scanned': 0,
            'countries': defaultdict(int),
            'domains': set(),
            'date_range': {
                'start': None,
                'end': None
            },
            'misconfigurations': []
        }
        logger.debug("Analyzer state reset complete")

    def perform_reverse_dns(self, ip: str) -> str:
        """Perform reverse DNS lookup for an IP address
        Uses cache to avoid redundant lookups"""
        logger.debug(f"Performing reverse DNS lookup for IP: {ip}")
        cached_result = self.dns_cache.get(ip)
        if cached_result:
            logger.debug(f"DNS cache hit for {ip}: {cached_result}")
            return cached_result
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            logger.info(f"DNS lookup successful for {ip}: {hostname}")
            self.dns_cache.set(ip, hostname)
            return hostname
        except (socket.herror, socket.gaierror) as e:
            logger.warning(f"DNS lookup failed for {ip}: {str(e)}")
            self.dns_cache.set(ip, "Unknown")
            return "Unknown"

    def get_ip_geolocation(self, ip: str) -> Dict[str, str]:
        """Get geolocation information for an IP address
        Uses ipinfo.io API with caching"""
        logger.debug(f"Getting geolocation for IP: {ip}")
        cached_result = self.geo_cache.get(ip)
        if cached_result:
            logger.debug(f"Geo cache hit for {ip}: {cached_result}")
            return cached_result
        
        try:
            logger.debug(f"Making API request to ipinfo.io for {ip}")
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            if response.status_code == 200:
                data = response.json()
                result = {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown')
                }
                logger.info(f"Geolocation successful for {ip}: {result}")
                self.geo_cache.set(ip, result)
                return result
            else:
                logger.warning(f"Geolocation API returned status code {response.status_code}")
        except Exception as e:
            logger.error(f"Error getting geolocation for {ip}: {str(e)}")
            logger.debug(traceback.format_exc())
        
        result = {'country': 'Unknown', 'city': 'Unknown'}
        self.geo_cache.set(ip, result)
        return result

    def categorize_sender(self, ip: str, hostname: str) -> Tuple[str, str]:
        """Categorize email sender based on hostname
        Returns tuple of (category, system_name)"""
        logger.debug(f"Categorizing sender - IP: {ip}, Hostname: {hostname}")
        hostname_lower = hostname.lower()
        
        # Check against known server categories
        for category, domains in [
            ('legitimate', LEGITIMATE_SERVERS),
            ('forwarder', FORWARDER_SERVERS),
            ('security_gateway', SECURITY_GATEWAYS)
        ]:
            for domain, name in domains.items():
                if domain in hostname_lower:
                    logger.info(f"Sender {ip} ({hostname}) categorized as {category}: {name}")
                    return category, name
        
        logger.warning(f"Unable to categorize sender {ip} ({hostname})")
        return 'unknown', 'Unknown System'

    def analyze_authentication(self, record: Dict[str, Any], sender_category: str, system_name: str) -> str:
        """Analyze DMARC authentication results
        Returns authentication status based on DKIM/SPF results and sender category"""
        logger.debug(f"Analyzing authentication for {system_name} ({sender_category})")
        logger.debug(f"Authentication record: {record}")
        
        policy = record['policy_evaluated']
        dkim_result = policy['dkim']
        spf_result = policy['spf']
        
        logger.info(f"Authentication results - DKIM: {dkim_result}, SPF: {spf_result}")
        
        # Special handling for known legitimate services
        if system_name in ['Microsoft 365', 'Google Workspace'] and spf_result == 'fail':
            logger.info(f"Special case: {system_name} with SPF fail -> forwarded")
            return 'forwarded'
        
        # Determine authentication status
        result = None
        if dkim_result == 'pass' and spf_result == 'pass':
            result = 'authenticated'
        elif dkim_result == 'pass' and sender_category == 'legitimate':
            result = 'legitimate_with_spf_fail'
        elif dkim_result == 'pass' and sender_category == 'forwarder':
            result = 'forwarded'
        elif dkim_result == 'pass':
            result = 'suspicious_forward'
        elif sender_category == 'security_gateway':
            result = 'security_scanned'
        else:
            result = 'potential_phishing'
        
        logger.info(f"Final authentication result: {result}")
        return result

    def update_date_range(self, begin_timestamp: str, end_timestamp: str) -> None:
        """Update the analysis date range based on report timestamps"""
        logger.debug(f"Updating date range - Begin: {begin_timestamp}, End: {end_timestamp}")
        try:
            begin_date = datetime.datetime.fromtimestamp(int(begin_timestamp))
            end_date = datetime.datetime.fromtimestamp(int(end_timestamp))
            
            current_start = self.combined_results['date_range']['start']
            current_end = self.combined_results['date_range']['end']
            
            if current_start is None or begin_date < current_start:
                logger.info(f"Updating start date to {begin_date}")
                self.combined_results['date_range']['start'] = begin_date
            
            if current_end is None or end_date > current_end:
                logger.info(f"Updating end date to {end_date}")
                self.combined_results['date_range']['end'] = end_date
                
            logger.debug(f"Updated date range: {self.combined_results['date_range']}")
        except (ValueError, TypeError) as e:
            logger.error(f"Error updating date range: {str(e)}")
            logger.debug(traceback.format_exc())

    def analyze_dmarc_report(self, report_data: Dict[str, Any]) -> None:
        """Main method to analyze a DMARC report
        Processes all records and updates combined results"""
        logger.info("\nStarting DMARC report analysis")
        logger.debug(f"Report data: {json.dumps(report_data, indent=2)}")
        
        try:
            # Update date range from report metadata
            begin_time = report_data['report_metadata'].get('date_range_begin')
            end_time = report_data['report_metadata'].get('date_range_end')
            if begin_time and end_time:
                self.update_date_range(begin_time, end_time)
            
            # Track domain being analyzed
            domain = report_data['policy_published'].get('domain')
            if domain:
                logger.info(f"Processing domain: {domain}")
                self.combined_results['domains'].add(domain)
            
            # Process individual records
            records = report_data.get('records', [])
            logger.info(f"Processing {len(records)} records")
            
            for record in records:
                ip = record.get('source_ip')
                if not ip:
                    logger.warning("Record missing source IP, skipping")
                    continue
                
                logger.debug(f"\nProcessing record for IP: {ip}")
                count = int(record.get('count', 0))
                self.combined_results['total_emails'] += count
                logger.debug(f"Email count: {count}")
                
                # Gather information about the sender
                hostname = self.perform_reverse_dns(ip)
                sender_category, system_name = self.categorize_sender(ip, hostname)
                logger.debug(f"Sender info - Category: {sender_category}, System: {system_name}")
                
                # Get and record geolocation data
                geo_info = self.get_ip_geolocation(ip)
                self.combined_results['countries'][geo_info['country']] += count
                logger.debug(f"Geolocation: {geo_info}")
                
                # Analyze authentication results
                auth_result = self.analyze_authentication(record, sender_category, system_name)
                logger.debug(f"Authentication result: {auth_result}")
                
                # Update statistics based on authentication result
                if auth_result in ('authenticated', 'legitimate_with_spf_fail'):
                    self.combined_results['legitimate_systems'][system_name] += count
                elif auth_result == 'forwarded':
                    self.combined_results['forwarded'] += count
                elif auth_result == 'suspicious_forward':
                    self.combined_results['suspicious_forwards'] += count
                elif auth_result == 'security_scanned':
                    self.combined_results['security_scanned'] += count
                elif auth_result == 'potential_phishing':
                    self.combined_results['potential_phishing'] += count
                
                logger.debug(f"Updated combined results: {json.dumps(self.combined_results, default=str, indent=2)}")

        except Exception as e:
            logger.error(f"Error analyzing report: {str(e)}")
            logger.debug