# Standard library imports for core functionality
import logging
from pprint import pformat
from typing import Dict, Any, List, Tuple, Optional
import socket  # For DNS lookups
import requests  # For making HTTP requests
from collections import defaultdict  # For automatic dictionary initialization
from datetime import datetime # For timestamp handling
import os  # For file operations
import json  # For JSON processing
import traceback  # For detailed error tracking
import pandas as pd

# =======================================================================
# Email Security Report Documentation:
# 
# This report summarizes the email authentication and security outcomes
# for a specific period. It includes key statistics on forwarded emails,
# legitimate systems, phishing attempts, and security gateway scans.
#
# Email Security Report 
# Total Emails Sent: 1,200 
# Emails Forwarded: 114 
# - Recognized Forwarders: 104 emails. 
# - Suspicious Forwarders: 10 emails. 

# Authentication Results: 
# - Legitimate Systems: 
# - Follow Up Boss: 500 emails 
# - Mailchimp: 300 emails 

# - Forwarded Emails: 
# - 114 emails have been forwarded. No action required.
# - 10 emails were forwarded via suspicious servers. Closer monitoring required. 

# - Phishing Attempts: 
# - 50 phishing emails pretending to come from your domain. Immediate action required. 

# - Security Gateway: 
# - 50 emails were scanned by spam filters. No further action needed. 

# Country Summary: 
# "During the week of Nov 1 - Nov 7, most of your emails originated from the United States, 
# with additional traffic detected from Pakistan, Turkey, and India."
# =======================================================================


# Set up logging configuration
# - Logs will be written to both a file and console
# - Debug level enables detailed tracking
# - Format includes timestamp, log level, and message

# Generate unique log filename with timestamp
log_filename = f'dmarc_analyzer_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'

# Set up logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Dictionary mappings for categorizing different types of email servers
# These help identify the source and legitimacy of emails

def download_dmarc_dictionaries():
    """
    Downloads dictionaries from multiple sheets in a Google Spreadsheet.
    
    Returns:
        tuple: (legitimate_servers, forwarder_servers, security_gateways)
            - legitimate_servers: dict[str, str] mapping domains to their services
            - forwarder_servers: set[str] containing forwarder domain names
            - security_gateways: set[str] containing security gateway domain names
    """
    # Base URL of the Google Sheet
    base_url = "https://docs.google.com/spreadsheets/d/1yTh7HDf7yoeydtr_fgx54xg_cIkAad6nHRWEwHMKX9c"
    
    # Dictionary mapping sheet gids to their categories
    sheet_configs = {
        "0": "Legitimate",
        "1818030106": "Security Gateway",
        "1706054660": "Forwarders",
        "178339195": "Phishing"  # Added but not used in final output
    }
    
    # Initialize empty structures
    LEGITIMATE_SERVERS = {}  # Dictionary for domain->service mapping
    FORWARDER_SERVERS = set()  # Set for just domain names
    SECURITY_GATEWAYS = set()  # Set for just domain names
    
    try:
        for gid, category in sheet_configs.items():
            # Construct the export URL for each sheet
            export_url = f"{base_url}/export?format=csv&gid={gid}"
            
            # Read the CSV into a pandas DataFrame
            df = pd.read_csv(export_url)
            
            # Skip empty DataFrames
            if df.empty:
                continue
                
            # Process each row
            for index, row in df.iterrows():
                # Assuming first column is always domain
                domain = str(row.iloc[0])
                
                # Skip empty domains
                if pd.isna(domain) or domain.strip() == '':
                    continue
                    
                # Remove any leading asterisk (*) and clean domain
                domain = domain.strip('* \t')
                
                # Get service name (usually in third column, fallback to empty string)
                service = str(row.iloc[2]) if len(row) > 2 else ''
                service = service if not pd.isna(service) else ''
                
                # Add to appropriate dictionary based on sheet category
                if category == 'Legitimate':
                    LEGITIMATE_SERVERS[domain] = service
                elif category == 'Forwarders':
                    FORWARDER_SERVERS.add(domain)  # Just add the domain to the set
                elif category == 'Security Gateway':
                    SECURITY_GATEWAYS.add(domain)  # Just add the domain to the set
                # Note: Phishing category is collected but not included in output
        
        # Log legitimate server information
        logger.debug("LEGITIMATE_SERVERS:")
        logger.debug(pformat(LEGITIMATE_SERVERS))
        
        # Log forwarder servers - adding newline for readability
        logger.debug("\nFORWARDER_SERVERS:")
        logger.debug(pformat(FORWARDER_SERVERS))
        
        # Log security gateways - adding newline for readability
        logger.debug("\nSECURITY_GATEWAYS:")
        logger.debug(pformat(SECURITY_GATEWAYS))
        
        return LEGITIMATE_SERVERS, FORWARDER_SERVERS, SECURITY_GATEWAYS
        
    except Exception as e:
        logger.error(f"Failed to download DMARC dictionaries: {str(e)}")
        return {}, {}, {}

# from the google sheets
# Known legitimate email service providers and their corresponding services
LEGITIMATE_SERVERS, FORWARDER_SERVERS, SECURITY_GATEWAYS = download_dmarc_dictionaries()

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

# Categorized results for legitimate systems, forwarded emails, 
# and suspicious/phishing activity. Summary of countries emails originated from. 

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

        # associated with each IP using IP intelligence databases

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
        """
        Categorize email sender based on hostname.
        
        This function checks if the hostname matches any known domains in our three collections:
        - LEGITIMATE_SERVERS (dictionary mapping domains to service names)
        - FORWARDER_SERVERS (set of forwarder domains)
        - SECURITY_GATEWAYS (set of security gateway domains)
        
        Args:
            ip: The IP address of the sender
            hostname: The hostname to categorize
            
        Returns:
            tuple: (category, system_name) where:
                - category is one of: 'legitimate', 'forwarder', 'security_gateway', 'unknown'
                - system_name is the service name for legitimate servers or a default value for others
        """
        logger.debug(f"Categorizing sender - IP: {ip}, Hostname: {hostname}")
        
        hostname_lower = hostname.lower()

        # First check legitimate servers since they have service name mappings
        for domain, service_name in LEGITIMATE_SERVERS.items():
            if domain in hostname_lower:
                logger.info(f"Sender {ip} ({hostname}) categorized as legitimate: {service_name}")
                return 'legitimate', service_name
        
        # Check forwarders (using set membership)
        for domain in FORWARDER_SERVERS:
            if domain in hostname_lower:
                logger.info(f"Sender {ip} ({hostname}) categorized as forwarder")
                return 'forwarder', 'Email Forwarder'
        
        # Check security gateways (using set membership)
        for domain in SECURITY_GATEWAYS:
            if domain in hostname_lower:
                logger.info(f"Sender {ip} ({hostname}) categorized as security gateway")
                return 'security_gateway', 'Security Gateway'
        
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
        if system_name in LEGITIMATE_SERVERS.values() and spf_result == 'fail':
            logger.info(f"Special case: {system_name} with SPF fail -> forwarded")
            return 'forwarded'

        # Check whether each email passed or failed authentication. 

        # Legitimate, Forwarder, Phishing, Servers and Security Gateway

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

        # TODO: Alignment (Internally Processed):
        # Validate if SPF and DKIM align with the domain in the "From" header.
        # Use alignment data internally to categorize emails but exclude
        # it from client-facing reports.
        
        logger.info(f"Final authentication result: {result}")
        return result

    def check_alignment(self, record: Dict[str, Any]) -> Dict[str, bool]:
        """
        Validate if SPF and DKIM domains align with the From header domain.
        
        This method handles various authentication result formats including string-based
        pass/fail results and more detailed domain-based results. It implements both
        strict and relaxed alignment checking according to DMARC specifications.
        
        Args:
            record: Dictionary containing DMARC record data with authentication results.
                Expected structure includes:
                - identifiers.header_from: domain from email From header
                - auth_results: authentication results which may be either:
                    - Simple format: {'spf': 'pass', 'dkim': 'pass'}
                    - Detailed format: {'spf': {'domain': 'example.com', 'result': 'pass'}}
        
        Returns:
            Dictionary indicating alignment status:
                {
                    'spf_aligned': bool,  # True if SPF domain aligns with From domain
                    'dkim_aligned': bool  # True if DKIM domain aligns with From domain
                }
        """
        alignment_results = {
            'spf_aligned': False,
            'dkim_aligned': False
        }
        
        try:
            # Extract and validate the From header domain
            identifiers = record.get('identifiers', {})
            if isinstance(identifiers, str):
                logger.warning(f"Unexpected identifiers format (string): {identifiers}")
                return alignment_results
                
            from_domain = identifiers.get('header_from', '').lower()
            if not from_domain:
                logger.warning("No From domain found in record")
                return alignment_results
                
            # Get authentication results, handling potential string format
            auth_results = record.get('auth_results', {})
            if isinstance(auth_results, str):
                logger.warning(f"Unexpected auth_results format (string): {auth_results}")
                return alignment_results
                
            # Process SPF alignment with support for both string and dict formats
            spf_data = auth_results.get('spf')
            if spf_data:
                if isinstance(spf_data, str):
                    # For string results, if SPF passed, consider it aligned
                    # This assumes relaxed alignment mode as we can't verify domain
                    alignment_results['spf_aligned'] = (spf_data.lower() == 'pass')
                    logger.debug(f"SPF string result '{spf_data}' considered aligned: {alignment_results['spf_aligned']}")
                else:
                    # For detailed results, check domain alignment
                    spf_domain = spf_data.get('domain', '').lower()
                    if spf_domain:
                        # Implement both strict and relaxed alignment checks
                        alignment_results['spf_aligned'] = (
                            spf_domain == from_domain or  # Strict alignment
                            from_domain.endswith('.' + spf_domain)  # Relaxed alignment
                        )
                        logger.debug(f"SPF domain alignment check: {spf_domain} vs {from_domain} = {alignment_results['spf_aligned']}")
            
            # Process DKIM alignment with support for multiple formats
            dkim_data = auth_results.get('dkim')
            if dkim_data:
                if isinstance(dkim_data, str):
                    # For string results, if DKIM passed, consider it aligned
                    # This assumes relaxed alignment mode as we can't verify domain
                    alignment_results['dkim_aligned'] = (dkim_data.lower() == 'pass')
                    logger.debug(f"DKIM string result '{dkim_data}' considered aligned: {alignment_results['dkim_aligned']}")
                elif isinstance(dkim_data, list):
                    # Handle list of DKIM results (take first passing result)
                    for dkim_entry in dkim_data:
                        if isinstance(dkim_entry, dict):
                            dkim_domain = dkim_entry.get('domain', '').lower()
                            if dkim_domain and dkim_entry.get('result', '').lower() == 'pass':
                                alignment_results['dkim_aligned'] = (
                                    dkim_domain == from_domain or
                                    from_domain.endswith('.' + dkim_domain)
                                )
                                if alignment_results['dkim_aligned']:
                                    break
                elif isinstance(dkim_data, dict):
                    # Handle single DKIM result dictionary
                    dkim_domain = dkim_data.get('domain', '').lower()
                    if dkim_domain:
                        alignment_results['dkim_aligned'] = (
                            dkim_domain == from_domain or
                            from_domain.endswith('.' + dkim_domain)
                        )
                        logger.debug(f"DKIM domain alignment check: {dkim_domain} vs {from_domain} = {alignment_results['dkim_aligned']}")
                        
        except Exception as e:
            logger.error(f"Error checking alignment: {str(e)}")
            logger.debug(f"Record structure: {record}")
            logger.debug(traceback.format_exc())
        
        return alignment_results

    def analyze_authentication_with_alignment(self, record: Dict[str, Any], sender_category: str, system_name: str) -> Tuple[str, Dict[str, bool]]:
        """
        Enhanced version of analyze_authentication that includes alignment checking.
        
        This method analyzes both authentication results and domain alignment,
        with special handling for different sender categories and authentication formats.
        
        Args:
            record: DMARC record data containing authentication results and policy information
            sender_category: Category of the sending system (legitimate, forwarder, security_gateway)
            system_name: Name of the sending system for logging and categorization
            
        Returns:
            Tuple of (authentication_result, alignment_results)
        """
        logger.debug(f"Analyzing authentication and alignment for {system_name} ({sender_category})")
        logger.debug(f"Record structure received: {json.dumps(record, indent=2)}")
        
        # Extract authentication results, handling both string and dict formats
        policy = record.get('policy_evaluated', {})
        auth_results = record.get('auth_results', {})
        
        # Get DKIM and SPF results from both policy evaluation and auth_results
        # Policy evaluation results are used for final disposition
        dkim_policy = policy.get('dkim', 'fail')
        spf_policy = policy.get('spf', 'fail')
        
        # Auth results are used for additional validation
        dkim_auth = auth_results.get('dkim', 'fail')
        spf_auth = auth_results.get('spf', 'fail')
        
        # Handle string results by normalizing to lowercase
        if isinstance(dkim_policy, str):
            dkim_policy = dkim_policy.lower()
        if isinstance(spf_policy, str):
            spf_policy = spf_policy.lower()
        if isinstance(dkim_auth, str):
            dkim_auth = dkim_auth.lower()
        if isinstance(spf_auth, str):
            spf_auth = spf_auth.lower()
            
        # Check domain alignment
        # This will work with the existing check_alignment method
        alignment_results = self.check_alignment(record)
        
        # Initialize authentication result
        auth_result = None
        
        # Special handling for legitimate services (including SendGrid)
        if system_name in LEGITIMATE_SERVERS.values() or '.sendgrid.net' in str(record.get('source_ip_hostname', '')):
            if spf_policy == 'fail':
                if alignment_results['dkim_aligned'] and dkim_policy == 'pass':
                    auth_result = 'forwarded'
                else:
                    auth_result = 'suspicious_legitimate'
            else:
                auth_result = 'authenticated'
        
        # Handle other cases based on authentication and alignment
        elif dkim_policy == 'pass' and spf_policy == 'pass':
            # Both authentications passed - check alignment
            if alignment_results['dkim_aligned'] or alignment_results['spf_aligned']:
                auth_result = 'authenticated'
            else:
                # At least one authentication passed but alignment failed
                auth_result = 'authentication_mismatch'
        
        # Handle forwarded email cases
        elif dkim_policy == 'pass' and sender_category == 'forwarder':
            if alignment_results['dkim_aligned']:
                auth_result = 'forwarded'
            else:
                auth_result = 'suspicious_forward'
        
        # Handle security gateway cases
        elif sender_category == 'security_gateway':
            auth_result = 'security_scanned'
        
        # Default case - potential phishing
        else:
            auth_result = 'potential_phishing'
        
        logger.info(f"Authentication result: {auth_result}, Alignment results: {alignment_results}")
        return auth_result, alignment_results

    def update_alignment_statistics(self, auth_result: str, alignment_results: Dict[str, bool]) -> None:
        """
        Update internal alignment statistics for monitoring and analysis.
        
        These statistics help identify patterns and potential issues with
        email authentication configuration, though they aren't included
        in client-facing reports.
        
        Args:
            auth_result: Result of authentication analysis
            alignment_results: Results of domain alignment checks
        """
        # Track alignment statistics internally
        if not hasattr(self, 'alignment_stats'):
            self.alignment_stats = {
                'total_checked': 0,
                'spf_aligned': 0,
                'dkim_aligned': 0,
                'both_aligned': 0,
                'alignment_issues': {
                    'authentication_mismatch': 0,
                    'suspicious_legitimate': 0
                }
            }
        
        self.alignment_stats['total_checked'] += 1
        
        if alignment_results['spf_aligned']:
            self.alignment_stats['spf_aligned'] += 1
        if alignment_results['dkim_aligned']:
            self.alignment_stats['dkim_aligned'] += 1
        if alignment_results['spf_aligned'] and alignment_results['dkim_aligned']:
            self.alignment_stats['both_aligned'] += 1
        
        # Track specific alignment-related issues
        if auth_result in ('authentication_mismatch', 'suspicious_legitimate'):
            self.alignment_stats['alignment_issues'][auth_result] += 1

    def update_date_range(self, begin_timestamp: str, end_timestamp: str) -> None:
        """Update the analysis date range based on report timestamps"""
        logger.debug(f"Updating date range - Begin: {begin_timestamp}, End: {end_timestamp}")
        try:
            begin_date = datetime.fromtimestamp(int(begin_timestamp))
            end_date = datetime.fromtimestamp(int(end_timestamp))
            
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
        """
        Analyze a single DMARC report and update combined statistics
        
        This enhanced version includes alignment checking while keeping
        technical details internal and maintaining clear client reporting.
        """
        logger.info("\nStarting DMARC report analysis")
        logger.debug(f"Report data: {json.dumps(report_data, indent=2)}")
        
        try:
            # Process report metadata and date range
            begin_time = report_data['report_metadata'].get('date_range_begin')
            end_time = report_data['report_metadata'].get('date_range_end')
            if begin_time and end_time:
                self.update_date_range(begin_time, end_time)
            
            # Track analyzed domain
            domain = report_data['policy_published'].get('domain')
            if domain:
                logger.info(f"Processing domain: {domain}")
                self.combined_results['domains'].add(domain)
            
            # Process individual authentication records
            records = report_data.get('records', [])
            logger.info(f"Processing {len(records)} records")
            
            for record in records:
                # Skip records without source IP
                ip = record.get('source_ip')
                if not ip:
                    logger.warning("Record missing source IP, skipping")
                    continue
                
                # Process email count
                logger.debug(f"\nProcessing record for IP: {ip}")
                count = int(record.get('count', 0))
                self.combined_results['total_emails'] += count
                
                # Perform DNS and sender categorization
                hostname = self.perform_reverse_dns(ip)
                sender_category, system_name = self.categorize_sender(ip, hostname)
                
                # Get geographical information
                geo_info = self.get_ip_geolocation(ip)
                self.combined_results['countries'][geo_info['country']] += count
                
                # Perform enhanced authentication analysis with alignment
                auth_result, alignment_results = self.analyze_authentication_with_alignment(
                    record, sender_category, system_name
                )
                
                # Update alignment statistics (kept internal)
                self.update_alignment_statistics(auth_result, alignment_results)
                
                # Update client-facing statistics based on authentication result
                if auth_result == 'authenticated':
                    self.combined_results['legitimate_systems'][system_name] += count
                elif auth_result == 'forwarded':
                    self.combined_results['forwarded'] += count
                elif auth_result == 'suspicious_forward' or auth_result == 'suspicious_legitimate':
                    self.combined_results['suspicious_forwards'] += count
                elif auth_result == 'security_scanned':
                    self.combined_results['security_scanned'] += count
                elif auth_result == 'potential_phishing' or auth_result == 'authentication_mismatch':
                    self.combined_results['potential_phishing'] += count
                
                # Add alignment-based recommendations if needed
                if auth_result == 'authentication_mismatch':
                    recommendation = (
                        f"Domain alignment issue detected for {system_name}. "
                        "Consider reviewing DMARC policy configuration."
                    )
                    if recommendation not in self.combined_results['misconfigurations']:
                        self.combined_results['misconfigurations'].append(recommendation)
                
                logger.debug(f"Updated combined results: {json.dumps(self.combined_results, default=str, indent=2)}")

        except Exception as e:
            logger.error(f"Error analyzing report: {str(e)}")
            logger.debug(traceback.format_exc())

    def generate_combined_report(self) -> str:
        """
        Generate a human-readable report summarizing all analyzed DMARC data
        
        Creates a comprehensive report including:
        - Overall email statistics
        - Authentication results by system
        - Forwarding analysis
        - Security concerns (phishing attempts)
        - Geographic distribution
        - Recommendations
        
        Returns:
            str: Formatted report text
        """
        logger.info("Generating combined DMARC report")
        
        # Format date range for reporting period
        date_range = ""
        if self.combined_results['date_range']['start'] and self.combined_results['date_range']['end']:
            start_date = self.combined_results['date_range']['start'].strftime("%b %d")
            end_date = self.combined_results['date_range']['end'].strftime("%b %d")
            date_range = f"{start_date} - {end_date}"
        
        # Construct report header and overall statistics
        report_lines = [
            "Email Security Report",
            f"Total Emails Sent: {self.combined_results['total_emails']:,}",
            f"Emails Forwarded: {self.combined_results['forwarded']}",
            f"- Recognized Forwarders: {self.combined_results['forwarded'] - self.combined_results['suspicious_forwards']} emails.",
            f"- Suspicious Forwarders: {self.combined_results['suspicious_forwards']} emails.",
            "",
            "Authentication Results:",
            "- Legitimate Systems:"
        ]
        
        # Add details for each legitimate email system
        for system, count in self.combined_results['legitimate_systems'].items():
            report_lines.append(f"- {system}: {count} emails")
        
        # Add information about forwarded emails
        report_lines.extend([
            "",
            "- Forwarded Emails:",
            f"- {self.combined_results['forwarded']} emails have been forwarded. No action required."
        ])
        
        # Add warning for suspicious forwarding activity
        if self.combined_results['suspicious_forwards'] > 0:
            report_lines.append(
                f"- {self.combined_results['suspicious_forwards']} emails were forwarded via suspicious servers. "
                "Closer monitoring required."
            )
        
        # Add phishing attempt warnings if detected
        if self.combined_results['potential_phishing'] > 0:
            report_lines.extend([
                "",
                "- Phishing Attempts:",
                f"- {self.combined_results['potential_phishing']} phishing emails pretending to come from your domain. "
                "Immediate action required."
            ])
        
        # Add security gateway processing information
        if self.combined_results['security_scanned'] > 0:
            report_lines.extend([
                "",
                "- Security Gateway:",
                f"- {self.combined_results['security_scanned']} emails were scanned by spam filters. "
                "No further action needed."
            ])
        
        # Add geographic distribution summary
        if self.combined_results['countries']:
            report_lines.extend([
                "",
                "Country Summary:"
            ])
            
            # Sort countries by email volume for reporting
            sorted_countries = sorted(
                self.combined_results['countries'].items(),
                key=lambda x: x[1],
                reverse=True
            )
            
            # Format country information for display
            main_country = sorted_countries[0][0]
            other_countries = [country for country, _ in sorted_countries[1:]]
            
            # Add country distribution details
            if date_range and other_countries:
                country_list = ", ".join(other_countries)
                report_lines.append(
                    f'During the week of {date_range}, most of your emails originated from {main_country}, '
                    f'with additional traffic detected from {country_list}.'
                )
            elif date_range:
                report_lines.append(
                    f'During the week of {date_range}, your emails originated from {main_country}.'
                )
        
        # Add any identified misconfigurations or recommendations
        if self.combined_results['misconfigurations']:
            report_lines.extend([
                "",
                "Recommendations:",
                *[f"- {issue}" for issue in self.combined_results['misconfigurations']]
            ])
        
        logger.debug("Report generation complete")
        return "\n".join(report_lines)

def process_dmarc_report(report_data: Dict[str, Any], report_dir: str, analyzer: 'DMARCAnalyzer') -> None:
    """
    Process a single DMARC report and save results
    
    Args:
        report_data: Dictionary containing parsed DMARC report data
        report_dir: Directory to save individual report results
        analyzer: DMARCAnalyzer instance for processing
    """
    logger.info(f"\nProcessing DMARC report for directory: {report_dir}")
    try:
        # Analyze the report data
        analyzer.analyze_dmarc_report(report_data)
        
        # Save individual report results
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, 'report.json')
        logger.debug(f"Saving individual report to: {report_path}")
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        logger.info("Individual report saved successfully")
            
    except Exception as e:
        logger.error(f"Error processing DMARC report: {str(e)}")
        logger.debug(traceback.format_exc())

def save_combined_report(base_dir: str, analyzer: 'DMARCAnalyzer') -> None:
    """
    Save final combined report and analysis results
    
    Creates both a human-readable text report and a JSON file
    containing detailed analysis results.
    
    Args:
        base_dir: Base directory for saving reports
        analyzer: DMARCAnalyzer instance containing analysis results
    """
    logger.info(f"\nSaving combined report to directory: {base_dir}")
    try:
        # Create directory for combined results
        combined_dir = os.path.join(base_dir, 'combined_results')
        os.makedirs(combined_dir, exist_ok=True)
        
        # Generate and save human-readable report
        logger.debug("Generating combined report")
        report_text = analyzer.generate_combined_report()
        
        report_path = os.path.join(combined_dir, 'combined_report.txt')
        logger.debug(f"Saving report to: {report_path}")
        with open(report_path, 'w') as f:
            f.write(report_text)
        
        # Prepare analysis results for JSON serialization
        logger.debug("Preparing results for JSON serialization")
        results_dict = {
            **analyzer.combined_results,
            'legitimate_systems': dict(analyzer.combined_results['legitimate_systems']),
            'countries': dict(analyzer.combined_results['countries']),
            'domains': list(analyzer.combined_results['domains']),
            'date_range': {
                'start': analyzer.combined_results['date_range']['start'].isoformat() 
                    if analyzer.combined_results['date_range']['start'] else None,
                'end': analyzer.combined_results['date_range']['end'].isoformat() 
                    if analyzer.combined_results['date_range']['end'] else None
            }
        }
        
        # Save detailed analysis results as JSON
        analysis_path = os.path.join(combined_dir, 'combined_analysis.json')
        logger.debug(f"Saving analysis results to: {analysis_path}")
        with open(analysis_path, 'w') as f:
            json.dump(results_dict, f, indent=2)
        
        # Log completion and summary
        logger.info(f"Combined report saved successfully to: {report_path}")
        logger.info("\nAnalysis Results Summary:")
        logger.info("========================")
        logger.info(report_text)
        
    except Exception as e:
        logger.error(f"Error saving combined report: {str(e)}")
        logger.debug(traceback.format_exc())


# TODO: ask alex if this is the way to go 
# (google sheet can't be public?) - however this will 
# result in need of redeeming credentials every week in google api
# pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib

# from google.oauth2.credentials import Credentials
# from googleapiclient.discovery import build
# from google.oauth2 import service_account

# def download_legitimate_servers_api():
#     SCOPES = ['https://www.googleapis.com/auth/spreadsheets.readonly']
#     SPREADSHEET_ID = '1yTh7HDf7yoeydtr_fgx54xg_cIkAad6nHRWEwHMKX9c'
#     RANGE_NAME = 'Sheet1!A:C'  # Adjust range as needed
    
#     try:
#         # Load credentials from service account file
#         creds = service_account.Credentials.from_service_account_file(
#             'path/to/service-account-key.json', scopes=SCOPES)
            
#         service = build('sheets', 'v4', credentials=creds)
        
#         # Call the Sheets API
#         sheet = service.spreadsheets()
#         result = sheet.values().get(
#             spreadsheetId=SPREADSHEET_ID,
#             range=RANGE_NAME
#         ).execute()
        
#         values = result.get('values', [])
        
#         # Convert to dictionary
#         LEGITIMATE_SERVERS = {row[0]: row[2] for row in values[1:]}  # Skip header row
        
#         return LEGITIMATE_SERVERS
        
#     except Exception as e:
#         logger.error(f"Failed to download legitimate servers via API: {str(e)}")
#         return {}