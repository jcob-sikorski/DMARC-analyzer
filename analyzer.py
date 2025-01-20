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

# Create the logs directory if it doesn't exist
log_directory = "logs"
os.makedirs(log_directory, exist_ok=True)

# Generate unique log filename with timestamp
log_filename = f'logs/dmarc_analyzer_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'

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
        "178339195": "Phishing"
    }
    
    # Initialize empty structures
    LEGITIMATE_SERVERS = {}  # Dictionary for domain->service mapping
    FORWARDER_SERVERS = set()  # Set for just domain names
    SECURITY_GATEWAYS = set()  # Set for just domain names
    PHISHING_SERVERS = set() # Set for just domain names
    
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

        # Log phishing servers - adding newline for readability
        logger.debug("\nPHISHING_SERVERS:")
        logger.debug(pformat(PHISHING_SERVERS))
        
        return LEGITIMATE_SERVERS, FORWARDER_SERVERS, SECURITY_GATEWAYS, PHISHING_SERVERS
        
    except Exception as e:
        logger.error(f"Failed to download DMARC dictionaries: {str(e)}")
        return {}, {}, {}

# from the google sheets
# Known legitimate email service providers and their corresponding services
LEGITIMATE_SERVERS, FORWARDER_SERVERS, SECURITY_GATEWAYS, PHISHING_SERVERS = download_dmarc_dictionaries()

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
        """Reset all analysis results to initial state"""
        logger.info("Resetting analyzer state")
        # Domain-specific results
        self.domain_results = defaultdict(lambda: {
            'total_emails': 0,
            'legitimate_systems': defaultdict(int),
            'forwarded': 0,
            'suspicious_forwards': 0,
            'phishing': 0,
            'security_scanned': 0,
            'countries': defaultdict(int),
            'misconfigurations': []
        })

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
        Categorize email sender with enhanced SendGrid detection rules.
        
        Special SendGrid classification rules:
        1. If hostname matches the current domain being analyzed (e.g., mail.example.com)
        2. If hostname contains sendgrid.net regardless of IP list
        
        Other classification follows standard hierarchy:
        1. Check for missing/unknown hostname (phishing indicator)
        2. Check against known phishing domains
        3. Check against legitimate servers
        4. Check forwarders and security gateways
        5. Default to potential phishing for unknown systems
        
        Args:
            ip: The IP address of the sender
            hostname: The hostname to categorize
                    
        Returns:
            tuple: (category, system_name)
        """
        logger.debug(f"Categorizing sender - IP: {ip}, Hostname: {hostname}")
        
        # Handle missing or failed DNS lookup
        if hostname == "Unknown" or not hostname:
            logger.warning(f"No valid hostname for IP {ip} - marking as phishing")
            return 'phishing', 'Unknown Sender (No DNS)'
        
        hostname_lower = hostname.lower()
        
        # Enhanced SendGrid Detection Rules
        if hasattr(self, 'current_domain') and self.current_domain:
            current_domain_lower = self.current_domain.lower()
            # Rule 1: Hostname matches current domain
            if current_domain_lower in hostname_lower:
                logger.info(f"Sender {ip} ({hostname}) matches current domain - categorizing as SendGrid")
                return 'legitimate', 'SendGrid'
        
        # Rule 2: Hostname contains sendgrid.net
        if 'sendgrid.net' in hostname_lower:
            logger.info(f"Sender {ip} ({hostname}) contains sendgrid.net - categorizing as SendGrid")
            return 'legitimate', 'SendGrid'
        
        # Standard classification hierarchy
        if any(domain in hostname_lower for domain in PHISHING_SERVERS):
            logger.warning(f"Matched known phishing domain: {hostname}")
            return 'phishing', 'Known Phishing Domain'
        
        for domain, service_name in LEGITIMATE_SERVERS.items():
            if domain in hostname_lower:
                logger.info(f"Sender {ip} ({hostname}) categorized as legitimate: {service_name}")
                return 'legitimate', service_name
        
        for domain in FORWARDER_SERVERS:
            if domain in hostname_lower:
                logger.info(f"Sender {ip} ({hostname}) categorized as forwarder")
                return 'forwarder', 'Email Forwarder'
        
        for domain in SECURITY_GATEWAYS:
            if domain in hostname_lower:
                logger.info(f"Sender {ip} ({hostname}) categorized as security gateway")
                return 'security_gateway', 'Security Gateway'
        
        logger.warning(f"Unknown sender {ip} ({hostname}) - marking as potential phishing")
        return 'phishing', 'Unknown System'

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

    def analyze_authentication(self, record: Dict[str, Any], sender_category: str, system_name: str) -> Tuple[str, Dict[str, bool]]:
        """
        Authentication analysis implementing all specified requirements exactly.
        
        Core authentication rules:
        1. SendGrid special cases:
            - If hostname matches current domain: Classify as SendGrid
            - If hostname contains sendgrid.net: Classify as SendGrid
        
        2. DKIM Pass + SPF Fail cases:
            - For Outlook/Google: Always mark as forwarded
            - For Legitimate List + DKIM aligned: Use system name (e.g., Mailchimp)
            - For Forwarder List: Mark as forwarded
            - For unrecognized: Mark as suspicious forward
        
        3. Both Fail or DKIM not aligned + SPF fail:
            - For Phishing List: Mark as phishing
            - For Security Gateway: Mark as security scanned
            - For Legitimate List: Mark as "[System] Misconfigured"
            - For unrecognized: Mark as phishing
        
        4. Both Pass:
            - Mark as authenticated with system name
        
        Args:
            record: DMARC record data
            sender_category: Category from categorize_sender
            system_name: System name from categorize_sender
            
        Returns:
            Tuple of (authentication_result, alignment_results)
        """
        logger.debug(f"Analyzing authentication for {system_name} ({sender_category})")
        
        # Extract authentication results
        policy = record.get('policy_evaluated', {})
        dkim_policy = policy.get('dkim', 'fail').lower()
        spf_policy = policy.get('spf', 'fail').lower()
        
        # Get alignment results - critical for categorization
        alignment_results = self.check_alignment(record)
        
        # Extract hostname for SendGrid and special case checking
        source_ip = record.get('source_ip', '')
        hostname = self.perform_reverse_dns(source_ip) if source_ip else ''
        hostname_lower = hostname.lower()
        
        # Initialize authentication result
        auth_result = None
        
        # Case 1: DKIM Pass, SPF Fail
        if dkim_policy == 'pass' and spf_policy == 'fail':
            # Special case: Outlook/Google always indicates forwarding
            if any(domain in hostname_lower for domain in ['outlook.com', 'google.com']) or sender_category == 'forwarder':
                auth_result = 'forwarded'
            # For legitimate systems with aligned DKIM, use system name
            elif alignment_results['dkim_aligned']:
                if sender_category == 'legitimate':
                    auth_result = 'legitimate'
                else:
                    auth_result = 'suspicious_forward'
            else:
                auth_result = 'suspicious_forward'
                
        # Case 2: Both Fail
        elif dkim_policy == 'fail' and spf_policy == 'fail':
            if sender_category == 'security_gateway':
                auth_result = 'security_scanned'
            elif sender_category == 'legitimate':
                auth_result = 'misconfigured'  # Don't mark legitimate servers as phishing
            elif sender_category == 'phishing':
                auth_result = 'phishing'  # Only mark as phishing if on phishing list
            else:
                auth_result = 'suspicious_forward'  # Otherwise mark as suspicious
                
        # Case 3: Both Pass
        elif dkim_policy == 'pass' and spf_policy == 'pass':
            auth_result = 'legitimate'
                
        # Case 4: Any other combination is a mismatch
        else:
            auth_result = 'authentication_mismatch'
            
        logger.info(f"Authentication result: {auth_result}, Alignment results: {alignment_results}")
        return auth_result, alignment_results

    def analyze_dmarc_report(self, report_data: Dict[str, Any]) -> None:
        """Analyze a single DMARC report and update both domain-specific statistics"""
        
        logger.info("\nStarting DMARC report analysis")

        try:
            domain = report_data['policy_published'].get('domain')
            if not domain:
                logger.warning("Report missing domain, skipping")
                return
            
            # Store current domain for SendGrid classification
            self.current_domain = domain
            
            records = report_data.get('records', [])
            logger.info(f"Processing {len(records)} records for domain {domain}")
            
            for record in records:
                ip = record.get('source_ip')
                if not ip:
                    continue
                
                count = int(record.get('count', 0))
                
                # Update both domain email counts
                self.domain_results[domain.lower()]['total_emails'] += count
                
                hostname = self.perform_reverse_dns(ip)
                sender_category, system_name = self.categorize_sender(ip, hostname)
                
                geo_info = self.get_ip_geolocation(ip)
                self.domain_results[domain.lower()]['countries'][geo_info['country']] += count
                
                auth_result, alignment_results = self.analyze_authentication(
                    record, sender_category, system_name
                )

                if auth_result == 'legitimate':
                    self.domain_results[domain.lower()]['legitimate_systems'][system_name] += count
                elif auth_result == 'forwarded':
                    self.domain_results[domain.lower()]['forwarded'] += count
                elif auth_result in ('suspicious_forward'):
                    self.domain_results[domain.lower()]['suspicious_forwards'] += count
                elif auth_result == 'security_scanned':
                    self.domain_results[domain.lower()]['security_scanned'] += count
                elif auth_result in ('phishing'):
                    self.domain_results[domain.lower()]['phishing'] += count

            # # Clear current domain after processing
            self.current_domain = None
            
        except Exception as e:
            logger.error(f"Error analyzing report: {str(e)}")
            logger.debug(traceback.format_exc())

    def generate_domain_report(self) -> str:
        """Generate a human-readable report with domain-specific breakdowns"""
        logger.info("Generating domain-specific DMARC report")
        
        report_lines = ["Email Security Report by Domain", ""]
        
        for domain, results in self.domain_results.items():
            # Calculate recognized forwarders (ensure non-negative)
            total_forwarded = max(0, results['forwarded'])
            suspicious_forwards = max(0, results['suspicious_forwards'])
            recognized_forwards = max(0, total_forwarded - suspicious_forwards)
            
            report_lines.extend([
                f"Domain: {domain}",
                f"Total Emails Sent: {results['total_emails']:,}",
                f"Emails Forwarded: {total_forwarded}",
                f"- Recognized Forwarders: {recognized_forwards} emails",
                f"- Suspicious Forwarders: {suspicious_forwards} emails",
                "",
                "Authentication Results:",
                "- Legitimate Systems:"
            ])
            
            for system, count in results['legitimate_systems'].items():
                report_lines.append(f"  - {system}: {count} emails")
            
            report_lines.extend([
                "",
                "- Forwarded Emails:",
                f"  - {total_forwarded} emails have been forwarded. No action required."
            ])
            
            if suspicious_forwards > 0:
                report_lines.append(
                    f"  - {suspicious_forwards} emails were forwarded via suspicious servers. "
                    "Closer monitoring required."
                )
            
            if results['phishing'] > 0:
                report_lines.extend([
                    "",
                    "- Phishing Attempts:",
                    f"  - {results['phishing']} phishing emails pretending to come from this domain. "
                    "Immediate action required."
                ])
            
            if results['security_scanned'] > 0:
                report_lines.extend([
                    "",
                    "- Security Gateway:",
                    f"  - {results['security_scanned']} emails were scanned by spam filters. "
                    "No further action needed."
                ])
            
            if results.get('countries'):
                report_lines.extend(["\nCountry Summary:"])
                sorted_countries = sorted(
                    results['countries'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:4]  # Get top 4 countries
                
                if sorted_countries:
                    main_country = sorted_countries[0][0]
                    other_countries = [country for country, _ in sorted_countries[1:]]
                    
                    if other_countries:
                        country_list = ", and ".join([", ".join(other_countries[:-1]), other_countries[-1]] if len(other_countries) > 1 else other_countries)
                        report_lines.append(
                            f"During last week, most of your emails originated from {main_country}, "
                            f"with additional traffic detected from {country_list}."
                        )
                    else:
                        report_lines.append(
                            f"During last week, most of your emails originated from {main_country}."
                        )
            
            report_lines.extend(["", "-" * 80, ""])
        
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
            
    except Exception as e:
        logger.error(f"Error processing DMARC report: {str(e)}")
        logger.debug(traceback.format_exc())

def save_reports(base_dir: str, analyzer: 'DMARCAnalyzer') -> None:
    """
    Save final domain-specific reports with proper error handling and logging
    
    Creates a directory structure:
    base_dir/
    └── domain_reports/
        ├── example.com/
        │   ├── report.txt
        │   └── analysis.json
        └── another-domain.com/
            ├── report.txt
            └── analysis.json
    
    Args:
        base_dir: Base directory for saving reports
        analyzer: DMARCAnalyzer instance containing analysis results
    """
    logger.info(f"Starting report generation process in directory: {base_dir}")
    logger.info(f"Number of domains to process: {len(analyzer.domain_results)}")
    
    try:
        # Create directories for domain-specific results
        domain_dir = os.path.join(base_dir, 'domain_reports')
        logger.debug(f"Creating main domain reports directory: {domain_dir}")
        os.makedirs(domain_dir, exist_ok=True)
        
        # Generate the complete domain report text first
        logger.debug("Generating complete domain report text")
        domain_report_text = analyzer.generate_domain_report()
        logger.debug(f"Generated report text length: {len(domain_report_text)} characters")
        
        # Split the report into sections by domain
        logger.debug("Splitting report into domain-specific sections")
        sections = domain_report_text.split("-" * 80)
        domain_sections = {}
        logger.debug(f"Number of sections found: {len(sections)}")
        
        # Process each section to identify the domain and content
        for i, section in enumerate(sections, 1):
            logger.debug(f"Processing section {i}/{len(sections)}")
            if not section.strip():
                logger.debug(f"Section {i} is empty, skipping")
                continue
                
            # Find all domains mentioned in the section
            section_matched = False
            for domain in analyzer.domain_results.keys():
                if domain.lower() in section.lower():
                    domain_sections[domain] = section.strip()
                    logger.debug(f"Matched section {i} to domain: {domain}")
                    section_matched = True
                    break
            
            if not section_matched:
                logger.warning(f"Section {i} could not be matched to any domain")
        
        # Save individual domain reports and analysis
        logger.info(f"Beginning to save individual domain reports. Found {len(domain_sections)} domain sections")
        for domain in analyzer.domain_results:
            logger.info(f"Processing domain: {domain}")
            
            # Create domain-specific directory
            domain_specific_dir = os.path.join(domain_dir, domain)
            logger.debug(f"Creating directory for {domain}: {domain_specific_dir}")
            os.makedirs(domain_specific_dir, exist_ok=True)
            
            # Save domain report text
            domain_report_path = os.path.join(domain_specific_dir, 'report.txt')
            logger.debug(f"Preparing to save report for {domain} to: {domain_report_path}")
            
            # Get this domain's section from our processed sections
            if domain in domain_sections:
                section_length = len(domain_sections[domain])
                logger.debug(f"Found report section for {domain} ({section_length} characters)")
                with open(domain_report_path, 'w') as f:
                    f.write(domain_sections[domain])
                logger.info(f"Successfully saved report for {domain} to {domain_report_path}")
            else:
                logger.warning(f"No report section found for domain: {domain}")
            
            # Save domain analysis results
            logger.debug(f"Preparing analysis results for {domain}")
            try:
                domain_results_dict = {
                    **analyzer.domain_results[domain.lower()],
                    'legitimate_systems': dict(analyzer.domain_results[domain.lower()]['legitimate_systems']),
                    'countries': dict(analyzer.domain_results[domain.lower()]['countries'])
                }
                
                domain_analysis_path = os.path.join(domain_specific_dir, 'analysis.json')
                logger.debug(f"Saving analysis for {domain} to: {domain_analysis_path}")
                with open(domain_analysis_path, 'w') as f:
                    json.dump(domain_results_dict, f, indent=2)
                logger.info(f"Successfully saved analysis results for {domain} to {domain_analysis_path}")
                
            except KeyError as ke:
                logger.error(f"Missing key in domain results for {domain}: {str(ke)}")
                logger.debug(f"Available keys: {list(analyzer.domain_results[domain.lower()].keys())}")
            except TypeError as te:
                logger.error(f"Type error while processing results for {domain}: {str(te)}")
            
        logger.info("All reports saved successfully")
        logger.info("\nSummary of saved files:")
        logger.info(f"Base directory: {base_dir}")
        logger.info(f"Total domains processed: {len(analyzer.domain_results)}")
        logger.info("Individual domain reports:")
        for domain in analyzer.domain_results:
            domain_path = os.path.join(domain_dir, domain)
            report_exists = os.path.exists(os.path.join(domain_path, 'report.txt'))
            analysis_exists = os.path.exists(os.path.join(domain_path, 'analysis.json'))
            logger.info(f"- {domain}:")
            logger.info(f"  Directory: {domain_path}")
            logger.info(f"  Report: {'✓' if report_exists else '✗'}")
            logger.info(f"  Analysis: {'✓' if analysis_exists else '✗'}")
            
    except OSError as ose:
        logger.error(f"OS error while saving reports: {str(ose)}")
        logger.debug(f"Error details: {traceback.format_exc()}")
    except Exception as e:
        logger.error(f"Unexpected error while saving reports: {str(e)}")
        logger.debug(f"Error details: {traceback.format_exc()}")

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