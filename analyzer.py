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

# from the google sheets
# Known legitimate email service providers and their corresponding services
LEGITIMATE_SERVERS, FORWARDER_SERVERS, SECURITY_GATEWAYS = download_dmarc_dictionaries()

# TODO: understand what this cache class does and what's the purpose of it in the first 
# place -- if it's not important - delete it -- else add external memory to store 
# the cache for each run of the script

# TODO: check if Maintain a database for known IP-to-system mappings. 
# Cache reverse DNS and geolocation results to reduce repeated lookups. 


# Cache class to store DNS and geolocation lookups
# This reduces API calls and improves performance

# TODO: we could host and use redis as lookup cache (is this important or can 
# we use the file) -- what would be the efficiency gain compared to implementation time cost?
# If you're not using the cache for any of these purposes, or if you're only using
# it for small amounts of data that could be recomputed quickly,
# you might want to remove it and either:
# Store the data directly in your application's memory
# Use a simpler persistence mechanism like a configuration file
# Recompute the data as needed
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
            """
            Analyze a single DMARC report and update combined statistics
            
            This method processes each DMARC report by:
            1. Extracting date ranges and domains
            2. Processing individual records for authentication results
            3. Updating cumulative statistics
            4. Tracking geographic distribution
            """
            logger.info("\nStarting DMARC report analysis")
            logger.debug(f"Report data: {json.dumps(report_data, indent=2)}")
            
            try:
                # Extract and update the date range for the reporting period
                begin_time = report_data['report_metadata'].get('date_range_begin')
                end_time = report_data['report_metadata'].get('date_range_end')
                if begin_time and end_time:
                    self.update_date_range(begin_time, end_time)
                
                # Track the domain being analyzed
                domain = report_data['policy_published'].get('domain')
                if domain:
                    logger.info(f"Processing domain: {domain}")
                    self.combined_results['domains'].add(domain)
                
                # Process each authentication record in the report
                records = report_data.get('records', [])
                logger.info(f"Processing {len(records)} records")
                
                for record in records:
                    # Extract source IP and skip if missing
                    ip = record.get('source_ip')
                    if not ip:
                        logger.warning("Record missing source IP, skipping")
                        continue
                    
                    # Process email count for this record
                    logger.debug(f"\nProcessing record for IP: {ip}")
                    count = int(record.get('count', 0))
                    self.combined_results['total_emails'] += count
                    logger.debug(f"Email count: {count}")
                    
                    # Perform DNS and sender categorization
                    hostname = self.perform_reverse_dns(ip)
                    sender_category, system_name = self.categorize_sender(ip, hostname)
                    logger.debug(f"Sender info - Category: {sender_category}, System: {system_name}")
                    
                    # Get and record geographical information
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
def download_dmarc_dictionaries():
    """
    Downloads all three dictionaries (legitimate servers, forwarders, security gateways)
    from the Google Sheet.
    
    Returns:
        tuple: (LEGITIMATE_SERVERS, FORWARDER_SERVERS, SECURITY_GATEWAYS)
    """
    # URL of the published Google Sheet
    sheet_url = "https://docs.google.com/spreadsheets/d/1yTh7HDf7yoeydtr_fgx54xg_cIkAad6nHRWEwHMKX9c/edit?gid=0#gid=0"
    
    try:
        # Convert sheet URL to export URL
        export_url = sheet_url.replace('/edit?gid=0#gid=0', '/export?format=csv')
        
        # Read the CSV into a pandas DataFrame
        df = pd.read_csv(export_url)
        
        # Initialize empty dictionaries
        LEGITIMATE_SERVERS = {}
        FORWARDER_SERVERS = {}
        SECURITY_GATEWAYS = {}
        
        # Process each row based on the category (visible in the screenshot's bottom tabs)
        for index, row in df.iterrows():
            domain = row.iloc[0]
            category = row.iloc[1]  # Assuming column B has the category
            service = row.iloc[2]   # Assuming column C has the service name
            
            # Remove any leading asterisk (*) from domain
            if isinstance(domain, str):
                domain = domain.strip('*')
            
            # Add to appropriate dictionary based on category
            if category == 'Legitimate':
                LEGITIMATE_SERVERS[domain] = service
            elif category == 'Forwarders':
                FORWARDER_SERVERS[domain] = service
            elif category == 'Security Gateway':
                SECURITY_GATEWAYS[domain] = service
        
        return LEGITIMATE_SERVERS, FORWARDER_SERVERS, SECURITY_GATEWAYS
        
    except Exception as e:
        logger.error(f"Failed to download DMARC dictionaries: {str(e)}")
        return {}, {}, {}