import logging
from typing import Dict, Any, List, Tuple, Optional
import socket
import requests
from collections import defaultdict
import datetime
import os
import json
import traceback

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dmarc_analyzer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constants for server categorization
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

FORWARDER_SERVERS = {
    'protonmail': 'ProtonMail',
    'fastmail.com': 'FastMail',
    'forwardemail.net': 'Forward Email',
    'improvmx.com': 'ImprovMX',
    'zoho.com': 'Zoho Mail',
    'pobox.com': 'Pobox'
}

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

# Cache class with debug logging
class Cache:
    def __init__(self, cache_file: str):
        logger.info(f"Initializing cache with file: {cache_file}")
        self.cache_file = cache_file
        self.cache = {}
        self.load()
    
    def load(self) -> None:
        """Load cache from disk"""
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
        """Save cache to disk"""
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
        """Get value from cache"""
        value = self.cache.get(key)
        logger.debug(f"Cache get: {key} -> {value}")
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set value in cache and save to disk"""
        logger.debug(f"Cache set: {key} = {value}")
        self.cache[key] = value
        self.save()

class DMARCAnalyzer:
    def __init__(self):
        logger.info("Initializing DMARCAnalyzer")
        # Initialize caches
        self.dns_cache = Cache('cache/dns_cache.json')
        self.geo_cache = Cache('cache/geo_cache.json')
        self.reset()

    def reset(self):
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
        logger.debug(f"Categorizing sender - IP: {ip}, Hostname: {hostname}")
        hostname_lower = hostname.lower()
        
        # Check each category and log the result
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
        logger.debug(f"Analyzing authentication for {system_name} ({sender_category})")
        logger.debug(f"Authentication record: {record}")
        
        policy = record['policy_evaluated']
        dkim_result = policy['dkim']
        spf_result = policy['spf']
        
        logger.info(f"Authentication results - DKIM: {dkim_result}, SPF: {spf_result}")
        
        if system_name in ['Microsoft 365', 'Google Workspace'] and spf_result == 'fail':
            logger.info(f"Special case: {system_name} with SPF fail -> forwarded")
            return 'forwarded'
        
        # Log the authentication decision process
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
        logger.info("\nStarting DMARC report analysis")
        logger.debug(f"Report data: {json.dumps(report_data, indent=2)}")
        
        try:
            # Update date range
            begin_time = report_data['report_metadata'].get('date_range_begin')
            end_time = report_data['report_metadata'].get('date_range_end')
            if begin_time and end_time:
                self.update_date_range(begin_time, end_time)
            
            # Track domain
            domain = report_data['policy_published'].get('domain')
            if domain:
                logger.info(f"Processing domain: {domain}")
                self.combined_results['domains'].add(domain)
            
            # Process records
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
                
                hostname = self.perform_reverse_dns(ip)
                sender_category, system_name = self.categorize_sender(ip, hostname)
                logger.debug(f"Sender info - Category: {sender_category}, System: {system_name}")
                
                geo_info = self.get_ip_geolocation(ip)
                self.combined_results['countries'][geo_info['country']] += count
                logger.debug(f"Geolocation: {geo_info}")
                
                auth_result = self.analyze_authentication(record, sender_category, system_name)
                logger.debug(f"Authentication result: {auth_result}")
                
                # Update results
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
        Generate a plain-text combined report based on the analyzed DMARC data.
        Returns a formatted string containing the report.
        """
        logger.info("Generating combined DMARC report")
        
        # Format date range for the report
        date_range = ""
        if self.combined_results['date_range']['start'] and self.combined_results['date_range']['end']:
            start_date = self.combined_results['date_range']['start'].strftime("%b %d")
            end_date = self.combined_results['date_range']['end'].strftime("%b %d")
            date_range = f"{start_date} - {end_date}"
        
        # Build the report sections
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
        
        # Add legitimate systems section
        for system, count in self.combined_results['legitimate_systems'].items():
            report_lines.append(f"- {system}: {count} emails")
        
        # Add forwarded emails section
        report_lines.extend([
            "",
            "- Forwarded Emails:",
            f"- {self.combined_results['forwarded']} emails have been forwarded. No action required."
        ])
        
        if self.combined_results['suspicious_forwards'] > 0:
            report_lines.append(
                f"- {self.combined_results['suspicious_forwards']} emails were forwarded via suspicious servers. "
                "Closer monitoring required."
            )
        
        # Add phishing attempts section
        if self.combined_results['potential_phishing'] > 0:
            report_lines.extend([
                "",
                "- Phishing Attempts:",
                f"- {self.combined_results['potential_phishing']} phishing emails pretending to come from your domain. "
                "Immediate action required."
            ])
        
        # Add security gateway section
        if self.combined_results['security_scanned'] > 0:
            report_lines.extend([
                "",
                "- Security Gateway:",
                f"- {self.combined_results['security_scanned']} emails were scanned by spam filters. "
                "No further action needed."
            ])
        
        # Add country summary
        if self.combined_results['countries']:
            report_lines.extend([
                "",
                "Country Summary:"
            ])
            
            # Sort countries by email volume
            sorted_countries = sorted(
                self.combined_results['countries'].items(),
                key=lambda x: x[1],
                reverse=True
            )
            
            # Format countries for display
            main_country = sorted_countries[0][0]
            other_countries = [country for country, _ in sorted_countries[1:]]
            
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
        
        # Add any misconfigurations or recommendations
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
    Process a DMARC report and save individual results.
    The analyzer parameter is type-hinted with a string to avoid the forward reference issue.
    """
    logger.info(f"\nProcessing DMARC report for directory: {report_dir}")
    try:
        analyzer.analyze_dmarc_report(report_data)
        
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
    Save the combined report from all processed DMARC reports.
    The analyzer parameter is type-hinted with a string to avoid the forward reference issue.
    """
    logger.info(f"\nSaving combined report to directory: {base_dir}")
    try:
        combined_dir = os.path.join(base_dir, 'combined_results')
        os.makedirs(combined_dir, exist_ok=True)
        
        logger.debug("Generating combined report")
        report_text = analyzer.generate_combined_report()
        
        report_path = os.path.join(combined_dir, 'combined_report.txt')
        logger.debug(f"Saving report to: {report_path}")
        with open(report_path, 'w') as f:
            f.write(report_text)
        
        # Prepare results for JSON
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
        
        analysis_path = os.path.join(combined_dir, 'combined_analysis.json')
        logger.debug(f"Saving analysis results to: {analysis_path}")
        with open(analysis_path, 'w') as f:
            json.dump(results_dict, f, indent=2)
        
        logger.info(f"Combined report saved successfully to: {report_path}")
        logger.info("\nAnalysis Results Summary:")
        logger.info("========================")
        logger.info(report_text)
        
    except Exception as e:
        logger.error(f"Error saving combined report: {str(e)}")
        logger.debug(traceback.format_exc())