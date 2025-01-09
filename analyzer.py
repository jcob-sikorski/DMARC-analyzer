from typing import Dict, Any, List, Tuple
import socket
import requests
from collections import defaultdict
import datetime
import os
import json

# Constants for sender categorization
LEGITIMATE_SERVERS = {
    'mailchimp.com': 'Mailchimp',
    'followupboss.com': 'Follow Up Boss',
    'kvcore.com': 'kvCore',
    'outlook.com': 'Microsoft 365',
    'google.com': 'Google Workspace',
    'protection.outlook.com': 'Microsoft 365'
}

FORWARDER_SERVERS = {
    'gmail.com': 'Gmail',
    'yahoo.com': 'Yahoo',
    'outlook.com': 'Outlook',
    'hotmail.com': 'Hotmail',
    'aol.com': 'AOL'
}

SECURITY_GATEWAYS = {
    'mimecast.com': 'Mimecast',
    'barracuda.com': 'Barracuda',
    'proofpoint.com': 'Proofpoint'
}

# Cache dictionaries
dns_cache = {}
geo_cache = {}

def perform_reverse_dns(ip: str) -> str:
    """
    Perform reverse DNS lookup with caching
    """
    if ip in dns_cache:
        return dns_cache[ip]
    
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        dns_cache[ip] = hostname
        return hostname
    except (socket.herror, socket.gaierror):
        dns_cache[ip] = "Unknown"
        return "Unknown"

def get_ip_geolocation(ip: str) -> Dict[str, str]:
    """
    Get IP geolocation information using ipinfo.io
    """
    if ip in geo_cache:
        return geo_cache[ip]
    
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            geo_cache[ip] = {
                'country': data.get('country', 'Unknown'),
                'city': data.get('city', 'Unknown')
            }
            return geo_cache[ip]
    except Exception:
        pass
    
    geo_cache[ip] = {'country': 'Unknown', 'city': 'Unknown'}
    return geo_cache[ip]

def categorize_sender(ip: str, hostname: str) -> Tuple[str, str]:
    """
    Categorize the sender based on IP and hostname
    Returns (category, system_name)
    """
    hostname_lower = hostname.lower()
    
    # Check legitimate servers
    for domain, name in LEGITIMATE_SERVERS.items():
        if domain in hostname_lower:
            return 'legitimate', name
    
    # Check forwarders
    for domain, name in FORWARDER_SERVERS.items():
        if domain in hostname_lower:
            return 'forwarder', name
    
    # Check security gateways
    for domain, name in SECURITY_GATEWAYS.items():
        if domain in hostname_lower:
            return 'security_gateway', name
    
    return 'unknown', 'Unknown System'

def analyze_authentication(record: Dict[str, Any], sender_category: str) -> str:
    """
    Analyze authentication results and categorize the email
    """
    policy = record['policy_evaluated']
    dkim_result = policy['dkim']
    spf_result = policy['spf']
    
    if dkim_result == 'pass' and spf_result == 'pass':
        return 'authenticated'
    
    if dkim_result == 'pass' and sender_category == 'legitimate':
        return 'legitimate_with_spf_fail'
    
    if dkim_result == 'pass' and sender_category == 'forwarder':
        return 'forwarded'
    
    if dkim_result == 'pass':
        return 'suspicious_forward'
    
    if sender_category == 'security_gateway':
        return 'security_scanned'
    
    return 'potential_phishing'

def generate_report(dmarc_data: Dict[str, Any], analysis_results: Dict[str, Any]) -> str:
    """
    Generate a plain-text report from the analysis results
    """
    report = []
    report.append("Email Security Report")
    report.append("===================")
    report.append("")
    
    try:
        # Date range
        begin_date = datetime.datetime.fromtimestamp(
            int(dmarc_data['report_metadata']['date_range_begin']), 
            datetime.timezone.utc
        ).strftime('%Y-%m-%d')
        
        end_date = datetime.datetime.fromtimestamp(
            int(dmarc_data['report_metadata']['date_range_end']), 
            datetime.timezone.utc
        ).strftime('%Y-%m-%d')
        report.append(f"Period: {begin_date} to {end_date}")
    except (ValueError, KeyError) as e:
        report.append("Period: Date range unavailable")
    
    report.append("")
    
    # Total statistics
    total_emails = analysis_results['total_emails']
    report.append(f"Total Emails Analyzed: {total_emails}")
    
    # Legitimate Systems
    report.append("\nLegitimate Systems:")
    for system, count in analysis_results['legitimate_systems'].items():
        report.append(f"- {system}: {count} emails")
    
    # Forwarded Emails
    forwarded = analysis_results['forwarded']
    suspicious_forwards = analysis_results['suspicious_forwards']
    if forwarded or suspicious_forwards:
        report.append("\nForwarded Emails:")
        if forwarded:
            report.append(f"- {forwarded} emails have been forwarded. No action required.")
        if suspicious_forwards:
            report.append(f"- {suspicious_forwards} emails were forwarded via suspicious servers. Closer monitoring required.")
    
    # Security Gateway
    if analysis_results['security_scanned']:
        report.append(f"\nSecurity Gateway:")
        report.append(f"- {analysis_results['security_scanned']} emails were scanned by spam filters. No further action needed.")
    
    # Phishing Attempts
    if analysis_results['potential_phishing']:
        report.append(f"\nPhishing Attempts:")
        report.append(f"- {analysis_results['potential_phishing']} phishing emails pretending to come from your domain. Immediate action required.")
    
    # Geographic Summary
    report.append("\nCountry Summary:")
    countries = analysis_results['countries']
    if countries:
        main_country = max(countries.items(), key=lambda x: x[1])[0]
        other_countries = [k for k, v in countries.items() if k != main_country]
        country_text = f"Most of your emails originated from {main_country}"
        if other_countries:
            country_text += f", with additional traffic detected from {', '.join(other_countries)}"
        report.append(country_text + ".")
    
    # Recommendations
    report.append("\nRecommendations:")
    if analysis_results['potential_phishing']:
        report.append("- Enable strong DMARC policy to block phishing attempts")
    if analysis_results['suspicious_forwards']:
        report.append("- Monitor suspicious forwarding activity")
    if not all(system in analysis_results['legitimate_systems'] for system in LEGITIMATE_SERVERS.values()):
        report.append("- Review email configuration for all legitimate systems")
    
    return "\n".join(report)

def analyze_dmarc_report(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a DMARC report and return structured results
    """
    results = {
        'total_emails': 0,
        'legitimate_systems': defaultdict(int),
        'forwarded': 0,
        'suspicious_forwards': 0,
        'potential_phishing': 0,
        'security_scanned': 0,
        'countries': defaultdict(int)
    }
    
    for record in report_data['records']:
        ip = record['source_ip']
        count = int(record['count'])
        results['total_emails'] += count
        
        # Get hostname and location
        hostname = perform_reverse_dns(ip)
        geo_info = get_ip_geolocation(ip)
        results['countries'][geo_info['country']] += count
        
        # Categorize sender
        sender_category, system_name = categorize_sender(ip, hostname)
        
        # Analyze authentication
        auth_result = analyze_authentication(record, sender_category)
        
        # Update results based on authentication and categorization
        if auth_result == 'authenticated' or auth_result == 'legitimate_with_spf_fail':
            results['legitimate_systems'][system_name] += count
        elif auth_result == 'forwarded':
            results['forwarded'] += count
        elif auth_result == 'suspicious_forward':
            results['suspicious_forwards'] += count
        elif auth_result == 'security_scanned':
            results['security_scanned'] += count
        elif auth_result == 'potential_phishing':
            results['potential_phishing'] += count
    
    return results

def process_dmarc_report(report_data: Dict[str, Any], report_dir: str) -> str:
    """
    Process a DMARC report and generate a plain-text summary
    """
    try:
        # Analyze the report
        analysis_results = analyze_dmarc_report(report_data)
        
        # Generate the report
        report_text = generate_report(report_data, analysis_results)
        
        # Save the analysis results and report
        with open(os.path.join(report_dir, 'analysis_results.json'), 'w') as f:
            json.dump(analysis_results, f, indent=2)
        
        with open(os.path.join(report_dir, 'report.txt'), 'w') as f:
            f.write(report_text)
        
        print(f"Analysis complete. Report saved to: {os.path.join(report_dir, 'report.txt')}")
        return report_text
    except Exception as e:
        error_msg = f"Error processing DMARC report: {str(e)}"
        print(error_msg)
        return error_msg