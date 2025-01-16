from typing import Dict, Any, Optional
import logging
import os
import json
import datetime
from collections import defaultdict
import xml.etree.ElementTree as ET
import gzip
import zipfile

# Set up logging with both file and console output for better debugging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dmarc_counting.log'),
        logging.StreamHandler()
    ]
)

def extract_compressed_file(file_path: str, extract_dir: str) -> Optional[str]:
    """
    Extract DMARC reports from compressed files (ZIP or GZIP).
    
    Args:
        file_path: Path to the compressed file
        extract_dir: Directory where files should be extracted
        
    Returns:
        Optional[str]: Path to the extracted report file, or None if extraction fails
    """
    logging.info(f"Extracting file: {file_path}")
    
    try:
        # Create a unique subdirectory for each extracted file to avoid naming conflicts
        file_basename = os.path.splitext(os.path.basename(file_path))[0]
        unique_extract_dir = os.path.join(extract_dir, file_basename)
        os.makedirs(unique_extract_dir, exist_ok=True)
        
        # Handle ZIP files
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # Look for XML or JSON report files in the ZIP
                report_files = [f for f in zip_ref.namelist() if f.endswith(('.xml', '.json'))]
                if not report_files:
                    logging.warning(f"No report files found in {file_path}")
                    return None
                zip_ref.extractall(unique_extract_dir)
                return os.path.join(unique_extract_dir, report_files[0])
        
        # Handle GZIP files
        elif file_path.endswith('.gz'):
            extracted_path = os.path.join(unique_extract_dir, file_basename)
            with gzip.open(file_path, 'rb') as gz:
                with open(extracted_path, 'wb') as out_file:
                    out_file.write(gz.read())
            return extracted_path
            
    except Exception as e:
        logging.error(f"Error extracting {file_path}: {str(e)}")
        return None

def process_dmarc_reports(base_path: str) -> Dict[str, int]:
    """
    Process all DMARC reports in the specified directory and count emails per domain.
    
    Args:
        base_path: Path to directory containing DMARC report files
        
    Returns:
        Dict[str, int]: Dictionary mapping domains to their email counts
    """
    domain_counts = defaultdict(int)
    
    try:
        # Create extraction directory if it doesn't exist
        extracted_dir = os.path.join(base_path, 'extracted')
        os.makedirs(extracted_dir, exist_ok=True)
        
        # Process all compressed files in the base directory
        for file_name in os.listdir(base_path):
            if file_name.endswith(('.zip', '.gz')):
                file_path = os.path.join(base_path, file_name)
                
                # Extract and parse report
                extracted_path = extract_compressed_file(file_path, extracted_dir)
                if extracted_path:
                    logging.info(f"Parsing report: {extracted_path}")
                    
                    try:
                        # Handle JSON format
                        if extracted_path.endswith('.json'):
                            with open(extracted_path, 'r') as f:
                                data = json.load(f)
                            domain = data.get('policy_published', {}).get('domain', '')
                            records = data.get('records', [])
                        
                        # Handle XML format
                        else:
                            tree = ET.parse(extracted_path)
                            root = tree.getroot()
                            policy = root.find('policy_published')
                            domain = getattr(policy.find('domain'), 'text', '') if policy is not None else ''
                            records = root.findall('record')

                        # Count emails for the domain
                        if domain:
                            for record in records:
                                if isinstance(record, dict):  # JSON format
                                    count = int(record.get('row', {}).get('count', 0))
                                else:  # XML format
                                    row = record.find('row')
                                    count = int(getattr(row.find('count'), 'text', '0')) if row is not None else 0
                                domain_counts[domain] += count
                        else:
                            logging.warning(f"No domain found in report: {extracted_path}")
                            
                    except Exception as e:
                        logging.error(f"Error parsing report {extracted_path}: {str(e)}")
                        continue
        
        # Log the results
        logging.info("\nEmail counts by domain:")
        for domain, count in sorted(domain_counts.items()):
            logging.info(f"{domain}: {count:,} emails")
        
        return dict(domain_counts)
        
    except Exception as e:
        logging.error(f"Error processing reports: {str(e)}")
        return {}

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Process DMARC reports and count emails by domain')
    parser.add_argument('--reports-dir', type=str, default='dmarc_reports',
                       help='Directory containing DMARC reports (default: downloaded_reports)')
    args = parser.parse_args()
    
    # Process reports and save results
    domain_counts = process_dmarc_reports(args.reports_dir)
    
    # Save results to JSON file with timestamp
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f'domain_email_counts_{timestamp}.json'
    
    with open(output_file, 'w') as f:
        json.dump(domain_counts, f, indent=2)
    
    logging.info(f"Results saved to {output_file}")