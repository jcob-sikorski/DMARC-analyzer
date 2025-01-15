# Standard library and third-party imports for core functionality
from dotenv import load_dotenv  # For loading environment variables
import os  # For file and directory operations
import shutil
import imaplib  # For IMAP email access
import email  # For email parsing
from email.header import decode_header  # For decoding email headers
import datetime  # For timestamp handling
import gzip  # For handling gzip compressed files
import zipfile  # For handling zip archives
import xml.etree.ElementTree as ET  # For XML parsing
from typing import Dict, Any, Optional  # Type hints
from analyzer import DMARCAnalyzer, process_dmarc_report, save_combined_report  # Custom DMARC analysis
import logging  # For application logging
import argparse
import functools
import time
import socket
import ssl
from glob import glob
import json

# TODO: write the functionality to email the reports to clients automatically

# Set up logging configuration
# - Logs both to file and console
# - Uses DEBUG level for detailed tracking
# - Includes timestamp, log level, and message in log format
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dmarc_processing.log'),
        logging.StreamHandler()
    ]
)

# Enable detailed IMAP debugging for troubleshooting connection issues
imaplib.Debug = 4

# Load environment variables from .env file
load_dotenv()
logging.info("Environment variables loaded")

def log_timing(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Get start time
        start_time = time.time()
        
        # Execute the function
        result = func(*args, **kwargs)
        
        # Calculate elapsed time
        end_time = time.time()
        elapsed = end_time - start_time
        
        # Format current time as HH:MM.SS
        current_time = datetime.datetime.fromtimestamp(end_time)
        formatted_time = current_time.strftime("%H:%M.%S")
        
        # Add milliseconds to the formatted time
        ms = int((elapsed % 1) * 100)
        formatted_time = f"{formatted_time}.{ms:02d}"
        
        # Log the timing
        logging.debug(f"{formatted_time} - Finished {func.__name__}")
        
        return result
    return wrapper

def parse_arguments():
    parser = argparse.ArgumentParser(description='Process DMARC reports from email')
    parser.add_argument('--days', type=int, default=7,
                       help='Number of days of emails to process (default: 7)')
    return parser.parse_args()

def extract_compressed_file(file_path: str, extract_dir: str) -> Optional[str]:
    """
    Extract DMARC reports from compressed files (ZIP or GZIP), handling both XML and JSON formats
    
    Args:
        file_path: Path to the compressed file
        extract_dir: Directory where files should be extracted
        
    Returns:
        Optional[str]: Path to the extracted file, or None if extraction fails
    """
    logging.info(f"Starting extraction of file: {file_path}")
    logging.debug(f"Extraction directory: {extract_dir}")
    
    try:
        # Handle ZIP files
        if file_path.endswith('.zip'):
            logging.debug("Processing ZIP file")
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # Find XML or JSON files in the archive
                report_files = [f for f in zip_ref.namelist() if f.endswith(('.xml', '.json'))]
                logging.debug(f"Found report files in ZIP: {report_files}")
                
                if not report_files:
                    logging.warning(f"No XML or JSON files found in {file_path}")
                    return None
                    
                zip_ref.extractall(extract_dir)
                extracted_path = os.path.join(extract_dir, report_files[0])
                logging.info(f"Successfully extracted ZIP to: {extracted_path}")
                return extracted_path
        
        # Handle GZIP files
        elif file_path.endswith('.gz'):
            logging.debug("Processing GZIP file")
            base_name = os.path.basename(file_path)[:-3]  # Remove .gz extension
            extracted_path = os.path.join(extract_dir, base_name)
            with gzip.open(file_path, 'rb') as gz:
                with open(extracted_path, 'wb') as out_file:
                    out_file.write(gz.read())
            logging.info(f"Successfully extracted GZIP to: {extracted_path}")
            return extracted_path
            
    except Exception as e:
        logging.error(f"Error extracting {file_path}: {str(e)}", exc_info=True)
        return None

def process_local_attachment(file_path: str, extracted_dir: str, analyzer: DMARCAnalyzer) -> None:
    """
    Process a single DMARC report file from local storage
    
    Args:
        file_path: Path to the attachment file
        extracted_dir: Directory for extracted files
        analyzer: DMARCAnalyzer instance for processing
    """
    logging.info(f"Processing file: {file_path}")
    logging.debug(f"Extraction directory: {extracted_dir}")
    
    if file_path.endswith(('.zip', '.gz')):
        xml_path = extract_compressed_file(file_path, extracted_dir)
        if xml_path and os.path.exists(xml_path):
            logging.debug(f"Successfully extracted XML file: {xml_path}")
            report_data = parse_dmarc_report(xml_path)
            if report_data:
                logging.info("Processing parsed DMARC report")
                process_dmarc_report(report_data, extracted_dir, analyzer)
            else:
                logging.error(f"Failed to parse DMARC report from {xml_path}")
        else:
            logging.error(f"Failed to extract or find XML from {file_path}")

@log_timing
def process_local_files(days: int = 7) -> None:
    """
    Process DMARC report files from local directory
    
    Args:
        days: Number of days to look back (default: 7)
    """
    logging.info(f"Starting to process local files from last {days} days")
    
    # Initialize DMARC analyzer
    dmarc_analyzer = DMARCAnalyzer()
    logging.debug("Initialized DMARCAnalyzer")

    try:
        # Find all compressed files in the downloaded_attachments directory
        base_path = "downloaded_attachments"
        # Change: Use glob() function directly instead of glob.glob
        email_dirs = glob(os.path.join(base_path, "email*"))
        
        if not email_dirs:
            logging.warning(f"No email directories found in {base_path}")
            return

        total_files = 0
        successful_count = 0

        for email_dir in email_dirs:
            # Create extraction directory for this email
            extracted_dir = os.path.join(email_dir, "extracted")
            os.makedirs(extracted_dir, exist_ok=True)

            # Find all compressed files in this email directory
            compressed_files = []
            for ext in ['.zip', '.gz']:
                # Change: Use glob() function directly
                compressed_files.extend(glob(os.path.join(email_dir, f"*{ext}")))

            total_files += len(compressed_files)
            
            for file_path in compressed_files:
                logging.info(f"Processing file: {file_path}")
                
                if is_recent_dmarc_report(file_path, extracted_dir, days):
                    try:
                        process_local_attachment(file_path, extracted_dir, dmarc_analyzer)
                        successful_count += 1
                    except Exception as e:
                        logging.error(f"Error processing {file_path}: {str(e)}")
                else:
                    logging.info(f"Skipping {file_path} - outside date range")

        # Generate final combined report
        logging.info(f"Successfully processed {successful_count}/{total_files} files")
        logging.info("Saving combined report")
        save_combined_report(base_path, dmarc_analyzer)

    except Exception as e:
        logging.error(f"Fatal error in file processing: {str(e)}")
        raise


def parse_dmarc_report(file_path: str) -> Dict[str, Any]:
    """
    Parse DMARC report file (XML or JSON) into a structured dictionary format
    
    Processes three main sections:
    1. Report metadata (organization info, dates)
    2. Policy information (domain settings)
    3. Individual records (authentication results)
    
    Args:
        file_path: Path to the report file
        
    Returns:
        Dict containing parsed report data with standardized structure:
        {
            "report_metadata": {
                "org_name": str,
                "email": str,
                "report_id": str,
                "date_range_begin": str,
                "date_range_end": str
            },
            "policy_published": {
                "domain": str,
                "adkim": str,
                "aspf": str,
                "p": str,
                "sp": str,
                "pct": str
            },
            "records": [
                {
                    "source_ip": str,
                    "count": str,
                    "policy_evaluated": {
                        "disposition": str,
                        "dkim": str,
                        "spf": str
                    },
                    "identifiers": {
                        "header_from": str
                    },
                    "auth_results": {
                        "dkim": str,
                        "spf": str
                    }
                },
                ...
            ]
        }
    """
    logging.info(f"Starting to parse DMARC report: {file_path}")
    
    try:
        # Initialize the basic report structure
        report_data = {
            "report_metadata": {},
            "policy_published": {},
            "records": []
        }

        # Determine file type and parse accordingly
        if file_path.endswith('.json'):
            logging.debug("Parsing JSON format DMARC report")
            with open(file_path, 'r') as f:
                json_data = json.load(f)
            
            # Parse JSON structure
            try:
                # Extract metadata
                metadata = json_data.get('report_metadata', {})
                report_data['report_metadata'] = {
                    'org_name': metadata.get('org_name', ''),
                    'email': metadata.get('email', ''),
                    'report_id': metadata.get('report_id', ''),
                    'date_range_begin': metadata.get('date_range', {}).get('begin', ''),
                    'date_range_end': metadata.get('date_range', {}).get('end', '')
                }
                logging.debug(f"Parsed metadata: {report_data['report_metadata']}")

                # Extract policy
                policy = json_data.get('policy_published', {})
                report_data['policy_published'] = {
                    'domain': policy.get('domain', ''),
                    'adkim': policy.get('adkim', ''),
                    'aspf': policy.get('aspf', ''),
                    'p': policy.get('p', ''),
                    'sp': policy.get('sp', ''),
                    'pct': policy.get('pct', '')
                }
                logging.debug(f"Parsed policy: {report_data['policy_published']}")

                # Extract records
                records = json_data.get('records', [])
                for idx, record in enumerate(records, 1):
                    logging.debug(f"Parsing record {idx}/{len(records)}")
                    
                    record_data = {
                        'source_ip': record.get('row', {}).get('source_ip', ''),
                        'count': record.get('row', {}).get('count', ''),
                        'policy_evaluated': {
                            'disposition': record.get('row', {}).get('policy_evaluated', {}).get('disposition', ''),
                            'dkim': record.get('row', {}).get('policy_evaluated', {}).get('dkim', ''),
                            'spf': record.get('row', {}).get('policy_evaluated', {}).get('spf', '')
                        },
                        'identifiers': {
                            'header_from': record.get('identifiers', {}).get('header_from', '')
                        },
                        'auth_results': {
                            'dkim': record.get('auth_results', {}).get('dkim', [{}])[0].get('result', ''),
                            'spf': record.get('auth_results', {}).get('spf', [{}])[0].get('result', '')
                        }
                    }
                    report_data['records'].append(record_data)
                
                logging.info(f"Successfully parsed JSON report with {len(records)} records")

            except Exception as e:
                logging.error(f"Error parsing JSON structure: {str(e)}", exc_info=True)
                return {}

        else:  # Handle XML format
            logging.debug("Parsing XML format DMARC report")
            tree = ET.parse(file_path)
            root = tree.getroot()
            logging.debug(f"XML root tag: {root.tag}")
            
            # Parse metadata section
            metadata = root.find("report_metadata")
            if metadata is not None:
                logging.debug("Parsing metadata section")
                date_range = metadata.find("date_range")
                report_data["report_metadata"] = {
                    "org_name": getattr(metadata.find("org_name"), "text", ""),
                    "email": getattr(metadata.find("email"), "text", ""),
                    "report_id": getattr(metadata.find("report_id"), "text", ""),
                    "date_range_begin": getattr(date_range.find("begin"), "text", "") if date_range is not None else "",
                    "date_range_end": getattr(date_range.find("end"), "text", "") if date_range is not None else ""
                }
                logging.debug(f"Metadata parsed: {report_data['report_metadata']}")
            else:
                logging.warning("No metadata section found in XML")
            
            # Parse policy published section
            policy = root.find("policy_published")
            if policy is not None:
                logging.debug("Parsing policy section")
                report_data["policy_published"] = {
                    "domain": getattr(policy.find("domain"), "text", ""),
                    "adkim": getattr(policy.find("adkim"), "text", ""),
                    "aspf": getattr(policy.find("aspf"), "text", ""),
                    "p": getattr(policy.find("p"), "text", ""),
                    "sp": getattr(policy.find("sp"), "text", ""),
                    "pct": getattr(policy.find("pct"), "text", "")
                }
                logging.debug(f"Policy parsed: {report_data['policy_published']}")
            else:
                logging.warning("No policy section found in XML")
            
            # Parse individual records
            records = root.findall("record")
            logging.debug(f"Found {len(records)} records to parse")
            
            for idx, record in enumerate(records, 1):
                logging.debug(f"Parsing record {idx}/{len(records)}")
                
                # Extract row data
                row = record.find("row")
                policy_evaluated = row.find("policy_evaluated") if row is not None else None
                
                # Extract identifiers
                identifiers = record.find("identifiers")
                
                # Extract authentication results
                auth_results = record.find("auth_results")
                dkim_result = auth_results.find("dkim/result") if auth_results is not None else None
                spf_result = auth_results.find("spf/result") if auth_results is not None else None
                
                record_data = {
                    "source_ip": getattr(row.find("source_ip"), "text", "") if row is not None else "",
                    "count": getattr(row.find("count"), "text", "") if row is not None else "",
                    "policy_evaluated": {
                        "disposition": getattr(policy_evaluated.find("disposition"), "text", "") if policy_evaluated is not None else "",
                        "dkim": getattr(policy_evaluated.find("dkim"), "text", "") if policy_evaluated is not None else "",
                        "spf": getattr(policy_evaluated.find("spf"), "text", "") if policy_evaluated is not None else ""
                    },
                    "identifiers": {
                        "header_from": getattr(identifiers.find("header_from"), "text", "") if identifiers is not None else ""
                    },
                    "auth_results": {
                        "dkim": getattr(dkim_result, "text", ""),
                        "spf": getattr(spf_result, "text", "")
                    }
                }
                logging.debug(f"Record {idx} data: {record_data}")
                report_data["records"].append(record_data)
            
            logging.info(f"Successfully parsed XML report with {len(records)} records")
        
        return report_data
        
    except ET.ParseError as e:
        logging.error(f"XML parsing error in {file_path}: {str(e)}", exc_info=True)
        return {}
    except json.JSONDecodeError as e:
        logging.error(f"JSON parsing error in {file_path}: {str(e)}", exc_info=True)
        return {}
    except Exception as e:
        logging.error(f"Error processing {file_path}: {str(e)}", exc_info=True)
        logging.debug(traceback.format_exc())
        return {}

def connect_to_email() -> Optional[imaplib.IMAP4_SSL]:
    """
    Establish secure IMAP connection with improved error handling
    """
    logging.info("Attempting to connect to email server")
    
    email_address = os.getenv('EMAIL_ADDRESS')
    app_password = os.getenv('APP_PASSWORD')
    imap_server = "imap.gmail.com"
    
    if not email_address or not app_password:
        logging.error("Missing email credentials in environment variables")
        return None
    
    try:
        # Set up SSL context with modern security settings
        context = ssl.create_default_context()
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Add connection timeout
        socket.setdefaulttimeout(30)  # 30 second timeout
        
        logging.debug(f"Connecting to IMAP server: {imap_server}")
        imap = imaplib.IMAP4_SSL(imap_server, ssl_context=context)
        
        logging.debug(f"Attempting login for: {email_address}")
        imap.login(email_address, app_password)
        
        logging.info("Successfully connected to email server")
        return imap
        
    except (socket.gaierror, socket.timeout) as e:
        logging.error(f"Network error connecting to server: {str(e)}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL error connecting to server: {str(e)}")
        return None
    except imaplib.IMAP4.error as e:
        logging.error(f"IMAP error connecting to server: {str(e)}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error connecting to email: {str(e)}")
        return None

def process_email_attachment(attachment_path: str, extracted_dir: str, analyzer: DMARCAnalyzer) -> None:
    """
    Process a single DMARC report attachment
    
    Handles the workflow of:
    1. Extracting compressed files
    2. Parsing XML reports
    3. Processing report data
    
    Args:
        attachment_path: Path to the attachment file
        extracted_dir: Directory for extracted files
        analyzer: DMARCAnalyzer instance for processing
    """
    logging.info(f"Processing attachment: {attachment_path}")
    logging.debug(f"Extraction directory: {extracted_dir}")
    
    if attachment_path.endswith(('.zip', '.gz')):
        xml_path = extract_compressed_file(attachment_path, extracted_dir)
        if xml_path and os.path.exists(xml_path):
            logging.debug(f"Successfully extracted XML file: {xml_path}")
            report_data = parse_dmarc_report(xml_path)
            if report_data:
                logging.info("Processing parsed DMARC report")
                process_dmarc_report(report_data, extracted_dir, analyzer)
            else:
                logging.error(f"Failed to parse DMARC report from {xml_path}")
        else:
            logging.error(f"Failed to extract or find XML from {attachment_path}")

def process_email_content(email_message: email.message.Message, attachments_dir: str, 
                         extracted_dir: str, analyzer: DMARCAnalyzer, days: int) -> None:
    """
    Process email content and filter DMARC reports by date range
    
    Args:
        email_message: Email message object
        attachments_dir: Directory for saving attachments
        extracted_dir: Directory for extracted files
        analyzer: DMARCAnalyzer instance
        days: Number of days to look back
    """
    if email_message.is_multipart():
        logging.debug("Processing multipart email")
        for part in email_message.walk():
            if part.get_content_maintype() == 'multipart':
                continue
                
            filename = part.get_filename()
            if filename:
                logging.debug(f"Processing attachment: {filename}")
                # Clean filename
                filename = "".join(c for c in filename if c.isalnum() or c in '._- ')
                filepath = os.path.join(attachments_dir, filename)
                
                # Save attachment
                with open(filepath, 'wb') as f:
                    f.write(part.get_payload(decode=True))
                logging.debug(f"Saved attachment to: {filepath}")
                
                if is_recent_dmarc_report(filepath, extracted_dir, days):
                    process_email_attachment(filepath, extracted_dir, analyzer)
                else:
                    logging.info(f"Skipping {filename} - outside date range")

def parse_timestamp(timestamp_str: str) -> Optional[datetime.datetime]:
    """
    Parse various timestamp formats commonly found in DMARC reports.
    
    Args:
        timestamp_str: String representation of timestamp
        
    Returns:
        datetime.datetime object in UTC if parsing successful, None otherwise
    """
    if not timestamp_str:
        return None
        
    try:
        # First try: Parse as Unix timestamp (epoch seconds)
        try:
            # Handle both string and integer inputs
            timestamp = int(float(timestamp_str))
            # Validate timestamp is within reasonable range (1970-2100)
            if 0 <= timestamp <= 4102444800:  # Until year 2100
                return datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
        except (ValueError, TypeError, OverflowError):
            pass
            
        # Second try: Parse ISO 8601 format
        try:
            # Handle formats like "2025-01-13T00:00:00Z"
            if 'T' in timestamp_str and timestamp_str.endswith('Z'):
                dt = datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
                return dt.replace(tzinfo=datetime.timezone.utc)
                
            # Handle formats with timezone offset like "2025-01-13T00:00:00+00:00"
            if 'T' in timestamp_str and ('+' in timestamp_str or '-' in timestamp_str):
                import dateutil.parser
                return dateutil.parser.isoparse(timestamp_str)
                
        except (ValueError, TypeError):
            pass
            
        # Third try: Parse common date formats
        common_formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%d/%m/%Y %H:%M:%S",
            "%d/%m/%Y"
        ]
        
        for fmt in common_formats:
            try:
                dt = datetime.datetime.strptime(timestamp_str, fmt)
                return dt.replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                continue
                
        return None
        
    except Exception as e:
        logging.error(f"Error parsing timestamp {timestamp_str}: {str(e)}")
        return None

def is_recent_dmarc_report(filepath: str, extract_dir: str, days: int) -> bool:
    """
    Check if DMARC report is within specified date range, supporting multiple timestamp formats.
    
    Args:
        filepath: Path to the report file
        extract_dir: Directory for extraction
        days: Number of days to look back
    
    Returns:
        bool: True if report is within date range, False otherwise
    """
    xml_path = None
    try:
        # Extract file if compressed
        if filepath.endswith(('.zip', '.gz')):
            xml_path = extract_compressed_file(filepath, extract_dir)
            if not xml_path:
                return False
        else:
            xml_path = filepath

        begin_time = None
        end_time = None

        # Handle JSON files
        if xml_path.endswith('.json'):
            with open(xml_path, 'r') as f:
                data = json.load(f)
            
            # Handle different JSON structures
            if 'report_metadata' in data:
                # Standard DMARC format
                date_range = data.get('report_metadata', {}).get('date_range', {})
                begin_time = date_range.get('begin') or date_range.get('start-datetime')
                end_time = date_range.get('end') or date_range.get('end-datetime')
            elif 'date-range' in data:
                # Alternative format seen in the error
                date_range = data.get('date-range', {})
                begin_time = date_range.get('start-datetime')
                end_time = date_range.get('end-datetime')
        else:
            # Handle XML files
            tree = ET.parse(xml_path)
            root = tree.getroot()
            metadata = root.find("report_metadata")
            if metadata is None:
                return False
            date_range = metadata.find("date_range")
            if date_range is None:
                return False
            begin_elem = date_range.find("begin")
            end_elem = date_range.find("end")
            if begin_elem is None or end_elem is None:
                return False
            begin_time = begin_elem.text
            end_time = end_elem.text

        # Parse timestamps using enhanced parser
        report_begin = parse_timestamp(begin_time)
        report_end = parse_timestamp(end_time)
        
        if not report_begin or not report_end:
            # Create an 'invalid_timestamps' directory if it doesn't exist
            invalid_dir = os.path.join(os.path.dirname(extract_dir), 'invalid_timestamps')
            os.makedirs(invalid_dir, exist_ok=True)
            
            # Save the file with invalid timestamp
            filename = os.path.basename(xml_path)
            save_path = os.path.join(invalid_dir, filename)
            
            # Copy the file instead of moving it to preserve the original
            shutil.copy2(xml_path, save_path)
            
            logging.error(f"Invalid timestamp format in DMARC report. File saved to: {save_path}")
            return False

        # Calculate cutoff date in UTC
        cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
        
        # Report is recent if either begin or end date is within our window
        is_recent = (report_begin >= cutoff_date) or (report_end >= cutoff_date)
        
        return is_recent
        
    except Exception as e:
        logging.error(f"Error checking report date: {str(e)}", exc_info=True)
        return False
        
    finally:
        # Cleanup temporary files
        if xml_path and xml_path != filepath and not os.path.exists(
            os.path.join(os.path.dirname(extract_dir), 'invalid_timestamps', os.path.basename(xml_path))
        ):
            try:
                os.remove(xml_path)
                logging.debug(f"Cleaned up temporary file: {xml_path}")
            except Exception as e:
                logging.warning(f"Failed to clean up file {xml_path}: {str(e)}")

def is_recent_dmarc_report(filepath: str, extract_dir: str, days: int) -> bool:
    """
    Check if DMARC report is within specified date range, supporting multiple timestamp formats.
    
    Args:
        filepath: Path to the report file
        extract_dir: Directory for extraction
        days: Number of days to look back
    
    Returns:
        bool: True if report is within date range, False otherwise
    """
    xml_path = None
    try:
        # Extract file if compressed
        if filepath.endswith(('.zip', '.gz')):
            xml_path = extract_compressed_file(filepath, extract_dir)
            if not xml_path:
                return False
        else:
            xml_path = filepath

        begin_time = None
        end_time = None

        # Handle JSON files
        if xml_path.endswith('.json'):
            with open(xml_path, 'r') as f:
                data = json.load(f)
            
            # Handle different JSON structures
            if 'report_metadata' in data:
                # Standard DMARC format
                date_range = data.get('report_metadata', {}).get('date_range', {})
                begin_time = date_range.get('begin') or date_range.get('start-datetime')
                end_time = date_range.get('end') or date_range.get('end-datetime')
            elif 'date-range' in data:
                # Alternative format seen in the error
                date_range = data.get('date-range', {})
                begin_time = date_range.get('start-datetime')
                end_time = date_range.get('end-datetime')
        else:
            # Handle XML files
            tree = ET.parse(xml_path)
            root = tree.getroot()
            metadata = root.find("report_metadata")
            if metadata is None:
                return False
            date_range = metadata.find("date_range")
            if date_range is None:
                return False
            begin_elem = date_range.find("begin")
            end_elem = date_range.find("end")
            if begin_elem is None or end_elem is None:
                return False
            begin_time = begin_elem.text
            end_time = end_elem.text

        # Parse timestamps using enhanced parser
        report_begin = parse_timestamp(begin_time)
        report_end = parse_timestamp(end_time)
        
        if not report_begin or not report_end:
            # Create an 'invalid_timestamps' directory if it doesn't exist
            invalid_dir = os.path.join(os.path.dirname(extract_dir), 'invalid_timestamps')
            os.makedirs(invalid_dir, exist_ok=True)
            
            # Save the file with invalid timestamp
            filename = os.path.basename(xml_path)
            save_path = os.path.join(invalid_dir, filename)
            
            # Copy the file instead of moving it to preserve the original
            shutil.copy2(xml_path, save_path)
            
            logging.error(f"Invalid timestamp format in DMARC report. File saved to: {save_path}")
            return False

        # Calculate cutoff date in UTC
        cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
        
        # Report is recent if either begin or end date is within our window
        is_recent = (report_begin >= cutoff_date) or (report_end >= cutoff_date)
        
        return is_recent
        
    except Exception as e:
        logging.error(f"Error checking report date: {str(e)}", exc_info=True)
        return False
        
    finally:
        # Cleanup temporary files
        if xml_path and xml_path != filepath and not os.path.exists(
            os.path.join(os.path.dirname(extract_dir), 'invalid_timestamps', os.path.basename(xml_path))
        ):
            try:
                os.remove(xml_path)
                logging.debug(f"Cleaned up temporary file: {xml_path}")
            except Exception as e:
                logging.warning(f"Failed to clean up file {xml_path}: {str(e)}")

if __name__ == "__main__":
    args = parse_arguments()

    logging.info("=== Starting DMARC report processing ===")
    try:
        process_local_files(days=args.days)  # Use the days argument from command line
        logging.info("=== File processing completed ===")
    except Exception as e:
        logging.error(f"Processing failed: {str(e)}")
        raise