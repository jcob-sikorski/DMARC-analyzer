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
    Extract DMARC reports from compressed files (ZIP or GZIP)
    
    Args:
        file_path: Path to the compressed file
        extract_dir: Directory where files should be extracted
        
    Returns:
        Optional[str]: Path to the extracted XML file, or None if extraction fails
    """
    logging.info(f"Starting extraction of file: {file_path}")
    logging.debug(f"Extraction directory: {extract_dir}")
    
    try:
        # Handle ZIP files
        if file_path.endswith('.zip'):
            logging.debug("Processing ZIP file")
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # Find XML files in the archive
                xml_files = [f for f in zip_ref.namelist() if f.endswith('.xml')]
                logging.debug(f"Found XML files in ZIP: {xml_files}")
                
                if not xml_files:
                    logging.warning(f"No XML files found in {file_path}")
                    return None
                    
                zip_ref.extractall(extract_dir)
                extracted_path = os.path.join(extract_dir, xml_files[0])
                logging.info(f"Successfully extracted ZIP to: {extracted_path}")
                return extracted_path
        
        # Handle GZIP files
        elif file_path.endswith('.gz'):
            logging.debug("Processing GZIP file")
            xml_path = os.path.join(extract_dir, os.path.basename(file_path)[:-3])
            with gzip.open(file_path, 'rb') as gz:
                with open(xml_path, 'wb') as xml_file:
                    xml_file.write(gz.read())
            logging.info(f"Successfully extracted GZIP to: {xml_path}")
            return xml_path
            
    except Exception as e:
        logging.error(f"Error extracting {file_path}: {str(e)}", exc_info=True)
        return None

def parse_dmarc_report(xml_path: str) -> Dict[str, Any]:
    """
    Parse DMARC XML report into a structured dictionary format
    
    Processes three main sections:
    1. Report metadata (organization info, dates)
    2. Policy information (domain settings)
    3. Individual records (authentication results)
    
    Args:
        xml_path: Path to the XML report file
        
    Returns:
        Dict containing parsed report data
    """
    logging.info(f"Starting to parse DMARC report: {xml_path}")
    
    try:
        # Parse XML tree
        tree = ET.parse(xml_path)
        root = tree.getroot()
        logging.debug(f"XML root tag: {root.tag}")
        
        # Initialize basic report structure
        report_data = {
            "report_metadata": {},
            "policy_published": {},
            "records": []
        }
        
        # Parse report metadata section
        metadata = root.find("report_metadata")
        if metadata is not None:
            logging.debug("Parsing metadata section")
            report_data["report_metadata"] = {
                "org_name": getattr(metadata.find("org_name"), "text", ""),
                "email": getattr(metadata.find("email"), "text", ""),
                "report_id": getattr(metadata.find("report_id"), "text", ""),
                "date_range_begin": getattr(metadata.find("date_range/begin"), "text", ""),
                "date_range_end": getattr(metadata.find("date_range/end"), "text", "")
            }
            logging.debug(f"Metadata parsed: {report_data['report_metadata']}")
        else:
            logging.warning("No metadata section found in XML")
        
        # Parse policy published section (domain settings)
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
        
        # Parse individual authentication records
        records = root.findall("record")
        logging.debug(f"Found {len(records)} records to parse")
        
        for idx, record in enumerate(records, 1):
            logging.debug(f"Parsing record {idx}/{len(records)}")
            record_data = {
                "source_ip": getattr(record.find("row/source_ip"), "text", ""),
                "count": getattr(record.find("row/count"), "text", ""),
                "policy_evaluated": {
                    "disposition": getattr(record.find("row/policy_evaluated/disposition"), "text", ""),
                    "dkim": getattr(record.find("row/policy_evaluated/dkim"), "text", ""),
                    "spf": getattr(record.find("row/policy_evaluated/spf"), "text", "")
                },
                "identifiers": {
                    "header_from": getattr(record.find("identifiers/header_from"), "text", "")
                },
                "auth_results": {
                    "dkim": getattr(record.find("auth_results/dkim/result"), "text", ""),
                    "spf": getattr(record.find("auth_results/spf/result"), "text", "")
                }
            }
            logging.debug(f"Record {idx} data: {record_data}")
            report_data["records"].append(record_data)
        
        logging.info(f"Successfully parsed DMARC report with {len(records)} records")
        return report_data
        
    except ET.ParseError as e:
        logging.error(f"XML parsing error in {xml_path}: {str(e)}", exc_info=True)
        return {}
    except Exception as e:
        logging.error(f"Error processing {xml_path}: {str(e)}", exc_info=True)
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

@log_timing
def get_recent_emails(imap: imaplib.IMAP4_SSL, days: int = 7) -> None:
    """
    Retrieve and process emails with enhanced error handling and automatic reconnection.
    
    Args:
        imap: Active IMAP connection
        days: Number of days to look back (default: 7)
    """
    logging.info(f"Starting to fetch emails from last {days} days")
    
    # Set up directory structure
    email_dir = "downloaded_emails_test_imap"
    os.makedirs(email_dir, exist_ok=True)
    logging.debug(f"Created directory: {email_dir}")

    # Initialize DMARC analyzer
    dmarc_analyzer = DMARCAnalyzer()
    logging.debug("Initialized DMARCAnalyzer")

    def reconnect_imap() -> Optional[imaplib.IMAP4_SSL]:
        """Helper function to establish a new IMAP connection"""
        try:
            logging.info("Attempting to reconnect to IMAP server")
            new_imap = connect_to_email()
            if new_imap:
                new_imap.select('INBOX')
                return new_imap
        except Exception as e:
            logging.error(f"Failed to reconnect: {str(e)}")
        return None

    def process_single_email(imap_conn: imaplib.IMAP4_SSL, email_id: bytes,
                           retry_count: int = 0, max_retries: int = 3,
                           batch_size: int = 10) -> tuple[bool, Optional[imaplib.IMAP4_SSL]]:
        """
        Process a single email with retry logic
        
        Returns:
            bool: True if processing succeeded, False otherwise
        """
        try:
            email_id_str = email_id.decode('utf-8')
            _, msg_data = imap_conn.fetch(email_id_str, '(RFC822)')
            
            if not msg_data or not msg_data[0]:
                logging.error(f"Failed to fetch email {email_id_str}")
                return False, imap_conn

            email_body = msg_data[0][1]
            email_message = email.message_from_bytes(email_body)
            
            # Create email-specific directories
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            email_specific_dir = os.path.join(email_dir, f"email_{email_id_str}_{timestamp}")
            attachments_dir = os.path.join(email_specific_dir, "attachments")
            extracted_dir = os.path.join(email_specific_dir, "extracted")
            
            os.makedirs(email_specific_dir, exist_ok=True)
            os.makedirs(attachments_dir, exist_ok=True)
            os.makedirs(extracted_dir, exist_ok=True)
            
            process_email_content(email_message, attachments_dir, extracted_dir, dmarc_analyzer, days)
            return True, imap_conn
            
        except (imaplib.IMAP4.abort, ssl.SSLError, socket.error) as e:
            if retry_count < max_retries:
                logging.warning(f"Connection error, attempt {retry_count + 1}/{max_retries}: {str(e)}")
                new_imap = reconnect_imap()
                if new_imap:
                    return process_single_email(new_imap, email_id, retry_count + 1, max_retries)
            logging.error(f"Failed to process email after {max_retries} attempts")
            return False
            
        except Exception as e:
            logging.error(f"Error processing email: {str(e)}")
            return False

    try:
        # Calculate date range
        date_since = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%d-%b-%Y")
        search_criterion = f'(SINCE "{date_since}")'
        
        # Select and search inbox with retry logic
        max_search_retries = 3
        for attempt in range(max_search_retries):
            try:
                imap.select('INBOX')
                _, messages = imap.search(None, search_criterion)
                email_ids = messages[0].split()
                break
            except (imaplib.IMAP4.abort, ssl.SSLError, socket.error):
                if attempt < max_search_retries - 1:
                    logging.warning(f"Search failed, attempt {attempt + 1}/{max_search_retries}")
                    imap = reconnect_imap()
                    if not imap:
                        raise Exception("Failed to reconnect to IMAP server")
                    continue
                raise
        
        total_emails = len(email_ids)
        successful_count = 0
        logging.info(f"Found {total_emails} emails within date range")

        # Process each email, only reconnecting on errors
        current_connection = imap
        
        for i, email_id in enumerate(email_ids, 1):
            logging.info(f"Processing email {i}/{total_emails} (ID: {email_id.decode('utf-8')})")
            
            success, updated_conn = process_single_email(current_connection, email_id)
            if success:
                successful_count += 1
            
            # Update connection only if we got a new one from error recovery
            if updated_conn and updated_conn != current_connection:
                try:
                    current_connection.logout()
                except Exception:
                    pass
                current_connection = updated_conn
            
            # Add a small delay between emails
            time.sleep(0.2)  # Increased delay to reduce server load

        # Generate final combined report
        logging.info(f"Successfully processed {successful_count}/{total_emails} emails")
        logging.info("Saving combined report")
        save_combined_report(email_dir, dmarc_analyzer)

    except Exception as e:
        logging.error(f"Fatal error in email processing: {str(e)}")
        raise

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

def is_recent_dmarc_report(filepath: str, extract_dir: str, days: int) -> bool:
    """
    Check if DMARC report is within specified date range
    
    Args:
        filepath: Path to the compressed report file
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

        # Parse XML to check date range
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        # Get report date range
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
            
        # Convert Unix timestamps to UTC datetime objects
        try:
            report_begin = datetime.datetime.fromtimestamp(
                int(begin_elem.text), 
                tz=datetime.timezone.utc
            )
            report_end = datetime.datetime.fromtimestamp(
                int(end_elem.text), 
                tz=datetime.timezone.utc
            )
        except (ValueError, TypeError):
            logging.error("Invalid timestamp format in DMARC report")
            return False

        # Calculate cutoff date in UTC
        cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
        
        # Report is recent if either:
        # 1. Report begin date is within our window
        # 2. Report end date is within our window
        is_recent = (report_begin >= cutoff_date) or (report_end >= cutoff_date)
        
        return is_recent
        
    except Exception as e:
        logging.error(f"Error checking report date: {str(e)}", exc_info=True)
        return False
        
    finally:
        # Clean up temporary XML file if it was extracted
        if xml_path and xml_path != filepath:
            try:
                os.remove(xml_path)
                logging.debug(f"Cleaned up temporary XML file: {xml_path}")
            except Exception as e:
                logging.warning(f"Failed to clean up XML file {xml_path}: {str(e)}")

# Main execution block
if __name__ == "__main__":
    args = parse_arguments()

    # if os.path.exists("downloaded_emails"):
    #     shutil.rmtree("downloaded_emails")
    #     logging.info("Removed existing downloaded_emails directory")

    logging.info("=== Starting DMARC report processing ===")
    imap = connect_to_email()
    if imap:
        try:
            get_recent_emails(imap, days=args.days)  # Use the days argument from command line
        finally:
            imap.logout()
            logging.info("Logged out of IMAP server")
        logging.info("=== Email processing completed ===")
    else:
        logging.error("Failed to establish email connection")