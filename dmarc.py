# main.py
from dotenv import load_dotenv
import os
import imaplib
import email
from email.header import decode_header
import datetime
import gzip
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional
from analyzer import DMARCAnalyzer, process_dmarc_report, save_combined_report
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dmarc_processing.log'),
        logging.StreamHandler()
    ]
)

# Enable IMAP debug logging for troubleshooting
imaplib.Debug = 4

# Load environment variables
load_dotenv()
logging.info("Environment variables loaded")

def extract_compressed_file(file_path: str, extract_dir: str) -> Optional[str]:
    """
    Extract a compressed DMARC report file (zip or gzip) and return the path to the extracted XML file.
    """
    logging.info(f"Starting extraction of file: {file_path}")
    logging.debug(f"Extraction directory: {extract_dir}")
    
    try:
        if file_path.endswith('.zip'):
            logging.debug("Processing ZIP file")
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # Look for XML files in the archive
                xml_files = [f for f in zip_ref.namelist() if f.endswith('.xml')]
                logging.debug(f"Found XML files in ZIP: {xml_files}")
                
                if not xml_files:
                    logging.warning(f"No XML files found in {file_path}")
                    return None
                    
                zip_ref.extractall(extract_dir)
                extracted_path = os.path.join(extract_dir, xml_files[0])
                logging.info(f"Successfully extracted ZIP to: {extracted_path}")
                return extracted_path
                
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
    Parse a DMARC XML report file and convert it to a dictionary format.
    """
    logging.info(f"Starting to parse DMARC report: {xml_path}")
    
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        logging.debug(f"XML root tag: {root.tag}")
        
        # Initialize report structure
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
    Establish a connection to the email server using credentials from environment variables.
    """
    logging.info("Attempting to connect to email server")
    
    email_address = os.getenv('EMAIL_ADDRESS')
    app_password = os.getenv('APP_PASSWORD')
    imap_server = "imap.gmail.com"
    
    if not email_address or not app_password:
        logging.error("Missing email credentials in environment variables")
        return None
        
    try:
        logging.debug(f"Connecting to IMAP server: {imap_server}")
        imap = imaplib.IMAP4_SSL(imap_server)
        logging.debug(f"Attempting login for: {email_address}")
        imap.login(email_address, app_password)
        logging.info("Successfully connected to email server")
        return imap
    except Exception as e:
        logging.error(f"Error connecting to email: {str(e)}", exc_info=True)
        return None

def process_email_attachment(attachment_path: str, extracted_dir: str, analyzer: DMARCAnalyzer) -> None:
    """
    Process a single email attachment containing a DMARC report.
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

def get_last_n_emails(imap: imaplib.IMAP4_SSL, n: int) -> None:
    """
    Retrieve and process the last n emails from the inbox.
    """
    logging.info(f"Starting to fetch last {n} emails")
    
    # Create necessary directories
    email_dir = "downloaded_emails"
    os.makedirs(email_dir, exist_ok=True)
    logging.debug(f"Created directory: {email_dir}")

    # Initialize analyzer
    dmarc_analyzer = DMARCAnalyzer()
    logging.debug("Initialized DMARCAnalyzer")

    # Select the inbox
    imap.select('INBOX')
    logging.debug("Selected INBOX")

    # Get all email IDs and select the most recent n
    _, messages = imap.search(None, 'ALL')
    email_ids = messages[0].split()
    total_emails = len(email_ids)
    logging.debug(f"Found {total_emails} total emails")
    
    last_n_emails = email_ids[-n:] if len(email_ids) > n else email_ids
    logging.info(f"Processing {len(last_n_emails)} emails")

    for i, email_id in enumerate(reversed(last_n_emails), 1):
        try:
            email_id_str = email_id.decode('utf-8')
            logging.info(f"Processing email {i}/{n} (ID: {email_id_str})")
            
            # Fetch the email content
            logging.debug(f"Fetching email content for ID: {email_id_str}")
            _, msg_data = imap.fetch(email_id_str, '(RFC822)')
            if not msg_data or not msg_data[0]:
                logging.error(f"Failed to fetch email {i}")
                continue

            email_body = msg_data[0][1]
            email_message = email.message_from_bytes(email_body)
            logging.debug(f"Email subject: {email_message.get('Subject')}")
            
            # Create directories for this email
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            email_specific_dir = os.path.join(email_dir, f"email_{i}_{timestamp}")
            attachments_dir = os.path.join(email_specific_dir, "attachments")
            extracted_dir = os.path.join(email_specific_dir, "extracted")
            
            os.makedirs(email_specific_dir, exist_ok=True)
            os.makedirs(attachments_dir, exist_ok=True)
            os.makedirs(extracted_dir, exist_ok=True)
            logging.debug(f"Created directories for email {i}")
            
            # Process email parts
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
                        
                        with open(filepath, 'wb') as f:
                            f.write(part.get_payload(decode=True))
                        logging.debug(f"Saved attachment to: {filepath}")
                            
                        process_email_attachment(filepath, extracted_dir, dmarc_analyzer)
            
            logging.info(f"Successfully processed email {i}")
            
        except Exception as e:
            logging.error(f"Error processing email {i}: {str(e)}", exc_info=True)
            continue

    # Save the combined report
    logging.info("Saving combined report")
    save_combined_report(email_dir, dmarc_analyzer)

if __name__ == "__main__":
    logging.info("=== Starting DMARC report processing ===")
    imap = connect_to_email()
    if imap:
        try:
            get_last_n_emails(imap, 20)  # Process the last 3 emails
        finally:
            imap.logout()
            logging.info("Logged out of IMAP server")
        logging.info("=== Email processing completed ===")
    else:
        logging.error("Failed to establish email connection")