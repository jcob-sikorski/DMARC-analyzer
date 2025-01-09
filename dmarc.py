from dotenv import load_dotenv
import os
import imaplib
import email
from email.header import decode_header
import datetime
import gzip
import zipfile
import xml.etree.ElementTree as ET
import json
from typing import Dict, Any
from analyzer import *

# Enable IMAP debug logging
imaplib.Debug = 4

load_dotenv()

def extract_compressed_file(file_path: str, extract_dir: str) -> str:
    """
    Extract a compressed file (zip or gzip) and return the path to the extracted XML file.
    """
    try:
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
                # Assume the XML file is the first file in the archive
                return os.path.join(extract_dir, zip_ref.namelist()[0])
        elif file_path.endswith('.gz'):
            xml_path = os.path.join(extract_dir, os.path.basename(file_path)[:-3])
            with gzip.open(file_path, 'rb') as gz:
                with open(xml_path, 'wb') as xml_file:
                    xml_file.write(gz.read())
            return xml_path
    except Exception as e:
        print(f"Error extracting {file_path}: {str(e)}")
    return ""

def parse_dmarc_report(xml_path: str) -> Dict[str, Any]:
    """
    Parse a DMARC XML report and return it as a dictionary.
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        report_data = {
            "report_metadata": {},
            "policy_published": {},
            "records": []
        }
        
        # Parse report metadata
        metadata = root.find("report_metadata")
        if metadata is not None:
            report_data["report_metadata"] = {
                "org_name": getattr(metadata.find("org_name"), "text", ""),
                "email": getattr(metadata.find("email"), "text", ""),
                "report_id": getattr(metadata.find("report_id"), "text", ""),
                "date_range_begin": getattr(metadata.find("date_range/begin"), "text", ""),
                "date_range_end": getattr(metadata.find("date_range/end"), "text", "")
            }
        
        # Parse policy published
        policy = root.find("policy_published")
        if policy is not None:
            report_data["policy_published"] = {
                "domain": getattr(policy.find("domain"), "text", ""),
                "adkim": getattr(policy.find("adkim"), "text", ""),
                "aspf": getattr(policy.find("aspf"), "text", ""),
                "p": getattr(policy.find("p"), "text", ""),
                "sp": getattr(policy.find("sp"), "text", ""),
                "pct": getattr(policy.find("pct"), "text", "")
            }
        
        # Parse records
        for record in root.findall("record"):
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
                }
            }
            report_data["records"].append(record_data)
        
        return report_data
    except Exception as e:
        print(f"Error parsing XML {xml_path}: {str(e)}")
        return {}

def connect_to_email():
    email_address = os.getenv('EMAIL_ADDRESS')
    app_password = os.getenv('APP_PASSWORD')
    imap_server = "imap.gmail.com"
    
    try:
        imap = imaplib.IMAP4_SSL(imap_server)
        imap.login(email_address, app_password)
        print("Successfully connected to email")
        return imap
    except Exception as e:
        print(f"Error connecting to email: {str(e)}")
        return None

def get_last_n_emails(imap, n):
    print("\n=== Starting email fetch process ===")
    
    email_dir = "downloaded_emails"
    if not os.path.exists(email_dir):
        os.makedirs(email_dir)

    # Select the mailbox
    imap.select('INBOX')

    # Get all email IDs
    _, messages = imap.search(None, 'ALL')
    email_ids = messages[0].split()
    
    # Get last n emails
    last_n_emails = email_ids[-n:] if len(email_ids) > n else email_ids

    for i, email_id in enumerate(reversed(last_n_emails), 1):
        try:
            # Convert email_id to string
            email_id_str = email_id.decode('utf-8')
            print(f"\nFetching email {i}/{n} (ID: {email_id_str})")
            
            # Fetch the email
            status, msg_data = imap.fetch(email_id_str, '(RFC822)')
            
            if status != 'OK' or not msg_data[0]:
                print(f"Failed to fetch email {i}")
                continue

            email_body = msg_data[0][1]
            email_message = email.message_from_bytes(email_body)
            
            # Get subject
            subject = decode_header(email_message['subject'])[0][0]
            if isinstance(subject, bytes):
                subject = subject.decode()
            print(f"Subject: {subject}")
            
            # Create directories
            email_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            this_email_dir = os.path.join(email_dir, f"email_{i}_{email_timestamp}")
            attachments_dir = os.path.join(this_email_dir, "attachments")
            extracted_dir = os.path.join(this_email_dir, "extracted")
            os.makedirs(this_email_dir, exist_ok=True)
            os.makedirs(attachments_dir, exist_ok=True)
            os.makedirs(extracted_dir, exist_ok=True)
            
            # Save metadata
            with open(os.path.join(this_email_dir, "metadata.txt"), "w", encoding='utf-8') as f:
                f.write(f"Subject: {subject}\n")
                f.write(f"From: {email_message['from']}\n")
                f.write(f"Date: {email_message['date']}\n")
            
            # Handle multipart messages
            if email_message.is_multipart():
                for part in email_message.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        body = part.get_payload(decode=True)
                        if body:
                            with open(os.path.join(this_email_dir, "content.txt"), "w", encoding='utf-8') as f:
                                f.write(body.decode('utf-8', 'ignore'))
                    elif content_type == "text/html":
                        body = part.get_payload(decode=True)
                        if body:
                            with open(os.path.join(this_email_dir, "content.html"), "w", encoding='utf-8') as f:
                                f.write(body.decode('utf-8', 'ignore'))
                    elif part.get_content_maintype() != 'multipart':
                        # This is an attachment
                        filename = part.get_filename()
                        if filename:
                            # Clean the filename
                            filename = "".join(c for c in filename if c.isalnum() or c in '._- ')
                            filepath = os.path.join(attachments_dir, filename)
                            
                            # Save the attachment
                            with open(filepath, 'wb') as f:
                                f.write(part.get_payload(decode=True))
                            print(f"Saved attachment: {filename}")
                            
                            # Extract and parse if it's a compressed file
                            if filename.endswith(('.zip', '.gz')):
                                xml_path = extract_compressed_file(filepath, extracted_dir)
                                if xml_path and os.path.exists(xml_path):
                                    # Parse the DMARC report
                                    report_data = parse_dmarc_report(xml_path)
                                    if report_data:
                                        # Save parsed report as JSON
                                        json_path = os.path.join(extracted_dir, 'report.json')
                                        with open(json_path, 'w', encoding='utf-8') as f:
                                            json.dump(report_data, f, indent=2)
                                        print(f"Parsed DMARC report saved to: {json_path}")
                                        
                                        # Process the DMARC report and generate analysis
                                        report_text = process_dmarc_report(report_data, extracted_dir)
                                        print("\nReport Summary:")
                                        print("==============")
                                        print(report_text)
            else:
                body = email_message.get_payload(decode=True)
                if body:
                    with open(os.path.join(this_email_dir, "content.txt"), "w", encoding='utf-8') as f:
                        f.write(body.decode('utf-8', 'ignore'))
            
            print(f"Successfully saved email {i}")
            
        except Exception as e:
            print(f"Error processing email {i}: {str(e)}")
            continue

if __name__ == "__main__":
    imap = connect_to_email()
    if imap:
        try:
            get_last_n_emails(imap, 1)
        finally:
            imap.logout()
        print("\n=== Email process completed! ===")