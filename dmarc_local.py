# Standard library and third-party imports for core functionality
from dotenv import load_dotenv  # For loading environment variables
import os  # For file and directory operations
import imaplib  # For IMAP email access
import email  # For email parsing
from email.header import decode_header  # For decoding email headers
import datetime  # For timestamp handling
import xml.etree.ElementTree as ET  # For XML parsing
from typing import Dict, Any, Optional  # Type hints
from analyzer import DMARCAnalyzer, process_dmarc_report, save_reports  # Custom DMARC analysis
import logging  # For application logging
import argparse
import functools
import time
import socket
import ssl
from glob import glob
import json

# Set up logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dmarc_processing.log'),
        logging.StreamHandler()
    ]
)

def log_timing(func):
    """Decorator to log function execution time"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        elapsed = end_time - start_time
        current_time = datetime.datetime.fromtimestamp(end_time)
        formatted_time = current_time.strftime("%H:%M.%S")
        ms = int((elapsed % 1) * 100)
        formatted_time = f"{formatted_time}.{ms:02d}"
        logging.debug(f"{formatted_time} - Finished {func.__name__}")
        return result
    return wrapper

def parse_dmarc_report(file_path: str) -> Dict[str, Any]:
    """
    Parse DMARC report file (XML) into a structured dictionary format
    
    Args:
        file_path: Path to the report file
        
    Returns:
        Dict containing parsed report data
    """
    # logging.info(f"Starting to parse DMARC report: {file_path}")
    
    # Handle XML files
    try:
        # Parse XML tree
        tree = ET.parse(file_path)
        root = tree.getroot()
        # logging.debug(f"XML root tag: {root.tag}")
        
        # Initialize basic report structure
        report_data = {
            "report_metadata": {},
            "policy_published": {},
            "records": []
        }
        
        # Parse report metadata section
        metadata = root.find("report_metadata")
        if metadata is not None:
            # logging.debug("Parsing metadata section")
            report_data["report_metadata"] = {
                "org_name": getattr(metadata.find("org_name"), "text", ""),
                "email": getattr(metadata.find("email"), "text", ""),
                "report_id": getattr(metadata.find("report_id"), "text", ""),
                "date_range_begin": getattr(metadata.find("date_range/begin"), "text", ""),
                "date_range_end": getattr(metadata.find("date_range/end"), "text", "")
            }
            # logging.debug(f"Metadata parsed: {report_data['report_metadata']}")
        # else:
        #     logging.warning("No metadata section found in XML")
        
        # Parse policy published section
        policy = root.find("policy_published")
        if policy is not None:
            # logging.debug("Parsing policy section")
            report_data["policy_published"] = {
                "domain": getattr(policy.find("domain"), "text", ""),
                "adkim": getattr(policy.find("adkim"), "text", ""),
                "aspf": getattr(policy.find("aspf"), "text", ""),
                "p": getattr(policy.find("p"), "text", ""),
                "sp": getattr(policy.find("sp"), "text", ""),
                "pct": getattr(policy.find("pct"), "text", "")
            }
            # logging.debug(f"Policy parsed: {report_data['policy_published']}")
        # else:
        #     logging.warning("No policy section found in XML")
        
        # Parse records
        records = root.findall("record")
        # logging.debug(f"Found {len(records)} records to parse")
        
        for idx, record in enumerate(records, 1):
            # logging.debug(f"Parsing record {idx}/{len(records)}")
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
            # logging.debug(f"Record {idx} data: {record_data}")
            report_data["records"].append(record_data)
        
        # logging.info(f"Successfully parsed XML DMARC report with {len(records)} records")
        return report_data
        
    except ET.ParseError as e:
        logging.error(f"XML parsing error in {file_path}: {str(e)}", exc_info=True)
        return {}
    except Exception as e:
        logging.error(f"Error processing XML {file_path}: {str(e)}", exc_info=True)
        return {}

@log_timing
def process_local_files() -> None:
    """
    Process DMARC report files from local directory with improved directory handling
    """
    # logging.info(f"Starting to process local files")
    
    # Initialize DMARC analyzer
    dmarc_analyzer = DMARCAnalyzer()
    # logging.debug("Initialized DMARCAnalyzer")

    try:
        # Base directory for DMARC reports
        base_path = "dmarc_reports"
        extract_dir = os.path.join(base_path, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        # Find all XML files recursively in extracted directories
        xml_files = []
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if file.endswith(('.xml')):
                    full_path = os.path.join(root, file)
                    xml_files.append(full_path)

        if not xml_files:
            # logging.warning(f"No report files found in {extract_dir}")
            return

        total_files = len(xml_files)
        successful_count = 0

        for file_path in xml_files:
            if not os.path.isfile(file_path):
                # logging.warning(f"Skipping {file_path} - not a regular file")
                continue
                
            # logging.info(f"Processing file: {file_path}")
            
            try:
                report_data = parse_dmarc_report(file_path)
                if report_data:
                    # logging.info("Processing parsed DMARC report")
                    process_dmarc_report(report_data, os.path.dirname(file_path), dmarc_analyzer)
                    pass
                else:
                    logging.error(f"Failed to parse DMARC report from {file_path}")
                successful_count += 1
            except Exception as e:
                logging.error(f"Error processing {file_path}: {str(e)}", exc_info=True)

        # Generate final reports
        logging.info(f"Successfully processed {successful_count}/{total_files} files")
        if successful_count > 0:
            logging.info("Saving reports")
            save_reports(base_path, dmarc_analyzer)
        else:
            logging.warning("No files were successfully processed - skipping saving reports")

    except Exception as e:
        logging.error(f"Fatal error in file processing: {str(e)}", exc_info=True)
        raise

if __name__ == "__main__":
    logging.info("=== Starting DMARC report processing ===")
    try:
        process_local_files()
        # logging.info("=== File processing completed ===")
    except Exception as e:
        logging.error(f"Processing failed: {str(e)}")
        raise