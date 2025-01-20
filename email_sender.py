import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
from typing import Dict, List
import logging
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# def download_client_domains():
#     """
#     Downloads client email to domains mapping from a Google Spreadsheet.
    
#     Returns:
#         dict[str, list[str]]: Dictionary mapping client emails to their list of domains
#     """
#     # TODO: make this base url a real one
#     # Base URL of the Google Sheet
#     base_url = "https://docs.google.com/spreadsheets/d/1yTh7HDf7yoeydtr_fgx54xg_cIkAad6nHRWEwHMKX9c"
    
#     # Initialize empty dictionary for client email->domains mapping
#     client_domains = {}
    
#     try:
#         # Construct the export URL for the sheet
#         export_url = f"{base_url}/export?format=csv"
        
#         # Read the CSV into a pandas DataFrame
#         df = pd.read_csv(export_url)
        
#         # Skip if DataFrame is empty
#         if not df.empty:
#             # Process each row
#             for index, row in df.iterrows():
#                 # Get email and domain from columns
#                 email = str(row.iloc[0]).strip()
#                 domain = str(row.iloc[1]).strip()
                
#                 # Skip if either email or domain is empty
#                 if pd.isna(email) or pd.isna(domain) or email == '' or domain == '':
#                     continue
                
#                 # Initialize list for email if not exists
#                 if email not in client_domains:
#                     client_domains[email] = []
                
#                 # Add domain to list if not already present
#                 if domain not in client_domains[email]:
#                     client_domains[email].append(domain)
        
#         logger.debug("Client Domains Mapping:")
#         logger.debug(pformat(client_domains))
        
#         return client_domains
        
#     except Exception as e:
#         logger.error(f"Failed to download client email mappings: {str(e)}")
#         return {}

# CLIENT_DOMAINS = download_client_domains()

class EmailSender:
    def __init__(self, api_key: str):
        """
        Initialize EmailSender with SendGrid API key.
        
        Args:
            api_key (str): SendGrid API key
        """
        self.sg = SendGridAPIClient(api_key)

        self.from_email = Email("a@theshcompany.com")

    def read_report(self, domain: str) -> str:
        """
        Read the report file for a specific domain.
        
        Args:
            domain (str): Domain name
            
        Returns:
            str: Content of the report file
        """
        report_path = Path(f"dmarc_reports/domain_reports/{domain}/report.txt")
        try:
            with open(report_path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            logger.error(f"Report file not found for domain: {domain}")
            return f"Error: Report not found for domain {domain}"
        except Exception as e:
            logger.error(f"Error reading report for domain {domain}: {e}")
            return f"Error reading report for domain {domain}"

    def send_email(self, to_email: str, domain: str, report_content: str) -> bool:
        """
        Send an email with the domain report.
        
        Args:
            to_email (str): Recipient email address
            domain (str): Domain name
            report_content (str): Content of the report
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        try:
            subject = f"DMARC Report for {domain}"
            content = Content(
                "text/plain",
                f"Please find below the DMARC report for {domain}:\n\n{report_content}"
            )
            
            mail = Mail(
                from_email=self.from_email,
                to_emails=To(to_email),
                subject=subject,
                plain_text_content=content
            )
            
            response = self.sg.client.mail.send.post(request_body=mail.get())
            
            if response.status_code in [201, 202]:
                logger.info(f"Email sent successfully to {to_email} for domain {domain}")
                return True
            else:
                logger.error(f"Failed to send email to {to_email} for domain {domain}. Status code: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending email to {to_email} for domain {domain}: {e}")
            return False

def send_domain_reports(client_domains: Dict[str, List[str]], api_key: str) -> Dict[str, List[str]]:
    """
    Send domain reports to clients. Skips sending emails for domains where reports are not found.
    
    Args:
        client_domains (Dict[str, List[str]]): Mapping of client emails to their list of domains
        api_key (str): SendGrid API key
        
    Returns:
        Dict[str, List[str]]: Dictionary of failed deliveries {email: [failed_domains]}
    """
    email_sender = EmailSender(api_key)
    failed_deliveries = {}
    
    for email, domains in client_domains.items():
        failed_domains = []
        
        for domain in domains:
            report_content = email_sender.read_report(domain)
            # Check if report was not found
            if report_content.startswith("Error: Report not found"):
                logger.warning(f"Skipping email send for {domain} - report not found")
                failed_domains.append(domain)
                continue
                
            if not email_sender.send_email(email, domain, report_content):
                failed_domains.append(domain)
                
        if failed_domains:
            failed_deliveries[email] = failed_domains
            
    return failed_deliveries