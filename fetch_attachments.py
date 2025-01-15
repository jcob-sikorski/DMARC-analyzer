import os
import imaplib
import email
import logging
from datetime import datetime, timedelta
from email.header import decode_header
from dotenv import load_dotenv

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('email_downloader.log'),
        logging.StreamHandler()
    ]
)

def connect_to_email():
    """Establish IMAP connection with error handling"""
    load_dotenv()  # Load environment variables
    
    email_address = os.getenv('EMAIL_ADDRESS')
    app_password = os.getenv('APP_PASSWORD')
    
    if not email_address or not app_password:
        logging.error("Missing email credentials in environment variables")
        return None
        
    try:
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(email_address, app_password)
        return imap
    except Exception as e:
        logging.error(f"Failed to connect to email: {str(e)}")
        return None

def download_attachments():
    """Download attachments from emails in the last 3 days"""
    
    # Create directory for attachments
    download_dir = "downloaded_attachments"
    os.makedirs(download_dir, exist_ok=True)
    
    # Connect to email
    imap = connect_to_email()
    if not imap:
        return
        
    try:
        # Select inbox and calculate date range
        imap.select('INBOX')
        date_since = (datetime.now() - timedelta(days=3)).strftime("%d-%b-%Y")
        
        # Search for emails within date range
        _, messages = imap.search(None, f'(SINCE "{date_since}")')
        email_ids = messages[0].split()
        
        logging.info(f"Found {len(email_ids)} emails within date range")
        
        # Process each email
        for email_id in email_ids:
            try:
                # Fetch email content
                _, msg_data = imap.fetch(email_id, '(RFC822)')
                email_body = msg_data[0][1]
                email_message = email.message_from_bytes(email_body)
                
                # Create timestamp-based subdirectory for this email
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                email_dir = os.path.join(download_dir, f"email_{email_id.decode()}_{timestamp}")
                os.makedirs(email_dir, exist_ok=True)
                
                if email_message.is_multipart():
                    for part in email_message.walk():
                        if part.get_content_maintype() == 'multipart':
                            continue
                            
                        filename = part.get_filename()
                        if filename:
                            # Decode filename if needed
                            if decode_header(filename)[0][1] is not None:
                                filename = decode_header(filename)[0][0].decode(decode_header(filename)[0][1])
                            
                            # Clean filename
                            filename = "".join(c for c in filename if c.isalnum() or c in '._- ')
                            
                            # Save attachment
                            filepath = os.path.join(email_dir, filename)
                            with open(filepath, 'wb') as f:
                                f.write(part.get_payload(decode=True))
                            logging.info(f"Saved attachment: {filepath}")
                
            except Exception as e:
                logging.error(f"Error processing email {email_id}: {str(e)}")
                continue
                
    except Exception as e:
        logging.error(f"Error downloading attachments: {str(e)}")
    finally:
        try:
            imap.logout()
            logging.info("Logged out of IMAP server")
        except:
            pass

if __name__ == "__main__":
    logging.info("Starting attachment download process")
    download_attachments()
    logging.info("Completed attachment download process")