from dotenv import load_dotenv
import os
import imaplib
import email
from email.header import decode_header
import datetime

# Enable IMAP debug logging
imaplib.Debug = 4

load_dotenv()

def connect_to_email():
    email_address = os.getenv('EMAIL_ADDRESS')
    app_password = os.getenv('APP_PASSWORD')
    imap_server = "imap.mail.me.com"
    
    try:
        imap = imaplib.IMAP4_SSL(imap_server)
        imap.login(email_address, app_password)
        print("Successfully connected to email")
        return imap
    except Exception as e:
        print(f"Error connecting to email: {str(e)}")
        return None

def get_last_10_emails(imap):
    print("\n=== Starting email fetch process ===")
    
    email_dir = "downloaded_emails"
    if not os.path.exists(email_dir):
        os.makedirs(email_dir)

    # Select the mailbox
    imap.select('INBOX')

    # Get all email IDs
    _, messages = imap.search(None, 'ALL')
    email_ids = messages[0].split()
    
    # Get last 10 emails
    last_10_emails = email_ids[-10:] if len(email_ids) > 10 else email_ids

    for i, email_id in enumerate(reversed(last_10_emails), 1):
        try:
            # Convert email_id to string
            email_id_str = email_id.decode('utf-8')
            print(f"\nFetching email {i}/10 (ID: {email_id_str})")
            
            # Try different fetch command format
            status, msg_data = imap.fetch(email_id_str, '(BODY[])')
            
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
            
            # Create directory for this email
            email_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            this_email_dir = os.path.join(email_dir, f"email_{i}_{email_timestamp}")
            os.makedirs(this_email_dir, exist_ok=True)
            
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
            get_last_10_emails(imap)
        finally:
            imap.logout()
        print("\n=== Email process completed! ===")