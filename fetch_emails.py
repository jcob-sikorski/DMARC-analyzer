import imaplib
import email
from email import policy
import os
from datetime import datetime, timedelta
import logging
import sys
import inspect

def debug_print_var(var, var_name, logger=None):
    """
    Print detailed information about a variable including its name, type, and content.
    
    Args:
        var: The variable to inspect
        var_name: Name of the variable
        logger: Optional logger instance for structured logging
    """
    var_type = type(var).__name__
    var_content = str(var)
    
    # Truncate long content for readability
    if len(var_content) > 200:
        var_content = var_content[:200] + "..."
    
    debug_info = f"Variable: {var_name}\nType: {var_type}\nContent: {var_content}\n"
    
    if logger:
        logger.debug(debug_info)
    else:
        print(debug_info)

def setup_logging():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f'dmarc_fetch_{timestamp}.log'
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    
    file_handler = logging.FileHandler(log_filename)
    file_handler.setFormatter(formatter)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    logging.basicConfig(
        level=logging.DEBUG,  # Changed to DEBUG to show all variable information
        handlers=[file_handler, console_handler]
    )
    
    logger = logging.getLogger(__name__)
    debug_print_var(log_filename, 'log_filename', logger)
    debug_print_var(formatter, 'formatter', logger)
    return logger

def parse_imap_search_result(data):
    """Parse IMAP search results, handling iCloud's specific format."""
    logger = logging.getLogger(__name__)
    debug_print_var(data, 'data', logger)
    
    if not data[0]:
        return []
    
    number_strings = data[0].decode('ascii').split()
    debug_print_var(number_strings, 'number_strings', logger)
    
    result = [int(num) for num in number_strings]
    debug_print_var(result, 'result', logger)
    return result

def process_fetch_response(msg_data):
    """
    Process IMAP FETCH response, handling both standard and flag-included formats.
    
    Args:
        msg_data: Raw FETCH response from IMAP server
    
    Returns:
        bytes: Email body data if found, None otherwise
    """
    if not msg_data:
        return None
        
    # Handle standard format
    if len(msg_data) == 1 and isinstance(msg_data[0], tuple):
        return msg_data[0][1]
        
    # Handle format with flags
    for item in msg_data:
        if isinstance(item, tuple) and len(item) > 1:
            return item[1]
            
    return None

def fetch_dmarc_reports(imap_server, username, password, batch_size=100, days_back=30):
    """Enhanced version of the DMARC report fetcher with detailed variable debugging."""
    logger = setup_logging()
    
    # Debug print function parameters
    debug_print_var(imap_server, 'imap_server', logger)
    debug_print_var(username, 'username', logger)
    debug_print_var('*' * len(password), 'password', logger)  # Don't log actual password
    debug_print_var(batch_size, 'batch_size', logger)
    debug_print_var(days_back, 'days_back', logger)
    
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        debug_print_var(mail, 'mail', logger)
        
        mail.socket().settimeout(60)
        mail.login(username, password)
        
        status, messages = mail.select('"DMARC Reports"', readonly=True)
        debug_print_var(status, 'status', logger)
        debug_print_var(messages, 'messages', logger)
        
        if status != 'OK':
            raise Exception("Failed to select DMARC Reports folder")
        
        date = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")
        debug_print_var(date, 'date', logger)
        
        search_criteria = f'SINCE "{date}"'
        debug_print_var(search_criteria, 'search_criteria', logger)
        
        status, search_data = mail.search(None, search_criteria)
        debug_print_var(status, 'search_status', logger)
        debug_print_var(search_data, 'search_data', logger)
        
        message_ids = parse_imap_search_result(search_data)
        debug_print_var(message_ids, 'message_ids', logger)
        
        total_messages = len(message_ids)
        debug_print_var(total_messages, 'total_messages', logger)
        
        save_dir = "dmarc_reports_new"
        os.makedirs(save_dir, exist_ok=True)
        debug_print_var(save_dir, 'save_dir', logger)
        
        processed_count = 0
        saved_count = 0
        error_count = 0
        
        for i in range(0, len(message_ids), batch_size):
            batch = message_ids[i:i + batch_size]
            debug_print_var(batch, 'current_batch', logger)
            
            for msg_id in batch:
                try:
                    status, msg_data = mail.fetch(str(msg_id), '(BODY[])')
                    debug_print_var(status, f'fetch_status_msg_{msg_id}', logger)
                    debug_print_var(msg_data, f'msg_data_structure_{msg_id}', logger)
                    
                    if status != 'OK':
                        logger.error(f"Failed to fetch message {msg_id}")
                        error_count += 1
                        continue
                    
                    email_body = process_fetch_response(msg_data)
                    if not email_body:
                        logger.error(f"Could not extract email body for message {msg_id}")
                        error_count += 1
                        continue
                        
                    debug_print_var(len(email_body), 'email_body_length', logger)
                    message = email.message_from_bytes(email_body, policy=policy.default)
                    debug_print_var(message.get('subject'), f'message_subject_{msg_id}', logger)
                    
                    for part in message.walk():
                        if part.get_content_maintype() == 'multipart':
                            continue
                        
                        filename = part.get_filename()
                        debug_print_var(filename, f'attachment_filename_{msg_id}', logger)
                        
                        if filename and any(ext in filename.lower() for ext in ['.zip', '.xml', '.gz']):
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            safe_filename = f"{timestamp}_{filename}"
                            filepath = os.path.join(save_dir, safe_filename)
                            debug_print_var(filepath, f'saving_filepath_{msg_id}', logger)
                            
                            with open(filepath, 'wb') as f:
                                f.write(part.get_payload(decode=True))
                            saved_count += 1
                    
                    processed_count += 1
                    
                except Exception as e:
                    logger.error(f"Error processing message {msg_id}: {str(e)}")
                    error_count += 1
                    continue
        
        # Debug print final counts
        debug_print_var(processed_count, 'final_processed_count', logger)
        debug_print_var(saved_count, 'final_saved_count', logger)
        debug_print_var(error_count, 'final_error_count', logger)
        
        mail.close()
        mail.logout()
        
    except Exception as e:
        logger.error(f"Critical error: {str(e)}")
        raise

if __name__ == "__main__":
    # Configuration
    IMAP_SERVER = "imap.mail.me.com"
    USERNAME = "alex.shakhov@icloud.com"
    PASSWORD = "fpbo-wyxs-ppzw-albz"
    
    # Debug print configuration variables
    logger = logging.getLogger(__name__)
    debug_print_var(IMAP_SERVER, 'IMAP_SERVER', logger)
    debug_print_var(USERNAME, 'USERNAME', logger)
    debug_print_var('*' * len(PASSWORD), 'PASSWORD', logger)  # Don't log actual password
    
    try:
        fetch_dmarc_reports(
            imap_server=IMAP_SERVER,
            username=USERNAME,
            password=PASSWORD,
            batch_size=100,
            days_back=3
        )
    except KeyboardInterrupt:
        print("\nScript interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Script failed: {str(e)}")
        sys.exit(1)