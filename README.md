# Usage Instructions

## Overview
This script processes data for a specified number of days and sends email notifications to domain owners. You can customize the number of days to process using the `--days` argument or use the default value of 7 days.

## Prerequisites
- Python version: **3.10.10**
- Virtual environment
- Required dependencies
- Environment variables file (`.env`)

## Initial Setup

1. Create and configure `.env` file:
   ```bash
   # .env file format
   export IMAP_SERVER=""      # Your IMAP server address
   export IMAP_USERNAME=""    # Your IMAP username/email
   export IMAP_PASSWORD=""    # Your IMAP password
   
   export SENDGRID_API_KEY="" # Your SendGrid API key
   ```

2. Activate the virtual environment:
   ```bash
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure domain ownership:
   - Open `CLIENT_DOMAINS.csv`
   - Map domain names to their owners' email addresses
   - Format: `domain,owner_email`
   - Example:
     ```
     example.com,owner@company.com
     domain.net,admin@organization.com
     ```

## Usage

Run the script with the following commands:

1. Process the last 30 days:
   ```bash
   python main.py --days 30
   ```

2. Process only the last day:
   ```bash
   python main.py --days 1
   ```

3. Use the default value (7 days):
   ```bash
   python main.py
   ```

## Notes
- Ensure all dependencies are installed before running the script
- Verify that `CLIENT_DOMAINS.csv` is properly configured with valid email addresses
- Make sure all environment variables in `.env` are properly set before running the script
- The script will send email notifications to domain owners based on the mappings in `CLIENT_DOMAINS.csv`

## Caution
- Never commit the `.env` file to version control
- Keep your email credentials and API keys secure
- Double-check your environment variables before running the script to ensure proper email functionality