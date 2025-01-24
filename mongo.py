from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from datetime import datetime
import json
import os
import glob

# MongoDB connection
uri = "mongodb+srv://jmsiekiera:2QEZXz5OPX7KsBYk@dmarccluster.kcpi8.mongodb.net/?retryWrites=true&w=majority&appName=DMARCcluster"
client = MongoClient(uri, server_api=ServerApi('1'))

try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(f"Connection error: {e}")
    exit(1)

# Get the database and collection
db = client['dmarc']
collection = db['reports']

def read_text_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except Exception as e:
        print(f"Error reading text file {file_path}: {e}")
        return None

def read_json_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except Exception as e:
        print(f"Error reading JSON file {file_path}: {e}")
        return None

def process_domain_reports():
    base_path = "dmarc_reports/domain_reports"
    
    # Check if base path exists
    if not os.path.exists(base_path):
        print(f"Base path {base_path} does not exist")
        return

    # Get all domain directories
    domain_dirs = glob.glob(os.path.join(base_path, "*"))

    print(domain_dirs)

    for domain_dir in domain_dirs:
        domain = os.path.basename(domain_dir)
        print(f"Processing domain: {domain}")

        # Paths for both files
        json_path = os.path.join(domain_dir, "analysis.json")
        txt_path = os.path.join(domain_dir, "report.txt")

        # Initialize document
        document = {
            "domain": domain,
            "date_created": datetime.now()
        }

        # Process JSON file if it exists
        if os.path.exists(json_path):
            json_content = read_json_file(json_path)
            if json_content:
                document["report_json"] = json_content

        # Process text file if it exists
        if os.path.exists(txt_path):
            txt_content = read_text_file(txt_path)
            if txt_content:
                document["report_txt"] = txt_content

        # Only insert if we have at least one report
        if "report_json" in document and "report_txt" in document:
            try:
                collection.insert_one(document)
                print(f"Successfully inserted document for domain: {domain}")
            except Exception as e:
                print(f"Error inserting document for domain {domain}: {e}")
        else:
            print(f"No valid reports found for domain: {domain}")

if __name__ == "__main__":
    process_domain_reports()
    print("Processing complete")
    client.close()