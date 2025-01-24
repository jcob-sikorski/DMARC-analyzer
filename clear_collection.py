from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def clear_collection():
    try:
        # Load environment variables from .env file
        load_dotenv()

        # Get MongoDB connection URI from environment variable
        uri = os.getenv('MONGODB_URI')
        if not uri:
            raise ValueError("MONGODB_URI environment variable not set")

        # Create MongoDB client
        client = MongoClient(uri, server_api=ServerApi('1'))

        try:
            # Test connection
            client.admin.command('ping')
            logger.info("Successfully connected to MongoDB")

            # Get database and collection
            db = client['dmarc']
            collection = db['reports']

            # Get count before deletion
            initial_count = collection.count_documents({})
            logger.info(f"Documents before deletion: {initial_count}")

            # Delete all documents
            result = collection.delete_many({})
            logger.info(f"Deleted {result.deleted_count} documents")

            # Verify deletion
            remaining = collection.count_documents({})
            logger.info(f"Remaining documents: {remaining}")

        finally:
            # Always close the connection
            client.close()
            logger.info("MongoDB connection closed")

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        raise

if __name__ == "__main__":
    clear_collection()