import os
import pymongo
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import logging

logger = logging.getLogger(__name__)

class MongoDBRepository:
    """Repository for storing deep analysis evidence in MongoDB"""
    
    def __init__(self):
        self.uri = os.environ.get('MONGODB_URI')
        self.db_name = os.environ.get('MONGODB_DATABASE', 'nikhil_db')
        self.collection_name = os.environ.get('MONGODB_COLLECTION', 'deep_analysis_cases')
        self.client = None
        self.collection = None
        
        if self.uri:
            try:
                # 2-second timeout for connection
                self.client = pymongo.MongoClient(self.uri, serverSelectionTimeoutMS=2000)
                # Test connection
                self.client.admin.command('ping')
                self.collection = self.client[self.db_name][self.collection_name]
                logger.info("Connected to MongoDB successfully")
            except (ConnectionFailure, ServerSelectionTimeoutError) as e:
                logger.error(f"Failed to connect to MongoDB: {e}")
                self.client = None
                self.collection = None

    def is_available(self):
        """Check if MongoDB is available"""
        return self.collection is not None

    def store_evidence(self, evidence_data):
        """
        Store deep analysis evidence in MongoDB
        
        Returns:
            str: Document ID if successful, None otherwise
        """
        if not self.is_available():
            logger.warning("MongoDB not available, skipping storage")
            return None
        
        try:
            # Use scan_id as the primary key/link or use update with upsert
            result = self.collection.update_one(
                {"scan_id": evidence_data["scan_id"]},
                {"$set": evidence_data},
                upsert=True
            )
            
            if result.upserted_id:
                return str(result.upserted_id)
            else:
                # If updated, find the document ID
                doc = self.collection.find_one({"scan_id": evidence_data["scan_id"]}, {"_id": 1})
                return str(doc["_id"]) if doc else None
                
        except Exception as e:
            logger.error(f"Error storing evidence in MongoDB: {e}")
            return None

    def get_evidence(self, scan_id):
        """Retrieve evidence for a scan"""
        if not self.is_available():
            return None
            
        try:
            return self.collection.find_one({"scan_id": scan_id})
        except Exception as e:
            logger.error(f"Error retrieving evidence from MongoDB: {e}")
            return None
