import os
import pymongo
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, PyMongoError
import logging
import time

logger = logging.getLogger(__name__)

class MongoDBRepository:
    """
    Repository for storing deep analysis evidence in MongoDB Atlas.
    Target collection: deep_analysis_cases
    Linked by: scan_id
    
    Fault-tolerant: If MongoDB Atlas is unreachable or IP restricted,
    operations degrade gracefully without crashing the scan pipeline.
    """
    
    # In-memory fallback cache to allow idempotent retrieval even if Atlas network is blocked
    _fallback_cache = {}

    def __init__(self):
        self.uri = os.environ.get('MONGODB_URI')
        self.db_name = os.environ.get('MONGODB_DATABASE', 'nikhil_db')
        self.collection_name = os.environ.get('MONGODB_COLLECTION', 'deep_analysis_cases')
        self.client = None
        self.collection = None
        
        if self.uri:
            try:
                client_kwargs = {
                    "serverSelectionTimeoutMS": 4000,
                    "connectTimeoutMS": 4000,
                    "socketTimeoutMS": 4000,
                }
                try:
                    import certifi
                    client_kwargs["tlsCAFile"] = certifi.where()
                except ImportError:
                    pass
                self.client = pymongo.MongoClient(self.uri, **client_kwargs)
                # Test connection
                self.client.admin.command('ping')
                self.collection = self.client[self.db_name][self.collection_name]
                logger.info(f"Connected to MongoDB Atlas: {self.db_name}.{self.collection_name}")
            except Exception as e:
                logger.warning(f"MongoDB connection unavailable: {e}")
                if self.client:
                    try:
                        self.client.close()
                    except Exception:
                        pass
                self.client = None
                self.collection = None

    def is_available(self):
        """Check if live MongoDB connection is available"""
        return self.collection is not None

    def store_evidence(self, evidence_data):
        """
        Store or update complete deep analysis document in deep_analysis_cases collection.
        Uses scan_id as unique index/linkage for upsert.
        
        Args:
            evidence_data: dict containing structured analysis data
            
        Returns:
            str: Document ID or scan reference string
        """
        scan_id = evidence_data.get("scan_id")
        if not scan_id:
            logger.error("Evidence document missing scan_id")
            return None

        # Always update local fallback cache for instant retrieval & testing
        self._fallback_cache[scan_id] = dict(evidence_data)

        if not self.is_available():
            logger.info(f"MongoDB offline: stored scan {scan_id} in local memory cache")
            return f"local-cache-scan-{scan_id}"

        try:
            # Upsert by scan_id
            result = self.collection.update_one(
                {"scan_id": scan_id},
                {"$set": evidence_data},
                upsert=True
            )
            
            if result.upserted_id:
                return str(result.upserted_id)
            else:
                doc = self.collection.find_one({"scan_id": scan_id}, {"_id": 1})
                return str(doc["_id"]) if doc else f"scan-{scan_id}"
                
        except PyMongoError as e:
            logger.error(f"Error storing evidence in MongoDB Atlas: {e}")
            return f"local-cache-scan-{scan_id}"

    def get_evidence(self, scan_id):
        """
        Retrieve evidence document by scan_id
        
        Args:
            scan_id: int or str
            
        Returns:
            dict or None
        """
        if self.is_available():
            try:
                doc = self.collection.find_one({"scan_id": int(scan_id)})
                if not doc:
                    doc = self.collection.find_one({"scan_id": str(scan_id)})
                if doc:
                    # Convert ObjectId to string for JSON serialization
                    if "_id" in doc:
                        doc["_id"] = str(doc["_id"])
                    return doc
            except PyMongoError as e:
                logger.warning(f"Failed to fetch evidence from MongoDB Atlas: {e}")

        # Check in-memory fallback
        return self._fallback_cache.get(scan_id) or self._fallback_cache.get(int(scan_id) if str(scan_id).isdigit() else scan_id)

    def delete_evidence(self, scan_id):
        """Delete evidence document for testing cleanup"""
        if scan_id in self._fallback_cache:
            del self._fallback_cache[scan_id]
            
        if self.is_available():
            try:
                self.collection.delete_one({"scan_id": scan_id})
                return True
            except PyMongoError:
                return False
        return True
