import os
import django
from datetime import datetime
import time

# Configure Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MaliciousBot.settings')
django.setup()

from User.services.nikhil.mongodb_repository import MongoDBRepository

def run_verification():
    print("=" * 60)
    print("MONGODB ATLAS REAL RUNTIME VERIFICATION")
    print("=" * 60)
    
    # 1. Initialize Repository (Connect)
    repo = MongoDBRepository()
    
    if not repo.is_available():
        print("FAILED: Could not connect to MongoDB Atlas.")
        return False
    
    print("SUCCESS: Connected to MongoDB Atlas.")
    print(f"Database: {repo.db_name}")
    print(f"Collection: {repo.collection_name}")
    
    test_scan_id = 999999
    
    # 2. Insert test document
    test_doc = {
        "scan_id": test_scan_id,
        "url": "https://verification-test.com",
        "analysis_status": "VERIFICATION_TEST",
        "webpage": {"title": "Test Page"},
        "network": {"ip": "1.1.1.1"},
        "ai_analysis": {"mock": True},
        "timestamps": {
            "verified_at": str(datetime.now())
        }
    }
    
    print(f"\nInserting test document for scan_id: {test_scan_id}...")
    doc_id = repo.store_evidence(test_doc)
    
    if not doc_id:
        print("FAILED: Could not insert document.")
        return False
    
    print(f"SUCCESS: Document inserted/updated. MongoDB _id: {doc_id}")
    
    # 3. Read back
    print("Reading document back...")
    retrieved = repo.get_evidence(test_scan_id)
    
    if not retrieved or retrieved["scan_id"] != test_scan_id:
        print("FAILED: Could not retrieve correct document.")
        return False
    
    print(f"SUCCESS: Retrieved document. URL: {retrieved.get('url')}")
    
    # 4. Update document
    print("\nUpdating document...")
    test_doc["webpage"]["updated"] = True
    update_id = repo.store_evidence(test_doc)
    
    # 5. Verify update
    updated_retrieved = repo.get_evidence(test_scan_id)
    if not updated_retrieved or not updated_retrieved["webpage"].get("updated"):
        print("FAILED: Document update not verified.")
        return False
        
    print("SUCCESS: Document update verified.")
    
    # 6. Idempotency test
    print("Testing idempotency (storing same data again)...")
    idempotent_id = repo.store_evidence(test_doc)
    if idempotent_id != update_id:
        print(f"INFO: Idempotency resulted in different ID: {idempotent_id} vs {update_id}")
    else:
        print("SUCCESS: Idempotency check passed (same ID).")
        
    # 7. Cleanup
    print("\nCleaning up test document...")
    try:
        res = repo.collection.delete_one({"scan_id": test_scan_id})
        if res.deleted_count > 0:
            print("SUCCESS: Test document removed.")
        else:
            print("WARNING: Could not find document to delete.")
    except Exception as e:
        print(f"ERROR during cleanup: {e}")
        
    print("\n" + "=" * 60)
    print("VERIFICATION COMPLETED SUCCESSFULLY")
    print("=" * 60)
    return True

if __name__ == "__main__":
    run_verification()
