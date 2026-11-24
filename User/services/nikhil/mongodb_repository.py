"""
Tenant-isolated MongoDB repository for Nikhil forensic evidence.

Collection: ``deep_analysis_cases`` (``MONGODB_DATABASE`` / ``MONGODB_COLLECTION``).

Identity (Phase 1)
------------------
Per-user MySQL databases each generate their own auto-increment ``scan_id``, so
``scan_id`` alone is NOT unique across users. Every document is therefore keyed
by the compound identity ``(tenant_id, scan_id)`` and also carries the globally
unique ``investigation_id`` (``Scan.investigation_id``). ``tenant_id`` is always
derived server-side (``User.security.tenancy``), never from client input.

Legacy documents (written before Phase 1) have no ``tenant_id``. They are never
returned by normal retrieval (tenant filter excludes them) and are only
re-assigned by the explicit, verifiable backfill in
``manage.py mongo_tenant_maintenance``. Nothing here deletes legacy evidence.

Durability
----------
``store_evidence`` returns a reference string and sets ``last_store_durable``.
When MongoDB is not configured/unreachable the document is kept only in a
bounded, tenant-keyed, per-process cache and the reference starts with
``local-cache:`` -- callers must record this as CACHE_ONLY, never as stored.
"""

import copy
import logging
import os
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone

from User.security.redaction import redact_document
from User.security.tenancy import is_valid_tenant_id

try:  # pragma: no cover - import guard for environments without pymongo
    import pymongo
    from pymongo.errors import PyMongoError
except ImportError:  # pragma: no cover
    pymongo = None

    class PyMongoError(Exception):
        pass

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 2
LOCAL_CACHE_PREFIX = 'local-cache:'

INDEX_SPECS = (
    {
        'keys': [('tenant_id', 1), ('scan_id', 1)],
        'name': 'uq_tenant_scan',
        'unique': True,
        'partialFilterExpression': {'tenant_id': {'$exists': True}},
    },
    {
        'keys': [('investigation_id', 1)],
        'name': 'uq_investigation_id',
        'unique': True,
        'partialFilterExpression': {'investigation_id': {'$exists': True}},
    },
)


class TenantScopedCache:
    """Bounded, thread-safe LRU cache keyed strictly by (tenant_id, scan_id)."""

    def __init__(self, max_entries=256):
        self.max_entries = max(1, int(max_entries))
        self._data = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _key(tenant_id, scan_id):
        if not is_valid_tenant_id(tenant_id):
            raise ValueError('valid tenant_id required for evidence cache')
        return (tenant_id, int(scan_id))

    def put(self, tenant_id, scan_id, document):
        key = self._key(tenant_id, scan_id)
        with self._lock:
            self._data[key] = copy.deepcopy(document)
            self._data.move_to_end(key)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)

    def get(self, tenant_id, scan_id):
        key = self._key(tenant_id, scan_id)
        with self._lock:
            doc = self._data.get(key)
            if doc is None:
                return None
            self._data.move_to_end(key)
            return copy.deepcopy(doc)

    def delete(self, tenant_id, scan_id):
        with self._lock:
            self._data.pop(self._key(tenant_id, scan_id), None)

    def clear(self):
        with self._lock:
            self._data.clear()

    def __len__(self):
        with self._lock:
            return len(self._data)


_client_lock = threading.Lock()
_clients = {}            # uri -> MongoClient
_client_failures = {}    # uri -> monotonic timestamp of last failure
_FAILURE_BACKOFF_SECONDS = 60


def _get_shared_client(uri):
    """Create (once) and reuse a MongoClient per URI; back off after failures."""
    if pymongo is None or not uri:
        return None
    with _client_lock:
        client = _clients.get(uri)
        if client is not None:
            return client
        failed_at = _client_failures.get(uri)
        if failed_at and time.monotonic() - failed_at < _FAILURE_BACKOFF_SECONDS:
            return None
        kwargs = {'serverSelectionTimeoutMS': 4000, 'connectTimeoutMS': 4000, 'socketTimeoutMS': 4000}
        try:
            import certifi
            kwargs['tlsCAFile'] = certifi.where()
        except ImportError:
            pass
        try:
            client = pymongo.MongoClient(uri, **kwargs)
            client.admin.command('ping')  # once per process, not per repository use
        except Exception as exc:
            logger.warning("MongoDB unavailable: %s", type(exc).__name__)
            _client_failures[uri] = time.monotonic()
            return None
        _clients[uri] = client
        _client_failures.pop(uri, None)
        return client


def reset_shared_clients():
    """Close and forget shared clients (tests / maintenance)."""
    with _client_lock:
        for client in _clients.values():
            try:
                client.close()
            except Exception:
                pass
        _clients.clear()
        _client_failures.clear()


class MongoDBRepository:
    """Repository for tenant-scoped deep-analysis evidence."""

    _fallback_cache = TenantScopedCache(int(os.environ.get('MONGO_FALLBACK_CACHE_SIZE', '256')))

    def __init__(self, collection=None):
        self.uri = os.environ.get('MONGODB_URI')
        self.db_name = os.environ.get('MONGODB_DATABASE', 'nikhil_db')
        self.collection_name = os.environ.get('MONGODB_COLLECTION', 'deep_analysis_cases')
        self.last_store_durable = False
        self.client = None
        self.collection = collection
        if self.collection is None and self.uri:
            self.client = _get_shared_client(self.uri)
            if self.client is not None:
                self.collection = self.client[self.db_name][self.collection_name]

    def is_available(self):
        return self.collection is not None

    @staticmethod
    def _require_identity(tenant_id, scan_id):
        if not is_valid_tenant_id(tenant_id):
            raise ValueError('A valid server-derived tenant_id is required for forensic evidence')
        try:
            return int(scan_id)
        except (TypeError, ValueError):
            raise ValueError('scan_id must be an integer')

    @staticmethod
    def is_durable_reference(reference):
        return bool(reference) and not str(reference).startswith(LOCAL_CACHE_PREFIX) \
            and not str(reference).startswith('local-cache-scan-')

    def store_evidence(self, evidence_data, tenant_id=None, investigation_id=None):
        """Upsert one tenant-scoped case document. Returns a reference string."""
        tenant_id = tenant_id or evidence_data.get('tenant_id')
        scan_id = self._require_identity(tenant_id, evidence_data.get('scan_id'))
        investigation_id = investigation_id or evidence_data.get('investigation_id')

        document = redact_document(dict(evidence_data))
        document.pop('_id', None)
        document['tenant_id'] = tenant_id
        document['scan_id'] = scan_id
        if investigation_id:
            document['investigation_id'] = str(investigation_id)
        document['schema_version'] = SCHEMA_VERSION
        document['updated_at'] = datetime.now(timezone.utc).isoformat()

        self.last_store_durable = False
        self._fallback_cache.put(tenant_id, scan_id, document)
        local_ref = f"{LOCAL_CACHE_PREFIX}{tenant_id}:{scan_id}"

        if not self.is_available():
            logger.info("MongoDB offline: evidence for scan %s kept in volatile cache only", scan_id)
            return local_ref
        try:
            result = self.collection.update_one(
                {'tenant_id': tenant_id, 'scan_id': scan_id},
                {'$set': document, '$setOnInsert': {'created_at': document['updated_at']}},
                upsert=True,
            )
            if getattr(result, 'upserted_id', None):
                ref = str(result.upserted_id)
            else:
                found = self.collection.find_one({'tenant_id': tenant_id, 'scan_id': scan_id}, {'_id': 1})
                ref = str(found['_id']) if found else None
            if not ref:
                return local_ref
            self.last_store_durable = True
            return ref
        except PyMongoError as exc:
            logger.error("MongoDB evidence write failed for scan %s: %s", scan_id, type(exc).__name__)
            return local_ref

    def get_evidence(self, scan_id, tenant_id=None):
        """Return the tenant's own evidence document, or None. Never returns legacy/quarantined docs."""
        scan_id = self._require_identity(tenant_id, scan_id)
        if self.is_available():
            try:
                doc = self.collection.find_one({'tenant_id': tenant_id, 'scan_id': scan_id,
                                                'quarantined': {'$ne': True}})
                if doc:
                    if '_id' in doc:
                        doc['_id'] = str(doc['_id'])
                    return doc
            except PyMongoError as exc:
                logger.warning("MongoDB evidence read failed for scan %s: %s", scan_id, type(exc).__name__)
        return self._fallback_cache.get(tenant_id, scan_id)

    def exists(self, scan_id, tenant_id):
        scan_id = self._require_identity(tenant_id, scan_id)
        if not self.is_available():
            return False
        try:
            return self.collection.count_documents({'tenant_id': tenant_id, 'scan_id': scan_id}, limit=1) > 0
        except PyMongoError:
            return False

    def delete_evidence(self, scan_id, tenant_id=None):
        """Delete one tenant's document (test cleanup only)."""
        scan_id = self._require_identity(tenant_id, scan_id)
        self._fallback_cache.delete(tenant_id, scan_id)
        if self.is_available():
            try:
                self.collection.delete_one({'tenant_id': tenant_id, 'scan_id': scan_id})
            except PyMongoError:
                return False
        return True

    # ------------------------------------------------------------------
    # Index + legacy maintenance (explicit operator action only)
    # ------------------------------------------------------------------
    def ensure_indexes(self):
        if not self.is_available():
            raise RuntimeError('MongoDB is not available')
        names = []
        for spec in INDEX_SPECS:
            options = {k: v for k, v in spec.items() if k != 'keys'}
            names.append(self.collection.create_index(spec['keys'], **options))
        return names

    def iter_legacy_documents(self, limit=1000):
        """Documents without tenant scoping (written before Phase 1)."""
        if not self.is_available():
            return iter(())
        cursor = self.collection.find({'tenant_id': {'$exists': False}},
                                      {'_id': 1, 'scan_id': 1, 'url': 1, 'quarantined': 1}).limit(int(limit))
        return iter(cursor)

    def backfill_legacy_owner(self, document_id, tenant_id, investigation_id=None):
        """Assign ownership to a legacy document only if it is still unscoped."""
        if not is_valid_tenant_id(tenant_id):
            raise ValueError('valid tenant_id required')
        update = {'tenant_id': tenant_id, 'legacy_backfilled_at': datetime.now(timezone.utc).isoformat(),
                  'quarantined': False}
        if investigation_id:
            update['investigation_id'] = str(investigation_id)
        result = self.collection.update_one({'_id': document_id, 'tenant_id': {'$exists': False}},
                                            {'$set': update})
        return result.modified_count == 1

    def quarantine_legacy_document(self, document_id, reason):
        """Mark a legacy document as quarantined (non-destructive)."""
        result = self.collection.update_one(
            {'_id': document_id, 'tenant_id': {'$exists': False}},
            {'$set': {'quarantined': True, 'quarantine_reason': str(reason)[:300],
                      'quarantined_at': datetime.now(timezone.utc).isoformat()}})
        return result.modified_count == 1
