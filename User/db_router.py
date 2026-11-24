import logging
from User.db_manager import get_current_db

logger = logging.getLogger(__name__)

# 'django_cache' = Django DatabaseCache (shared rate-limit state) lives in the core DB.
CONTROL_APPS = {'auth', 'sessions', 'contenttypes', 'admin', 'django_cache'}
CONTROL_MODELS = {'userdatabaseregistry'}

class UserDatabaseRouter:
    """
    Database router enforcing strict user isolation:
    - Control models (auth, sessions, admin, contenttypes, UserDatabaseRegistry)
      are routed to 'default' (maliciousbot_core).
    - Application models (Domain, URL, IP, Scan, Prediction, ThreatIndicator,
      ScanIndicator, AnalystReview, MaliciousBot, HistoryClearEvent) are routed
      to the current user's isolated database, or 'guest_db' when unauthenticated.
    """

    @staticmethod
    def _tenant_db(model, hints):
        if model._meta.app_label in CONTROL_APPS or model._meta.model_name in CONTROL_MODELS:
            return 'default'
        # Related-object access (scan.url, scan.prediction, ...) must stay in the
        # database the instance was loaded from, even outside a request context
        # (management commands, worker threads).
        instance = hints.get('instance')
        if instance is not None:
            inst_db = getattr(getattr(instance, '_state', None), 'db', None)
            inst_meta = getattr(instance, '_meta', None)
            if inst_db and inst_db != 'default' and inst_meta is not None                     and inst_meta.app_label not in CONTROL_APPS and inst_meta.model_name not in CONTROL_MODELS:
                return inst_db
        return get_current_db() or 'guest_db'

    def db_for_read(self, model, **hints):
        return self._tenant_db(model, hints)

    def db_for_write(self, model, **hints):
        return self._tenant_db(model, hints)

    def allow_relation(self, obj1, obj2, **hints):
        """Allow relations across models (e.g. Scan referencing auth.User)."""
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        """
        Control schema distribution:
        - 'default' (maliciousbot_core) only gets control tables and user_database_registry.
        - Per-user and guest databases get the application domain/scan/history tables.
        """
        if db == 'default':
            if app_label in CONTROL_APPS:
                return True
            if app_label == 'User' and model_name == 'userdatabaseregistry':
                return True
            return False
        else:
            # Per-user database or guest_db
            if app_label == 'User' and model_name != 'userdatabaseregistry':
                return True
            if app_label in ('contenttypes',):
                return True
            return False
