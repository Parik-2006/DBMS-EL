import logging
from User.db_manager import get_current_db

logger = logging.getLogger(__name__)

CONTROL_APPS = {'auth', 'sessions', 'contenttypes', 'admin'}
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

    def db_for_read(self, model, **hints):
        if model._meta.app_label in CONTROL_APPS or model._meta.model_name in CONTROL_MODELS:
            return 'default'
        current = get_current_db()
        return current or 'guest_db'

    def db_for_write(self, model, **hints):
        if model._meta.app_label in CONTROL_APPS or model._meta.model_name in CONTROL_MODELS:
            return 'default'
        current = get_current_db()
        return current or 'guest_db'

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
