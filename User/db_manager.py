import os
import re
import logging
import threading
import contextvars
from django.conf import settings
from django.db import connections
from django.utils import timezone

from MaliciousBot.db_config import get_mysql_ssl_options

logger = logging.getLogger(__name__)

# Context variable for thread/async-safe request database routing
_current_db_var = contextvars.ContextVar('current_db', default=None)

# Concurrency control for per-user provisioning
_provision_mutex = threading.Lock()
_user_locks = {}

def _get_user_provision_lock(user_id):
    """Retrieve or create an in-process lock per user to serialize provisioning."""
    with _provision_mutex:
        if user_id not in _user_locks:
            _user_locks[user_id] = threading.Lock()
        return _user_locks[user_id]

def set_current_db(db_alias):
    """Set the database alias for the current request context."""
    return _current_db_var.set(db_alias)

def get_current_db():
    """Get the active database alias for the current request context."""
    return _current_db_var.get()

def reset_current_db(token):
    """Reset the database alias back to its previous state."""
    if token is not None:
        try:
            _current_db_var.reset(token)
        except Exception:
            pass

def get_mysql_server_config():
    """Retrieve base application MySQL connection settings from environment/settings."""
    return {
        'HOST': os.environ.get('MYSQL_HOST', 'localhost'),
        'PORT': int(os.environ.get('MYSQL_PORT', 3306)),
        'USER': os.environ.get('MYSQL_USER', 'maliciousbot_app'),
        'PASSWORD': os.environ.get('MYSQL_PASSWORD', ''),
    }

def get_mysql_admin_config():
    """Retrieve administrative MySQL credentials used strictly for database provisioning."""
    return {
        'HOST': os.environ.get('MYSQL_HOST', 'localhost'),
        'PORT': int(os.environ.get('MYSQL_PORT', 3306)),
        'USER': os.environ.get('MYSQL_ADMIN_USER', os.environ.get('MYSQL_USER', 'root')),
        'PASSWORD': os.environ.get('MYSQL_ADMIN_PASSWORD', os.environ.get('MYSQL_PASSWORD', '')),
    }

def get_mysql_db_config(database_name):
    """Generate Django database dictionary for a specific MySQL database.

    The 'default' connection is cloned so that every dynamically registered
    per-user database inherits exactly the same host, port, credentials and
    Aiven SSL configuration as 'default' and 'guest_db'.
    """
    base = get_mysql_server_config()
    if 'default' in connections.databases:
        cfg = connections.databases['default'].copy()
        cfg['NAME'] = database_name
        cfg['CONN_MAX_AGE'] = 0
        return cfg
    # Fallback used only when Django connections are unavailable. Built from the
    # same helpers so SSL is still applied consistently.
    return {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': database_name,
        'USER': base['USER'],
        'PASSWORD': base['PASSWORD'],
        'HOST': base['HOST'],
        'PORT': base['PORT'],
        'OPTIONS': dict({
            'charset': 'utf8mb4',
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
        }, **get_mysql_ssl_options(base['HOST'])),
        'ATOMIC_REQUESTS': False,
        'AUTOCOMMIT': True,
        'CONN_MAX_AGE': 0,
        'CONN_HEALTH_CHECKS': False,
        'TIME_ZONE': 'UTC',
    }


def get_user_db_name(user_id):
    """
    Generate safe, predictable, immutable database name from user ID.
    Never uses user-supplied strings or raw usernames.
    """
    return f"maliciousbot_user_{int(user_id):06d}"

def ensure_mysql_database_exists(database_name):
    """
    Create MySQL database on the server if it does not already exist.
    Uses administrative credentials for database creation and grants application privileges.
    Validates name strictly against alphanumeric/underscore characters.

    SSL: Reads MYSQL_SSL_CA / MYSQL_SSL_MODE from the environment so the
    provisioning connection to Aiven also uses TLS when configured.
    """
    if not re.match(r'^[a-zA-Z0-9_]+$', database_name):
        raise ValueError(f"Invalid database name: {database_name}")

    admin_cfg = get_mysql_admin_config()

    # Reuse the exact same Aiven TLS configuration as the Django connections so
    # database provisioning cannot silently fall back to an unencrypted socket.
    ssl_kwargs = get_mysql_ssl_options(admin_cfg['HOST'])

    connect_kwargs = {
        'host': admin_cfg['HOST'],
        'port': admin_cfg['PORT'],
        'user': admin_cfg['USER'],
    }

    try:
        import MySQLdb
        conn = MySQLdb.connect(
            passwd=admin_cfg['PASSWORD'],
            **connect_kwargs,
            **ssl_kwargs,
        )
    except ImportError:
        import pymysql
        conn = pymysql.connect(
            password=admin_cfg['PASSWORD'],
            **connect_kwargs,
            **ssl_kwargs,
        )

    try:
        cursor = conn.cursor()
        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{database_name}` "
            f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        app_user = os.environ.get('MYSQL_USER', 'maliciousbot_app')
        for host in ['localhost', '127.0.0.1']:
            try:
                cursor.execute(
                    f"GRANT ALL PRIVILEGES ON `{database_name}`.* TO '{app_user}'@'{host}'"
                )
            except Exception:
                pass
        cursor.execute("FLUSH PRIVILEGES")
        conn.commit()
    finally:
        conn.close()

def register_database_connection(db_alias, database_name):
    """
    Dynamically register a database connection alias with Django connections handler.
    Inherits SSL configuration from the 'default' connection.
    """
    if db_alias not in connections.databases:
        connections.databases[db_alias] = get_mysql_db_config(database_name)

def reconcile_user_database_migrations(db_alias):
    """
    Safely reconcile migration state for a user database.
    - Inspects existing tables in the database.
    - If initial tables exist (pari_domain, user_maliciousbot) and initial migrations
      are not recorded in django_migrations, marks fake_initial=True.
    - If 0004_pari_schema was interrupted midway, safely creates any missing tables/indexes
      for that initial schema so fake_initial can succeed.
    - Runs call_command('migrate', database=db_alias, fake_initial=should_fake_initial).
    - Unapplied later migrations (0005 to 0011) run genuinely and create their tables.
    - Migration errors are logged and re-raised.
    """
    from django.core.management import call_command
    from django.db.migrations.recorder import MigrationRecorder
    from django.db.migrations.loader import MigrationLoader
    from django.db.migrations.operations.models import CreateModel, AddIndex

    connection = connections[db_alias]

    with connection.cursor() as cursor:
        existing_tables = {t.lower() for t in connection.introspection.table_names(cursor)}

    recorder = MigrationRecorder(connection)
    try:
        applied_migrations = recorder.applied_migrations()
    except Exception:
        applied_migrations = set()

    # Initial tables defined in 0001_initial and 0004_pari_schema
    initial_pari_tables = {
        'pari_domain', 'pari_ip', 'pari_threat_indicator',
        'pari_url', 'pari_scan', 'pari_scan_indicator', 'pari_prediction',
    }
    has_pari_tables = any(t in existing_tables for t in initial_pari_tables)
    pari_0004_applied = ('User', '0004_pari_schema') in applied_migrations
    initial_0001_applied = ('User', '0001_initial') in applied_migrations
    has_0001_table = 'user_maliciousbot' in existing_tables

    # Case D / Interrupted 0004: If 0004_pari_schema is NOT recorded as applied,
    # but some of its tables already exist in the database (e.g. pari_domain),
    # reconcile any missing tables from 0004_pari_schema so that fake_initial
    # will detect that all created models exist and mark 0004 applied without error.
    if has_pari_tables and not pari_0004_applied:
        try:
            loader = MigrationLoader(connection)
            migration_0004 = loader.get_migration('User', '0004_pari_schema')
            state = loader.project_state(('User', '0003_alter_maliciousbot_options_maliciousbot_confidence_and_more'))
            with connection.schema_editor() as schema_editor:
                for op in migration_0004.operations:
                    new_state = state.clone()
                    op.state_forwards('User', new_state)
                    if isinstance(op, CreateModel):
                        model = new_state.apps.get_model('User', op.name)
                        table_name = model._meta.db_table.lower()
                        if table_name not in existing_tables:
                            logger.info(f"[PROVISION] reconciling missing initial table: {table_name}")
                            op.database_forwards('User', schema_editor, state, new_state)
                            existing_tables.add(table_name)
                    elif isinstance(op, AddIndex):
                        try:
                            op.database_forwards('User', schema_editor, state, new_state)
                        except Exception:
                            pass
                    state = new_state
        except Exception as e:
            logger.warning(f"[PROVISION] partial initial table reconciliation notice: {e}")

    # Determine whether fake_initial is justified:
    # ONLY when existing initial tables are found and their initial migration is not yet recorded as applied.
    should_fake_initial = bool(
        (has_pari_tables and not pari_0004_applied) or
        (has_0001_table and not initial_0001_applied) or
        ('django_content_type' in existing_tables and ('contenttypes', '0001_initial') not in applied_migrations)
    )

    logger.info(f"[PROVISION] migration reconciliation started: {db_alias}")
    try:
        call_command(
            'migrate',
            database=db_alias,
            fake_initial=should_fake_initial,
            interactive=False,
            verbosity=0,
        )
    except Exception as e:
        logger.error(f"[PROVISION] migration failed for user database {db_alias}: {e}")
        raise
    logger.info(f"[PROVISION] migration completed: {db_alias}")

def ensure_user_database(user):
    """
    Resolve and prepare the isolated MySQL database for a user.
    - If user is unauthenticated or None, routes to 'guest_db' (maliciousbot_guest).
    - If user is authenticated, resolves maliciousbot_user_XXXXXX,
      ensures database exists on MySQL, registers connection, applies/reconciles user migrations,
      and tracks in user_database_registry.
    Returns the database alias string to be used for routing.
    """
    from User.models import UserDatabaseRegistry

    if user is None or not getattr(user, 'is_authenticated', False):
        db_name = 'maliciousbot_guest'
        db_alias = 'guest_db'
        ensure_mysql_database_exists(db_name)
        register_database_connection(db_alias, db_name)
        return db_alias

    user_id = user.id
    db_name = get_user_db_name(user_id)
    db_alias = f"user_{user_id}"

    # Fast path (Case B): If registry already exists and is active, avoid lock and provisioning
    registry = UserDatabaseRegistry.objects.using('default').filter(user_id=user_id, status='active').first()
    if registry is not None:
        register_database_connection(db_alias, db_name)
        UserDatabaseRegistry.objects.using('default').filter(id=registry.id).update(
            last_used_at=timezone.now()
        )
        return db_alias

    # Concurrency control: per-user lock prevents simultaneous provisioning requests
    user_lock = _get_user_provision_lock(user_id)
    with user_lock:
        # Re-check registry under lock in case another request completed provisioning
        registry = UserDatabaseRegistry.objects.using('default').filter(user_id=user_id, status='active').first()
        if registry is not None:
            register_database_connection(db_alias, db_name)
            UserDatabaseRegistry.objects.using('default').filter(id=registry.id).update(
                last_used_at=timezone.now()
            )
            return db_alias

        logger.info(f"[PROVISION] start: user_id={user_id} db={db_name}")

        # 1. Ensure MySQL database exists on server (Case A: creates, Case C/D: no-op)
        ensure_mysql_database_exists(db_name)
        logger.info(f"[PROVISION] database exists/created: {db_name}")

        # 2. Register dynamic Django connection
        register_database_connection(db_alias, db_name)
        logger.info(f"[PROVISION] connection registered: {db_alias}")

        # 3. Apply / reconcile migrations (handles Case A, Case C, Case D)
        reconcile_user_database_migrations(db_alias)

        # 4. Atomically create or update registry row in control database (default)
        UserDatabaseRegistry.objects.using('default').update_or_create(
            user_id=user_id,
            defaults={
                'username': user.username,
                'database_name': db_name,
                'status': 'active',
                'last_used_at': timezone.now(),
            }
        )
        logger.info(f"[PROVISION] registry reconciled: user_id={user_id} db={db_name}")
        logger.info(f"[PROVISION] provisioning complete: {db_alias}")

    return db_alias
