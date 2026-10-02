import os
import re
import logging
import contextvars
from django.conf import settings
from django.db import connections
from django.utils import timezone

logger = logging.getLogger(__name__)

# Context variable for thread/async-safe request database routing
_current_db_var = contextvars.ContextVar('current_db', default=None)

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
    """Generate Django database dictionary for a specific MySQL database."""
    base = get_mysql_server_config()
    if 'default' in connections.databases:
        cfg = connections.databases['default'].copy()
        cfg['NAME'] = database_name
        return cfg
    return {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': database_name,
        'USER': base['USER'],
        'PASSWORD': base['PASSWORD'],
        'HOST': base['HOST'],
        'PORT': base['PORT'],
        'OPTIONS': {
            'charset': 'utf8mb4',
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
        },
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
    """
    if not re.match(r'^[a-zA-Z0-9_]+$', database_name):
        raise ValueError(f"Invalid database name: {database_name}")
    
    admin_cfg = get_mysql_admin_config()
    try:
        import MySQLdb
        conn = MySQLdb.connect(
            host=admin_cfg['HOST'],
            port=admin_cfg['PORT'],
            user=admin_cfg['USER'],
            passwd=admin_cfg['PASSWORD']
        )
    except ImportError:
        import pymysql
        conn = pymysql.connect(
            host=admin_cfg['HOST'],
            port=admin_cfg['PORT'],
            user=admin_cfg['USER'],
            password=admin_cfg['PASSWORD']
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
    """
    if db_alias not in connections.databases:
        connections.databases[db_alias] = get_mysql_db_config(database_name)

def ensure_user_database(user):
    """
    Resolve and prepare the isolated MySQL database for a user.
    - If user is unauthenticated or None, routes to 'guest_db' (maliciousbot_guest).
    - If user is authenticated, resolves maliciousbot_user_XXXXXX,
      ensures database exists on MySQL, registers connection, applies user migrations,
      and tracks in user_database_registry.
    Returns the database alias string to be used for routing.
    """
    from django.core.management import call_command
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

    # 1. Ensure MySQL database exists on server
    ensure_mysql_database_exists(db_name)

    # 2. Register dynamic Django connection
    register_database_connection(db_alias, db_name)

    # 3. Check or create registry entry in control database (default)
    registry = UserDatabaseRegistry.objects.using('default').filter(user_id=user_id).first()
    if registry is None:
        # First-time provisioning: apply user schema migrations to this database
        try:
            call_command('migrate', database=db_alias, interactive=False, verbosity=0)
        except Exception as e:
            logger.error(f"Migration failed for user database {db_name}: {e}")
            raise

        UserDatabaseRegistry.objects.using('default').create(
            user_id=user_id,
            username=user.username,
            database_name=db_name,
            status='active',
            last_used_at=timezone.now()
        )
    else:
        # Update last used timestamp
        UserDatabaseRegistry.objects.using('default').filter(id=registry.id).update(
            last_used_at=timezone.now()
        )

    return db_alias
