"""
Isolated test settings.

Usage:
    python manage.py test User --settings=MaliciousBot.settings_test

* Every database alias is a local SQLite database created by the test runner
  (core 'default', 'guest_db' and two tenant aliases 'user_1' / 'user_2' used to
  simulate two isolated users with colliding scan ids).
* No MySQL, MongoDB, Render or external API credentials are read; outbound
  provider keys and MONGODB_URI are removed from the environment.
"""

import os

for _name in ('MONGODB_URI', 'GEMINI_API_KEY', 'OPENROUTER_API_KEY', 'THREATFOX_API_KEY',
              'URLHAUS_API_KEY', 'ABUSEIPDB_API_KEY', 'FALLBACK_SERVICE_TOKEN', 'RENDER', 'PRODUCTION'):
    os.environ.pop(_name, None)
os.environ.setdefault('MYSQL_HOST', 'localhost')

from MaliciousBot.settings import *  # noqa: E402,F401,F403

DEBUG = False
SECRET_KEY = 'test-only-secret-key-not-for-production-0123456789abcdef'


def _sqlite(name):
    return {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
        'TEST': {'NAME': f'file:memorydb_{name}?mode=memory&cache=shared'},
        'ATOMIC_REQUESTS': False,
        'CONN_MAX_AGE': 0,
    }


DATABASES = {
    'default': _sqlite('core'),
    'guest_db': _sqlite('guest'),
    'user_1': _sqlite('user_1'),
    'user_2': _sqlite('user_2'),
}

PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']
CACHES = {'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', 'LOCATION': 'tests'}}
RATELIMIT_CACHE_ALIAS = 'default'
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
MEDIA_ROOT = os.path.join(BASE_DIR, '.test_media')
VISUAL_ANALYSIS_ENABLED = False
LOGGING = {'version': 1, 'disable_existing_loggers': False,
           'handlers': {'null': {'class': 'logging.NullHandler'}},
           'root': {'handlers': ['null'], 'level': 'CRITICAL'}}
