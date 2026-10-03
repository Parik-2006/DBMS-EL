"""
Project package bootstrap.

Django's MySQL backend imports the ``MySQLdb`` module, which is provided by the
mysqlclient C extension. On Render (and anywhere a compiler toolchain is not
available) we instead rely on the pure-Python PyMySQL driver, registering it as
``MySQLdb`` before Django ever opens a database connection.

Importing this package happens as a side effect of importing
``MaliciousBot.settings`` / ``MaliciousBot.wsgi``, which is early enough for the
alias to be in place before any connection is created.
"""

try:  # pragma: no cover - depends on the installed environment
    import MySQLdb  # noqa: F401
except ImportError:  # pragma: no cover - PyMySQL fallback path
    try:
        import pymysql

        pymysql.install_as_MySQLdb()
    except ImportError as exc:  # pragma: no cover - misconfigured install
        raise ImportError(
            "No MySQL driver is available. Install the project requirements "
            "(pip install -r requirements.txt), which provide PyMySQL."
        ) from exc
