from User.db_manager import ensure_user_database, set_current_db, reset_current_db

# Diagnostic endpoints must stay cheap: Render polls them continuously, and
# provisioning a database issues CREATE DATABASE / GRANT against the MySQL
# server. These paths never read application tables, so they skip provisioning.
NO_PROVISIONING_PATHS = frozenset({'/health', '/status'})

class UserDatabaseMiddleware:
    """
    Middleware that establishes the active MySQL database context per request.
    Authenticated users are routed to their personal database (e.g. maliciousbot_user_000001).
    Unauthenticated users are routed to maliciousbot_guest.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = None
        try:
            if request.path in NO_PROVISIONING_PATHS:
                # Route to guest_db without provisioning, so health/status probes
                # do not run DDL on every poll.
                db_alias = 'guest_db'
            elif hasattr(request, 'user') and request.user.is_authenticated:
                db_alias = ensure_user_database(request.user)
            else:
                db_alias = ensure_user_database(None)

            token = set_current_db(db_alias)
            request.user_db = db_alias
            response = self.get_response(request)
            return response
        finally:
            if token is not None:
                reset_current_db(token)
