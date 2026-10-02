from User.db_manager import ensure_user_database, set_current_db, reset_current_db

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
            if hasattr(request, 'user') and request.user.is_authenticated:
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
