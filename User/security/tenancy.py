"""
Authoritative tenant identity.

Tenant identity is ALWAYS derived from server-side context (the authenticated
request user or the database alias selected by ``UserDatabaseMiddleware``),
never from a client-supplied user id.

Formats
-------
tenant_id     : 'user:<id>' or 'guest'           (stored in MongoDB documents)
db alias      : 'user_<id>' or 'guest_db'        (Django connection alias)
storage key   : 'user_000042' or 'guest'          (filesystem-safe directory name)
"""

import re
from typing import Optional

GUEST_TENANT = 'guest'
GUEST_ALIAS = 'guest_db'
_TENANT_RE = re.compile(r'^user:(\d{1,12})$')
_ALIAS_RE = re.compile(r'^user_(\d{1,12})$')


def tenant_id_for_user(user) -> str:
    if user is not None and getattr(user, 'is_authenticated', False) and getattr(user, 'id', None):
        return f"user:{int(user.id)}"
    return GUEST_TENANT


def tenant_id_for_alias(alias: Optional[str]) -> str:
    if not alias or alias == GUEST_ALIAS:
        return GUEST_TENANT
    match = _ALIAS_RE.match(alias)
    if match:
        return f"user:{int(match.group(1))}"
    raise ValueError(f"Alias {alias!r} is not a tenant database alias")


def alias_for_tenant_id(tenant_id: str) -> str:
    if tenant_id == GUEST_TENANT:
        return GUEST_ALIAS
    match = _TENANT_RE.match(tenant_id or '')
    if not match:
        raise ValueError("Invalid tenant identifier")
    return f"user_{int(match.group(1))}"


def is_valid_tenant_id(tenant_id) -> bool:
    return tenant_id == GUEST_TENANT or bool(_TENANT_RE.match(str(tenant_id or '')))


def storage_key(tenant_id: str) -> str:
    if tenant_id == GUEST_TENANT:
        return 'guest'
    match = _TENANT_RE.match(tenant_id or '')
    if not match:
        raise ValueError("Invalid tenant identifier")
    return f"user_{int(match.group(1)):06d}"


def current_alias() -> str:
    from User.db_manager import get_current_db
    return get_current_db() or GUEST_ALIAS


def current_tenant_id() -> str:
    return tenant_id_for_alias(current_alias())


def resolve_existing_tenant_alias(tenant_id: str) -> Optional[str]:
    """
    Resolve a tenant id to a registered DB alias WITHOUT provisioning anything.
    Used by service-authenticated workers and admin views. Returns None if the
    tenant has no active registry row.
    """
    if not is_valid_tenant_id(tenant_id):
        return None
    if tenant_id == GUEST_TENANT:
        return GUEST_ALIAS
    from User.db_manager import get_user_db_name, register_database_connection
    from User.models import UserDatabaseRegistry
    user_id = int(_TENANT_RE.match(tenant_id).group(1))
    reg = UserDatabaseRegistry.objects.using('default').filter(user_id=user_id, status='active').first()
    if reg is None:
        return None
    alias = alias_for_tenant_id(tenant_id)
    register_database_connection(alias, get_user_db_name(user_id))
    return alias
