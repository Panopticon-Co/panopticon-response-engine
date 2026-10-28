"""Closed analyst roles and permissions; authentication remains Manager-owned."""

from enum import Enum


class AnalystRole(str, Enum):
    VIEWER = "viewer"
    RESPONDER = "responder"
    APPROVER = "approver"
    ANALYST = "analyst"


class AnalystPermission(str, Enum):
    REQUEST = "response:request"
    DECIDE = "response:decide"
    INVESTIGATE = "incident:write"


_PERMISSIONS = {
    AnalystRole.VIEWER: frozenset(),
    AnalystRole.RESPONDER: frozenset({AnalystPermission.REQUEST, AnalystPermission.INVESTIGATE}),
    AnalystRole.APPROVER: frozenset({AnalystPermission.DECIDE, AnalystPermission.INVESTIGATE}),
    AnalystRole.ANALYST: frozenset(AnalystPermission),
}


def permissions_for(role: str) -> frozenset[AnalystPermission]:
    """Unknown persisted roles fail closed; the legacy default is explicit, not a fallback."""
    return _PERMISSIONS.get(role, frozenset())
