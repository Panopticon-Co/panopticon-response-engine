"""Closed analyst roles and permissions; authentication remains Manager-owned."""

from enum import Enum

ACCESS_POLICY_VERSION = 3


class AnalystRole(str, Enum):
    VIEWER = "viewer"
    RESPONDER = "responder"
    APPROVER = "approver"
    ANALYST = "analyst"
    ARTIFACT_ADMIN = "artifact_admin"
    TRIAGE_ADMIN = "triage_admin"


class AnalystPermission(str, Enum):
    REQUEST = "response:request"
    DECIDE = "response:decide"
    INVESTIGATE = "incident:write"
    ARTIFACT_READ = "artifact:read"
    ARTIFACT_SCOPE_MANAGE = "artifact:scope:manage"
    TRIAGE_MANAGE = "triage:manage"


_PERMISSIONS = {
    AnalystRole.TRIAGE_ADMIN: frozenset({AnalystPermission.TRIAGE_MANAGE}),
    AnalystRole.VIEWER: frozenset(),
    AnalystRole.RESPONDER: frozenset(
        {AnalystPermission.REQUEST, AnalystPermission.INVESTIGATE, AnalystPermission.ARTIFACT_READ}
    ),
    AnalystRole.APPROVER: frozenset(
        {AnalystPermission.DECIDE, AnalystPermission.INVESTIGATE, AnalystPermission.ARTIFACT_READ}
    ),
    AnalystRole.ANALYST: frozenset(
        {
            AnalystPermission.REQUEST,
            AnalystPermission.DECIDE,
            AnalystPermission.INVESTIGATE,
            AnalystPermission.ARTIFACT_READ,
        }
    ),
    AnalystRole.ARTIFACT_ADMIN: frozenset(
        {AnalystPermission.ARTIFACT_READ, AnalystPermission.ARTIFACT_SCOPE_MANAGE}
    ),
}


def permissions_for(role: str) -> frozenset[AnalystPermission]:
    """Unknown persisted roles fail closed; the legacy default is explicit, not a fallback."""
    return _PERMISSIONS.get(role, frozenset())
