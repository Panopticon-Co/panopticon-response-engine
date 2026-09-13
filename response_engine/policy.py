"""Response tier classification -- the locked policy deciding which actions
may fire automatically and which always require analyst approval.

Moved here unchanged from panopticon-manager's manager/detection/response.py
``_TIERS`` table. These decisions are frozen: KILL_PROCESS, ISOLATE_HOST, and
RELEASE_HOST_ISOLATION always require analyst approval, regardless of alert
severity or any future rule change. Do not weaken them to make some other
part of the system simpler.
"""

from __future__ import annotations

from enum import Enum


class Tier(str, Enum):
    AUTO_SAFE = "AUTO_SAFE"
    ANALYST_APPROVAL = "ANALYST_APPROVAL"


# COLLECT_PROCESS_INFO/COLLECT_NETWORK_CONNECTIONS are read-only and safe to
# auto-enqueue. COLLECT_FILE and QUARANTINE_FILE default to requiring
# approval too -- COLLECT_FILE has no operator-configured path allowlist
# implemented yet (a real path-scoped AUTO_SAFE carve-out is future work,
# not something to fake now), and QUARANTINE_FILE is not read-only.
# KILL_PROCESS, ISOLATE_HOST, and RELEASE_HOST_ISOLATION are locked decisions
# -- never auto-fire, regardless of severity.
_TIERS: dict[str, Tier] = {
    "COLLECT_PROCESS_INFO": Tier.AUTO_SAFE,
    "COLLECT_NETWORK_CONNECTIONS": Tier.AUTO_SAFE,
    "COLLECT_FILE": Tier.ANALYST_APPROVAL,
    "QUARANTINE_FILE": Tier.ANALYST_APPROVAL,
    "KILL_PROCESS": Tier.ANALYST_APPROVAL,
    "ISOLATE_HOST": Tier.ANALYST_APPROVAL,
    "RELEASE_HOST_ISOLATION": Tier.ANALYST_APPROVAL,
}


def classify_tier(action: str) -> Tier:
    """Returns the action's authorization tier. An action outside the closed
    set (which should never happen if callers validate against
    response_engine.contract.ACTIONS first) is treated as ANALYST_APPROVAL,
    never AUTO_SAFE -- an unrecognized action must never default to
    auto-fire."""
    return _TIERS.get(action, Tier.ANALYST_APPROVAL)
