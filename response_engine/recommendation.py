"""Translation from a detection engine's recommendation vocabulary onto the
closed 7-action command set.

Moved here unchanged from panopticon-manager's
manager/detection/response.py. This function is intentionally the only
place recommendation-to-command mapping happens -- callers must never guess
a target when it returns None; a recommendation this package cannot safely
translate produces no command, full stop.
"""

from __future__ import annotations

from typing import Any


def translate_recommendation(
    action: str, active_response: dict[str, Any]
) -> tuple[str, dict[str, Any], str] | None:
    """Maps a detection engine's recommendation action (e.g. eyedetect's
    ActiveResponseAction.action vocabulary: TERMINATE_PROCESS, ISOLATE_HOST,
    BLOCK_FIREWALL_IP) onto the closed 7-action Command enum. Returns
    (command_action, target, decided_reason) or None if no command can
    safely be produced.
    """
    if action == "TERMINATE_PROCESS":
        # No known detection engine recommendation payload carries a
        # process-creation timestamp yet -- the closed contract's
        # KILL_PROCESS target requires start_time_ticks specifically to
        # prevent PID-reuse (killing/collecting on the wrong process after
        # the original pid was reused), so this always fails closed rather
        # than ever guessing a start time. Fixing this requires the
        # detection engine to carry that data through its own recommendation
        # payload -- not a workaround here. See docs/OWNERSHIP.md.
        return None
    if action == "ISOLATE_HOST":
        return "ISOLATE_HOST", {}, "direct mapping"
    if action == "BLOCK_FIREWALL_IP":
        # Locked decision: no 8th action. Coarser than per-IP blocking, but
        # stays within the closed, security-reviewed action set.
        return (
            "ISOLATE_HOST",
            {},
            "BLOCK_FIREWALL_IP has no equivalent action; downgraded to ISOLATE_HOST",
        )
    return None
