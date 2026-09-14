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
    ActiveResponseAction.action vocabulary: TERMINATE_PROCESS,
    COLLECT_PROCESS_INFO, COLLECT_NETWORK_CONNECTIONS, QUARANTINE_FILE,
    ISOLATE_HOST) onto the closed 7-action Command enum. Returns
    (command_action, target, decided_reason) or None if no command can
    safely be produced. Any recommendation string outside this vocabulary
    (e.g. "BLOCK_FIREWALL_IP") produces None -- this function never
    substitutes a different, unrelated closed-set action for one it cannot
    translate.
    """
    if action == "TERMINATE_PROCESS":
        # The closed contract's KILL_PROCESS target requires start_time_ticks
        # specifically to prevent PID-reuse (killing the wrong process after
        # the original pid was recycled by the OS). See docs/adr/002 for why
        # this value is an opaque, OS-native, pass-through-only token: it is
        # never valid unless the detection engine actually observed it on the
        # originating agent's telemetry, so a missing/wrong-typed/zero value
        # must always fail closed rather than ever being guessed or defaulted.
        pid = active_response.get("target_pid")
        start_time_ticks = active_response.get("target_start_time_ticks")
        if (
            not isinstance(pid, int)
            or isinstance(pid, bool)
            or not isinstance(start_time_ticks, int)
            or isinstance(start_time_ticks, bool)
            or start_time_ticks <= 0
        ):
            return None
        return "KILL_PROCESS", {"pid": pid, "start_time_ticks": start_time_ticks}, "direct mapping"
    if action == "COLLECT_PROCESS_INFO":
        # Same PID-reuse-safety requirement as TERMINATE_PROCESS -- collecting
        # info about a since-recycled pid would be misleading to an analyst,
        # so this fails closed identically rather than only guarding the
        # destructive action.
        pid = active_response.get("target_pid")
        start_time_ticks = active_response.get("target_start_time_ticks")
        if (
            not isinstance(pid, int)
            or isinstance(pid, bool)
            or not isinstance(start_time_ticks, int)
            or isinstance(start_time_ticks, bool)
            or start_time_ticks <= 0
        ):
            return None
        target = {"pid": pid, "start_time_ticks": start_time_ticks}
        return "COLLECT_PROCESS_INFO", target, "direct mapping"
    if action == "COLLECT_NETWORK_CONNECTIONS":
        return "COLLECT_NETWORK_CONNECTIONS", {}, "direct mapping"
    if action == "QUARANTINE_FILE":
        # Same fail-closed shape as the process actions above: the closed
        # contract's QUARANTINE_FILE target requires a non-empty path, and a
        # missing/wrong-typed one must never be guessed or defaulted -- the
        # detection engine only ever populates target_file from the actual
        # triggering event's file.path, so a missing value here means no
        # command can safely be produced.
        target_file = active_response.get("target_file")
        if not isinstance(target_file, str) or not target_file:
            return None
        return "QUARANTINE_FILE", {"path": target_file}, "direct mapping"
    if action == "ISOLATE_HOST":
        return "ISOLATE_HOST", {}, "direct mapping"
    # "BLOCK_FIREWALL_IP" (eyedetect's C2-egress recommendation string) has no
    # equivalent in the closed 7-action set. This package previously
    # "downgraded" it to a real ISOLATE_HOST command -- silently substituting
    # full host isolation for what the detection engine actually recommended
    # (a narrow, IP-scoped block). That is exactly the opportunistic
    # unrelated-action mapping this contract's fail-closed design exists to
    # prevent: an analyst approving what looks like a routine response could
    # unknowingly authorize taking an entire host offline. There is no 8th
    # action and no per-IP block in the closed set, so this now falls through
    # to the same `return None` as any other unrecognized action: no command
    # is produced, and the alert remains visible with no active_response.
    return None
