"""Translation from a detection engine's recommendation vocabulary onto the
closed 7-action command set.

Moved here unchanged from panopticon-manager's
manager/detection/response.py. This function is intentionally the only
place recommendation-to-command mapping happens -- callers must never guess
a target when it returns None; a recommendation this package cannot safely
translate produces no command, full stop.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from response_engine.linux_identity import MODEL, verified_linux_subject


def _canonical_process_target(context: Any, recommendation: dict[str, Any]) -> dict | None:
    if not isinstance(context, dict):
        return None
    endpoint = context.get("endpoint")
    subject = context.get("subject")
    if not isinstance(endpoint, dict) or not isinstance(subject, dict):
        return None
    host, boot = endpoint.get("host_id"), endpoint.get("boot_id")
    pid, ticks = subject.get("observed_pid"), subject.get("native_creation_ticks")
    if (
        not isinstance(host, str)
        or not host
        or not isinstance(boot, str)
        or not re.fullmatch(r"boot_[0-9a-f]{64}", boot)
        or subject.get("boot_id") != boot
        or subject.get("resolution") != "native_exact"
        or type(pid) is not int
        or not 0 < pid <= 0xFFFFFFFF
        or not isinstance(ticks, str)
        or not re.fullmatch(r"[1-9][0-9]{0,19}", ticks)
        or int(ticks) > 0xFFFFFFFFFFFFFFFF
    ):
        return None
    fields = ["native-process-instance-v1", host, boot, str(pid), ticks]
    material = "".join(str(len(field.encode("utf-8"))) + ":" + field for field in fields)
    expected = "proc_" + hashlib.sha256(material.encode("utf-8")).hexdigest()
    if context.get("identity_model") == MODEL:
        if not verified_linux_subject(context):
            return None
    elif subject.get("entity_id") != expected:
        return None
    observed_ticks = recommendation.get("target_start_time_ticks")
    if (
        type(recommendation.get("target_pid")) is not int
        or recommendation["target_pid"] != pid
        or type(observed_ticks) is not int
        or observed_ticks != int(ticks)
        or recommendation.get("host_id", host) != host
    ):
        return None
    return {"pid": pid, "start_time_ticks": ticks, "boot_id": boot}


def translate_recommendation(
    action: str,
    active_response: dict[str, Any],
    endpoint_context: Any = None,
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
    if endpoint_context is not None and action in {"TERMINATE_PROCESS", "COLLECT_PROCESS_INFO"}:
        target = _canonical_process_target(endpoint_context, active_response)
        if target is None:
            return None
        mapped = "KILL_PROCESS" if action == "TERMINATE_PROCESS" else action
        return mapped, target, "verified canonical native process target"
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
