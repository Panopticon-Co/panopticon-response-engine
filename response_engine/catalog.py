"""Analyst-facing metadata for the closed command set; no endpoint capability claims."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from response_engine.contract import ACTIONS, Action
from response_engine.policy import Tier, classify_tier


class ActionDescriptor(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    action: Action
    label: str
    target_kind: Literal["process", "file", "host"]
    tier: Tier
    disruptive: bool
    description: str


_METADATA = {
    "KILL_PROCESS": ("Terminate process", "process", True,
                     "Terminate the exact process identity; cannot be undone."),
    "COLLECT_PROCESS_INFO": ("Collect process information", "process", False,
                             "Inspect an exact process identity without terminating it."),
    "COLLECT_NETWORK_CONNECTIONS": ("Collect network connections", "host", False,
                                    "Collect the endpoint's current network connections."),
    "COLLECT_FILE": ("Collect file", "file", False,
                     "Collect a specific file; collected content may contain sensitive data."),
    "QUARANTINE_FILE": ("Quarantine file", "file", True,
                        "Move a specific file into endpoint quarantine."),
    "ISOLATE_HOST": ("Isolate host", "host", True,
                     "Restrict endpoint networking while retaining management connectivity."),
    "RELEASE_HOST_ISOLATION": ("Release host isolation", "host", True,
                               "Restore networking on an isolated endpoint."),
}


def action_catalog() -> tuple[ActionDescriptor, ...]:
    """Fresh immutable descriptors; manual requests still require explicit approval.

    Tier describes detection policy, not permission to execute from a UI.
    Actual support and OS safety checks remain the native endpoint's responsibility.
    """
    return tuple(
        ActionDescriptor(action=action, label=_METADATA[action][0],
                         target_kind=_METADATA[action][1], tier=classify_tier(action),
                         disruptive=_METADATA[action][2], description=_METADATA[action][3])
        for action in ACTIONS
    )
