"""The closed, typed response-action contract.

This is the canonical definition of Panopticon's 7-action response
vocabulary and its wire contract -- the same enum and target-schema rules
previously hand-maintained inside ``panopticon-manager``'s
``manager/routers/commands.py``. Moving it here makes this package, not
Manager, the source of truth: Manager depends on this contract, not the
other way around.

The action set is frozen by design. Do not add an eighth action, a
free-form execute action, or a generic target field -- the whole point of
this contract is that a dispatched command can only ever be one of these
seven closed, narrowly-targeted operations. See docs/adr/001-repository-
boundary.md for why this list is closed and docs/OWNERSHIP.md for what this
package does and does not own.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

Action = Literal[
    "KILL_PROCESS",
    "COLLECT_PROCESS_INFO",
    "COLLECT_NETWORK_CONNECTIONS",
    "COLLECT_FILE",
    "QUARANTINE_FILE",
    "ISOLATE_HOST",
    "RELEASE_HOST_ISOLATION",
]

# The same seven values as the Action Literal, as a concrete tuple -- useful
# anywhere code needs to iterate/validate against the closed set rather than
# just type-check against it (e.g. a consumer building a UI dropdown, or a
# cross-repo consistency check against an agent's own hardcoded list).
ACTIONS: tuple[str, ...] = (
    "KILL_PROCESS",
    "COLLECT_PROCESS_INFO",
    "COLLECT_NETWORK_CONNECTIONS",
    "COLLECT_FILE",
    "QUARANTINE_FILE",
    "ISOLATE_HOST",
    "RELEASE_HOST_ISOLATION",
)

_PROCESS_ACTIONS = {"KILL_PROCESS", "COLLECT_PROCESS_INFO"}
_FILE_ACTIONS = {"COLLECT_FILE", "QUARANTINE_FILE"}


class Command(BaseModel):
    """A single typed, dispatchable command. Identical validation rules to
    the ones this contract replaces in panopticon-manager -- process actions
    require exactly ``{pid, start_time_ticks}`` (the latter specifically to
    reject PID-reuse: an agent must refuse to act on a pid whose start time
    no longer matches), file actions require exactly ``{path}``, and every
    other action must carry no target at all. ``extra="forbid"`` means no
    consumer can smuggle an additional, unvalidated field onto the wire."""

    model_config = ConfigDict(extra="forbid")
    command_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    action: Action
    expires_at: datetime
    target: dict = Field(default_factory=dict, max_length=16)
    correlation_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=128)

    @model_validator(mode="after")
    def enforce_closed_target_schema(self) -> "Command":
        if self.action in _PROCESS_ACTIONS:
            if set(self.target) != {"pid", "start_time_ticks"}:
                raise ValueError("process action target must contain only pid and start_time_ticks")
            if not all(
                isinstance(self.target[key], int)
                and not isinstance(self.target[key], bool)
                and self.target[key] > 0
                for key in ("pid", "start_time_ticks")
            ):
                raise ValueError("process action target values must be positive integers")
        elif self.action in _FILE_ACTIONS:
            if set(self.target) != {"path"} or not isinstance(self.target["path"], str):
                raise ValueError("file action target must contain only a path")
            if not self.target["path"] or len(self.target["path"]) > 4096:
                raise ValueError("file action path is invalid")
        elif self.target:
            raise ValueError("this action does not accept a target")
        return self


class ResultOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REJECTED = "rejected"


class CommandResult(BaseModel):
    """A single typed result an agent reports back for a command it was
    dispatched. Binding this result to the *correct* command/agent/alert is
    the consuming backend's job (it alone holds the state needed to check
    that), not this contract's -- this only defines the wire shape."""

    model_config = ConfigDict(extra="forbid")
    result_id: str = Field(min_length=1, max_length=128)
    command_id: str = Field(min_length=1, max_length=128)
    outcome: Literal["succeeded", "rejected", "failed"]
    detail: str | None = Field(default=None, max_length=512)
    correlation_id: str | None = Field(default=None, min_length=1, max_length=128)
