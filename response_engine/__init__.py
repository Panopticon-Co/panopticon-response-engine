"""panopticon-response-engine: the Panopticon Response Engine's pure domain
contract and policy logic.

This package owns:
  - the closed 7-action response vocabulary and its typed command/result
    contract, including per-action target-schema validation
    (``response_engine.contract``);
  - tier classification -- which actions may fire automatically and which
    always require analyst approval (``response_engine.policy``);
  - translation from a detection engine's recommendation vocabulary onto the
    closed command action set (``response_engine.recommendation``);
  - the canonical response lifecycle state machine
    (``response_engine.lifecycle``).

It deliberately owns nothing else. It has no HTTP framework dependency, no
database/persistence code, and no OS-specific execution logic -- those stay
in the consuming backend (panopticon-manager persists state and exposes HTTP
using this package's contract) and in each endpoint agent (which executes a
dispatched command using its own OS APIs). See docs/adr/001-repository-
boundary.md for the full reasoning and docs/OWNERSHIP.md for the boundary
this package draws with its neighbors.

Consumed by panopticon-manager today as a pinned git submodule + editable
install (see that repo's docs/adr/006-response-engine-package-extraction.md)
-- one deployable backend, no network RPC, no separate service.
"""

from response_engine.contract import (
    ACTIONS,
    Action,
    Command,
    CommandResult,
    ResultOutcome,
)
from response_engine.lifecycle import (
    ResponseActionState,
    is_legal_transition,
)
from response_engine.policy import Tier, classify_tier
from response_engine.recommendation import translate_recommendation

__all__ = [
    "ACTIONS",
    "Action",
    "Command",
    "CommandResult",
    "ResultOutcome",
    "ResponseActionState",
    "is_legal_transition",
    "Tier",
    "classify_tier",
    "translate_recommendation",
]
