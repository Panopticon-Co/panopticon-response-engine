"""The canonical response lifecycle state machine.

This is the idealized, single-response-action state machine the driving
specification locks:

    PENDING -> AUTHORIZED -> DISPATCHED -> ACCEPTED -> SUCCEEDED | FAILED | REJECTED
    PENDING -> CANCELLED
    ANY -> EXPIRED

No state is added beyond this set (in particular, no EXECUTING state --
DISPATCHED/ACCEPTED already distinguish "sent" from "the agent has it," and
a cosmetic EXECUTING state between ACCEPTED and a terminal outcome adds
nothing an agent can meaningfully report before it already reports the
outcome).

IMPORTANT -- how this maps onto panopticon-manager's actual implementation
today: Manager persists this lifecycle across *two* tables rather than one.
A recommendation starts as a ``response_actions`` row in PENDING; once an
analyst (or the AUTO_SAFE path) authorizes it, a *separate* ``commands`` row
is created already at AUTHORIZED (there is no literal "PENDING command" row
-- the response_actions row IS the PENDING stage). From there the
``commands`` row's own lifecycle_state column tracks DISPATCHED and the
terminal states. This means:

  - ``response_actions.lifecycle_state`` only ever takes PENDING, AUTHORIZED
    (meaning "translated into a commands row"), REJECTED, or EXPIRED.
  - ``commands.lifecycle_state`` only ever takes AUTHORIZED, DISPATCHED, or
    a terminal state (SUCCEEDED/FAILED/REJECTED/EXPIRED).
  - Manager does not currently store a distinct CANCELLED value anywhere --
    an analyst declining a still-PENDING response_actions row is recorded as
    REJECTED, which is this state machine's CANCELLED concept (a pre-dispatch
    decline) reusing the terminal-outcome REJECTED string. This is a known,
    accepted naming compression, not a bug: the two concepts (never-dispatched
    decline vs. an agent's post-dispatch decline) are stored as the same
    string in two different tables, distinguishable by which table and which
    stage produced them. A future Manager change could rename
    ``response_actions``' REJECTED to CANCELLED without any wire-contract
    impact, since that column is never exposed to an agent.
  - ACCEPTED is implemented in Manager via an optional acknowledgement
    endpoint (``POST /api/v1/agents/{agent_id}/commands/{command_id}/accept``,
    ``manager/routers/commands.py``): DISPATCHED -> ACCEPTED. It is optional,
    not a second incompatible protocol -- an agent that never calls it can
    still submit a result straight from DISPATCHED; Manager treats a result
    submitted while in either DISPATCHED or ACCEPTED as legal. Once a result
    lands, or the command is swept to EXPIRED, neither accept() nor a second
    result submission can move the state again.

This module validates *transitions*, not persistence. It is the reusable
place that rule lives so multiple consumers of this contract don't each
re-derive (and potentially disagree on) which lifecycle jumps are legal.
"""

from __future__ import annotations

from enum import Enum


class ResponseActionState(str, Enum):
    PENDING = "PENDING"
    AUTHORIZED = "AUTHORIZED"
    DISPATCHED = "DISPATCHED"
    ACCEPTED = "ACCEPTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


_TERMINAL = frozenset(
    {
        ResponseActionState.SUCCEEDED,
        ResponseActionState.FAILED,
        ResponseActionState.REJECTED,
        ResponseActionState.CANCELLED,
        ResponseActionState.EXPIRED,
    }
)

_LEGAL_TRANSITIONS: dict[ResponseActionState, frozenset[ResponseActionState]] = {
    ResponseActionState.PENDING: frozenset(
        {ResponseActionState.AUTHORIZED, ResponseActionState.CANCELLED}
    ),
    ResponseActionState.AUTHORIZED: frozenset({ResponseActionState.DISPATCHED}),
    ResponseActionState.DISPATCHED: frozenset({ResponseActionState.ACCEPTED}),
    ResponseActionState.ACCEPTED: frozenset(
        {
            ResponseActionState.SUCCEEDED,
            ResponseActionState.FAILED,
            ResponseActionState.REJECTED,
        }
    ),
    # Every non-terminal state may also transition to EXPIRED (a bounded
    # authorization/dispatch/acceptance window lapsed). Terminal states have
    # no outbound transitions at all.
    ResponseActionState.SUCCEEDED: frozenset(),
    ResponseActionState.FAILED: frozenset(),
    ResponseActionState.REJECTED: frozenset(),
    ResponseActionState.CANCELLED: frozenset(),
    ResponseActionState.EXPIRED: frozenset(),
}


def is_legal_transition(current: ResponseActionState, requested: ResponseActionState) -> bool:
    """Whether ``current -> requested`` is a legal single-step transition.
    ANY -> EXPIRED is legal from any non-terminal state; every other
    transition must appear in _LEGAL_TRANSITIONS. Idempotent re-application
    of a state onto itself is not considered a transition here (callers
    checking for a no-op should compare states directly first)."""
    if current in _TERMINAL:
        return False
    if requested is ResponseActionState.EXPIRED:
        return True
    return requested in _LEGAL_TRANSITIONS[current]
