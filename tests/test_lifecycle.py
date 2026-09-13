import pytest

from response_engine.lifecycle import ResponseActionState, is_legal_transition

S = ResponseActionState


@pytest.mark.parametrize(
    "current,requested",
    [
        (S.PENDING, S.AUTHORIZED),
        (S.PENDING, S.CANCELLED),
        (S.AUTHORIZED, S.DISPATCHED),
        (S.DISPATCHED, S.ACCEPTED),
        (S.ACCEPTED, S.SUCCEEDED),
        (S.ACCEPTED, S.FAILED),
        (S.ACCEPTED, S.REJECTED),
        # An agent may skip the optional accept() acknowledgement and report
        # an outcome straight from DISPATCHED -- see the module docstring
        # and panopticon-manager's test_result_without_prior_accept_still_works.
        (S.DISPATCHED, S.SUCCEEDED),
        (S.DISPATCHED, S.FAILED),
        (S.DISPATCHED, S.REJECTED),
    ],
)
def test_legal_transitions(current: S, requested: S) -> None:
    assert is_legal_transition(current, requested)


@pytest.mark.parametrize(
    "current",
    [S.PENDING, S.AUTHORIZED, S.DISPATCHED, S.ACCEPTED],
)
def test_any_non_terminal_state_can_expire(current: S) -> None:
    assert is_legal_transition(current, S.EXPIRED)


@pytest.mark.parametrize(
    "current",
    [S.SUCCEEDED, S.FAILED, S.REJECTED, S.CANCELLED, S.EXPIRED],
)
def test_terminal_states_have_no_outbound_transitions(current: S) -> None:
    for requested in S:
        assert not is_legal_transition(current, requested)


@pytest.mark.parametrize(
    "current,requested",
    [
        # Cannot skip DISPATCHED and go straight from AUTHORIZED to a
        # terminal outcome or to ACCEPTED.
        (S.AUTHORIZED, S.ACCEPTED),
        (S.AUTHORIZED, S.SUCCEEDED),
        # Cannot dispatch something still PENDING (must be AUTHORIZED first).
        (S.PENDING, S.DISPATCHED),
        # Cannot cancel something already authorized/dispatched -- CANCELLED
        # is only reachable from PENDING.
        (S.AUTHORIZED, S.CANCELLED),
        (S.DISPATCHED, S.CANCELLED),
    ],
)
def test_illegal_skipped_or_out_of_order_transitions(current: S, requested: S) -> None:
    assert not is_legal_transition(current, requested)
