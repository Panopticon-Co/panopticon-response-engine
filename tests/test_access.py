from response_engine.access import AnalystPermission as P
from response_engine.access import permissions_for


def test_roles_separate_request_from_approval_and_unknown_roles_fail_closed():
    assert P.REQUEST in permissions_for("responder")
    assert P.DECIDE not in permissions_for("responder")
    assert P.DECIDE in permissions_for("approver")
    assert P.REQUEST not in permissions_for("approver")
    assert permissions_for("analyst") == frozenset(P)
    assert not permissions_for("viewer")
    assert not permissions_for("administrator")
