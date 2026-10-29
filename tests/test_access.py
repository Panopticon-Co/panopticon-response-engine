from response_engine.access import AnalystPermission as P
from response_engine.access import permissions_for


def test_roles_separate_request_from_approval_and_unknown_roles_fail_closed():
    assert P.REQUEST in permissions_for("responder")
    assert P.DECIDE not in permissions_for("responder")
    assert P.DECIDE in permissions_for("approver")
    assert P.REQUEST not in permissions_for("approver")
    assert permissions_for("analyst") == frozenset(
        {P.REQUEST, P.DECIDE, P.INVESTIGATE, P.ARTIFACT_READ}
    )
    assert not permissions_for("viewer")
    assert not permissions_for("administrator")


def test_artifact_scope_administration_never_grants_response_approval():
    from response_engine.access import ACCESS_POLICY_VERSION

    assert ACCESS_POLICY_VERSION == 2
    assert P.ARTIFACT_SCOPE_MANAGE in permissions_for("artifact_admin")
    assert P.DECIDE not in permissions_for("artifact_admin")
    for role in ("viewer", "responder", "approver", "analyst"):
        assert P.ARTIFACT_SCOPE_MANAGE not in permissions_for(role)


def test_closed_analyst_roles_match_central_enrollment_contract():
    import json
    from pathlib import Path

    from response_engine.access import AnalystRole

    schema = json.loads(
        (
            Path(__file__).parent / "vendor/panopticon-contracts/schema/"
            "analyst-enrollment.schema.json"
        ).read_text()
    )
    assert set(schema["properties"]["role"]["enum"]) == {role.value for role in AnalystRole}
