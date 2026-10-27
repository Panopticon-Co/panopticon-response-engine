from copy import deepcopy

import pytest
from pydantic import ValidationError

from response_engine.contract import CommandResult


def result_fields():
    return {
        "schema_version": "2", "result_id": "result-evidence", "command_id": "cmd-evidence",
        "correlation_id": "corr-evidence", "outcome": "indeterminate",
        "execution": {
            "representation": "windows_process_termination_v1", "stage": "completion",
            "action_initiated": True, "completion_observed": False, "native_error": 6,
        },
    }


@pytest.mark.parametrize("outcome,stage,initiated,completed,error", [
    ("succeeded", "completion", True, True, None),
    ("indeterminate", "completion", True, False, 6),
    ("indeterminate", "completion", True, False, None),
    ("failed", "open", False, False, 5),
    ("rejected", "identity", False, False, None),
])
def test_conclusive_execution_facts_preserve_types(outcome, stage, initiated, completed, error):
    fields = result_fields()
    fields["outcome"] = outcome
    fields["execution"].update(stage=stage, action_initiated=initiated,
                               completion_observed=completed, native_error=error)
    parsed = CommandResult(**fields)
    assert parsed.model_dump(mode="json")["execution"] == fields["execution"]


@pytest.mark.parametrize("patch", [
    {"stage": "unknown"}, {"representation": "other"}, {"stdout": "unbounded"},
    {"native_error": True}, {"native_error": "6"}, {"native_error": -1},
    {"native_error": 4294967296}, {"native_error": 1.0}, {"action_initiated": "true"},
    {"action_initiated": False}, {"completion_observed": True}, {"stage": "open"},
])
def test_malformed_or_contradictory_execution_facts_refuse(patch):
    fields = result_fields()
    fields["execution"].update(patch)
    with pytest.raises(ValidationError):
        CommandResult(**fields)


def test_execution_evidence_is_versioned_optional_but_never_explicit_null():
    fields = result_fields()
    legacy = deepcopy(fields)
    legacy.update(schema_version="1", outcome="failed")
    with pytest.raises(ValidationError):
        CommandResult(**legacy)
    fields["execution"] = None
    with pytest.raises(ValidationError):
        CommandResult(**fields)
    del fields["execution"]
    assert CommandResult(**fields).execution is None
    assert "execution" not in CommandResult(**fields).model_dump(mode="json")


@pytest.mark.parametrize("outcome", ["succeeded", "failed", "rejected"])
def test_initiated_unobserved_completion_cannot_be_definite(outcome):
    fields = result_fields()
    fields["outcome"] = outcome
    with pytest.raises(ValidationError):
        CommandResult(**fields)
