import copy
import hashlib

import pytest

from response_engine.recommendation import translate_recommendation


def facts():
    host, boot, pid, ticks = "host-1", "boot_" + "a" * 64, 42, "18446744073709551615"
    fields = ["native-process-instance-v1", host, boot, str(pid), ticks]
    material = "".join(str(len(x.encode())) + ":" + x for x in fields)
    context = {
        "endpoint": {"host_id": host, "boot_id": boot, "agent_id": "agent-1"},
        "subject": {
            "observed_pid": pid,
            "native_creation_ticks": ticks,
            "boot_id": boot,
            "resolution": "native_exact",
            "entity_id": "proc_" + hashlib.sha256(material.encode()).hexdigest(),
        },
    }
    recommendation = {"host_id": host, "target_pid": pid, "target_start_time_ticks": int(ticks)}
    return context, recommendation


@pytest.mark.parametrize("action", ["TERMINATE_PROCESS", "COLLECT_PROCESS_INFO"])
def test_canonical_exact_target_preserves_scope_and_maximum_token(action):
    context, recommendation = facts()
    result = translate_recommendation(action, recommendation, context)
    assert result[1] == {
        "pid": 42,
        "start_time_ticks": "18446744073709551615",
        "boot_id": "boot_" + "a" * 64,
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("resolution", "source_scoped"),
        ("resolution", "unresolved"),
        ("entity_id", "proc_" + "b" * 64),
        ("boot_id", "boot_" + "b" * 64),
        ("native_creation_ticks", None),
        ("observed_pid", True),
    ],
)
def test_invalid_context_never_falls_back_to_legacy_target(field, value):
    context, recommendation = facts()
    context["subject"][field] = value
    assert translate_recommendation("TERMINATE_PROCESS", recommendation, context) is None


def test_recommendation_must_name_exactly_the_verified_subject():
    context, recommendation = facts()
    for key, value in [("target_pid", 43), ("target_start_time_ticks", 123), ("host_id", "other")]:
        modified = copy.deepcopy(recommendation)
        modified[key] = value
        assert translate_recommendation("TERMINATE_PROCESS", modified, context) is None
