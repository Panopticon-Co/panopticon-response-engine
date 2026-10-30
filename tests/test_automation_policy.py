import pytest
from pydantic import ValidationError

from response_engine.automation import (
    DEFAULT_POLICIES,
    RESPONSE_EXECUTOR_MARKER,
    PolicyMatch,
    ResponsePolicy,
    derive_response_status,
    evaluate_policy,
)


def _alert(**overrides):
    alert = {
        "alert_id": "ALT-1",
        "rule_id": "DET-PROC-012",
        "host_id": "LAB-1",
        "level": 13,
        "confidence": 0.95,
        "detection_source": "rule",
        "mitre_tactic": "Execution",
        "evidence": {"process.command_line": "powershell.exe ... DownloadString(...)"},
    }
    alert.update(overrides)
    return alert


def test_high_confidence_cradle_requires_approval_when_enforcing():
    decision = evaluate_policy(_alert(), "KILL_PROCESS", global_mode="enforce")
    assert decision.policy_id == "contain-download-cradle"
    assert decision.mode == "approval"
    assert decision.simulate and not decision.auto_execute


def test_default_global_mode_only_simulates_containment():
    decision = evaluate_policy(_alert(), "KILL_PROCESS")
    assert decision.global_mode == "simulate"
    assert decision.mode == "simulate"
    assert decision.simulate and not decision.auto_execute


def test_unknown_global_mode_fails_closed_to_simulate():
    decision = evaluate_policy(_alert(), "KILL_PROCESS", global_mode="YOLO")
    assert decision.global_mode == "simulate" and decision.mode == "simulate"


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"confidence": 0.5}, "confidence 0.5 below 0.8"),
        ({"confidence": None}, "alert carries no confidence"),
        ({"confidence": True}, "alert carries no confidence"),
        ({"level": 7}, "level 7 below 12"),
        ({"evidence": {}}, "evidence missing process.command_line"),
        ({"detection_source": "behavioral"}, "detection source 'behavioral' not eligible"),
        ({"detection_source": None}, "detection source None not eligible"),
    ],
)
def test_failed_gates_record_only(overrides, reason):
    decision = evaluate_policy(_alert(**overrides), "KILL_PROCESS", global_mode="enforce")
    assert decision.mode == "record"
    assert not decision.simulate and not decision.auto_execute
    assert f"gate failed: {reason}" in decision.reasons


def test_auto_policy_for_disruptive_action_is_downgraded_to_approval():
    policy = ResponsePolicy(
        policy_id="unsafe-auto-kill",
        description="misconfigured",
        match=PolicyMatch(rule_ids=("DET-PROC-012",)),
        action="KILL_PROCESS",
        mode="auto",
    )
    decision = evaluate_policy(
        _alert(), "KILL_PROCESS", policies=(policy,), global_mode="enforce"
    )
    assert decision.mode == "approval" and not decision.auto_execute
    assert any("downgraded" in r for r in decision.reasons)


def test_read_only_collection_auto_executes():
    decision = evaluate_policy(_alert(rule_id="DET-PS-010", level=10), "COLLECT_PROCESS_INFO")
    assert decision.policy_id == "investigate-process"
    assert decision.mode == "auto" and decision.auto_execute


def test_policy_action_must_equal_translated_action():
    # DET-PROC-012's policy is KILL_PROCESS; a different translated action never
    # borrows it -- the alert cannot steer a policy onto another action.
    decision = evaluate_policy(_alert(), "ISOLATE_HOST", global_mode="enforce")
    assert decision.policy_id == "default-tier" and decision.mode == "approval"


def test_unmatched_alert_keeps_tier_behaviour_when_enforcing():
    alert = _alert(rule_id="DET-OTHER-1")
    assert evaluate_policy(alert, "KILL_PROCESS", global_mode="enforce").mode == "approval"
    assert evaluate_policy(alert, "COLLECT_NETWORK_CONNECTIONS").mode == "auto"


def test_unmatched_containment_is_only_simulated_by_default():
    decision = evaluate_policy(_alert(rule_id="DET-OTHER-1"), "KILL_PROCESS")
    assert decision.policy_id == "default-tier" and decision.mode == "simulate"
    assert decision.cooldown_seconds > 0


@pytest.mark.parametrize("action", ["EXECUTE_SHELL", "BLOCK_FIREWALL_IP", "kill_process", ""])
def test_actions_outside_closed_set_are_denied(action):
    decision = evaluate_policy(_alert(), action)
    assert decision.mode == "denied" and not decision.auto_execute and not decision.simulate


@pytest.mark.parametrize(
    "alert",
    [
        None,
        "ALT-1",
        _alert(alert_id=""),
        _alert(rule_id=None),
        _alert(host_id=" "),
        _alert(level="13"),
        _alert(level=99),
        _alert(level=True),
        _alert(evidence=["not", "a", "dict"]),
    ],
)
def test_malformed_alerts_are_denied(alert):
    decision = evaluate_policy(alert, "KILL_PROCESS", global_mode="enforce")
    assert decision.mode == "denied" and decision.policy_id == "validation"


def test_response_executor_activity_cannot_trigger_a_response():
    alert = _alert(evidence={"process.command_line": f"python {RESPONSE_EXECUTOR_MARKER} --poll"})
    decision = evaluate_policy(alert, "KILL_PROCESS", global_mode="enforce")
    assert decision.mode == "denied" and decision.policy_id == "loop-guard"


def test_no_recommendation_is_recorded():
    assert evaluate_policy(_alert(), None).mode == "record"


def test_policy_definitions_are_closed_and_validated():
    with pytest.raises(ValidationError):
        PolicyMatch()
    with pytest.raises(ValidationError):
        ResponsePolicy(policy_id="x", description="", match=PolicyMatch(rule_ids=("A",)),
                       action="KILL_PROCESS", mode="approval")
    with pytest.raises(ValidationError):
        ResponsePolicy(policy_id="shell", description="", match=PolicyMatch(rule_ids=("A",)),
                       action="RUN_SCRIPT", mode="auto")
    with pytest.raises(ValidationError):
        ResponsePolicy(policy_id="extra", description="", match=PolicyMatch(rule_ids=("A",)),
                       action="KILL_PROCESS", mode="approval", command="rm -rf /")
    assert len({p.policy_id for p in DEFAULT_POLICIES}) == len(DEFAULT_POLICIES)


def test_decisions_are_deterministic():
    assert evaluate_policy(_alert(), "KILL_PROCESS") == evaluate_policy(_alert(), "KILL_PROCESS")


_KILL = {"action": "KILL_PROCESS"}


@pytest.mark.parametrize(
    ("actions", "incident", "expected"),
    [
        ([], None, "detected"),
        ([{"action": "COLLECT_PROCESS_INFO", "command_lifecycle_state": "SUCCEEDED"}], None,
         "response_recorded"),
        ([{**_KILL, "lifecycle_state": "REJECTED", "simulation_status": "simulated"}], None,
         "simulated_containment"),
        ([{**_KILL, "lifecycle_state": "PENDING", "simulation_status": "simulated"}], None,
         "awaiting_approval"),
        ([{**_KILL, "command_lifecycle_state": "DISPATCHED"}], None, "response_executing"),
        ([{**_KILL, "command_lifecycle_state": "FAILED"}], None, "containment_failed"),
        ([{**_KILL, "command_lifecycle_state": "SUCCEEDED", "result_detail": "simulated"}],
         None, "containment_unverified"),
        ([{**_KILL, "command_lifecycle_state": "SUCCEEDED",
           "result_detail": "verified: pid 7 gone"}], None, "contained"),
        ([{**_KILL, "command_lifecycle_state": "SUCCEEDED",
           "result_detail": "verified: pid 7 gone"}], "resolved", "resolved"),
        ([{**_KILL, "lifecycle_state": "PENDING"}], "false_positive", "resolved"),
    ],
)
def test_derive_response_status(actions, incident, expected):
    assert derive_response_status(actions, incident) == expected


def test_acknowledged_incident_is_not_contained():
    assert derive_response_status([{**_KILL, "lifecycle_state": "PENDING"}], "investigating") == (
        "awaiting_approval"
    )
