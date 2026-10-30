"""Forensic domain checks; no endpoint, filesystem collection or Manager writes."""

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from response_engine.contract import ACTIONS, Command
from response_engine.forensics import (
    EvidenceExpectation,
    ForensicCollectionPolicy,
    ForensicCollectionRequest,
    ForensicContext,
    plan_forensic_collection,
    validate_evidence_metadata,
)
from response_engine.policy import Tier, classify_tier

NOW = datetime(2026, 10, 30, 9, tzinfo=timezone.utc)


def context():
    return {
        "alert_id": "alert-1", "agent_id": "agent-1", "host_id": "host-1",
        "source_id": "sensor-1", "source_record_id": "record-original-1",
        "observed_at": NOW, "rule_id": "rule-1", "recommendation_id": "recommendation-1",
    }


def request(action="COLLECT_NETWORK_CONNECTIONS", **fields):
    return ForensicCollectionRequest.model_validate({
        "request_id": "forensic-request-1", "action": action, "context": context(), **fields,
    })


def policy(**fields):
    return ForensicCollectionPolicy.model_validate({
        "policy_id": "forensic-policy", "version": 1, "enabled": True, **fields,
    })


def manifest():
    fixture = (
        Path(__file__).parent / "vendor/panopticon-contracts/fixtures/artifacts/signing-v2.json"
    )
    return json.loads(fixture.read_text())["manifest"]


def expectation(value, action="COLLECT_PROCESS_INFO"):
    return EvidenceExpectation(
        action=action,
        **{name: value[name] for name in ("agent_id", "host_id", "command_id", "correlation_id")},
    )


@pytest.mark.parametrize("action,fields,kind", [
    ("COLLECT_PROCESS_INFO", {"process": {"pid": 42, "start_time_ticks": 123}},
     "process_snapshot"),
    ("COLLECT_NETWORK_CONNECTIONS", {}, "network_snapshot"),
    ("COLLECT_FILE", {"file": {"platform": "linux", "path": "/tmp/sample"}},
     "file_metadata"),
    ("COLLECT_FILE", {"file": {"platform": "windows", "path": r"C:\Lab\sample.txt"}},
     "file_metadata"),
])
def test_collection_plans_fit_existing_commands_and_preserve_provenance(action, fields, kind):
    original = request(action, **fields)
    snapshot = original.model_dump()
    result = plan_forensic_collection(original, policy(), asset_class="standard")
    assert result.decision == "require_approval"
    assert result.authorization_tier == "ANALYST_APPROVAL"
    assert result.evidence_kind == kind
    assert result.request.context.model_dump() == ForensicContext(**context()).model_dump()
    assert result.request.model_dump() == snapshot == original.model_dump()
    assert result.policy_id == "forensic-policy" and result.policy_version == 1
    command = Command(
        command_id="consumer-owned-command", agent_id=result.request.context.agent_id,
        correlation_id="consumer-owned-correlation", expires_at=NOW,
        schema_version=result.command_schema_version, action=result.request.action,
        target=result.target,
    )
    assert command.action == action
    assert "command_id" not in result.model_dump()
    assert "lifecycle_state" not in result.model_dump()


def test_boot_bound_process_identity_preserves_native_uint64_not_wall_time():
    result = plan_forensic_collection(request("COLLECT_PROCESS_INFO", process={
        "pid": 42, "start_time_ticks": 0xFFFFFFFFFFFFFFFF, "boot_id": "boot_" + "a" * 64,
    }), policy())
    assert result.command_schema_version == "2"
    assert result.target == {
        "pid": 42, "start_time_ticks": "18446744073709551615", "boot_id": "boot_" + "a" * 64,
    }
    Command(
        command_id="cmd", agent_id="agent-1", expires_at=NOW,
        schema_version="2", action="COLLECT_PROCESS_INFO", target=result.target,
    )


def test_repeat_planning_is_idempotent_and_has_no_mutation_or_generated_metadata():
    original, configuration = request(), policy()
    before = (original.model_dump(), configuration.model_dump())
    first = plan_forensic_collection(original, configuration)
    second = plan_forensic_collection(original, configuration)
    assert first.model_dump() == second.model_dump()
    assert before == (original.model_dump(), configuration.model_dump())
    assert first.request.context.evidence == []
    assert "sha256" not in first.model_dump_json()


@pytest.mark.parametrize("asset", ["critical", "unknown"])
@pytest.mark.parametrize("action,fields", [
    ("COLLECT_NETWORK_CONNECTIONS", {}),
    ("COLLECT_PROCESS_INFO", {"process": {"pid": 42, "start_time_ticks": 123}}),
    ("COLLECT_FILE", {"file": {"platform": "linux", "path": "/tmp/sample"}}),
])
def test_blast_radius_always_requires_approval(asset, action, fields):
    result = plan_forensic_collection(
        request(action, **fields), policy(require_approval=[]), asset_class=asset,
    )
    assert result.decision == "require_approval"
    assert result.reason == "asset_requires_approval"
    assert result.authorization_tier == "ANALYST_APPROVAL"


def test_policy_cannot_lower_file_authorization_tier():
    result = plan_forensic_collection(request("COLLECT_FILE", file={
        "platform": "linux", "path": "/tmp/sample",
    }), policy(require_approval=[]), asset_class="standard")
    assert result.decision == "require_approval"
    assert result.authorization_tier == classify_tier("COLLECT_FILE").value


def test_read_only_recommendation_is_not_auto_authorization():
    result = plan_forensic_collection(
        request(), policy(require_approval=[]), asset_class="standard",
    )
    assert result.decision == "recommend"
    assert result.authorization_tier == "AUTO_SAFE"
    assert "authorized" not in result.model_dump()


@pytest.mark.parametrize("configuration,reason", [
    ({"enabled": False}, "policy_disabled"),
    ({"allowed_actions": []}, "action_not_allowed"),
])
def test_policy_skips_are_explicit(configuration, reason):
    result = plan_forensic_collection(request(), policy(**configuration), asset_class="standard")
    assert result.decision == "skip" and result.reason == reason


def test_policy_defaults_disabled_and_can_roundtrip_as_versioned_json():
    value = ForensicCollectionPolicy(policy_id="policy", version=1)
    assert not value.enabled
    assert ForensicCollectionPolicy.model_validate_json(value.model_dump_json()) == value
    assert plan_forensic_collection(request(), value).decision == "skip"


@pytest.mark.parametrize("action", [
    "KILL_PROCESS", "QUARANTINE_FILE", "ISOLATE_HOST", "RELEASE_HOST_ISOLATION",
    "ACQUIRE_FILE", "EXECUTE", "COLLECT_MEMORY", "TERMINATE_PROCESS", "unknown",
])
def test_non_collection_and_unsupported_actions_are_refused_everywhere(action):
    with pytest.raises(ValidationError):
        request(action)
    with pytest.raises(ValidationError):
        policy(allowed_actions=[action])
    with pytest.raises(ValidationError):
        policy(require_approval=[action])
    with pytest.raises(ValidationError):
        EvidenceExpectation(
            action=action, agent_id="a", host_id="h", command_id="c", correlation_id="x",
        )


@pytest.mark.parametrize("fields", [
    {"process": {"pid": 1, "start_time_ticks": 2}},
    {"file": {"platform": "linux", "path": "/tmp/sample"}},
    {"target": {"shell": "whoami"}}, {"approved": True}, {"asset_class": "standard"},
])
def test_network_request_cannot_smuggle_targets_approval_or_asset_class(fields):
    with pytest.raises(ValidationError):
        request(**fields)


@pytest.mark.parametrize("fields", [
    {}, {"process": {"pid": True, "start_time_ticks": 123}},
    {"process": {"pid": 42, "start_time_ticks": 0}},
    {"process": {"pid": 42, "start_time_ticks": "123"}},
    {"process": {"pid": 42, "start_time_ticks": 123, "boot_id": "unknown"}},
    {"process": {"pid": 0x100000000, "start_time_ticks": 123}},
    {"process": {"pid": 42, "start_time_ticks": 0x10000000000000000}},
    {"process": {"pid": 42, "start_time_ticks": 123, "observed_at": NOW}},
])
def test_missing_or_invented_process_identity_fails_closed(fields):
    with pytest.raises(ValidationError):
        request("COLLECT_PROCESS_INFO", **fields)


@pytest.mark.parametrize("platform,path", [
    ("linux", "relative/file"), ("linux", "/tmp/../secret"), ("linux", "/tmp/*"),
    ("windows", r"C:\Lab\file.txt:secret"), ("windows", r"\\host\share\file"),
    ("windows", r"C:\Lab\NUL"), ("windows", r"C:\Lab\file.txt."),
])
def test_file_metadata_requests_cannot_expand_path_scope(platform, path):
    with pytest.raises(ValidationError):
        request("COLLECT_FILE", file={"platform": platform, "path": path})


@pytest.mark.parametrize("fields", [{}, {"file": {"platform": "linux", "path": "/tmp/a",
                                                       "acquire_bytes": True}}])
def test_file_collection_requires_metadata_only_exact_target(fields):
    with pytest.raises(ValidationError):
        request("COLLECT_FILE", **fields)


@pytest.mark.parametrize("field,value", [
    ("alert_id", ""), ("source_id", " "), ("source_record_id", ""),
    ("observed_at", datetime(2026, 10, 30)), ("observed_at", 123),
    ("agent_id", True), ("host_id", ""),
])
def test_context_requires_real_provenance_and_aware_time(field, value):
    original = context()
    original[field] = value
    with pytest.raises(ValidationError):
        ForensicContext.model_validate(original)


@pytest.mark.parametrize("fields", [
    {"version": 0}, {"version": True}, {"version": "1"}, {"schema_version": "2"},
    {"enabled": 1}, {"auto_approve": True},
    {"allowed_actions": ["COLLECT_FILE", "COLLECT_FILE"]},
    {"require_approval": ["COLLECT_FILE", "COLLECT_FILE"]},
])
def test_policy_rejects_invalid_revisions_duplicates_and_approval_bypasses(fields):
    with pytest.raises(ValidationError):
        policy(**fields)


def test_unknown_asset_label_fails_instead_of_falling_back_to_standard():
    with pytest.raises(ValueError, match="asset classification"):
        plan_forensic_collection(request(), policy(), asset_class="server")


def test_metadata_preserves_original_values_without_attesting_signature_or_content():
    original = manifest()
    snapshot = copy.deepcopy(original)
    validated = validate_evidence_metadata(original, expected=expectation(original))
    assert validated.model_dump() == snapshot == original
    # A correctly shaped hash is not proof of bytes or signature authenticity.
    original["sha256"] = "0" * 64
    assert validate_evidence_metadata(original, expected=expectation(original)).sha256 == "0" * 64


@pytest.mark.parametrize("field,value", [
    ("sha256", "a" * 63), ("sha256", "A" * 64), ("sha256", "g" * 64),
    ("sha256", None), ("sha256", 1), ("content_bytes", True),
    ("content_bytes", 0), ("content_bytes", 1048577), ("authorization", {}),
    ("produced_at_unix", -1), ("produced_at_unix", "123"),
    ("kind", "raw_file"), ("content_base64", "e30="),
])
def test_malformed_evidence_metadata_is_refused(field, value):
    original = manifest()
    expected = expectation(original)
    original[field] = value
    with pytest.raises(ValidationError):
        validate_evidence_metadata(original, expected=expected)


@pytest.mark.parametrize("field", ["sha256", "artifact_id", "command_id", "produced_at_unix"])
def test_missing_metadata_is_not_fabricated(field):
    original = manifest()
    expected = expectation(original)
    del original[field]
    with pytest.raises(ValidationError):
        validate_evidence_metadata(original, expected=expected)


@pytest.mark.parametrize("field", ["agent_id", "host_id", "command_id", "correlation_id"])
def test_metadata_scope_cannot_be_rebound_to_another_command_or_endpoint(field):
    original = manifest()
    expected = expectation(original)
    original[field] = "different-identity"
    with pytest.raises(ValueError, match="command scope"):
        validate_evidence_metadata(original, expected=expected)


@pytest.mark.parametrize("action,kind", [
    ("COLLECT_PROCESS_INFO", "process_snapshot"),
    ("COLLECT_NETWORK_CONNECTIONS", "network_snapshot"),
    ("COLLECT_FILE", "file_metadata"),
])
def test_metadata_action_kind_agreement(action, kind):
    original = manifest()
    original["kind"] = kind
    expected = expectation(original, action)
    assert validate_evidence_metadata(original, expected=expected).kind == kind
    original["kind"] = "execution_report"
    with pytest.raises(ValueError, match="kind"):
        validate_evidence_metadata(original, expected=expected)


def test_evidence_context_roundtrip_preserves_source_ids_and_endpoint_timestamp():
    original = manifest()
    value = context()
    value.update(agent_id=original["agent_id"], host_id=original["host_id"])
    value["evidence"] = [{
        "source_id": "manager-retained-evidence", "source_record_id": "original-record",
        "manifest": original,
    }]
    parsed = ForensicContext.model_validate(value)
    assert ForensicContext.model_validate_json(parsed.model_dump_json()) == parsed
    assert parsed.evidence[0].manifest.model_dump() == original
    assert parsed.evidence[0].source_record_id == "original-record"
    assert parsed.observed_at == NOW
    # Endpoint-produced time is an independent claim, not rewritten to alert time.
    assert parsed.evidence[0].manifest.produced_at_unix == original["produced_at_unix"]


@pytest.mark.parametrize("mode", ["other_agent", "other_host", "duplicate", "missing_source"])
def test_context_rejects_inconsistent_or_untraceable_evidence(mode):
    original = manifest()
    value = context()
    value.update(agent_id=original["agent_id"], host_id=original["host_id"])
    reference = {"source_id": "manager", "source_record_id": "record", "manifest": original}
    value["evidence"] = [reference]
    if mode == "other_agent":
        value["agent_id"] = "another-agent"
    elif mode == "other_host":
        value["host_id"] = "another-host"
    elif mode == "duplicate":
        value["evidence"].append(copy.deepcopy(reference))
    else:
        del reference["source_record_id"]
    with pytest.raises(ValidationError):
        ForensicContext.model_validate(value)


def test_mutated_nested_models_are_revalidated_at_planning_boundary():
    original = request("COLLECT_FILE", file={"platform": "linux", "path": "/tmp/sample"})
    original.file.path = "/tmp/*"
    with pytest.raises(ValidationError):
        plan_forensic_collection(original, policy())
    configuration = policy()
    configuration.allowed_actions.append("KILL_PROCESS")
    with pytest.raises(ValidationError):
        plan_forensic_collection(request(), configuration)


def test_existing_action_and_tier_contract_is_unchanged():
    assert ACTIONS == (
        "KILL_PROCESS", "COLLECT_PROCESS_INFO", "COLLECT_NETWORK_CONNECTIONS", "COLLECT_FILE",
        "QUARANTINE_FILE", "ISOLATE_HOST", "RELEASE_HOST_ISOLATION",
    )
    assert {action: classify_tier(action) for action in ACTIONS} == {
        action: (Tier.AUTO_SAFE if action in (
            "COLLECT_PROCESS_INFO", "COLLECT_NETWORK_CONNECTIONS",
        ) else Tier.ANALYST_APPROVAL) for action in ACTIONS
    }
