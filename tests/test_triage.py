import copy
import json
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

from response_engine.contract import ACTIONS
from response_engine.triage import (
    ARTIFACT_PROTOCOL,
    COLLECT_ACTIONS,
    ActionPolicy,
    ApprovedFile,
    AutoTriagePolicy,
    BudgetUsage,
    CollectionBudget,
    EndpointCapability,
    default_policy,
    evaluate,
)


def capabilities(platform="linux", **changes):
    return EndpointCapability.model_validate(
        {
            "platform": platform,
            "recent": True,
            "mode": "enforce",
            "implemented_actions": list(COLLECT_ACTIONS),
            "allowed_actions": list(COLLECT_ACTIONS),
            "signed_command_channel": True,
            "artifact_protocol": ARTIFACT_PROTOCOL,
            **changes,
        }
    )


def enabled(**changes):
    return AutoTriagePolicy.model_validate(
        {**default_policy("RULE-1").model_dump(), "enabled": True, **changes}
    )


@pytest.mark.parametrize("platform", ["windows", "linux"])
@pytest.mark.parametrize("asset", ["standard", "critical", "unknown"])
def test_default_matrix_and_critical_blast_radius(platform, asset):
    endpoint = capabilities(platform)
    path = r"C:\PanopticonLab\sample.txt" if platform == "windows" else "/tmp/sample.txt"
    for action in COLLECT_ACTIONS:
        assert (
            evaluate(
                default_policy("RULE-1"),
                action,
                asset,
                endpoint,
                BudgetUsage(),
                process_identity_verified=True,
                file_path=path,
            ).reason
            == "rule_disabled"
        )
        result = evaluate(
            enabled(),
            action,
            asset,
            endpoint,
            BudgetUsage(),
            process_identity_verified=True,
            file_path=path,
        )
        expected = (
            "auto_dispatch"
            if asset == "standard" and action != "COLLECT_FILE"
            else "require_approval"
        )
        assert result.decision == expected
        assert result.policy_version == 1 and result.rule_id == "RULE-1"


@pytest.mark.parametrize("action", sorted(set(ACTIONS) - set(COLLECT_ACTIONS)) + ["REMOTE_SHELL"])
def test_closed_boundary_rejects_every_non_collection_action(action):
    with pytest.raises(ValidationError):
        ActionPolicy(action=action, asset_class="standard", decision="auto_dispatch")
    with pytest.raises(ValueError, match="three collection actions"):
        evaluate(enabled(), action, "standard", capabilities(), BudgetUsage())


@pytest.mark.parametrize("asset", ["critical", "unknown"])
def test_critical_or_unclassified_cannot_be_configured_for_automatic_execution(asset):
    for action in COLLECT_ACTIONS:
        with pytest.raises(ValidationError, match="cannot auto-dispatch"):
            ActionPolicy(action=action, asset_class=asset, decision="auto_dispatch")


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"recent": False}, "capability_report_not_current"),
        ({"implemented_actions": ["COLLECT_PROCESS_INFO"]}, "action_not_supported"),
        ({"allowed_actions": ["COLLECT_PROCESS_INFO"]}, "endpoint_policy_denied"),
        ({"mode": "off"}, "endpoint_not_enforcing"),
        ({"mode": "dry_run"}, "endpoint_not_enforcing"),
        ({"signed_command_channel": False}, "signed_command_channel_required"),
        ({"artifact_protocol": None}, "signed_artifact_delivery_not_supported"),
    ],
)
def test_capability_and_current_policy_can_only_restrict_auto_dispatch(changes, reason):
    result = evaluate(
        enabled(), "COLLECT_NETWORK_CONNECTIONS", "standard", capabilities(**changes), BudgetUsage()
    )
    assert result.decision == "skip" and result.reason == reason


def test_process_collection_requires_verified_identity_without_truthy_coercion():
    for proof in (False, None, "true", 1):
        result = evaluate(
            enabled(),
            "COLLECT_PROCESS_INFO",
            "standard",
            capabilities(),
            BudgetUsage(),
            process_identity_verified=proof,
        )
        assert result.decision == "skip" and result.reason == "verified_process_identity_required"


@pytest.mark.parametrize(
    "platform,path,other",
    [
        ("linux", "/var/tmp/panopticon/sample.txt", "/var/tmp/panopticon/other.txt"),
        ("windows", r"C:\PanopticonLab\sample.txt", r"C:\PanopticonLab\other.txt"),
    ],
)
def test_file_automation_requires_an_exact_approved_native_path(platform, path, other):
    entry = ActionPolicy(
        action="COLLECT_FILE",
        asset_class="standard",
        decision="auto_dispatch",
        file_paths=[ApprovedFile(platform=platform, path=path)],
    )
    policy = enabled(entries=[entry.model_dump()])
    assert (
        evaluate(
            policy,
            "COLLECT_FILE",
            "standard",
            capabilities(platform),
            BudgetUsage(),
            file_path=path,
        ).decision
        == "auto_dispatch"
    )
    assert (
        evaluate(
            policy,
            "COLLECT_FILE",
            "standard",
            capabilities(platform),
            BudgetUsage(),
            file_path=other,
        ).reason
        == "alert_file_target_not_allowlisted"
    )
    assert (
        evaluate(
            policy,
            "COLLECT_FILE",
            "standard",
            capabilities(platform),
            BudgetUsage(),
            file_path=None,
        ).reason
        == "alert_file_target_missing"
    )


@pytest.mark.parametrize(
    "platform,path",
    [
        ("linux", "relative/file"),
        ("linux", "/tmp/../secret"),
        ("linux", "/tmp/./file"),
        ("linux", "/tmp//file"),
        ("linux", "//server/file"),
        ("linux", "/tmp/*"),
        ("linux", "/tmp/with\ncontrol"),
        ("linux", "/tmp/"),
        ("linux", "/"),
        ("windows", r"C:relative.txt"),
        ("windows", r"C:\lab\..\secret"),
        ("windows", r"\\server\share\file"),
        ("windows", r"\\?\C:\file"),
        ("windows", r"C:\lab\file:stream"),
        ("windows", r"C:\lab\CON.txt"),
        ("windows", "C:\\lab\\file. "),
        ("windows", r"C:\lab\*.txt"),
    ],
)
def test_ambiguous_or_wildcard_file_paths_are_never_auto_allowlisted(platform, path):
    with pytest.raises(ValidationError):
        ApprovedFile(platform=platform, path=path)


@pytest.mark.parametrize(
    "usage,reason",
    [
        ({"actions_for_alert": 3}, "alert_action_budget"),
        ({"bytes_for_alert": 2097153}, "alert_byte_budget"),
        ({"actions_in_endpoint_window": 12}, "endpoint_frequency_budget"),
        ({"bytes_in_endpoint_window": 12582912}, "endpoint_byte_budget"),
        ({"active_for_endpoint": 3}, "endpoint_concurrency_budget"),
        ({"active_global": 128}, "global_concurrency_budget"),
    ],
)
def test_each_collection_budget_dimension_is_independently_enforced(usage, reason):
    result = evaluate(
        enabled(), "COLLECT_NETWORK_CONNECTIONS", "standard", capabilities(), BudgetUsage(**usage)
    )
    assert result.decision == "skip" and result.reason == reason


@pytest.mark.parametrize(
    "changes",
    [
        {"reserved_bytes_per_action": 65536},
        {"max_actions_per_alert": True},
        {"max_actions_per_alert": 4},
        {"max_bytes_per_alert": 3145729},
        {"endpoint_window_seconds": 0},
        {"max_active_per_endpoint": 9},
        {"workflow_ttl_seconds": 901},
        {"max_actions_per_endpoint_window": 65},
    ],
)
def test_budget_bounds_cannot_claim_a_smaller_undeployed_collector_or_accept_bool(changes):
    with pytest.raises(ValidationError):
        CollectionBudget(**changes)


def test_duplicate_decisions_and_implicit_file_carveouts_are_rejected():
    entry = ActionPolicy(
        action="COLLECT_NETWORK_CONNECTIONS", asset_class="standard", decision="auto_dispatch"
    )
    with pytest.raises(ValidationError, match="duplicate"):
        enabled(entries=[entry.model_dump(), {**entry.model_dump(), "decision": "skip"}])
    with pytest.raises(ValidationError, match="allowlist"):
        ActionPolicy(action="COLLECT_FILE", asset_class="standard", decision="auto_dispatch")


def test_policy_decision_is_repeatable_and_does_not_mutate_policy_or_usage():
    policy, endpoint, usage = enabled(), capabilities(), BudgetUsage()
    before = copy.deepcopy((policy.model_dump(), endpoint.model_dump(), usage.model_dump()))
    first = evaluate(policy, "COLLECT_NETWORK_CONNECTIONS", "standard", endpoint, usage)
    assert evaluate(policy, "COLLECT_NETWORK_CONNECTIONS", "standard", endpoint, usage) == first
    assert before == (policy.model_dump(), endpoint.model_dump(), usage.model_dump())
    policy = enabled(
        entries=[
            ActionPolicy(
                action="COLLECT_PROCESS_INFO", asset_class="standard", decision="skip"
            ).model_dump()
        ]
    )
    assert (
        evaluate(policy, "COLLECT_NETWORK_CONNECTIONS", "standard", endpoint, usage).reason
        == "no_matching_policy_entry"
    )


def test_central_policy_fixtures_and_domain_model_agree():
    root = Path(__file__).parent / "vendor/panopticon-contracts"
    schema = json.loads((root / "schema/auto-triage-policy-v1.schema.json").read_text())
    fixtures = json.loads((root / "fixtures/triage/policy-v1.json").read_text())
    for case in fixtures["valid"]:
        jsonschema.validate(case["policy"], schema)
        AutoTriagePolicy.model_validate(case["policy"])
    for case in fixtures["invalid"]:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(case["policy"], schema)
        with pytest.raises(ValidationError):
            AutoTriagePolicy.model_validate(case["policy"])
