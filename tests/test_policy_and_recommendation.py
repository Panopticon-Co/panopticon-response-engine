from response_engine.policy import Tier, classify_tier
from response_engine.recommendation import translate_recommendation


def test_kill_isolate_and_release_always_require_analyst_approval() -> None:
    assert classify_tier("KILL_PROCESS") == Tier.ANALYST_APPROVAL
    assert classify_tier("ISOLATE_HOST") == Tier.ANALYST_APPROVAL
    assert classify_tier("RELEASE_HOST_ISOLATION") == Tier.ANALYST_APPROVAL


def test_read_only_collection_actions_are_auto_safe() -> None:
    assert classify_tier("COLLECT_PROCESS_INFO") == Tier.AUTO_SAFE
    assert classify_tier("COLLECT_NETWORK_CONNECTIONS") == Tier.AUTO_SAFE


def test_file_actions_require_analyst_approval() -> None:
    assert classify_tier("COLLECT_FILE") == Tier.ANALYST_APPROVAL
    assert classify_tier("QUARANTINE_FILE") == Tier.ANALYST_APPROVAL


def test_unknown_action_defaults_to_analyst_approval_never_auto_safe() -> None:
    assert classify_tier("SOMETHING_UNKNOWN") == Tier.ANALYST_APPROVAL


def test_tier_string_equality_for_sqlite_storage() -> None:
    # Tier is a str subclass so it can be bound directly as a SQL parameter
    # and compared against the raw strings a consumer's database stores.
    assert classify_tier("ISOLATE_HOST") == "ANALYST_APPROVAL"


def test_terminate_process_fails_closed_with_no_start_time_data() -> None:
    assert translate_recommendation("TERMINATE_PROCESS", {"target_pid": 123}) is None


def test_terminate_process_maps_to_kill_process_with_a_valid_start_time() -> None:
    assert translate_recommendation(
        "TERMINATE_PROCESS", {"target_pid": 123, "target_start_time_ticks": 456789}
    ) == ("KILL_PROCESS", {"pid": 123, "start_time_ticks": 456789}, "direct mapping")


def test_terminate_process_fails_closed_with_a_zero_start_time() -> None:
    assert translate_recommendation("TERMINATE_PROCESS", {"target_pid": 123, "target_start_time_ticks": 0}) is None


def test_terminate_process_fails_closed_with_a_negative_start_time() -> None:
    assert translate_recommendation("TERMINATE_PROCESS", {"target_pid": 123, "target_start_time_ticks": -1}) is None


def test_terminate_process_fails_closed_with_wrong_typed_fields() -> None:
    assert translate_recommendation("TERMINATE_PROCESS", {"target_pid": "123", "target_start_time_ticks": 456}) is None
    assert translate_recommendation("TERMINATE_PROCESS", {"target_pid": 123, "target_start_time_ticks": "456"}) is None
    assert translate_recommendation("TERMINATE_PROCESS", {"target_pid": True, "target_start_time_ticks": 456}) is None


def test_isolate_host_is_a_direct_mapping() -> None:
    assert translate_recommendation("ISOLATE_HOST", {}) == ("ISOLATE_HOST", {}, "direct mapping")


def test_block_firewall_ip_downgrades_to_isolate_host() -> None:
    action, target, reason = translate_recommendation("BLOCK_FIREWALL_IP", {"target_ip": "1.2.3.4"})
    assert action == "ISOLATE_HOST"
    assert target == {}
    assert "downgraded" in reason


def test_unknown_recommendation_returns_none() -> None:
    assert translate_recommendation("SOMETHING_ELSE", {}) is None
