"""Proves response_engine.contract's Command/CommandResult models are
compatible with the canonical golden fixtures in Panopticon-Co/panopticon-
contracts (vendored here as a test-only git submodule -- no runtime coupling
is introduced; only pytest imports this file).

Command's own field set is a *subset* of the full wire envelope: Manager's
authorize_and_enqueue() injects host_id/schema_version/created_at onto a
Command's dumped dict only at dispatch time (see panopticon-contracts/docs/
CONTRACT.md section 2), so a fixture's 'command' object cannot be passed to
Command(**...) unmodified -- Command's extra="forbid" would reject those three
fields. This test strips them explicitly and documents why, mirroring exactly
what manager/routers/commands.py already does in the other direction.

Fixtures that assert behavior outside Command's own Pydantic validation
(expiry against wall-clock time, non-UTC timestamp rejection, replay/cross-
agent/correlation-mismatch scenarios) are intentionally not exercised here --
they belong to manager/detection/response.py and manager/routers/commands.py's
own test suites (panopticon-manager/tests/test_response_engine.py), which is
where that behavior actually lives.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from response_engine.contract import ACTIONS, Command, CommandResult

FIXTURES_ROOT = Path(__file__).resolve().parent / "vendor" / "panopticon-contracts" / "fixtures"

# Fields Manager injects into the wire envelope after Command's own validation
# has already run -- see panopticon-contracts/docs/CONTRACT.md section 2.
_MANAGER_INJECTED_FIELDS = ("host_id", "schema_version", "created_at")

# invalid.json entries that are genuinely violations of Command's own Pydantic
# schema. The remaining entries (expired_command, non_utc_timestamp,
# replay_detected_scenario, cross_agent_mismatch, correlation_mismatch,
# malformed_command) test behavior this package does not implement (wall-clock
# expiry, transport-level replay/agent-binding, or non-JSON payloads) and are
# deliberately not asserted against Command here.
_COMMAND_SCHEMA_INVALID_FIXTURES = (
    "missing_required_field",
    "unknown_action",
    "invalid_target_types",
    "wrong_target_shape",
    "smuggled_shell_field",
    "oversized_correlation_id",
)


def _load(relative_path: str) -> dict:
    with (FIXTURES_ROOT / relative_path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _strip_manager_injected_fields(command: dict) -> dict:
    return {key: value for key, value in command.items() if key not in _MANAGER_INJECTED_FIELDS}


def test_valid_command_fixtures_cover_exactly_the_seven_closed_actions() -> None:
    valid_commands = _load("commands/valid.json")
    fixture_actions = {key for key in valid_commands if not key.startswith("$")}
    assert fixture_actions == set(ACTIONS)


@pytest.mark.parametrize("action", list(ACTIONS))
def test_command_accepts_every_valid_canonical_fixture(action: str) -> None:
    valid_commands = _load("commands/valid.json")
    wire_command = valid_commands[action]["command"]
    assert wire_command["action"] == action
    parsed = Command(**_strip_manager_injected_fields(wire_command))
    assert parsed.action == action
    assert parsed.command_id == wire_command["command_id"]
    assert parsed.correlation_id == wire_command["correlation_id"]


@pytest.mark.parametrize("fixture_name", _COMMAND_SCHEMA_INVALID_FIXTURES)
def test_command_rejects_every_intended_invalid_fixture(fixture_name: str) -> None:
    invalid_commands = _load("commands/invalid.json")
    wire_command = invalid_commands[fixture_name]["command"]
    with pytest.raises(ValidationError):
        Command(**_strip_manager_injected_fields(wire_command))


def test_command_result_accepts_every_valid_and_rejected_outcome_fixture() -> None:
    for relative_path in ("results/valid.json", "results/rejected.json"):
        entries = _load(relative_path)
        for name, entry in entries.items():
            if name.startswith("$"):
                continue
            wire_result = entry["result"]
            parsed = CommandResult(**wire_result)
            assert parsed.outcome == wire_result["outcome"]


def test_rejected_fixtures_all_carry_the_rejected_outcome() -> None:
    # Locks the receipt_code -> outcome collapse from the OTHER side of the
    # wire: every fixture documenting a local rejection reason must still
    # decode as CommandResult.outcome == "rejected", matching docs/CONTRACT.md
    # section 3's collapse table panopticon-linux-agent and panopticon-agent
    # both implement.
    rejected = _load("results/rejected.json")
    for name, entry in rejected.items():
        if name.startswith("$"):
            continue
        assert entry["result"]["outcome"] == "rejected", name
