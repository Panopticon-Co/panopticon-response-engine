from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from response_engine.contract import ACTIONS, Command, CommandResult


def _future() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=5)


def test_closed_action_set_has_exactly_seven_actions() -> None:
    assert ACTIONS == (
        "KILL_PROCESS",
        "COLLECT_PROCESS_INFO",
        "COLLECT_NETWORK_CONNECTIONS",
        "COLLECT_FILE",
        "QUARANTINE_FILE",
        "ISOLATE_HOST",
        "RELEASE_HOST_ISOLATION",
    )


def test_kill_process_requires_pid_and_start_time_ticks() -> None:
    Command(
        command_id="c1",
        agent_id="a1",
        action="KILL_PROCESS",
        expires_at=_future(),
        target={"pid": 42, "start_time_ticks": 99},
    )
    with pytest.raises(ValidationError):
        Command(
            command_id="c1",
            agent_id="a1",
            action="KILL_PROCESS",
            expires_at=_future(),
            target={"pid": 42},
        )


def test_process_target_rejects_non_positive_or_non_int_values() -> None:
    with pytest.raises(ValidationError):
        Command(
            command_id="c1",
            agent_id="a1",
            action="KILL_PROCESS",
            expires_at=_future(),
            target={"pid": -1, "start_time_ticks": 99},
        )
    with pytest.raises(ValidationError):
        Command(
            command_id="c1",
            agent_id="a1",
            action="KILL_PROCESS",
            expires_at=_future(),
            target={"pid": True, "start_time_ticks": 99},
        )


def test_file_action_requires_only_path() -> None:
    Command(
        command_id="c1",
        agent_id="a1",
        action="QUARANTINE_FILE",
        expires_at=_future(),
        target={"path": "/tmp/malware"},
    )
    with pytest.raises(ValidationError):
        Command(
            command_id="c1",
            agent_id="a1",
            action="QUARANTINE_FILE",
            expires_at=_future(),
            target={},
        )


def test_isolate_host_accepts_no_target() -> None:
    Command(
        command_id="c1", agent_id="a1", action="ISOLATE_HOST", expires_at=_future(), target={}
    )
    with pytest.raises(ValidationError):
        Command(
            command_id="c1",
            agent_id="a1",
            action="ISOLATE_HOST",
            expires_at=_future(),
            target={"unexpected": 1},
        )


def test_unknown_action_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Command(
            command_id="c1",
            agent_id="a1",
            action="EXECUTE_COMMAND",
            expires_at=_future(),
            target={},
        )


def test_command_forbids_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Command(
            command_id="c1",
            agent_id="a1",
            action="ISOLATE_HOST",
            expires_at=_future(),
            target={},
            shell="rm -rf /",
        )


def test_command_result_forbids_unknown_fields() -> None:
    CommandResult(result_id="r1", command_id="c1", outcome="succeeded")
    with pytest.raises(ValidationError):
        CommandResult(result_id="r1", command_id="c1", outcome="succeeded", extra="x")
