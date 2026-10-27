from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from response_engine.contract import Command


def fields():
    return dict(
        command_id="cmd-v2",
        agent_id="agent-1",
        schema_version="2",
        action="KILL_PROCESS",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        target=dict(pid=42, start_time_ticks="18446744073709551615", boot_id="boot_" + "a" * 64),
    )


def test_windows_command_preserves_boot_and_full_uint64():
    command = Command(**fields())
    assert command.model_dump(mode="json")["target"] == fields()["target"]
    assert command.schema_version == "2"


@pytest.mark.parametrize(
    "ticks", [0, 1, True, "0", "01", "+1", "-1", "1.0", "18446744073709551616", " 1"]
)
def test_v2_rejects_lossy_or_noncanonical_creation_tokens(ticks):
    value = fields()
    value["target"]["start_time_ticks"] = ticks
    with pytest.raises(ValidationError):
        Command(**value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("pid", True),
        ("pid", 4294967296),
        ("pid", "42"),
        ("boot_id", "boot_other"),
        ("boot_id", None),
    ],
)
def test_v2_rejects_invalid_target(field, value):
    request = fields()
    request["target"][field] = value
    with pytest.raises(ValidationError):
        Command(**request)


def test_v2_does_not_accept_a_legacy_or_nonprocess_target():
    request = fields()
    del request["target"]["boot_id"]
    with pytest.raises(ValidationError):
        Command(**request)
    request = fields()
    request.update(action="ISOLATE_HOST", target={})
    with pytest.raises(ValidationError):
        Command(**request)


def test_v2_requires_explicit_expiry_timezone():
    request = fields()
    request["expires_at"] = datetime(2999, 1, 1)
    with pytest.raises(ValidationError):
        Command(**request)
