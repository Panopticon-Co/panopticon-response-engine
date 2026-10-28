"""Canonical signing bytes shared with the Linux sensor; no key custody or I/O."""

from datetime import datetime

from response_engine.contract import Command

_DOMAIN = b"panopticon-command-auth/1\n"


class UnsignableCommand(ValueError):
    """The command cannot be expressed in the signing input (e.g. a time without a UTC offset)."""


def epoch_seconds(text: str) -> int:
    """Whole epoch seconds for an aware RFC 3339 time, matching endpoint parsing."""
    if not isinstance(text, str):
        raise UnsignableCommand("time is not a string")
    value = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        moment = datetime.fromisoformat(value)
    except ValueError as exc:
        raise UnsignableCommand(f"not an RFC 3339 time: {text!r}") from exc
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise UnsignableCommand(f"time has no UTC offset: {text!r}")
    seconds = int(moment.replace(microsecond=0).timestamp())
    if seconds < 0:
        raise UnsignableCommand(f"time is before 1970: {text!r}")
    return seconds


def _field(name: str, value: str) -> bytes:
    data = value.encode("utf-8")
    return name.encode() + b":" + str(len(data)).encode() + b":" + data + b"\n"


def _unsigned(target: dict, key: str) -> str:
    value = target.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise UnsignableCommand(f"target {key} is not an integer")
    number = int(value)
    if number < 0:
        raise UnsignableCommand(f"target {key} is negative")
    return str(number)


def signing_input(command: dict) -> bytes:
    """Canonical ES256 bytes matching the Linux sensor command_signing_input."""
    required = {
        "schema_version",
        "command_id",
        "correlation_id",
        "agent_id",
        "host_id",
        "action",
        "created_at",
        "expires_at",
        "target",
    }
    if (
        not isinstance(command, dict)
        or not required <= command.keys()
        or (command.keys() - required - {"authorization"})
    ):
        raise UnsignableCommand("signed command envelope is not closed")
    if not isinstance(command["host_id"], str) or not 1 <= len(command["host_id"]) <= 128:
        raise UnsignableCommand("host identity is invalid")
    try:
        Command.model_validate(
            {
                k: v
                for k, v in command.items()
                if k not in {"host_id", "created_at", "authorization"}
            }
        )
    except ValueError as exc:
        raise UnsignableCommand("command target does not meet the closed contract") from exc
    target = command.get("target") or {}
    if not isinstance(target, dict):
        raise UnsignableCommand("target is not an object")
    boot_id = target.get("boot_id", "")
    path = target.get("path", "")
    if not isinstance(boot_id, str) or not isinstance(path, str):
        raise UnsignableCommand("target boot_id and path must be strings")
    if "created_at" not in command:
        raise UnsignableCommand("a signed command needs created_at")
    if command["schema_version"] != ("2" if boot_id else "1"):
        raise UnsignableCommand("declared schema disagrees with target identity")
    fields = (
        ("schema_version", "2" if boot_id else "1"),
        ("command_id", command["command_id"]),
        ("correlation_id", command["correlation_id"]),
        ("agent_id", command["agent_id"]),
        ("host_id", command["host_id"]),
        ("action", command["action"]),
        ("created_at", str(epoch_seconds(command["created_at"]))),
        ("expires_at", str(epoch_seconds(command["expires_at"]))),
        ("pid", _unsigned(target, "pid")),
        ("start_time_ticks", _unsigned(target, "start_time_ticks")),
        ("boot_id", boot_id),
        ("path", path),
    )
    out = bytearray(_DOMAIN)
    for name, value in fields:
        if not isinstance(value, str):
            raise UnsignableCommand(f"{name} is not a string")
        out += _field(name, value)
    return bytes(out)
