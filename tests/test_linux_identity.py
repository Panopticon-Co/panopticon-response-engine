import copy
import hashlib
import json
from pathlib import Path

import pytest

from response_engine.linux_identity import linux_endpoint_context
from response_engine.recommendation import translate_recommendation


def native_record(ticks=2801760):
    boot = "a4d9d0e1-c8d8-4a67-a703-bdf6f6f01263"
    host = "0104a71202304516860b2a6fa481f00e"
    return {
        "schema_version": "1.0",
        "record_type": "event",
        "type": "process.exec",
        "id": hashlib.sha256(f"sensor-1|{boot}|7".encode()).hexdigest()[:32],
        "seq": 7,
        "host": {"id": host, "boot_id": boot},
        "sensor": {"id": "sensor-1"},
        "process": {
            "pid": 171975,
            "start_ticks": ticks,
            "entity_id": hashlib.sha256(f"{host}|{boot}|171975|{ticks}".encode()).hexdigest()[:32],
            "confidence": {"identity": "observed"},
        },
    }


def recommendation(record):
    return {
        "host_id": record["host"]["id"],
        "target_pid": record["process"]["pid"],
        "target_start_time_ticks": record["process"]["start_ticks"],
    }


@pytest.mark.parametrize("ticks", [2801760, 2**53 + 1, 2**64 - 1])
@pytest.mark.parametrize("action", ["TERMINATE_PROCESS", "COLLECT_PROCESS_INFO"])
def test_native_linux_target_is_boot_bound_and_preserves_full_precision(ticks, action):
    record = native_record(ticks)
    context = linux_endpoint_context(record, "enrolled-agent")
    target = translate_recommendation(action, recommendation(record), context)[1]
    assert target == {
        "pid": 171975,
        "start_time_ticks": str(ticks),
        "boot_id": "boot_" + hashlib.sha256(record["host"]["boot_id"].encode()).hexdigest(),
    }
    assert context["endpoint"]["agent_id"] == "enrolled-agent"
    assert context["subject"]["entity_id"] == record["process"]["entity_id"]


@pytest.mark.parametrize(
    "section,key,value",
    [
        ("process", "pid", True),
        ("process", "pid", 0),
        ("process", "start_ticks", 0),
        ("process", "start_ticks", 2**64),
        ("process", "start_ticks", "123"),
        ("process", "entity_id", "0" * 32),
        ("process", "confidence", {"identity": "inferred"}),
        ("host", "boot_id", "boot_" + "a" * 64),
        ("host", "id", "another-host"),
        ("sensor", "id", "another-sensor"),
    ],
)
def test_inconsistent_or_non_native_record_cannot_create_response_subject(section, key, value):
    record = native_record()
    record[section][key] = value
    assert linux_endpoint_context(record, "agent") is None


@pytest.mark.parametrize(
    "section,key,value",
    [
        ("subject", "native_creation_ticks", "2801761"),
        ("subject", "observed_pid", 171976),
        ("subject", "resolution", "source_scoped"),
        ("subject", "entity_id", "0" * 32),
        ("endpoint", "boot_id", "boot_" + "b" * 64),
        ("endpoint", "host_id", "other"),
        ("linux_identity", "seq", 8),
        ("linux_identity", "sensor_id", "other"),
        ("linux_identity", "boot_uuid", "a4d9d0e1-c8d8-4a67-a703-bdf6f6f01264"),
    ],
)
def test_retained_proof_is_rechecked_without_legacy_fallback(section, key, value):
    record = native_record()
    context = copy.deepcopy(linux_endpoint_context(record, "agent"))
    context[section][key] = value
    assert translate_recommendation("TERMINATE_PROCESS", recommendation(record), context) is None


def test_real_central_native_fixture_matches_sensor_identity_algorithm():
    path = (
        Path(__file__).parent
        / "vendor/panopticon-contracts/fixtures/linux-endpoint/valid/process-exec.json"
    )
    record = json.loads(path.read_text(encoding="utf-8"))
    assert linux_endpoint_context(record, "agent") is not None
