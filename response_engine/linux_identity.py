"""Linux sensor identity proof, preserving native boot/PID/start-tick tokens.

Input records must first pass the central Linux schema and authenticated host
binding in the Manager. Hash agreement detects internal identity disagreement;
it is not a substitute for endpoint authentication or a signature.
"""

import hashlib
import re
from typing import Any

MODEL = "linux_endpoint_v1"
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def linux_endpoint_context(record: Any, agent_id: str) -> dict | None:
    """Build a response subject only from internally consistent native identity."""
    if not isinstance(record, dict) or not isinstance(agent_id, str) or not agent_id:
        return None
    host, proc, sensor = (record.get(k) for k in ("host", "process", "sensor"))
    if not all(isinstance(value, dict) for value in (host, proc, sensor)):
        return None
    host_id, boot = host.get("id"), host.get("boot_id")
    pid, ticks, seq = proc.get("pid"), proc.get("start_ticks"), record.get("seq")
    confidence = proc.get("confidence")
    sensor_id = sensor.get("id")
    if (
        record.get("schema_version") != "1.0"
        or record.get("record_type") != "event"
        or record.get("type") != "process.exec"
        or not isinstance(host_id, str)
        or not host_id
        or not isinstance(boot, str)
        or not UUID.fullmatch(boot)
        or not isinstance(sensor_id, str)
        or not sensor_id
        or type(pid) is not int
        or not 0 < pid <= 0xFFFFFFFF
        or type(ticks) is not int
        or not 0 < ticks <= 0xFFFFFFFFFFFFFFFF
        or type(seq) is not int
        or not 0 < seq <= 0xFFFFFFFFFFFFFFFF
        or not isinstance(confidence, dict)
        or confidence.get("identity") != "observed"
    ):
        return None
    expected_entity = hashlib.sha256(f"{host_id}|{boot}|{pid}|{ticks}".encode()).hexdigest()[:32]
    expected_record = hashlib.sha256(f"{sensor_id}|{boot}|{seq}".encode()).hexdigest()[:32]
    if proc.get("entity_id") != expected_entity or record.get("id") != expected_record:
        return None
    digest = "boot_" + hashlib.sha256(boot.encode()).hexdigest()
    return {
        "identity_model": MODEL,
        "record_id": record["id"],
        "endpoint": {"agent_id": agent_id, "host_id": host_id, "boot_id": digest},
        "subject": {
            "observed_pid": pid,
            "native_creation_ticks": str(ticks),
            "boot_id": digest,
            "resolution": "native_exact",
            "entity_id": expected_entity,
        },
        "linux_identity": {"boot_uuid": boot, "sensor_id": sensor_id, "seq": seq},
    }


def verified_linux_subject(context: dict) -> bool:
    """Recheck the retained proof when staging and authorizing a process action."""
    endpoint, subject, proof = (context.get(k) for k in ("endpoint", "subject", "linux_identity"))
    if not all(isinstance(value, dict) for value in (endpoint, subject, proof)):
        return False
    ticks = subject.get("native_creation_ticks")
    if not isinstance(ticks, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", ticks):
        return False
    rebuilt = linux_endpoint_context(
        {
            "schema_version": "1.0",
            "record_type": "event",
            "type": "process.exec",
            "id": context.get("record_id"),
            "seq": proof.get("seq"),
            "host": {"id": endpoint.get("host_id"), "boot_id": proof.get("boot_uuid")},
            "sensor": {"id": proof.get("sensor_id")},
            "process": {
                "pid": subject.get("observed_pid"),
                "start_ticks": int(ticks),
                "entity_id": subject.get("entity_id"),
                "confidence": {"identity": "observed"},
            },
        },
        endpoint.get("agent_id"),
    )
    return rebuilt is not None and all(context.get(k) == v for k, v in rebuilt.items())
