# Forensic collection domain support

`response_engine.forensics` adds opt-in, deterministic collection planning and
metadata validation to the existing pure library. It does not wire a new workflow
into Manager. Existing translation, action enums, tiers, lifecycle states, public
imports and central command/artifact contracts are unchanged.

## Existing facilities reused

- `contract.py`: the seven existing actions and compatible version-1/version-2
  command targets. A plan is deliberately not a `Command`.
- `recommendation.py`: process recommendation translation preserves observed PID
  and native start-time tokens; a supplied boot identity selects the existing
  version-2 process target. No identity token is inferred from wall-clock time.
- `policy.py`: `classify_tier` is the minimum authorization tier. File metadata
  collection remains `ANALYST_APPROVAL` even if a forensic policy omits it from
  its additional approval list.
- `triage.py`: existing strict native absolute-path validation (`ApprovedFile`)
  rejects wildcards, traversal, Windows device/UNC/alternate-stream paths and
  ambiguous names. Reusing that validator does not invoke automated triage.
- `artifacts.py`: `ArtifactManifest` supplies the current signed JSON-manifest
  schema, digest representation, timestamp and size limits. No schema is copied
  or changed, and no signatures or evidence hashes are generated.

The inspected integration is Manager's `manager/detection/response.py` (existing
translation/tier consumer), `manager/response_artifacts.py` (artifact retention,
byte/hash checks and custody), and `manager/artifact_keys.py` (enrolled-key
signature verification). The central `SIGNED_RESPONSE_ARTIFACTS.md` and manifest
v2 schema retain their current meaning. None of these external files is changed.

## Planning API

```python
from datetime import datetime, timezone

from response_engine.forensics import (
    ForensicCollectionPolicy,
    ForensicCollectionRequest,
    plan_forensic_collection,
)

request = ForensicCollectionRequest.model_validate({
    "request_id": "forensic-request-from-consumer",
    "action": "COLLECT_PROCESS_INFO",
    "context": {
        "alert_id": "alert-123",
        "agent_id": "agent-123",
        "host_id": "host-123",
        "source_id": "original-sensor",
        "source_record_id": "original-record-id",
        "rule_id": "original-rule-id",
        "recommendation_id": "original-recommendation-id",
        "observed_at": datetime(2026, 10, 30, 9, tzinfo=timezone.utc),
    },
    "process": {"pid": 42, "start_time_ticks": 123456},
})
policy = ForensicCollectionPolicy(
    policy_id="forensic-policy", version=1, enabled=True,
)
plan = plan_forensic_collection(request, policy, asset_class="standard")
assert plan.decision == "require_approval"
assert plan.target == {"pid": 42, "start_time_ticks": 123456}
```

Only `COLLECT_PROCESS_INFO`, `COLLECT_NETWORK_CONNECTIONS` and `COLLECT_FILE`
are accepted. Process collection requires an observed positive uint32 PID and
positive uint64 native start token; an optional canonical `boot_` identity is
preserved. File collection requires `file={"platform": "windows" | "linux",
"path": <exact absolute native file path>}`. Network collection accepts neither
target. File scope means metadata/hash JSON, never raw bytes or binary acquisition.

Requests require original alert, endpoint, source and source-record identifiers
and an aware observation timestamp. Optional rule/recommendation identifiers and
up to 32 existing evidence references preserve provenance. Each evidence reference
contains its source identifiers and original manifest. Cross-endpoint references
and duplicate artifact identities are rejected. Missing evidence is represented
by an empty list, not invented evidence or hashes.

`ForensicCollectionPolicy` is a local domain policy, schema version `1`, with an
explicit positive revision `version` and `policy_id`. It defaults to disabled and
requires approval for every collection action. A consumer must persist immutable
revisions and increment the version when policy settings change; this pure library
adds no database or migration. Missing allowed actions produce `skip`; disabled
policy produces `skip`. The additional approval list may strengthen existing tiers
but cannot lower them. Critical and unknown asset classes require approval even
when the policy's additional approval list is empty. An invalid asset label fails
closed. Classification must come from a trusted consumer registry, not the alert.

The plan records the original request, policy identity/version, asset class,
decision and reason, effective tier, expected evidence kind, existing command
schema version and target. `recommend` is advisory, not `authorized` or
`auto_dispatch`; it cannot authorize an endpoint action. No command identifiers,
expiry times, lifecycle events or audit entries are generated. Repeated inputs
produce identical plans without mutating inputs. Entry points revalidate nested
model values before making decisions.

## Evidence metadata checks

```python
from response_engine.forensics import EvidenceExpectation, validate_evidence_metadata

# Supply these identities from the already-owned Manager command/case record.
expected = EvidenceExpectation(
    action="COLLECT_PROCESS_INFO",
    agent_id="agent-123", host_id="host-123",
    command_id="existing-command-id", correlation_id="existing-correlation-id",
)
# original_manifest is the original existing manifest dict, without content bytes.
checked = validate_evidence_metadata(original_manifest, expected=expected)
```

This verifies the existing closed manifest shape, lowercase 64-hex SHA-256
representation, bounded positive byte count, producer timestamp, signature-field
representation, exact expected agent/host/command/correlation and action/kind
agreement. Missing/malformed data or mismatched scope raises `ValueError`
(including Pydantic `ValidationError`). It returns the original validated values,
without normalizing identifiers, resigning data, computing hashes or claiming that
content integrity or signature authenticity has been verified.

The producer timestamp remains an endpoint claim, distinct from the alert's
observation time. Their clocks are not assumed synchronized, and no artificial
ordering or timestamps are manufactured. References alone cannot prove that an
artifact belongs to a case: Manager must check its persisted command-to-alert
binding as well as the explicit expectation.

## Integration requirements and limits

This module is available through explicit imports; it is not automatically called
by existing Manager or detection paths. To consume it later, Manager must:

1. Build provenance/targets from retained alert records and authoritative endpoint
   identities, not user-provided claims. Resolve exact case/command ownership for
   every evidence reference. Retain the forensic context alongside its decision.
2. Resolve versioned policy, authoritative asset class and authenticated actor;
   enforce RBAC and the effective tier through its existing request/approval path.
   A `skip` plan must never be queued. Never treat the advisory plan as permission.
3. Recheck capability, policy, target identity, platform and safe file access at
   dispatch/execution time. Path syntax validation cannot detect symlinks, file
   replacement or filesystem permissions and does not create a path allowlist.
4. Use existing signed-manifest/key-history verification, exact-byte hash checks,
   scoped retrieval, resumable delivery, retention and tamper-evident custody.
   A syntactically valid digest/signature is not verified evidence. Revocation and
   compromised-key flags remain Manager-owned. Do not trust an artifact-supplied
   expectation as authoritative command scope.

No Manager adapter, API, database, agent changes, dashboard changes, binary
acquisition, memory dump, packet capture, new response action, shell or subprocess
execution is included. Such collection or UI integration needs a separate task;
the response library cannot collect OS facts itself. Existing consumers continue
using the same public interfaces and receive no new wire fields automatically.

## Validation

`tests/test_forensics.py` covers the three collection actions, both native file
path styles, legacy and boot-bound process targets against `Command`, deterministic
repeat planning, policy versioning/JSON round trips, critical-asset blast radius,
approval bypasses, unsupported actions, malformed/missing metadata, scope rebinding,
provenance and timestamps, duplicate evidence and nested model revalidation.

Run `ruff check .` and `pytest -v` along with the existing contract fixtures,
recommendation, authorization and lifecycle regression suite. No native or
full-system E2E execution is required for these pure domain additions.
