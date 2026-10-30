# Automated response: policy, orchestration and adapters

- Status: accepted (capstone vertical slice)
- Date: 2026-10-30
- Module: `response_engine.automation`; consumer: `panopticon-manager`
  (`manager/detection/response.py`, `manager/response_simulation.py`,
  `tools/lab_responder.py`)

## Context

Before this change the only automated decision was an action's tier.
`COLLECT_*` auto-fired and everything else waited for an analyst. Nothing
looked at the detection itself (rule, level, confidence, evidence). There was
no simulation mode and no cooldown, and nothing distinguished "approved",
"executed" and "verified". This change adds those without changing the
closed 7-action set or the locked tiers (ADR 001).

Reference designs:

- **Wazuh active response.** Rules (`level`, `rules_id`, `rules_group`) bind to
  *pre-declared* commands. The agent only runs scripts that exist locally, and
  stateful responses carry a timeout and an undo.
  <https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html>
- **Microsoft Defender automated investigation and remediation.** Automation
  levels are *full*, *semi* (approval required) and *none*. Pending and
  completed actions live in an action center, and remediation follows a
  verdict.
  <https://learn.microsoft.com/en-us/defender-endpoint/automation-levels>
  and <https://learn.microsoft.com/en-us/defender-endpoint/auto-investigation-action-center>

## Decision

The layers stay separated, with no new service, broker or database.

| Layer | Owner | Responsibility |
|---|---|---|
| Detection | eyedetect | Alert with `rule_id`, `level`, `severity`, `confidence`, `evidence`, `detection_source`, `active_response` recommendation. Executes nothing. |
| Translation | `response_engine.recommendation` | Maps the recommendation onto the closed action and target; fails closed. **The only source of action and target.** |
| Policy | `response_engine.automation.evaluate_policy` | Pure and deterministic. Decides the execution mode for the translated action. |
| Orchestration | Manager `on_alert_created` | Runs inside the detection transaction. Applies the existing gates, then policy, cooldown, simulation, persistence and audit; stages or authorizes the command through the existing path. |
| Adapters | Manager `response_simulation` (no host effect); endpoint agents; `tools/lab_responder.py` (lab endpoint) | Execute only what was dispatched; report schema-2 results. |

### Execution modes

| Mode | Meaning | Manager effect |
|---|---|---|
| `record` | A policy gate failed (level, confidence, evidence, detection source or host scope). | `response_actions` REJECTED "record only …"; no command. |
| `simulate` | Containment is previewed only. | Simulation adapter runs; REJECTED "simulated only …"; no command. |
| `approval` | Containment needs an analyst. | Simulation preview plus PENDING row; real command only after authorize. |
| `auto` | Read-only collection. | Authorized immediately as `system:response-engine`. |
| `denied` | Malformed alert, action outside the closed set, or the response-loop guard. | REJECTED "policy denied …"; no command. |

`PANOPTICON_RESPONSE_MODE` controls the global mode:

- **`simulate`** is the default. Any other value also falls back to it, so a
  misconfiguration fails closed. Every `approval` decision is turned into
  `simulate`, whether it came from a policy or the default tier.
- **`enforce`** is required for any real containment, and even then an
  analyst must approve each action. Real containment therefore needs both an
  explicit configuration and an explicit human decision.

### Guardrails enforced in code (not configurable)

- The policy's declared action must equal the translated action. Alert
  content can never select an action, a target, a command string or an
  argument.
- `auto` is downgraded to `approval` for any non-`AUTO_SAFE` action.
  KILL_PROCESS, QUARANTINE_FILE, ISOLATE_HOST and RELEASE_HOST_ISOLATION
  never auto-fire.
- Missing confidence fails a confidence gate; it is never assumed.
- Idempotency and loops are handled at three levels:
  - **Alert level:** an alert is processed once, because `insert_alert`
    ignores repeats and decisions are `UNIQUE(alert_id)`.
  - **Target level:** two mechanisms apply.
    - `find_open_duplicate` stops a second open action on the same target.
    - A per-policy cooldown (default 300 s) stops re-previewing or re-running
      a response that was simulated or succeeded on the same
      host/action/target.
  - **Executor level:** alerts whose evidence carries the response
    executor's marker are denied (loop guard).
- Decisions are immutable (`response_policy_decisions` has
  UPDATE/DELETE-abort triggers). Each decision is also written to
  `response_decision_audit` as `policy_evaluated`.

### Status model

`derive_response_status` keeps *acknowledged*, *simulated*, *executed* and
*verified* apart. Statuses in precedence order:

1. `resolved`: the analyst set the incident to resolved or false_positive.
   This is not containment.
2. `contained`: the containment command SUCCEEDED and the endpoint reported a
   `verified:` observation.
3. `containment_unverified`: SUCCEEDED without verification.
4. `containment_failed`: FAILED, REJECTED, INDETERMINATE or EXPIRED.
5. `response_executing`
6. `awaiting_approval`
7. `simulated_containment`
8. `response_recorded`
9. `detected`

### Manager contract additions (all additive)

- **Migration 32:** `response_policy_decisions`.
- **`GET /api/v1/response-actions`, alert and incident detail:** each action
  gains these fields:
  - `policy_decision`: `{policy_id, mode, global_mode, reasons, simulation_status, simulation, decided_at}` or `null`
  - `execution`: `{kind: simulated|endpoint|none, outcome, verified, detail}`
  - `response_status`
- **`GET /api/v1/alerts/{id}`:** gains `response_status`.
- **`GET /api/v1/incidents[/{id}]`:** gains `incident.response_status`.
- **`GET /api/v1/response-policies`:** active policy set and global mode
  (analyst token).

## Consequences and limitations

- The policy set is code (`DEFAULT_POLICIES`), versioned with this package.
  It has no runtime editing UI.
- The only real executor exercised end to end is the **Linux lab endpoint
  emulator**. Its kill scope is limited to processes it launched itself, and
  it verifies the kill through `/proc`.
  - The Windows agent's native KILL path requires a schema-2 command with a
    `boot_id`. That comes from canonical endpoint-record alerts, not the
    legacy 0.3 ingest used here, and it was not exercised by this slice.
- `verified:` is a self-report from the endpoint, retained verbatim. The
  manager independently records lifecycle and audit, but does not observe
  the host.
