# ADR 002: threading a PID-reuse-safe start time from detection through to KILL_PROCESS

- Status: accepted
- Date: 2026-09-13

## Context

`response_engine.recommendation.translate_recommendation` has always failed
closed for `TERMINATE_PROCESS`:

```python
if action == "TERMINATE_PROCESS":
    # No known detection engine recommendation payload carries a
    # process-creation timestamp yet -- the closed contract's KILL_PROCESS
    # target requires start_time_ticks specifically to prevent PID-reuse...
    return None
```

`response_engine.contract`'s process-action target schema requires exactly
`{pid, start_time_ticks}` (not `pid` alone) precisely so that an endpoint
agent can refuse to act if the PID it's about to touch is not the same
process the detection engine actually observed — a PID can be recycled by
the OS between the moment a detection fires and the moment an analyst
authorizes and the agent executes the resulting command, which could
otherwise turn `KILL_PROCESS` into killing an unrelated, newly-spawned
process that happens to reuse the PID.

Both endpoint agents already understand this and already hold the value:

- `panopticon-linux-agent`'s `process_identity` struct
  (`include/panopticon/linux_agent/identity.hpp`) carries `start_time_ticks`
  (Linux: `/proc/[pid]/stat` field 22, clock ticks since boot) on every
  process it observes, including during ordinary telemetry collection, not
  only during on-demand command execution. `command_gate`'s handlers
  (`terminate_process`, `collect_process_info`) already re-observe this
  value fresh from procfs and compare it against the command's target
  before acting.
- `panopticon-agent` (Officer, Windows) has the equivalent OS-native value
  available via `GetProcessTimes`'s process creation `FILETIME`, but this
  ADR does not require Windows changes (see "Non-goals" below).

The value was never missing from the agents. It was missing from the wire:
Panopticon Schema 0.2/0.3 (`panopticon-agent/schema/event.schema.json`) has
no start-time field on `process`, so it never reached
`panopticon-detection-engine`'s `ProcessTree`/`ProcessNode`
(`src/correlation/process_tree.py`), and therefore never reached
`ActiveResponseAction` (`src/alerting/active_response.py`), which is the
payload this package's `translate_recommendation` receives. There was
nothing for this package to translate — the gap was upstream of it, in the
telemetry contract, exactly as `docs/OWNERSHIP.md` says: "This package
consumes a recommendation's `(action, payload)` shape; it does not decide
when a detection engine should recommend an action in the first place," and
it does not own the event schema either.

## Decision

**Add one optional field to the wire schema and thread it, opaque and
unmodified, from agent telemetry through to the `KILL_PROCESS` command
target — never reconstructed, interpreted, or guessed anywhere in between.**

1. **Schema 0.3 gains `process.start_time_ticks`** (`integer`, optional,
   `minimum: 0`): the OS-native process-creation value the producing agent
   already computes for its own re-verification purposes, emitted verbatim.
   It is deliberately **not** given portable/interpreted semantics (e.g.
   "milliseconds since epoch") — different OSes have different native
   clocks (Linux: ticks since boot; Windows: 100ns FILETIME since 1601), and
   the only property this field needs is that the *same OS's own agent* can
   compare a later fresh observation against it byte-for-byte. No consumer
   other than the originating host's own agent is ever allowed to interpret
   its magnitude (e.g. to compute an age or a wall-clock time) — every
   intermediate hop (schema, detection engine, this package, Manager)
   treats it as an opaque token, pass-through only. This ADR only requires
   `panopticon-linux-agent` to populate it now (see "Non-goals"); the field
   is optional so that Windows telemetry without it remains valid, and any
   consumer treats its absence as "no safe KILL_PROCESS target available,"
   never as zero or as "skip the check."
2. **`ProcessTree`/`ProcessNode` retains it.** `ProcessNode` gains a
   `start_time_ticks: Optional[int]` field, populated from the
   `process_create` event's new schema field, alongside the existing
   `start_time` (which remains the ISO-8601 *event timestamp* and is
   unrelated — it is not reused for this purpose, since it is wall-clock
   and does not match what an agent can re-derive from its own OS-native
   clock).
3. **`ActiveResponseAction` carries it.** `resolve_action` reads the
   triggering event's `process.start_time_ticks` (falling back to a
   `ProcessTree` lookup by `process_guid` when the triggering event itself
   is not the `process_create` event, e.g. a later `process_terminate` or a
   correlated event referencing an ancestor) and sets a new
   `target_start_time_ticks: Optional[int]` field on the dataclass. When it
   cannot be recovered, the field stays `None` — the action is still
   produced (so the alert always shows the *recommendation*, e.g. for
   analyst visibility even without an executable command), but downstream
   translation fails closed exactly as it does today.
4. **`translate_recommendation` now produces a command when the value is
   present:**

   ```python
   if action == "TERMINATE_PROCESS":
       pid = active_response.get("target_pid")
       start_time_ticks = active_response.get("target_start_time_ticks")
       if not isinstance(pid, int) or not isinstance(start_time_ticks, int) or start_time_ticks <= 0:
           return None
       return "KILL_PROCESS", {"pid": pid, "start_time_ticks": start_time_ticks}, "direct mapping"
   ```

   The `<= 0` check matters: it rejects both a missing value (already
   excluded by the `isinstance` check against `None`) and a value that is
   technically present but semantically "no real observation" (e.g. `0`),
   consistent with `panopticon-linux-agent`'s own `command.cpp` treating
   `start_time_ticks == 0` as invalid for the same reason.
5. **The agent-side re-verification this ADR relies on is not new** — it
   already exists (`command_gate`'s handlers already compare a fresh
   observation's `start_time_ticks` against the command target and refuse a
   mismatch with `receipt_code::target_mismatch`). This ADR's job is only to
   stop discarding the one signal that check needs, upstream of the agent.

## Non-goals (explicitly deferred, not silently skipped)

- **`panopticon-agent` (Windows/Officer) schema producer changes.** A
  background implementation pass is concurrently adding Windows command
  execution (including its own fresh re-observation via
  `GetProcessTimes`), touching the same serializer files this ADR would
  need to extend for Windows telemetry to carry `start_time_ticks` too.
  Making that edit here risked a direct collision on files actively being
  written by that other pass. Windows telemetry therefore continues to omit
  `process.start_time_ticks` until a follow-up change adds it — Windows
  `TERMINATE_PROCESS` recommendations will correctly keep failing closed
  (return `None`) until then, which is the existing, safe behavior; nothing
  regresses. Tracked as a follow-up in
  `panopticon-manager/docs/RESPONSE_ENGINE_STATE.md`.
- **Retroactively backfilling `start_time_ticks` for processes already in
  the tree before this change ships.** Not possible or necessary — a
  process observed by an older agent build simply never gets a safe
  `KILL_PROCESS` translation, which is the existing (safe) behavior.
- **`BLOCK_FIREWALL_IP` and `ISOLATE_HOST` translation.** Unaffected by this
  ADR; both already have a defined mapping today.

## Consequences

- `panopticon-agent`'s (schema owner) `schema/event.schema.json` gains one
  new optional integer property under `process`; this is additive and
  backward compatible per the workspace's schema-change rule (existing
  consumers that don't know the field ignore it; `additionalProperties:
  false` elsewhere is unaffected since this is a named, not an
  incidental, property).
- `panopticon-linux-agent` emits the field on every process event going
  forward (both live telemetry and the on-demand `collect_process_info`
  evidence it already produces reusing the same identity struct).
- `panopticon-detection-engine`'s `ProcessTree`, `active_response.py`, and
  their test suites are updated in the same change (per the workspace's
  "update every affected consumer/test in the same change" rule).
- `panopticon-response-engine`'s `translate_recommendation` for
  `TERMINATE_PROCESS` goes from "always `None`" to "produces `KILL_PROCESS`
  whenever the detection engine can prove a start time" — a real behavior
  change, covered by new tests in `tests/test_policy_and_recommendation.py`
  for: present-and-valid (produces a command), absent (still `None`),
  present-but-zero (still `None`), and present-but-wrong-type (still
  `None`).
- No change to the lifecycle state machine, the tier/policy classification
  (`KILL_PROCESS` still always requires analyst approval — this ADR only
  makes it reachable, never auto-fired), or any other action's translation.
