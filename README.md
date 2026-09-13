# panopticon-response-engine

The Panopticon Response Engine's pure domain contract and policy logic:
the closed 7-action response vocabulary and its typed command/result
contract, tier classification (which actions may auto-fire vs. always
require analyst approval), recommendation-to-command translation, and the
canonical response lifecycle state machine.

This package has no HTTP framework dependency, no persistence code, and no
OS-specific execution logic. See `docs/OWNERSHIP.md` for the exact boundary
and `docs/adr/001-repository-boundary.md` for why this is a separate
repository consumed as a library — not a separate deployed service. It is
consumed today by [`panopticon-manager`](https://github.com/Panopticon-Co/panopticon-manager)
as a pinned git submodule, installed editable into Manager's own process —
one deployable backend, no network hop.

## Modules

- `response_engine.contract` — the closed `Action` enum, `Command`,
  `CommandResult`, and per-action target-schema validation.
- `response_engine.policy` — `Tier` and `classify_tier`: the locked
  AUTO_SAFE / ANALYST_APPROVAL decisions.
- `response_engine.recommendation` — `translate_recommendation`: maps a
  detection engine's recommendation vocabulary onto the closed action set,
  failing closed when no safe mapping exists.
- `response_engine.lifecycle` — `ResponseActionState` and
  `is_legal_transition`: the canonical lifecycle state machine.

## Development

```
python -m venv .venv
.venv/Scripts/activate   # or source .venv/bin/activate on Linux/macOS
pip install -e . pytest ruff
pytest -q
ruff check .
```

## The frozen action set

```
KILL_PROCESS
COLLECT_PROCESS_INFO
COLLECT_NETWORK_CONNECTIONS
COLLECT_FILE
QUARANTINE_FILE
ISOLATE_HOST
RELEASE_HOST_ISOLATION
```

No eighth action, no free-form execute/shell path, no arbitrary command
string. See `response_engine/contract.py` for the enforced target schema
per action.
