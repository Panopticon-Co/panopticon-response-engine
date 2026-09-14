# panopticon-response-engine

[![CI](https://github.com/Panopticon-Co/panopticon-response-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/Panopticon-Co/panopticon-response-engine/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-brightgreen.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The Panopticon Response Engine's pure domain contract and policy logic: the closed 7-action
response vocabulary and its typed command/result contract, tier classification (which actions may
auto-fire vs. always require analyst approval), recommendation-to-command translation, and the
canonical response lifecycle state machine.

This is a capstone/research security project component, not a commercial product.

## Status / maturity

Working, tested domain library: 69 tests passing (`pytest -v`), `ruff check .` clean. It has one
consumer today, [`panopticon-manager`](https://github.com/Panopticon-Co/panopticon-manager), which
vendors it as a pinned git submodule and installs it editable into its own process.

## What this is not

**This package is not an independently deployed network service.** It has no HTTP framework
dependency, no server entrypoint, and no socket/listener code — verified by inspection, there is no
FastAPI/Flask/ASGI/WSGI app anywhere in `response_engine/`. It is a domain/library package consumed
in-process by `panopticon-manager` (same deployment, no network hop). If you are looking for the
service that exposes response actions over HTTP, authorizes them, and dispatches them to agents,
that is `panopticon-manager`.

It also does not execute anything against a real endpoint. See
[Detection vs. execution boundary](#detection--execution--response-boundary) below.

## Architecture role

```text
Detection Engine          Response Engine (this repo)              Manager
(panopticon-detection-   ->  translate_recommendation()  ->   (owns identity, HTTP API,
 engine: emits an            + Tier classification             persistence, dispatch to
 ActiveResponseAction         + lifecycle validation            endpoint agents, audit)
 recommendation)              (pure functions, no I/O)
```

`panopticon-manager` imports this package directly; `panopticon-detection-engine` does not depend
on it and knows nothing about it — the detection engine's `ActiveResponseAction` recommendation
vocabulary is just a string/dict shape that this package's `recommendation` module knows how to
translate.

## Modules

- **`response_engine.contract`** — the closed `Action` enum, `Command`, `CommandResult`, and
  per-action target-schema validation (e.g. `KILL_PROCESS` requires a PID-reuse-safe
  `start_time_ticks`, file actions take a path-only target, host-level actions take no target).
- **`response_engine.policy`** — `Tier` and `classify_tier`: the locked `AUTO_SAFE` /
  `ANALYST_APPROVAL` decisions. `KILL_PROCESS`, `ISOLATE_HOST`, and `RELEASE_HOST_ISOLATION` never
  auto-fire, regardless of severity; an action outside the closed set always defaults to
  `ANALYST_APPROVAL`, never `AUTO_SAFE`.
- **`response_engine.recommendation`** — `translate_recommendation(action, active_response)`: maps
  a detection engine's recommendation vocabulary onto the closed action set, **failing closed**
  (returns `None`) when no safe mapping exists rather than guessing.
- **`response_engine.lifecycle`** — `ResponseActionState` and `is_legal_transition`: the canonical
  `PENDING -> AUTHORIZED -> DISPATCHED -> ACCEPTED -> {SUCCEEDED, FAILED, REJECTED}` (plus
  `CANCELLED` and `EXPIRED`) state machine. See the module docstring for how Manager's real,
  two-table persistence maps onto this idealized model.

See [`docs/OWNERSHIP.md`](docs/OWNERSHIP.md) for the exact boundary (what this package owns vs.
explicitly does not) and [`docs/adr/001-repository-boundary.md`](docs/adr/001-repository-boundary.md)
for why this is a separate repository consumed as a library rather than a deployed service.

## The closed 7-action set

```text
KILL_PROCESS
COLLECT_PROCESS_INFO
COLLECT_NETWORK_CONNECTIONS
COLLECT_FILE
QUARANTINE_FILE
ISOLATE_HOST
RELEASE_HOST_ISOLATION
```

This set is locked. There is no 8th action, no free-form execute/shell path, and no arbitrary
command string. `BLOCK_FIREWALL_IP` recommendations from the detection engine are deliberately
**downgraded** to `ISOLATE_HOST` — coarser than per-IP blocking, but this is an intentional,
documented decision to stay within the closed, security-reviewed action set (see
`response_engine/recommendation.py`), not a bug or a gap to "fix" by adding an 8th action.

## Detection / execution / response boundary

Three separate concerns, three separate repositories:

1. **Detect and recommend** — [`panopticon-detection-engine`](https://github.com/Panopticon-Co/panopticon-detection-engine)
   evaluates telemetry and emits an `ActiveResponseAction` recommendation. It never executes
   anything.
2. **Translate, classify, and validate** — this repository (`panopticon-response-engine`) maps that
   recommendation onto the closed command set, decides its authorization tier, and validates
   lifecycle transitions. It performs no I/O and executes nothing itself.
3. **Authorize, dispatch, and execute** — [`panopticon-manager`](https://github.com/Panopticon-Co/panopticon-manager)
   owns analyst/agent identity and authorization, persists lifecycle state, and dispatches
   authorized commands to endpoint agents over the network. The endpoint agent
   ([`panopticon-agent`](https://github.com/Panopticon-Co/panopticon-agent) /
   [`panopticon-linux-agent`](https://github.com/Panopticon-Co/panopticon-linux-agent)) is the only
   component that ever actually terminates a process, quarantines a file, or isolates a host, using
   its own OS-specific APIs.

This repository's code path never calls a real endpoint, executes a shell command, or performs
any OS-level action.

## Dependencies

From `pyproject.toml`:

```text
pydantic>=2.0
```

Dev/test only: `pytest`, `ruff`. No web framework, no database driver, no message queue.

## Install

```bash
git clone --recurse-submodules https://github.com/Panopticon-Co/panopticon-response-engine.git
cd panopticon-response-engine
python -m venv .venv
.venv/Scripts/activate   # macOS/Linux: source .venv/bin/activate
pip install -e . pytest ruff
```

The `--recurse-submodules` flag matters: `tests/vendor/panopticon-contracts` is a git submodule
holding the canonical cross-repo fixtures `tests/test_contract_fixtures.py` loads. If you already
cloned without it, run `git submodule update --init --recursive`.

## Run tests

The authoritative commands are the ones CI runs (see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

```bash
ruff check .
pytest -v
```

`pyproject.toml` sets `testpaths = ["tests"]`, so plain `pytest` (or `pytest -v`) discovers the
suite; `ruff check .` excludes `tests/vendor` (a separate repository's source, vendored only for
fixtures, not linted as this package's own code).

## Configuration

This package has no runtime configuration of its own — no config file, no environment variables. It
is a set of pure functions and enums; behavior is fixed by the (intentionally frozen) policy and
contract decisions described above. Configuration of authorization, dispatch, and persistence lives
in the consuming service (`panopticon-manager`).

## Integration with other Panopticon repositories

- [`panopticon-agent`](https://github.com/Panopticon-Co/panopticon-agent) — Windows endpoint agent
  ("Officer"); the actual executor of `KILL_PROCESS`/`ISOLATE_HOST`/etc. commands dispatched by
  Manager.
- [`panopticon-linux-agent`](https://github.com/Panopticon-Co/panopticon-linux-agent) — Linux
  endpoint agent counterpart.
- [`panopticon-detection-engine`](https://github.com/Panopticon-Co/panopticon-detection-engine) —
  produces the `ActiveResponseAction` recommendations this package translates.
- [`panopticon-manager`](https://github.com/Panopticon-Co/panopticon-manager) — the sole current
  consumer; vendors this package as a pinned git submodule, owns HTTP API, authorization,
  persistence, dispatch, and audit.
- [`panopticon-contracts`](https://github.com/Panopticon-Co/panopticon-contracts) — canonical
  JSON-schema wire contracts; vendored under `tests/vendor/panopticon-contracts` for fixture-based
  contract tests.
- [Panopticon-Co organization](https://github.com/Panopticon-Co) — all repositories.

## Known limitations

- `COLLECT_FILE` has no operator-configured path allowlist implemented yet, so it defaults to
  `ANALYST_APPROVAL` rather than a scoped `AUTO_SAFE` carve-out (see `response_engine/policy.py`).
  This is documented future work, not a bug.
- `BLOCK_FIREWALL_IP` is coarser than per-IP blocking by design (downgraded to `ISOLATE_HOST`) — see
  above; this is a locked decision, not a gap.
- The lifecycle model is idealized; `panopticon-manager`'s real persistence spans two tables and
  compresses `CANCELLED` into `REJECTED` in one of them. See the docstring in
  `response_engine/lifecycle.py` for the exact mapping.
- This package cannot itself validate that its single consumer (`panopticon-manager`) is using it
  correctly at every call site — cross-repository behavior should be checked in `panopticon-manager`
  when this contract changes.

## Security

See [`SECURITY.md`](SECURITY.md). Report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/Panopticon-Co/panopticon-response-engine/security/advisories/new),
never as a public issue. Given the locked policy decisions above (no auto-fire for destructive
actions, fail-closed translation, no 8th action), a security report that proposes weakening any of
these should explain why in detail — they are intentional, reviewed guardrails.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE).
