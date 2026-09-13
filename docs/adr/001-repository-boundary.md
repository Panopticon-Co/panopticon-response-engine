# ADR 001: why this is its own repository, and why that does not mean a microservice

- Status: accepted
- Date: 2026-09-13

## Context

`panopticon-manager`'s Response Engine (recommendation translation, tier
classification, lifecycle staging, analyst authorization) was originally
built as a module inside `panopticon-manager` itself (see that repo's
`docs/adr/004-response-engine.md`). A follow-up architectural review asked
whether it should become its own repository, given that Panopticon already
follows a repository-per-domain convention (`panopticon-agent`,
`panopticon-linux-agent`, `panopticon-detection-engine`,
`panopticon-manager`, `panopticon-console`) and a repository boundary does
not, by itself, imply a separate deployment.

An initial pass (`panopticon-manager`'s ADR 005) considered and rejected
extraction, on the reasoning that the Response Engine's ~350 lines were
small, fully tested in place, and had no independent scaling or team
boundary. That reasoning correctly ruled out a *microservice*, but
conflated "no separate deployment" with "no separate repository" — the two
are independent questions. Manager already vendors
`panopticon-detection-engine` as a git submodule (`vendor/eyedetect`)
consumed entirely in-process, proving the workspace's own convention that a
repository boundary and a deployment boundary are different things.

## Decision

**`panopticon-response-engine` is its own repository, published as an
installable Python package, and consumed by `panopticon-manager` as a
pinned git submodule + editable install — never as a network service.**

- **What this package owns**: the pure domain contract and policy logic —
  the closed action/target contract, tier classification, recommendation
  translation, and the lifecycle state machine. See `docs/OWNERSHIP.md` for
  the full, explicit boundary (including what it deliberately does *not*
  own).
- **What Manager owns**: persistence (the `response_actions`/`commands`
  SQLite tables and their migrations), HTTP transport (FastAPI routers,
  analyst/agent bearer-token authentication), and orchestration (deciding
  *when* to call this package's pure functions — e.g. on a new alert, on an
  analyst's authorize/reject call, on a poll/result-submission request).
- **What Detection Engine owns**: producing a recommendation
  (`ActiveResponseAction`/`Alert.active_response`) in the first place. This
  package consumes that recommendation's `(action, payload)` shape; it does
  not import or depend on the detection engine's code.
- **What each endpoint agent owns**: OS-specific execution of a dispatched
  command (how `KILL_PROCESS` actually terminates a process on Windows vs.
  Linux, how `ISOLATE_HOST` actually isolates a host). Agents independently
  hardcode the same closed 7-action set today (see "Contract/versioning
  strategy" below for why that duplication is accepted, not fixed, by this
  ADR).
- **Dependency direction**:
  `Detection Engine -> recommendation/alert -> this package's contract ->
  Manager's persistence/transport -> Endpoint Agents`. Nothing in this
  package imports anything from Manager, Detection Engine, or any agent —
  it has zero Panopticon-specific dependencies, only `pydantic`.
- **Deployment model — unchanged from before this ADR**: one deployable
  backend. `panopticon-manager` vendors this package at `vendor/
  response_engine` (a pinned git submodule, mirroring the existing
  `vendor/eyedetect` pattern) and installs it editable
  (`pip install -e vendor/response_engine`) into the same process, the same
  `uvicorn` app, the same Python interpreter that serves the rest of
  Manager. There is no second process, no network call between Manager and
  this package, and no independent scaling story — extraction did not
  change the deployment topology at all, only where the source code for
  this slice of domain logic lives and how it is versioned.
- **Why separate repo != microservice**: a network service boundary exists
  to isolate failure, allow independent scaling, or allow independent
  release cadence across process/language boundaries. None of those apply
  here — this package has no I/O, so it cannot itself fail independently of
  its caller; it has no workload of its own to scale; and its "independent
  release cadence" is a version pin bumped in the same commit-review flow as
  any other dependency bump, not a coordinated multi-service rollout. The
  repository boundary buys testability and reuse (any future Panopticon
  consumer — a second backend, a CLI tool, a test harness — can depend on
  this package without depending on all of Manager), not deployment
  independence.

## Contract / versioning strategy

- This package is versioned independently via its own `pyproject.toml`
  (`0.1.0` at extraction), following semver: a breaking change to the
  action set, target schema, or lifecycle transitions is a MAJOR bump.
- Manager pins an exact submodule commit (not a floating branch), so exactly
  which version of this contract is running is always explicit and
  auditable — the same guarantee `vendor/eyedetect`'s pin already gives for
  the detection engine.
- The 7-action enum remains additionally hardcoded (not imported from this
  package) in each endpoint agent, since agents are not Python and cannot
  depend on a Python package. This is an accepted, hand-verified duplication
  — the same one `panopticon-manager`'s ADR 005 already documented before
  this package existed. This package becomes the single Python-side source
  of truth; a future cross-language contract (e.g. a JSON Schema or an IDL
  generated from `response_engine.contract`) is legitimate future work if
  drift between the Python and C++ definitions ever actually occurs, but is
  not built preemptively here.

## Future extraction criteria (when *would* a network boundary make sense)

None of the following are true today; if one becomes true, revisit this
ADR rather than assume the answer:

- A second backend (not just Manager) needs to consume live response-action
  state, not just this package's pure logic.
- The Response Engine acquires actual I/O of its own (e.g. it starts making
  outbound calls, holding its own connections, or needing independent
  scaling) rather than remaining pure computation.
- A different team, with a different release cadence, takes ownership of
  this package specifically.

## Consequences

- `panopticon-manager` gains one more pinned submodule to keep current
  (`git submodule update --remote vendor/response_engine` + a commit), the
  same operational cost `vendor/eyedetect` already carries.
- Manager's `manager/routers/commands.py` and `manager/detection/
  response.py` are updated to import the closed action contract, tier
  classification, and recommendation translation from this package instead
  of defining them locally — removing the last hand-maintained copies of
  that logic inside Manager itself (see Manager's
  `docs/adr/006-response-engine-package-extraction.md`).
- This package's own CI (lint + pytest, no cross-repo checkout needed, since
  it depends on nothing Panopticon-specific) runs independently of
  Manager's CI, and is fast (no database, no HTTP server, no sibling
  checkouts).
