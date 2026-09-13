# What this package owns, and what it explicitly does not

## Owns

- **The closed response-action vocabulary and its typed wire contract**
  (`response_engine.contract`): the 7-action `Literal`, `Command`,
  `CommandResult`, and per-action target-schema validation (PID-reuse-safe
  process targets, path-only file targets, no target for host-level
  actions).
- **Tier classification / response policy** (`response_engine.policy`):
  which actions may fire automatically (`AUTO_SAFE`) and which always
  require analyst approval (`ANALYST_APPROVAL`), including the locked
  decisions that KILL_PROCESS, ISOLATE_HOST, and RELEASE_HOST_ISOLATION
  never auto-fire.
- **Recommendation translation** (`response_engine.recommendation`): mapping
  a detection engine's recommendation vocabulary (e.g. `TERMINATE_PROCESS`,
  `BLOCK_FIREWALL_IP`) onto the closed action set, failing closed rather
  than guessing when a safe mapping doesn't exist.
- **The canonical lifecycle state machine** (`response_engine.lifecycle`):
  which state transitions are legal, independent of how any particular
  consumer persists state.

## Explicitly does not own

- **Persistence.** No database, no SQL, no ORM. A consumer decides how (and
  in how many tables) to store a response action's state; this package only
  tells it which transitions are legal and how to validate/classify an
  action.
- **HTTP / transport.** No web framework dependency. A consumer exposes
  whatever HTTP (or other) surface it needs on top of this contract.
- **Authentication / authorization identity.** Who is allowed to authorize
  or reject a response action is the consuming backend's concern (it owns
  analyst/agent identity); this package only defines what an authorized
  decision produces.
- **OS-specific execution.** How `KILL_PROCESS` actually terminates a
  process, or how `ISOLATE_HOST` actually isolates a host, is entirely the
  endpoint agent's responsibility (Windows and Linux agents implement this
  independently, using their own OS APIs). This package never contains
  execution logic, shell invocation, or OS-specific code of any kind.
- **The detection/correlation engine's own recommendation logic.** This
  package consumes a recommendation's `(action, payload)` shape; it does not
  decide when a detection engine should recommend an action in the first
  place.

## Why this boundary

Everything this package owns is pure domain logic: given an action name, a
target dict, or a state pair, it answers a question with no I/O and no
side effects. That purity is what makes extracting it into its own
repository valuable without turning it into a microservice — it is trivial
to unit test in isolation, trivial to reuse from any consumer regardless of
that consumer's persistence or transport choices, and it can never itself
become a source of I/O-related bugs (a hung network call, a lock contention
issue, a partial write) because it does none.
