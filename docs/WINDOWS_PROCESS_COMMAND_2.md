# Windows process command 2

`Command.schema_version` defaults to `1` for existing consumers. Version `2`
defines boot-bound Windows process targets only: exactly PID (positive uint32),
start_time_ticks (canonical positive uint64 decimal string), and boot_id (native
`boot_` plus 64 lowercase hex digest). It requires aware expiry timestamps. No
additional action or arbitrary execution capability is introduced.

Manager preserves version 2 instead of forcing version 1, binds enrolled host ID,
and emits UTC expiry. Windows verifies current native boot and exact creation ticks
before process action; legacy unscoped process actions refuse execution. Linux
source remains unchanged. Recommendation translation accepts canonical endpoint
context and independently verifies the native process digest, boot, PID and
decimal token, then requires exact agreement with the recommendation. Invalid,
unresolved or source-scoped context cannot fall back to a legacy target. Manager
stages these targets for the existing approval tier and rechecks retained context
and enrolled agent/host at authorization; changed enrollment refuses dispatch.
Legacy recommendations still produce version-1 targets. Console targeting and
full live response remain open.

The full contract and qualification limits are in the sibling Contracts repository,
`docs/WINDOWS_PROCESS_COMMAND_2.md`. Version 2 is not yet a complete leased/durable
command lifecycle. Result version 2 now supports typed indeterminate outcomes and
immutable retained receipts (Contracts docs/COMMAND_RESULT_2.md); native committed
outcomes have an encrypted outbox. Windows now commits inbox intent before action,
retains replay tombstones and reports interrupted intent as indeterminate without
repeating execution. Native polling selects Manager's durable redelivery mode;
legacy clients retain single-delivery behavior. Leases/fencing, action-specific
reconciliation, actual HTTPS redelivery/result transport, OS-action crash and full
operational qualification remain open.

Result version 2 now includes optional closed structured Windows process execution
evidence. Stage, strict initiation/completion facts and uint32/null native error
must agree with outcome; Manager binds evidence to queued KILL_PROCESS. Absent
evidence stays absent to preserve existing result digests, while explicit null or
schema-1 evidence refuses. The native producer, Python contract and published
execution fixtures agree in regression checks. This does not add a response action
or complete target/provenance, negotiation, Console or live action qualification.
