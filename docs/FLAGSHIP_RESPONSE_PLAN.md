# Flagship response implementation plan — 29 October 2026

## Direction

Build incrementally, merge green features quickly, and surface analyst decisions
in Console. The user has explicitly deferred E2E testing. Do not run native,
cross-VM or manual full-system E2E scenarios during this sprint. Continue unit,
contract, API regression and existing CI checks. Live qualification remains a
later release gate; implementation is not evidence of live OS execution.

Completed foundation: central telemetry schemas, seven-action catalog, manual
requests, queued cancellation, roles/separate approval, retry identity, immutable
decision history, outcome filters and case exports (Manager PRs 10–13).

## Shipped implementation sprint

Merged: contracts PR 5, domain PR 5, Manager PR 14, Console PR 10. PR CI passed
before each merge. Local focused checks: 151 domain tests plus 14 subtests,
112 Manager API/contract regressions (2 platform/native skips), 66 Console Python
tests and eight Node suites. No manual/native E2E runs were performed. The local
UI preview was started with `--preview-only`; it does not run response workflow
qualification. Deployment still requires explicitly provisioned command keys.

1. **Command authority:** integrate the organization's existing Linux ES256 signing
   work (`feat/linux-command-signing`, ADR 008) into current Manager without
   importing its unrelated ingestion branch. Centralize signed wire schemas and
   native reference vectors in contracts; put canonical signing bytes in the domain
   library. Sign at authorization, persist signature, negotiate delivery so legacy
   Windows decoders keep their exact envelope. Fail closed on configured-key errors.
2. **Response readiness:** retain authenticated command-channel observations and
   expose signing readiness, last poll and explicit unknowns. A poll proves contact,
   not action support, enforcement mode or execution success.
3. **Analyst preflight:** show retained target, approval eligibility, channel age,
   signature readiness and actionable blockers before dispatch. Recheck identity
   and configured authority in the real authorization path.
4. **Bounded response campaigns:** stage a small batch of alert-scoped manual
   requests with stable per-item retry identities and per-item results. Every item
   still requires the normal analyst approval; no bulk auto-execution. Keep blast
   radius bounded, preserve partial results and audit provenance.
5. **Console:** signing/readiness/preflight and campaign controls with exact target
   review. Permission restrictions stay server-enforced. Refresh the local preview.

## Release gates

- Central schemas and reference signing vectors validated.
- Canonical signing input agrees byte-for-byte with retained native vectors;
  key loading, rotation, tampering and negotiation have regression coverage.
- Old Windows polling is unchanged; ES256 requests cannot receive unsigned commands.
- Readiness and preflight label unknown/stale state honestly; never infer success.
- Batch creation is bounded and retry-safe, with individual failures and approvals.
- Domain/Manager/Console checks and CI pass before dependency-ordered merges.
- Record shipped PRs and residual work here for continuation.

## Shipped Linux response integration wave

Merged with PR CI passing: contracts PR 6, domain PR 7, Manager PRs 15–17,
Console PR 11. Local checks: 77 valid and 73 invalid central Linux fixtures;
177 domain tests plus 14 subtests; 78 focused ingestion/worker/response checks;
28 focused evidence/readiness/migration checks; 66 Console Python tests and nine
Node suites. No manual/native/full-system E2E was run.

- The existing organization Linux schema, policy/tamper/response evidence and
  retained fixtures now live on central contracts default branch. Manager's
  compatibility mirror is checked against central schema and all fixtures.
- Authenticated Linux ingestion retains immutable originals and reports exact
  accepted/duplicate/rejected-line counts. Fixed the older branch's line-less
  conflict ACK. Proper migrations replace request-time DDL. Host binding is
  rechecked inside the write transaction; oversized sequence integers are explicit
  per-line refusals rather than batch failures.
- Durable Linux process detection shares bounded worker capacity with Windows
  and legacy records. Lease recovery, per-record poisoning and scoped replay
  deduplication have regressions. Existing retained processes queue once.
- Per-record Linux alerts carry their own identity model and native record/entity
  proof. Process targets preserve boot/PID/start ticks and full 64-bit precision;
  invalid/inferred/aggregate identity cannot fall back to legacy PID targeting.
  Existing manual staging, authorization, signing and enrollment checks apply.
- Analyst cases show retained response.action reports with explicit correlation,
  action, host, process/file target and boot comparisons. Telemetry never changes
  command state. Preview is bounded; full exports include original JSON strings
  and SHA-256. Console emphasizes dry runs and linkage disagreements.
- Readiness shows existing Linux command-channel policy snapshots with capture
  and receive time. Freshness remains unverified and current enforcement mode
  unknown. This is partial capability visibility, not completed live capability
  negotiation. Windows collection coverage is not response capability evidence.

## Shipped current native runtime policy wave

Merged green: contracts PR7, Linux PR2, Windows PR7, Manager PR18, Console PR12.
Both native producers report current configuration through authenticated command
polls independently of queued telemetry. Reports distinguish implemented/allowed
actions, mode, boot identity and signature requirements. Manager receive-time
freshness expires after 300 seconds, omission clears it, and host rebind invalidates
it. Missing or stale reports stay unknown for legacy compatibility.

Policy gates run at actual authorization and delivery. Off/disallowed/unsupported
operations, changing actions in dry-run mode and mismatched process boots are
withheld. SQL filters before the delivery limit so blocked work cannot starve
permitted collection. Signature requirements retain ES256 demand. Console exposes
current/stale policy and held-delivery reasons, alongside existing approvals,
requests, cancellation, campaigns and evidence. Native verification remains the
execution authority; Windows explicitly reports its current signing limitation.

Validation: Manager 76 focused regressions and 29 profile checks; Console 66 Python
tests and ten Node suites; Linux native/sanitizer CI; Windows native Debug build
and response CTest plus full Debug/Release PR CI (48 tests per configuration).
Initial Windows Release CI exposed an existing USN fixture assumption about
named-stream creation versus content changes. The repaired fixture performs
write-through/flush/close and verifies creation plus a separate overwrite; both
configurations passed at 1f1035a before merge. No tests were disabled. Local USN
components passed but native volume access was denied, so live journal proof
comes from existing CI. No manual/full-system E2E was run.

## Following milestones, in priority order

1. Structured investigation artifact transfer and custody into analyst views.
   Follow STRUCTURED_ARTIFACT_PLAN.md for a bounded first slice: existing process,
   network and file-metadata collections produce durable JSON artifacts; uploads
   bind exact command, host and correlation; retained bytes have SHA-256 and
   append-only custody; analysts inspect/download from the Console. Do not silently
   expand COLLECT_FILE into binary acquisition. Full file-byte acquisition remains
   a later explicit extension to this work.
2. Per-browser analyst sessions/identity-gateway integration and endpoint scopes.
   Console still uses the server-configured analyst token; roles do not substitute
   for distinct browser identities.
3. Bounded multi-step playbooks with explicit approval gates, followed by endpoint
   execution reconciliation and fleet operations. Existing campaigns stage
   independent items and do not execute a sequential playbook.
4. Remaining trust and production hardening: Windows signature verification parity,
   artifact retention/storage operations, sustained-load and recovery qualification.

The user has deferred E2E testing. Continue implementation/unit/contract/API and
existing CI checks; do not turn that deferral into a reason to stop development.
Keep remaining work visible rather than claiming commercial parity from API/UI
features. The seven native actions remain the closed baseline.
