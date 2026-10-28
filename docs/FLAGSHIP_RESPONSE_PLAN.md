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

## Following milestones, in priority order

1. Reconcile the mature Linux sensor's telemetry/response provenance with central
   contracts. Its Manager `feat/linux-command-signing` branch also contains a
   separate Linux ingestion implementation; this sprint intentionally ported only
   command authority, not that ingestion branch. Audit and integrate the relevant
   pieces without parallel competing schema ownership.
2. Explicit response capability and policy reports from both native runtimes,
   including enforcement mode and per-action support, with freshness semantics.
3. Structured investigation artifact transfer and custody into analyst views.
4. Per-browser analyst sessions/identity-gateway integration and endpoint scopes.
5. Bounded multi-step playbooks with explicit approval gates, followed by endpoint
   execution reconciliation and fleet operations.

The user has deferred E2E testing. Continue implementation/unit/contract/API and
existing CI checks; do not turn that deferral into a reason to stop development.
Keep remaining work visible rather than claiming commercial parity from API/UI
features. The seven native actions remain the closed baseline.
