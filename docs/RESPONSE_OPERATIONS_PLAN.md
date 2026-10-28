# Response operations delivery — 29 October 2026

## Discovery and constraints

The existing ADRs (Manager 004–006, response-engine 001) keep response domain
logic in this package and orchestration in Manager. Preserve the seven actions,
PID reuse protection, Windows boot/decimal-tick identity, immutable receipts,
analyst identity and terminal-state immutability. Endpoint execution stays native.

Reviewed Manager `docs/RESPONSE_ENGINE_STATE.md`, both endpoint command paths,
canonical contracts, the Console panel/proxy and current default branches.
Prior feature branches and Manager's untracked `sim-run/` remain preserved.
Windows sensor commits on the older local branch are outside this release.

## Independently mergeable increments

1. **Contracts:** publish the legacy 0.2–0.4 telemetry schema centrally without
   breaking the agent's existing embedded mirror. Record ownership and add
   compatibility verification. Canonical endpoint-record 1.0 stays authoritative.
2. **Domain:** expose a typed seven-action catalog (target requirements, policy,
   operational risk); permit cancellation only before dispatch. Add fixture tests.
3. **Manager:** authenticated catalog, analyst-initiated actions scoped to an
   existing alert/enrolled endpoint, explicit reasons, duplicate prevention,
   cancellation with atomic dispatch exclusion, paged/filtered queue and full
   retained execution evidence. Manual actions always await explicit approval.
4. **Console:** guided action creation, target/context visibility, filtering,
   queued cancellation, outcome/evidence inspection and useful server errors.
5. **Qualification:** meaningful adversarial/integration tests, real CI, PRs and
   incremental merges; document commands and an E2E acceptance checklist.

Each increment must pass its checks before shipping. Update consumer submodule
pins in dependency order: contracts → response domain → Manager → Console.

## Market research and scope

Microsoft Defender's device response documentation describes device containment,
investigation and action history:
https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts

Elastic documents analyst response from alerts and endpoint views:
https://www.elastic.co/docs/solutions/security/respond-and-contain

Use these as workflow benchmarks. One day's implementation cannot establish
commercial parity, fleet-scale qualification or native OS fault/reboot guarantees.
No arbitrary shell, new endpoint action or fabricated execution success is added.
Cancellation after dispatch is refused because receipt/execution may already have
occurred. Late receipts remain evidence and never rewrite terminal state.

## Acceptance gates

- Canonical schema fixtures and local mirror parity pass.
- Domain suite and lint pass; all seven actions have catalog metadata.
- Manual actions bind to a live enrolled endpoint and cannot auto-execute;
  process identities must agree with retained canonical alert provenance.
- Authorize/cancel/poll serialize through the same database write lock.
- V2 execution facts and late receipts are visible separately from command state.
- Console routes preserve analyst credentials server-side and display errors.
- Manager and Console integration tests cover create → approve → poll → result,
  cancellation, duplicates, identity failures and uncertain outcomes.
- Live Windows/Linux E2E execution must be run against enrolled test endpoints;
  simulated API receipts alone do not establish native execution success.
