# Response governance delivery — 29 October 2026

Continue from merged response operations PRs (Contracts 2/3, Domain 3, Manager
10/11, Console 8). Preserve the seven native actions and all existing identity,
expiry, receipt and cancellation invariants. New work is orchestration/UI only.

## Findings

- Every enrolled analyst currently has the same mutation rights.
- Pending recommendations have no append-only event history; declining one
  preserves only its latest reason/actor. Command audit starts after approval.
- A timed-out manual POST has no stable retry identity after an action completes.
- Recommendation-state filtering cannot find failed/uncertain command outcomes.
- Console reads full histories on every poll and cannot export one case record.

## Incremental release order

1. Contracts: canonical manual-request and analyst-enrollment schemas/fixtures.
2. Domain: closed roles and permission policy. Legacy analyst behavior stays the
   default; optional separate-approver enforcement can tighten manual approval.
3. Manager: role checks, current-analyst identity, immutable decision history,
   idempotent manual requests, command-outcome filters and single-case export.
4. Console: permission-aware controls, retry identity, command-outcome filtering,
   decision history and case JSON export. Keep credentials server-side.
5. Qualification: adversarial API tests and cross-repo HTTP smoke on CI; merge in
   dependency order and update local defaults. Document real endpoint E2E limits.

## Market references

Microsoft Action center separates pending review/history and requires specific
permissions: https://learn.microsoft.com/en-gb/defender-xdr/m365d-action-center

Elastic documents response history, action output and history privilege:
https://www.elastic.co/docs/solutions/security/endpoint-response-actions/response-actions-history

These inform workflow choices, not a claim of full commercial parity. Native OS
execution, HA/fleet performance, SSO and per-browser analyst sessions are separate
qualification/integration work. No arbitrary shell or new endpoint action.

## Acceptance gates

- Canonical request fixtures agree with Manager validation.
- Viewers cannot mutate; responders can request; approvers can decide; existing
  analysts retain both rights. Agent tokens cannot authenticate as analysts.
- Optional separate approver refuses self-approval of manual requests.
- Create/reject/expire/authorize/cancel events persist atomically with decisions;
  audit table rejects update/delete, without backfilling invented history.
- Same analyst/request ID and same payload returns the original request even
  after completion; changed payload conflicts; different analysts are independent.
- Command filters distinguish CANCELLED/INDETERMINATE from recommendation state.
- Export includes retained command/receipt/audit evidence and no credentials.
- Console hides unavailable controls, preserves exact identities and surfaces
  actionable server errors. CI exercises the real HTTP path.
