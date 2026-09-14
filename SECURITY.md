# Security Policy

`panopticon-response-engine` is a capstone/research security project component. There is no SLA,
but reports are handled on a best-effort basis.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability, a policy-tier bypass, or
a way to smuggle an 8th/free-form action through `translate_recommendation`.

Instead, report privately via GitHub Security Advisories:

<https://github.com/Panopticon-Co/panopticon-response-engine/security/advisories/new>

Include, where possible:

- A description of the issue and its potential impact.
- Reproduction steps (a failing test is ideal).
- The affected module (`contract`, `policy`, `recommendation`, or `lifecycle`).

## Scope note

This package is a pure domain library: no I/O, no network service, no OS-level execution. It never
itself terminates a process, quarantines a file, or isolates a host — real execution happens in the
endpoint agents, dispatched by [`panopticon-manager`](https://github.com/Panopticon-Co/panopticon-manager).
A report should be scoped to this package's contract/policy/translation/lifecycle logic — for issues
in dispatch, authorization identity, or actual endpoint execution, report against
`panopticon-manager` or the relevant agent repository instead.

Reports proposing to weaken a locked decision (e.g. making `KILL_PROCESS` auto-fire, or adding an
8th action) should explain the specific risk being mitigated — these boundaries are intentional,
reviewed guardrails, not oversights.

## Supported versions

This project does not yet maintain multiple released versions; security fixes are applied to the
`main` branch.
