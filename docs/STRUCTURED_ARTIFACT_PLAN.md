# Next response slice: structured investigation artifacts

Implement after current runtime-profile PRs pass and merge. Keep closed seven
actions and their current semantics. COLLECT_FILE stays metadata/hash collection;
full binary file acquisition/transfer requires a later explicit extension.

## Deliverable

Analysts request existing process, connection or file-metadata collection in the
Console, then inspect/download the resulting JSON artifact and custody history
in the same response case. No analyst CLI step or arbitrary execution action.

## Contract and server

- A centrally governed bounded artifact envelope: version, artifact ID, command
  and correlation IDs, host ID, kind, content byte count, SHA-256 and Base64 of
  exact UTF-8 JSON bytes. Kinds: process_snapshot, network_snapshot, file_metadata,
  execution_report. JSON only in this slice; no arbitrary media/rendered HTML.
- Agent-authenticated POST under the owned command. Recheck credentials/current
  enrollment inside write transaction. Require actual prior dispatch, original
  host, exact command correlation and action-to-kind agreement.
- Immutable idempotence on agent/artifact ID; altered bytes or metadata is 409.
  Strict Base64/JSON, bounded streaming body, per-artifact/per-command/global
  storage quotas and bounded count, enforced atomically. No caller file paths
  are used for server storage or download names.
- SQLite BLOB original bytes plus immutable metadata; append-only custody events
  chained with SHA-256 over canonical event metadata and previous event hash.
  Hashes detect internal inconsistency; do not claim endpoint truth or external
  nonrepudiation. No automatic evidence eviction.
- Analyst-authenticated metadata/content endpoints, attachment-only JSON downloads,
  no-sniff headers, and recorded downloads. Case previews bounded; full exports
  include manifests/custody, not inline unbounded content.

## Native delivery

- Windows: identity-scoped ArtifactOutbox using existing encrypted DurableJournal.
  Save collected JSON before recording command completion. Separate upload API
  from result receipt, stable artifact ID on retry, verify artifact ID/digest in
  server receipt before retiring the local record. Failed uploads retain data;
  quota failure cannot falsely claim successful durable artifact capture.
- Linux: use a separate private WAL with admission before its dropping quota,
  force sync before artifact acceptance, same bound identity and exact receipts.
  Persist collection artifact before marking the command ledger done. Prepare
  actual process metadata from read_process, network evidence items already
  collected, and file metadata/hash from the held safe descriptor. Existing
  telemetry audit remains independent. No collection is rerun after interrupted
  intent merely to reconstruct a missing artifact.
- No manual/native/full-system E2E. Focused outbox, receipt, quotas, identity,
  tamper, API, Console and existing native CI checks gate each producer.

## Order

1. Central schema/fixtures and API custody storage with tests.
2. Native durable producers and upload receipts for both platforms.
3. Console collection artifacts/download/custody views and old-Manager compatibility.
4. Update the saved flagship plan with shipped scope and remaining binary acquisition.
