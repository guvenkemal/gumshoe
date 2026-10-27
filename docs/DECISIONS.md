# Design decisions

A running log. Each entry: the decision, why, and what we gave up. Newest last.
Status is `proposed` until reviewed, then `accepted` or `superseded`.

## D1. Python 3.12+, FastMCP, uv (accepted, from the brief)
The forensics ecosystem (python-evtx, plaso, Volatility, pySigma) is Python.

## D2. SQLite per case, no ORM (proposed)
One self-contained `case.db` per case is easy to archive and hand over with the
evidence. Plain SQL plus numbered migration files keeps queries auditable.
Gave up: concurrent multi-writer access, which a single-analyst tool doesn't need.

## D3. ECS-style field names, flattened columns plus `raw` JSON (proposed)
Sigma rules and analysts already think in ECS-like fields, which makes Phase 2
field mapping cheap. Hot fields are columns with indexes; everything else stays
in `raw` so no source data is lost. Gave up: OCSF's stricter typing.

## D4. EVTX mapping as data, not code (proposed)
A `(channel, EventID) -> fields` table is easy to review and extend. Unmapped
events still ingest as `category=other`, so coverage counts stay honest.

## D5. Stable event IDs from (evidence_id, record position) (proposed)
Findings cite event IDs, so re-ingesting or rebuilding a case must produce the
same IDs.

## D6. Immutable evidence copy with double hashing and read-only permissions (proposed)
Hash during copy, re-hash the copy, chmod 0444, parse only the copy. Filesystem
permissions are a guard rail, not a guarantee, so `verify_evidence` re-hashes on
demand and tests assert hashes never change.

## D7. Hash-chained audit log, full args, summarised results (proposed)
Full results would bloat the DB; a summary plus the SHA-256 of the full response
still proves what the model saw. The hash chain makes tampering detectable.

## D8. Untrusted-field wrapping in Phase 1, not Phase 2 (proposed)
`search_events` is the first tool that returns attacker-controlled text, so the
wrapping must exist from the start. Moved earlier than the brief's phase list.

## D9. Keyset pagination with opaque cursors (proposed)
Stable under large result sets and cheap in SQLite; offsets get slower and can
skip rows.

## D10. Gap detection relative to each source's own rhythm (proposed)
A fixed threshold either floods quiet logs with false gaps or misses gaps in busy
ones. Default: a gap is longer than 4x the source's median inter-event interval
and at least one hour.

## D11. Pinned, hash-verified fixture downloads (proposed)
Tests must not change because an upstream dataset changed. Downloaded data is
git-ignored; tests skip with a clear message if fixtures are missing.
