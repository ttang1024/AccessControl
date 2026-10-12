# ADR 0001: File-backed store and hash-chained audit logs instead of a database

- Status: accepted (revisit when a trigger below is hit)
- Date: 2026-10-12

## Context

The service needs, for configuration: atomic multi-document commits, optimistic concurrency, a unique card index,
referential integrity and an attributed change trail written with every change; and for badge reads: an append-only,
tamper-evident audit log written before each response. A relational database (PostgreSQL / SQL Server / SQLite)
provides the first set out of the box. It does not provide the second: a tamper-evident trail still has to be built.

## Decision

Keep the in-process, file-backed implementation for the single-site, single-instance deployment this project targets
(tens of thousands of configuration records, one API instance), behind the persistence ports in
`Application/Abstractions` so that it can be replaced without touching Domain, Application or Api.

- The change log is the write-ahead log: a commit is one fsync'd append carrying the full new documents, and
  `store.json` is a periodic checkpoint replayed from the log at startup. A change and its audit entry cannot
  disagree, and a commit does not rewrite the store.
- Constraints (unique card digest, foreign keys) are enforced once, at commit, and checked against the record types
  at startup.
- One process per data directory, enforced by an OS file lock.

## Consequences

- No database to operate, back up or secure for a small site; the whole state is a directory that can be copied.
- We own correctness-critical storage code (snapshot isolation, constraints, crash recovery). It is covered by tests
  for races, crash recovery, cut-off commits, tampering and migration, but it has had far less use than a database.
- Lists and searches scan the collection in memory and audit queries scan log files: fine at the target size, not beyond.
- Single node only: no failover. If the instance is down, every badge read is denied (life safety is independent of
  this service; controller offline behaviour is decided on the controllers).

## Triggers to move to a database

Any of: more than one API instance (availability or load), more than ~50k cardholders, audit queries that must span
months quickly, or an operations team that already runs PostgreSQL/SQL Server. Then implement the ports in a new
Infrastructure project (EF Core; `xmin`/rowversion for concurrency; a unique index on the card digest; the change
trail and the hash chain written in the same transaction as the change) and swap the registration in
`Infrastructure/DependencyInjection.cs`.

## Alternatives considered

- **SQLite + EF Core now.** Removes most of the store code and gives proven transactions. Rejected for this iteration
  only because the audit chain, the key handling and the one-writer rule are needed either way; it is the first
  choice once a trigger is hit.
- **Event store / Kafka.** More moving parts than a single site needs.
