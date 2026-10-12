# ADR 0002: Decisions are made online by the API; controllers own outage behaviour

- Status: accepted
- Date: 2026-10-12

## Context

Commercial access control systems usually push access lists down to door controllers, which decide locally and
upload events later, so doors keep working through network or server outages. This service instead answers every
badge read online (`POST /api/v1/access/requests`).

## Decision

Keep online decisions in this version, and make the trade-off explicit:

- **Pro:** a revocation, disable or lockdown takes effect on the very next read at every door (no propagation delay,
  no stale controller caches); every decision is audited centrally before it is returned.
- **Con:** availability of entry depends on this service and the network. A failure is a denial (fail closed).
  Egress and life safety must not depend on it (deployment checklist in CLAUDE.md).

## Path to offline operation (not built)

1. Versioned per-controller access lists (cards as digests, doors, schedules), served as deltas with a full resync.
2. Controllers decide locally when the API is unreachable and buffer events with their own read time and a
   per-controller sequence number.
3. Idempotent event upload keyed by (controller, sequence); late events appended to the audit chain with both the
   read time and the received time.
4. A bound on revocation latency, monitored per controller (last list version acknowledged).
