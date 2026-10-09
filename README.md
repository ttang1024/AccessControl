# Access Control System

A physical access control API in .NET 8. Operators manage cardholders, cards, doors, weekly schedules and access
groups; door controllers ask it to grant or deny each badge read. Every read and every configuration change goes
to a tamper-evident audit log.

A card opens a door only if the door isn't in lockdown, the card is active and unexpired, the cardholder is
enabled and within their validity period, and one of their access groups includes the door with a schedule active
now (in the schedule's time zone). Anything missing or inconsistent is a deny.

> **Entry only.** Exit, fire release and request-to-exit must work in the door hardware without this service.
> If the API is down, every badge read is denied.

## Quick start

Requires the .NET 8 SDK (or a newer SDK plus the .NET 8 and ASP.NET Core 8 runtimes).

```bash
dotnet build && dotnet test
dotnet run --project src/AccessControl.Api     # http://localhost:5080, data in ./data-dev
```

To explore the API in a browser, open http://localhost:5080/swagger (Development only), click **Authorize** and
paste one of the keys below.

Development keys (refused outside Development): `dev-admin-key-change-me` (Admin) and
`dev-door-controller-key-change-me` (DoorController, any door). Example, using `jq`:

```bash
API=http://localhost:5080/api/v1; JSON='Content-Type: application/json'
ADMIN='X-Api-Key: dev-admin-key-change-me'; CTRL='X-Api-Key: dev-door-controller-key-change-me'
post() { curl -s -X POST "$API/$1" -H "$ADMIN" -H "$JSON" -d "$2"; }

DOOR=$(post doors '{"name":"Front door"}' | jq -r .id)
SCHEDULE=$(post schedules "$(jq -n '{name:"Office hours", timeZone:"Pacific/Auckland",
  windows:[("Monday","Tuesday","Wednesday","Thursday","Friday") | {day:., start:"07:00", end:"19:00"}]}')" | jq -r .id)
GROUP=$(post access-groups "{\"name\":\"Staff\",\"scheduleId\":\"$SCHEDULE\"}" | jq -r .id)
PERSON=$(post cardholders '{"firstName":"Ada","lastName":"Lovelace"}' | jq -r .id)
curl -s -X PUT "$API/access-groups/$GROUP/doors/$DOOR" -H "$ADMIN" >/dev/null
curl -s -X PUT "$API/cardholders/$PERSON/access-groups/$GROUP" -H "$ADMIN" >/dev/null
post "cardholders/$PERSON/credentials" '{"cardNumber":"0A:1B:2C:3D"}' >/dev/null

# A badge read, as a door controller sends it (card numbers ignore case and separators):
curl -s -X POST "$API/access/requests" -H "$CTRL" -H "$JSON" -d "{\"doorId\":\"$DOOR\",\"cardNumber\":\"0a1b2c3d\"}"
# → {"eventId":"…","granted":true,"evaluatedAt":"…"}   (false outside office hours)

curl -s "$API/access/events" -H "$ADMIN"    # each read, with the reason
curl -s "$API/audit/changes" -H "$ADMIN"    # who changed what
```

## API

All routes are under `/api/v1` and need an `X-Api-Key` header; only `GET /health` is anonymous. Errors are
RFC 7807 problem documents with a stable `code` (for example `door.in_use` or `concurrency_conflict`).

| Area | Routes | Who |
| --- | --- | --- |
| Cardholders | `cardholders` (search `?q=`), `/{id}`, `/enable`, `/disable`, `/access-groups/{groupId}`, `/credentials` | read: Admin, Operator, Auditor · write: Admin, Operator |
| Credentials | `credentials/{id}`, `/suspend`, `/reinstate`, `/report-lost`, `/revoke`, `/expiry` | same as cardholders |
| Doors | `doors`, `/{id}`, `/lockdown`, `/release` | read: Admin, Operator, Auditor · write and release: Admin · lockdown: Admin, Operator |
| Schedules, groups | `schedules`, `access-groups`, `/members`, `/doors/{doorId}` | read: Admin, Operator, Auditor · write: Admin |
| Badge reads | `POST access/requests` `{doorId, cardNumber}` → `{eventId, granted, evaluatedAt}` | DoorController, assigned doors only |
| Audit | `access/events`, `audit/changes`, `audit/verify` | Admin, Auditor |

- Every list (cardholders, doors, schedules, groups, members, audit) takes `offset` and `limit` (max 500) and
  returns `{items, total, offset, limit}`. Audit results are newest first. Audit queries without `from`
  cover the last 30 days before `to` (or now), set by `AuditQuery:DefaultDays`; pass `from` to look further back.
  They accept an `offset` of at most 10,000; to go further back, narrow `from` and `to`.
- Doors and schedules can't be deleted while a group uses them. This holds even under concurrent requests: the
  store checks references when it commits.
- Responses never contain a full card number: they show at most the last four characters (`****2C3D`).
- A request that changes nothing (e.g. locking down a door that is already locked down) writes nothing.
- Cardholders and cards are never deleted: disable or revoke them instead.
- **Controllers must treat any non-200 response as a deny.** The response deliberately leaves out the deny
  reason, so a stolen controller key can't reveal which cards are enrolled. The reason is in `access/events`.

## Configuration

Use environment variables (`Auth__ApiKeys__0__Sha256`) or a secret store for anything secret.

**API keys:** create a key with `openssl rand -base64 32` and store only its hash (`printf '%s' "$KEY" | shasum -a 256`):

```json
"Auth": {
  "ApiKeys": [
    { "Name": "alice",      "Role": "Admin",          "Sha256": "<hex>" },
    { "Name": "ctrl-lobby", "Role": "DoorController", "Sha256": "<hex>", "Doors": ["<door id>"] }
  ]
}
```

- Roles are `Admin`, `Operator`, `Auditor` and `DoorController`.
- `Name` is recorded in the change log, so it must be unique.
- Give each controller its own key, listing only the doors it serves.
- Unsafe key settings stop startup.
- Outside Development, a key sent over plain HTTP is rejected (`Auth:RequireHttps`). Replace that key, since it
  crossed the network unencrypted.

| Setting | Default | Purpose |
| --- | --- | --- |
| `Storage:DataDirectory` | `data` | `store.json` and the audit logs. Back it up. |
| `Storage:AuditHmacKey` | none | Signs the audit hash chain. Required outside Development (32+ characters). Set it before first start; changing it breaks verification of older entries. |
| `Storage:AuditSegmentMaxBytes` | 64 MB | Audit log rotation size. |
| `Storage:AuditRetentionDays` | keep forever | Delete rotated audit files older than this. |
| `Storage:MinimumFreeDiskBytes` | 1 GB | `/health` (readiness) turns unhealthy below this; a full disk denies every door. `/health/live` only checks that the process answers. |
| `AuditQuery:DefaultDays` | 30 | How far back `access/events` and `audit/changes` look when no `from` is given. |
| `RateLimiting:DoorControllerPermitsPerMinute` | 120 | Per controller key. A throttled read is a denied entry, so size it above peak. |
| `RateLimiting:UserPermitsPerMinute` | 600 | Per Admin, Operator or Auditor key. |
| `RateLimiting:AnonymousPermitsPerMinute` | 60 | Per client IP, for requests with no key or a wrong key; `/health*` has its own budget of the same size. |
| `AllowedHosts` | `*` | Must list the real host name(s) outside Development, or startup fails. |

## Audit trail

- `access-events*.jsonl` records every badge read with its reason.
- `changes*.jsonl` records every configuration change: who made it, and the record before and after. Each entry
  is written before the change takes effect.
- Both logs are hash-chained. `GET /api/v1/audit/verify` reports any entry that was edited, removed, inserted or
  reordered, and any oldest entries removed other than by retention (which leaves a signed anchor).
- The chain can't show that its newest entries were removed while the service was stopped. Record each report's
  `lastSequence` and `lastHash` off the host and alert if a later report goes backwards.
- The chain can't stop someone with root on the host from deleting files, so copy the logs off the host.

## Before going live

- [ ] Exit, fire release and request-to-exit work with the API stopped, and you have decided what controllers do
      when the API is unreachable.
- [ ] TLS is on all the way to the API. Behind a TLS proxy, set `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true`, but
      only if the API can be reached through that proxy alone.
- [ ] `ASPNETCORE_ENVIRONMENT` is not `Development`, `AllowedHosts` is set, and `AuditHmacKey` and API keys come
      from a secret store.
- [ ] Monitoring covers `/health` and `/health/live`, `audit/verify` (with the chain head stored off-host), the
      `AccessControl.Access` metrics, log events 4000 (key sent over HTTP) and 4001 (controller used
      an unassigned door), and 429 responses to controllers.
- [ ] The data directory is backed up and the audit logs are copied off the host.

A `Dockerfile` (non-root, data in `/data`) and a CI workflow (`.github/workflows/ci.yml`) are included.

This runs as a single instance, sized for tens of thousands of configuration records. To scale out, put the
interfaces in `src/AccessControl.Application/Abstractions/` on a database.

Contributors: see [CLAUDE.md](CLAUDE.md) for the architecture and design rules.
