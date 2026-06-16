# SNR V3 — API Reference

Base URL: `https://<your-host>` (dev: `http://127.0.0.1:3001`)

SNR exposes two API surfaces:

- **Web/UI API** (`/api/*`) — authenticated with a **JWT** (`Authorization: Bearer <jwt>`); used by the SNR web app. Team context is set with the `X-Team-Id` header.
- **Integration API** (`/api/v1/*`) — authenticated with a **service API key** (`Authorization: Bearer snr_…` or `X-API-Key: snr_…`); for programmatic use by other systems. Team scope is implied by the key.

All endpoints return JSON unless noted.

---

## Health, readiness & metrics (no auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Liveness — `{ status, uptime, version, llm }` |
| GET | `/api/ready` | Readiness — verifies DB read/write |
| GET | `/metrics` | Prometheus metrics (optionally gated by `METRICS_TOKEN`) |
| GET | `/api/v1/openapi.json` | OpenAPI 3 spec for the integration API |

The **worker** process exposes its own `/metrics` on `WORKER_METRICS_PORT` (default 9091).

---

## Integration API (`/api/v1`) — machine auth

Authenticate with an API key minted by an admin (Admin Panel → **API Keys**, or `POST /api/keys/...`). Keys carry **scopes** and a **per-key rate limit** (default 60/min). All access is scoped to the key's team.

| Scope | Grants |
|---|---|
| `analyze:write` | Submit analyses |
| `sessions:read` | Read status & results |
| `export:read` | Fetch exports |

### Submit an analysis
`POST /api/v1/analyze` — scope `analyze:write` → **202**

```bash
curl -X POST https://host/api/v1/analyze \
  -H "Authorization: Bearer snr_…" -H "Content-Type: application/json" \
  -d '{"name":"Suspicious RDP","audience":"soc","siem":"<alert text>","webhook_url":"https://my-soar/hook"}'
# → { "sessionId": "…", "jobId": "…", "status": "queued" }
```

Body: `audience` (required), one of `siem` / `text` (required), optional `name`, `redacted_strings[]` (masked before analysis), `webhook_url` (POSTed on completion; HMAC-signed via `X-SNR-Signature` when `SNR_WEBHOOK_SECRET` is set).

### Poll status / fetch results
| Method | Endpoint | Scope | Description |
|---|---|---|---|
| GET | `/api/v1/analyses/{id}` | `sessions:read` | `{ status, severity, version, … }` (`pending`→`analyzing`→`complete`/`failed`) |
| GET | `/api/v1/analyses/{id}/result` | `sessions:read` | Structured result (409 until complete; false-positive IOCs excluded) |
| GET | `/api/v1/analyses/{id}/export/{format}` | `export:read` | `format` = `stix` \| `navigator` \| `iocs` |

### Completion webhook
If `webhook_url` was supplied, SNR POSTs `{ sessionId, teamId, status, version?, error?, ts }` on terminal state. Verify authenticity with the `X-SNR-Signature: sha256=<hmac>` header (HMAC-SHA256 of the raw body using `SNR_WEBHOOK_SECRET`).

---

## API key management (`/api/keys`) — admin (JWT)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/keys/scopes` | List valid scopes |
| GET / POST | `/api/keys/service-accounts` | List / create service accounts |
| PATCH | `/api/keys/service-accounts/{id}` | Enable/disable |
| GET / POST | `/api/keys/service-accounts/{id}/keys` | List / **mint** a key (token returned **once**) |
| POST | `/api/keys/{keyId}/revoke` | Revoke a key |

---

## Detection-as-code (`/api/publish`) — JWT, team-scoped

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/publish/status` | Whether a GitHub target is configured for the team |
| POST | `/api/publish/{sessionId}` | Open/update a PR with the session's rules + report → `{ prUrl, prNumber, files, updated }` |

Configure the target in **Settings → Detection-as-Code** (`dac_github_repo`, `dac_github_branch`, `dac_github_token`, `dac_path_prefix`).

---

## Threat-intel feeds (`/api/feeds`) — JWT, admin/lead

| Method | Endpoint | Description |
|---|---|---|
| GET / POST | `/api/feeds` | List / create a feed (`type` = `rss` \| `taxii` \| `misp`) |
| PATCH / DELETE | `/api/feeds/{id}` | Update (incl. `enabled`) / delete |
| POST | `/api/feeds/{id}/test` | Fetch items without ingesting |
| POST | `/api/feeds/{id}/poll` | Poll now (ingests new items immediately) |

Feeds are also polled automatically on their cadence (`FEED_POLL_INTERVAL_SECONDS`).

---

## Web/UI API (`/api`, JWT)

Auth: `POST /api/auth/login` · `/refresh` · `/logout` · `GET /api/auth/me` · `PATCH /api/auth/me/password`.
Resources (team-scoped via `X-Team-Id`): `/api/sessions`, `/api/analyze` (+ `/export/*`), `/api/settings`, `/api/analytics`, `/api/threat-actors`, `/api/search`, `/api/users`, `/api/teams`.

`POST /api/analyze` and `POST /api/analyze/rerun/:id` are **Server-Sent Event** streams (events: `status`, `chunk`, `complete`, `error`) — the work runs in the background worker and the API tails its progress.
