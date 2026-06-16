[← Troubleshooting](./06-troubleshooting.md) · [Manual index](./README.md) · Next: [Detection-as-Code →](./08-detection-as-code.md)

# 7. Integration API & Threat-Intel Feeds

SNR V3 can be driven by other systems — submit analyses programmatically, pull
results, and ingest intel automatically from external feeds. Everything lands as a
normal session, analyzed by the same pipeline the UI uses.

- [7.1 API keys & service accounts](#71-api-keys--service-accounts)
- [7.2 Submitting & retrieving analyses](#72-submitting--retrieving-analyses)
- [7.3 Webhooks](#73-webhooks)
- [7.4 Threat-intel feeds](#74-threat-intel-feeds)

---

## 7.1 API keys & service accounts

A **service account** is a non-human identity scoped to one team with a role
(`analyst` or `viewer`). It holds one or more **API keys** (credentials you can
rotate). Admins manage these in **Admin Panel → API Keys**:

1. **Create a service account** (e.g. `soar-prod`).
2. **Mint a key** — choose its **scopes**; the token (`snr_…`) is shown **once**, so copy it immediately.
3. Use it as `Authorization: Bearer snr_…` (or `X-API-Key: snr_…`).

| Scope | Grants |
|---|---|
| `analyze:write` | Submit analyses |
| `sessions:read` | Read status & results |
| `export:read` | Fetch STIX / Navigator / IOC exports |

Each key has a **per-minute rate limit** (default 60) and can be **revoked** at any
time. Every key action is recorded in the audit log.

## 7.2 Submitting & retrieving analyses

Base path: `/api/v1` (team scope is implied by the key). Full schema: `GET /api/v1/openapi.json`.

```bash
# Submit (scope analyze:write) → 202 { sessionId, jobId, status:"queued" }
curl -X POST https://snr.example/api/v1/analyze \
  -H "Authorization: Bearer snr_…" -H "Content-Type: application/json" \
  -d '{"name":"Suspicious RDP","audience":"soc","siem":"<alert text>"}'

# Poll (scope sessions:read) until status == "complete"
curl https://snr.example/api/v1/analyses/<sessionId> -H "Authorization: Bearer snr_…"

# Fetch the structured result, or an export (scope export:read)
curl https://snr.example/api/v1/analyses/<sessionId>/result        -H "Authorization: Bearer snr_…"
curl https://snr.example/api/v1/analyses/<sessionId>/export/stix   -H "Authorization: Bearer snr_…"
```

- Inputs: `audience` (required) and at least one of `siem` / `text`. Optional `name`,
  `redacted_strings[]` (masked before analysis), and `webhook_url`.
- `result` returns once the analysis is complete (HTTP 409 until then) with
  analyst-flagged false-positive IOCs already excluded.
- `export/{format}` supports `stix`, `navigator`, and `iocs`.

## 7.3 Webhooks

Include `"webhook_url": "https://…"` in a submission to be notified on completion.
SNR POSTs `{ sessionId, teamId, status, version?, error?, ts }`. If
`SNR_WEBHOOK_SECRET` is configured, verify the `X-SNR-Signature: sha256=<hmac>`
header (HMAC-SHA256 of the raw request body) before trusting the payload.

## 7.4 Threat-intel feeds

Feeds pull intel on a schedule and turn each new item into an analyzed session.
Configure them in **Admin Panel → Threat Feeds** (admin or team lead):

| Field | Meaning |
|---|---|
| **Type** | `RSS/Atom`, `TAXII 2.1`, or `MISP` |
| **URL** | Feed endpoint (RSS URL; TAXII API root or collection objects URL; MISP base URL) |
| **Auth token** | Optional bearer/API key (write-only; never shown again) |
| **Config** | Type-specific JSON, e.g. TAXII `{"collectionId":"…"}` |
| **Audience / Tags** | Applied to every session the feed creates |
| **Cadence / Max items** | Poll interval (minutes) and per-poll cap (bounds analysis cost) |

- **Test** fetches items without ingesting; **Poll now** ingests immediately.
- The scheduler polls due, enabled feeds automatically (`FEED_POLL_INTERVAL_SECONDS`).
- Items are **deduplicated** by source id, so re-polling won't re-create sessions.

---

Next: [Detection-as-Code →](./08-detection-as-code.md)
