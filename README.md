# SNR V3 — Signal to Noise

> **V3 is the enterprise-integration & scale evolution of SNR.** It builds on V2 with a
> Postgres data layer, asynchronous LLM analysis (job queue + background workers), a
> machine-authenticated integration API, threat-intel feed ingestion (TAXII/MISP/RSS),
> and detection-as-code publishing via Git pull requests. All V2 features and UX are
> preserved. Work lands phase by phase.

**AI-powered Cyber Threat Intelligence workbench.** Paste a SIEM alert, drop a log
file, or feed in free-text threat reporting, and SNR turns it into structured,
shareable intelligence: an ATT&CK technique chain **and** a MITRE Attack Flow,
extracted/validated IOCs, Sigma/YARA/Suricata detection rules, threat-actor
attribution, and audience-tailored briefs — exportable to STIX, ATT&CK Navigator,
Attack Flow Builder, email, and Markdown. It is **LLM-agnostic** (Anthropic Claude
or any OpenAI-compatible endpoint) and **self-hostable** on your own infrastructure.

> 📖 **New here? Read the [User Manual](./docs/README.md)** — analyst & administrator guides, reference, and troubleshooting.

---

## Features

**Analysis**
- Two-phase LLM pipeline — technical extraction, then an audience-scoped brief (streamed live)
- **ATT&CK chain** and **MITRE Attack Flow** (causal DAG) visualizations
- IOC extraction with validation/dedup; Sigma, YARA & Suricata detection rules
- Threat-actor attribution

**Review & edit**
- Per-session analyst overrides; rich-text editing of the brief
- Severity / TLP control; IOC defang toggle + false-positive marking
- **Re-analyze** an existing session (retry a failure, or regenerate for a different audience) with live progress

**Exports** — STIX 2.1 bundle, ATT&CK Navigator layer, **`.afb`** (Attack Flow Builder), email `.eml`, Markdown report, detection rules, IOC CSV, and a combined ZIP

**Organize & report** — session tags + filters, threat-actor grouping/merge with aggregated TTPs/IOCs, an analytics dashboard, an append-only audit trail, and global search (`Ctrl+K`)

**Customize** — email **layout** + **branding** editors, a CTI **report template** editor, configurable brief sections, and per-audience prompts (all in Settings)

**Integrate (V3)** — a machine-authenticated **Integration API** (`/api/v1`, API keys + scopes + per-key rate limits + webhooks), **threat-intel feed ingestion** (TAXII 2.1 / MISP / RSS, scheduled, auto-analyzed), and **detection-as-code** publishing (Sigma/YARA/Suricata + report to a GitHub PR)

**Enterprise (V3)** — Postgres data layer, **asynchronous analysis** (pg-boss job queue + background worker; restart-safe & concurrent), JWT auth + RBAC, team workspaces, client-side redaction, rate limiting, health/readiness probes, Prometheus `/metrics` (API + worker), scheduled `pg_dump` backups, OpenAPI spec, a Grafana dashboard, and a Docker/Compose deployment

---

## Requirements

- **Postgres 14+** (the V3 data store) — provided automatically by the Docker Compose stack
- **Node.js 22.5+** (server runtime, via `tsx`) for local development
- **Docker 24+** with the Compose plugin for the container deployment
- **An LLM credential:** an Anthropic API key, or any OpenAI-compatible endpoint (Ollama, LM Studio, vLLM, Azure OpenAI)

---

## Setup

### A. Run locally (npm) — for development

```bash
git clone <repo-url> && cd snr-v3
npm install
cp .env.example .env
#   set DATABASE_URL  (postgres://user:pass@localhost:5432/snr)
#   set ANTHROPIC_API_KEY  (or an OpenAI-compatible provider)
#   set A2N_ADMIN_EMAIL / A2N_ADMIN_PASSWORD  (first-run admin)
npm run dev      # runs the API (3001), the worker, and the Vite client (5173)
```

- A reachable Postgres is required (`docker run -d -e POSTGRES_PASSWORD=… -p 5432:5432 postgres:16` for a quick local one). Migrations apply automatically on first start.
- UI: **http://localhost:5173** · API: **http://localhost:3001**. Admin is bootstrapped from `A2N_ADMIN_EMAIL` / `A2N_ADMIN_PASSWORD`.

### B. Deploy with Docker (on-prem / self-hosted)

```bash
cp .env.example .env
#   set JWT_SECRET, ALLOWED_ORIGINS, an LLM key, admin creds, POSTGRES_PASSWORD, and SNR_DOMAIN
docker compose up -d
```

- Brings up **postgres**, the **app** (API + built UI), a background **worker**, and a **Caddy** TLS reverse proxy at **https://<SNR_DOMAIN>** (`localhost` → self-signed; a real domain → auto Let's Encrypt).
- Postgres data persists in the `snr-pgdata` volume; `pg_dump` backups in `snr-data`.
- **Full guide — TLS, secrets, backups/restore, upgrades, scaling, hardening — in [DEPLOYMENT.md](./DEPLOYMENT.md).**

> Migrating from a V2 (SQLite) install? `npm run migrate:sqlite -- /path/to/snr.db` imports
> your existing data into Postgres.

---

## Using SNR

1. **Log in** with the bootstrap admin. Admins create users and team workspaces from the **Admin** panel.
2. **New Analysis** — paste SIEM/alert text, upload a log file (`.csv/.txt/.log/.json`), and/or add free-text intel. **Redact** any sensitive strings (stripped before the LLM call), pick an **audience** (SOC, Purple Team, Red Team, Detection & Response, General, or a custom one), and **Analyze**. Progress streams through Phase 1 (extraction) → Phase 2 (brief).
3. **Review** — toggle **ATT&CK Chain ⇄ Attack Flow** (and expand to full screen); inspect the IOC table (defang, export CSV, flag false positives), detection rules, threat-actor attribution, and analyst notes.
4. **Refine** — edit the brief in rich text, adjust severity/TLP, assign or change the threat actor, or **Re-analyze** to regenerate / switch audience.
5. **Export** — STIX, Navigator, `.afb`, `.eml`, Markdown report, detection rules, IOC CSV, or a full ZIP.
6. **Organize** — tag and filter sessions, group them under threat actors (merge duplicates; see aggregated TTPs/IOCs), open the **Analytics** and **Audit** views, and jump anywhere with global search (`Ctrl+K`).
7. **Configure (Settings)** — LLM provider, analyst identity, **Email Template** + **Branding**, **Brief Sections**, **CTI Report Template**, and per-audience prompts.

---

## Configuration

Common variables (full reference in [`.env.example`](./.env.example) and [DEPLOYMENT.md](./DEPLOYMENT.md)):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | yes* | — | Claude API key. *Or configure an OpenAI-compatible provider (`LLM_PROVIDER`, `API_BASE_URL`, `MODEL_NAME`). |
| `A2N_ADMIN_EMAIL` / `A2N_ADMIN_PASSWORD` | yes (first run) | — | Bootstrap admin (password complexity enforced). |
| `JWT_SECRET` | prod | dev: auto | JWT signing secret. **Required in production.** |
| `ALLOWED_ORIGINS` | prod | — | Comma-separated CORS origins. **Required in production.** |
| `DATABASE_URL` | **yes** | — | Postgres connection string. Compose builds it from `POSTGRES_*`. |
| `PORT` / `HOST` | no | `3001` / dev `127.0.0.1`, prod `0.0.0.0` | Listen port / bind address. |
| `ANALYSIS_WORKER_CONCURRENCY` | no | `2` | Parallel analyses per worker process. |
| `DB_POOL_MAX` | no | `10` | Max Postgres connections per process. |
| `FEED_POLL_INTERVAL_SECONDS` | no | `60` | Feed scheduler tick (`0` disables). |
| `SNR_WEBHOOK_SECRET` | no | — | If set, integration-API webhooks are HMAC-signed. |
| `BACKUP_INTERVAL_HOURS` / `BACKUP_RETENTION` | no | `24` / `7` | Scheduled `pg_dump` cadence & retention (`0` disables). |
| `METRICS_TOKEN` | no | — | If set, `/metrics` requires `Authorization: Bearer <token>`. |
| `LLM_TIMEOUT` | no | `120` | Per-phase LLM timeout (seconds). |

Any secret also supports a `*_FILE` variant (e.g. `JWT_SECRET_FILE`) pointing at a
mounted file — the standard container-secrets convention; the file's contents win.

---

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | API + **worker** + Vite client (concurrently) |
| `npm run build` | Production frontend build (→ `dist/`) |
| `npm start` | Run the API server (serves API + built UI when `NODE_ENV=production`) |
| `npm run worker` | Run the background analysis worker |
| `npm test` / `npm run test:watch` | Vitest (unit; Postgres integration when `TEST_DATABASE_URL` is set) |
| `npm run lint` / `lint:fix` | ESLint + type check / autofix |
| `npm run db:backup` / `db:restore` | `pg_dump` backup / `pg_restore` restore |
| `npm run migrate:sqlite -- <snr.db>` | One-time V2 SQLite → Postgres import |
| `npm run check:actors` | Read-only threat-actor diagnostic |
| `npm run loadtest -- [n] [--wait]` | Load-test the async pipeline (needs `SNR_API_KEY`) |

---

## Architecture

```
            inbound API (/api/v1, API keys)        feeds (TAXII/MISP/RSS, scheduled)
                         \                              /
                          ▼                            ▼
  Web UI ──► API (Express) ──► job queue (pg-boss on Postgres) ──► worker(s)
                  │                                                   │ LLM analysis
                  ▼                                                   ▼
              Postgres  ◄──────────────── results / job_events ──────┘
                  │
                  └──► detection-as-code publisher ──► GitHub branch + PR (rules + report)

├── server/                 # Express.js backend (TypeScript, ESM)
│   ├── index.ts            # API entry: middleware, health/ready, /metrics, schedulers, shutdown
│   ├── worker.ts           # background worker entry: consumes the analysis queue
│   ├── db/
│   │   ├── client.ts       # Postgres pool + async query shim + advisory lock
│   │   ├── database.ts     # initDb, settings (cached), audit log, bootstrap
│   │   ├── migrate.ts      # forward-only SQL migration runner
│   │   └── migrations/     # 001 schema · 002 jobs · 003 api keys · 004 feeds · 005 dac
│   ├── jobs/               # queue.ts (pg-boss), events.ts (SSE channel), analysis-handler.ts
│   ├── lib/
│   │   ├── claude.ts       # two-phase LLM orchestration + JSON schema
│   │   ├── providers/      # LLM provider abstraction (Anthropic / OpenAI-compatible) + retry
│   │   ├── stix.ts afb.ts attack-flow.ts eml.ts report.ts sections.ts   # exporters/templates
│   │   ├── api-keys.ts     # service accounts + API key mint/resolve/revoke
│   │   ├── feeds/          # rss/taxii/misp connectors + ingest orchestrator + scheduler
│   │   ├── publish/        # github.ts — detection-as-code PR publisher (Octokit)
│   │   ├── auth-utils.ts secrets.ts backup.ts metrics.ts logger.ts
│   ├── middleware/         # auth.ts (JWT) + apiKey.ts (machine auth)
│   ├── routes/             # auth, users, teams, sessions, analyze, settings, analytics,
│   │                       #   threat-actors, search, keys, v1, feeds, publish
│   └── openapi.json        # OpenAPI 3 spec for /api/v1
├── src/                    # React + Vite frontend (TypeScript)
│   └── components/         # …, AdminPanel (Users/Teams/API Keys/Feeds tabs), SettingsModal, RightPanel
├── Dockerfile, docker-compose.yml (postgres + app + worker + caddy), deploy/   # on-prem deploy
├── deploy/grafana-dashboard.json   # Prometheus/Grafana ops dashboard
├── .github/workflows/      # CI (tsc/lint/test+postgres/build/docker) + release (GHCR)
├── scripts/                # backup/restore, sqlite→postgres migration, loadtest, diagnostics
└── tests/                  # Vitest (unit + Postgres integration)
```

---

## Operations & security

- **Probes:** `GET /api/health` (liveness) and `GET /api/ready` (DB read/write). **Metrics:** Prometheus at `GET /metrics` (API) and the worker's own port; import [deploy/grafana-dashboard.json](./deploy/grafana-dashboard.json).
- **Backups:** scheduled `pg_dump` snapshots with retention (see DEPLOYMENT.md for restore).
- **Logs:** structured JSON on stdout with secret redaction — ship to your SIEM.
- **Hardening:** Helmet (CSP/HSTS), account lockout, timing-safe auth, prompt-injection defense, client-side redaction, token revocation, rate limiting. The server binds to loopback in dev and `0.0.0.0` in production/containers (front it with TLS). Details in [SECURITY.md](./SECURITY.md).

---

## Documentation

- [User Manual](./docs/README.md) — analyst & administrator guides, reference, troubleshooting
- [DEPLOYMENT.md](./DEPLOYMENT.md) — on-prem install, TLS, backups, hardening
- [API.md](./API.md) — REST endpoint reference
- [SECURITY.md](./SECURITY.md) — security controls & posture
- [`.env.example`](./.env.example) — complete configuration reference

## License

Internal use only.
