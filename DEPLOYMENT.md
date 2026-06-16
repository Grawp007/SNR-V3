# SNR V3 — On-Prem Deployment Guide

Self-hosted deployment of SNR (Signal-to-Noise) for an enterprise security program.
V3 runs on **Postgres** with an **asynchronous worker**: the API stays responsive
while LLM analysis runs as background jobs that survive restarts and scale out.

## Architecture

```
            ┌────────────┐     ┌──────────────────────┐
  HTTPS ───▶│   Caddy    │───▶ │  app  (API + UI)     │──┐
            │ (TLS :443) │:3001│  Node 22             │  │ enqueue / read
            └────────────┘     └──────────────────────┘  │
                                ┌──────────────────────┐  ▼   ┌────────────┐
                                │  worker(s)           │◀────▶│  postgres  │
                                │  LLM analysis jobs   │      │ (pg-boss + │
                                └──────────────────────┘      │  app data) │
                                                              └────────────┘
   volumes:  snr-pgdata (database)   ·   snr-data (pg_dump backups)
```

## Prerequisites
- Docker Engine 24+ and the Compose plugin.
- An LLM credential: an Anthropic API key, **or** an OpenAI-compatible endpoint
  (Ollama / vLLM / LM Studio / Azure OpenAI) reachable from the host.
- A DNS name pointing at the host if you want a public TLS certificate.

## Quick start
```bash
cp .env.example .env
# Edit .env — at minimum set:
#   JWT_SECRET           (node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
#   ALLOWED_ORIGINS      e.g. https://snr.yourorg.com
#   ANTHROPIC_API_KEY    (or LLM_PROVIDER=openai-compatible + API_BASE_URL)
#   POSTGRES_PASSWORD    (used to build DATABASE_URL for app + worker)
#   A2N_ADMIN_EMAIL / A2N_ADMIN_PASSWORD   (first-run admin)
#   SNR_DOMAIN           your domain (or "localhost" for a self-signed cert)

docker compose up -d
docker compose logs -f app worker     # watch startup + migrations
```
Then browse to `https://<SNR_DOMAIN>` and log in with the bootstrap admin. The
`postgres`, `app`, `worker`, and `caddy` services come up together; migrations
apply automatically (serialized across app+worker via a Postgres advisory lock).

To run **without** the bundled proxy: delete the `caddy` service, publish `app`'s
`3001`, and set `TRUST_PROXY` to your proxy depth.

## Migrating from a V2 (SQLite) install
```bash
docker compose up -d postgres           # start just the DB
# from a checkout with deps installed, pointed at the same DATABASE_URL:
DATABASE_URL=postgres://snr:<pw>@localhost:5432/snr npm run migrate:sqlite -- /path/to/snr.db
docker compose up -d                    # bring up the rest
```
The importer is idempotent (re-runnable) and carries users, teams, sessions,
results, threat actors, audit log, and settings forward.

## Configuration reference

| Variable | Default | Notes |
|---|---|---|
| `NODE_ENV` | `development` | Compose sets `production`. |
| `DATABASE_URL` / `_FILE` | — | **Required.** Postgres connection string. Compose builds it from `POSTGRES_*`. |
| `POSTGRES_USER`/`POSTGRES_DB` | `snr` | Compose postgres service. |
| `POSTGRES_PASSWORD` | — | **Required** for compose. |
| `DB_POOL_MAX` | `10` | Max Postgres connections per process. |
| `ANALYSIS_WORKER_CONCURRENCY` | `2` | Parallel analyses per worker process. |
| `PORT` / `HOST` | `3001` / prod `0.0.0.0` | App listen port / bind address. |
| `TRUST_PROXY` | prod `1` | Reverse-proxy hops to trust. |
| `ALLOWED_ORIGINS` | — | **Required in prod.** Comma-separated CORS origins. |
| `JWT_SECRET` / `_FILE` | — | **Required in prod.** 64-byte hex recommended. |
| `ANTHROPIC_API_KEY` / `_FILE` | — | LLM key (or an OpenAI-compatible provider). |
| `A2N_ADMIN_EMAIL` / `A2N_ADMIN_PASSWORD` (`_FILE`) | — | First-run admin. |
| `FEED_POLL_INTERVAL_SECONDS` | `60` | Threat-intel feed scheduler tick (`0` disables). |
| `SNR_WEBHOOK_SECRET` / `_FILE` | — | If set, integration-API webhooks are HMAC-signed. |
| `BACKUP_INTERVAL_HOURS` / `BACKUP_RETENTION` | `24` / `7` | `pg_dump` cadence / retention (`0` disables). |
| `BACKUP_DIR` | `/data/backups` | Snapshot location. |
| `WORKER_METRICS_PORT` | `9091` | Worker Prometheus port. |
| `METRICS_TOKEN` | — | If set, `/metrics` requires `Authorization: Bearer <token>`. |
| `SNR_DOMAIN` | `localhost` | Domain for the Caddy TLS proxy. |

Any secret supports a `*_FILE` variant pointing at a mounted file (Docker/K8s
secrets); the file's contents take precedence.

## TLS
- **Public domain:** set `SNR_DOMAIN`; Caddy auto-provisions Let's Encrypt (ports 80/443 reachable).
- **Internal CA / provided cert:** edit `deploy/Caddyfile` → `tls /path/cert.pem /path/key.pem` and mount it.
- **Your own proxy:** terminate TLS there, proxy to `app:3001`, align `TRUST_PROXY`.

## Observability
- **Metrics:** Prometheus at `GET /metrics` on the **app** (HTTP, queue depth) and on
  each **worker** (`WORKER_METRICS_PORT`; job success/fail, durations, feeds). Import
  [deploy/grafana-dashboard.json](./deploy/grafana-dashboard.json). Protect with `METRICS_TOKEN`.
- **Health:** `GET /api/health` (liveness), `GET /api/ready` (DB read/write).
- **Logs:** structured JSON on stdout (secrets redacted) — ship to your SIEM.

## Backups & restore
- Scheduled snapshots use `pg_dump` (custom format), written to `BACKUP_DIR` and
  pruned to `BACKUP_RETENTION`. The image bundles `postgresql-client-16`.
- **Manual snapshot:** `docker compose exec app sh -c 'pg_dump -d "$DATABASE_URL" -Fc --no-owner -f /data/backups/manual.dump'`
- **Restore:**
  ```bash
  # stop the writers; keep postgres up
  docker compose stop app worker
  docker compose exec postgres sh -c 'pg_restore --clean --if-exists --no-owner -d "postgres://snr:$POSTGRES_PASSWORD@localhost/snr" /path/to.dump'
  # (or run `npm run db:restore -- <file.dump>` from a checkout pointed at DATABASE_URL)
  docker compose start app worker
  ```

## Upgrades
```bash
git pull                      # or pull a new image tag
docker compose build app worker
docker compose up -d
```
Postgres data persists; migrations apply automatically on startup. Take a `pg_dump`
backup first.

## Scaling
- **Throughput:** raise `ANALYSIS_WORKER_CONCURRENCY`, or run multiple `worker`
  containers (`docker compose up -d --scale worker=3`). Jobs are distributed via
  pg-boss; the API is unaffected.
- **Tune** `DB_POOL_MAX` alongside worker concurrency, and load-test with
  `npm run loadtest -- <n> --wait` (needs an API key).

## Hardening checklist
- [ ] `JWT_SECRET` set explicitly (64-byte hex); rotate periodically.
- [ ] `ALLOWED_ORIGINS` restricted to your real UI origin(s).
- [ ] Run behind TLS; never expose `app:3001` or `postgres` directly to clients.
- [ ] Secrets mounted as files (`*_FILE`) where possible; strong `POSTGRES_PASSWORD`.
- [ ] `/metrics` protected with `METRICS_TOKEN`; worker metrics port not internet-exposed.
- [ ] `SNR_WEBHOOK_SECRET` set so integration webhooks are verifiable.
- [ ] API keys scoped minimally; rotate/revoke from Admin → API Keys.
- [ ] `snr-pgdata` (and `snr-data` backups) in your DR plan; test a restore.
- [ ] Bootstrap admin password rotated after first login; per-analyst accounts created.
