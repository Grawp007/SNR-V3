# syntax=docker/dockerfile:1
# ── Builder: install all deps and build the frontend ──────────────────────────
FROM node:22-bookworm-slim AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --legacy-peer-deps
COPY . .
RUN npm run build

# ── Runtime: production deps only (incl. tsx) + built assets ───────────────────
FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production \
    PORT=3001 \
    HOST=0.0.0.0 \
    BACKUP_DIR=/data/backups
WORKDIR /app

# postgresql-client-16 (pg_dump / pg_restore) for scheduled backups & restore.
# Installed from the PGDG repo so the client major matches the Postgres 16 server
# (Debian bookworm ships only client 15, which refuses to dump a v16 server).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
         -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
         > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client-16 \
    && apt-get purge -y curl gnupg && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Production dependencies only (tsx is a runtime dep so the TS server can run)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --legacy-peer-deps && npm cache clean --force

# Built frontend + server source (includes server/db/migrations/*.sql)
COPY --from=builder /app/dist ./dist
COPY server ./server

# Data dir (DB + backups) owned by the unprivileged node user. /app stays
# root-owned but world-readable (the runtime only writes to /data), which avoids
# an expensive recursive chown of node_modules.
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 3001

# Health check uses Node's global fetch (no curl needed in the slim image)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3001)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["npm", "start"]
