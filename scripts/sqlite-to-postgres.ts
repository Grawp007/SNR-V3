#!/usr/bin/env tsx
/**
 * One-time data migration: SQLite (SNR V2) → Postgres (SNR V3).
 *
 * Usage:
 *   npm run migrate:sqlite -- <path-to-snr.db>
 *   (or set SQLITE_PATH; defaults to ./snr.db)
 *
 * Reads every table from the V2 SQLite database and inserts the rows into the
 * V3 Postgres database referenced by DATABASE_URL. Idempotent: existing rows are
 * skipped (ON CONFLICT DO NOTHING), so re-running is safe. Run AFTER the target
 * schema exists — this script applies migrations first.
 *
 * Always take a copy of your V2 snr.db and run against a COPY first.
 */
import path from 'path';
import { fileURLToPath } from 'url';
import { config } from 'dotenv';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — Node built-in, types not always resolved
import { DatabaseSync } from 'node:sqlite';
import { runMigrations } from '../server/db/migrate.js';
import { rawQuery, closeDb } from '../server/db/client.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
config({ path: path.resolve(__dirname, '../.env') });

const sqlitePath = path.resolve(process.argv[2] || process.env.SQLITE_PATH || './snr.db');

// Tables in FK-dependency order, with target columns and conflict handling.
interface TableSpec {
  table: string;
  columns: string[];
  conflict: string; // e.g. "(id) DO NOTHING" or "" to skip ON CONFLICT
}

const TABLES: TableSpec[] = [
  { table: 'users', columns: ['id', 'email', 'password_hash', 'display_name', 'role', 'created_at', 'updated_at', 'last_login_at', 'disabled', 'failed_login_attempts', 'locked_until', 'password_changed_at'], conflict: '(id) DO NOTHING' },
  { table: 'teams', columns: ['id', 'name', 'description', 'created_at', 'updated_at'], conflict: '(id) DO NOTHING' },
  { table: 'team_members', columns: ['team_id', 'user_id', 'role', 'joined_at'], conflict: '(team_id, user_id) DO NOTHING' },
  { table: 'team_settings', columns: ['team_id', 'key', 'value', 'updated_at'], conflict: '(team_id, key) DO NOTHING' },
  { table: 'sessions', columns: ['id', 'name', 'incident_id', 'created_at', 'updated_at', 'severity', 'audience', 'version', 'input_hash', 'status', 'team_id', 'created_by', 'tags', 'deleted_at'], conflict: '(id) DO NOTHING' },
  { table: 'session_inputs', columns: ['id', 'session_id', 'input_type', 'content', 'filename', 'created_at'], conflict: '(id) DO NOTHING' },
  { table: 'analysis_results', columns: ['id', 'session_id', 'version', 'result_json', 'created_at', 'analyst_overrides'], conflict: '(id) DO NOTHING' },
  { table: 'analyst_notes', columns: ['id', 'session_id', 'content', 'created_at', 'updated_at'], conflict: '(id) DO NOTHING' },
  // audit_log.id is GENERATED — insert without id and let Postgres assign new ones.
  { table: 'audit_log', columns: ['timestamp', 'analyst_name', 'user_id', 'session_id', 'action', 'input_hash', 'outputs_generated', 'techniques_identified', 'details'], conflict: '' },
  { table: 'settings', columns: ['key', 'value', 'updated_at'], conflict: '(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at' },
  { table: 'revoked_tokens', columns: ['jti', 'revoked_at', 'expires_at'], conflict: '(jti) DO NOTHING' },
  { table: 'threat_actors', columns: ['id', 'name', 'aliases', 'motivation', 'attribution_confidence', 'intrusion_set', 'campaign_name', 'malware_families', 'description', 'team_id', 'created_by', 'created_at', 'updated_at'], conflict: '(id) DO NOTHING' },
  { table: 'session_threat_actors', columns: ['session_id', 'threat_actor_id', 'link_type', 'linked_at', 'linked_by'], conflict: '(session_id, threat_actor_id) DO NOTHING' },
  { table: 'threat_actor_merges', columns: ['id', 'source_actor_id', 'target_actor_id', 'source_actor_name', 'merged_by', 'merged_at'], conflict: '(id) DO NOTHING' },
];

async function main() {
  console.log(`SQLite source : ${sqlitePath}`);
  console.log(`Postgres target: ${process.env.DATABASE_URL ? '(from DATABASE_URL)' : '(NOT SET!)'}`);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const sqlite: any = new DatabaseSync(sqlitePath, { readOnly: true });

  console.log('\nApplying Postgres migrations…');
  await runMigrations();

  let grandTotal = 0;
  for (const spec of TABLES) {
    let rows: Record<string, unknown>[];
    try {
      rows = sqlite.prepare(`SELECT * FROM ${spec.table}`).all() as Record<string, unknown>[];
    } catch {
      console.log(`  - ${spec.table}: (table not present in source, skipped)`);
      continue;
    }
    if (rows.length === 0) {
      console.log(`  - ${spec.table}: 0 rows`);
      continue;
    }

    const placeholders = spec.columns.map((_, i) => `$${i + 1}`).join(', ');
    const colList = spec.columns.join(', ');
    const onConflict = spec.conflict ? ` ON CONFLICT ${spec.conflict}` : '';
    const sql = `INSERT INTO ${spec.table} (${colList}) VALUES (${placeholders})${onConflict}`;

    let inserted = 0;
    for (const row of rows) {
      const values = spec.columns.map((c) => (row[c] === undefined ? null : row[c]));
      const res = await rawQuery(sql, values);
      inserted += res.rowCount ?? 0;
    }
    grandTotal += inserted;
    console.log(`  - ${spec.table}: ${rows.length} read, ${inserted} inserted`);
  }

  sqlite.close();
  await closeDb();
  console.log(`\n✓ Migration complete. ${grandTotal} rows inserted.`);
}

main().catch(async (err) => {
  console.error('\n✗ Migration failed:', err instanceof Error ? err.message : err);
  await closeDb().catch(() => {});
  process.exit(1);
});
