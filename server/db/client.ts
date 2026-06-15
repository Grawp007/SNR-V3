/**
 * Postgres connection pool + a thin async query layer.
 *
 * SNR V3 runs on Postgres (V2 used the synchronous node:sqlite API). To keep the
 * large surface of existing call sites readable and reviewable, this module
 * exposes a `getDb()` wrapper whose shape mirrors node:sqlite —
 * `db.prepare(sql).get/all/run(...params)` and `db.exec(sql)` — but every method
 * is async and runs against Postgres.
 *
 * Two conveniences make the port faithful:
 *  - Positional `?` placeholders are auto-translated to Postgres `$1..$n`, so
 *    ported SQL keeps the same placeholder style it had under SQLite.
 *  - `.run()` returns `{ changes }` (from `rowCount`), matching the few sites
 *    that read `result.changes`.
 *
 * NOTE: because `?` is rewritten to `$n`, do not use the Postgres jsonb key-exists
 * operator `?` in SQL passed through this layer — use `->`, `->>`, `jsonb_typeof`,
 * or `jsonb_array_elements` (which is what the ported analytics/search queries do).
 */
import pg from 'pg';
import { readSecret } from '../lib/secrets.js';
import logger from '../lib/logger.js';

// Postgres returns int8 (BIGINT) and COUNT(*) as strings by default to avoid
// precision loss. SNR stores epoch-millisecond timestamps and counts in BIGINT
// columns and treats them as JS numbers everywhere (Date.now() math, JSON). Parse
// int8 back to Number so behavior matches node:sqlite, which returned numbers.
// Epoch-ms and counts are well within Number.MAX_SAFE_INTEGER.
pg.types.setTypeParser(20, (val: string | null) => (val === null ? null : parseInt(val, 10)));

let pool: pg.Pool | undefined;

/** Translate node:sqlite-style `?` placeholders to Postgres `$1..$n`. */
function toPgPlaceholders(sql: string): string {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

export interface PreparedStatement {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  get(...params: any[]): Promise<any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  all(...params: any[]): Promise<any[]>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  run(...params: any[]): Promise<{ changes: number }>;
}

export interface DbClient {
  prepare(sql: string): PreparedStatement;
  exec(sql: string): Promise<void>;
}

function getPool(): pg.Pool {
  if (!pool) {
    const connectionString = readSecret('DATABASE_URL');
    if (!connectionString) {
      throw new Error(
        'DATABASE_URL (or DATABASE_URL_FILE) must be set — SNR V3 requires Postgres.'
      );
    }
    pool = new pg.Pool({
      connectionString,
      max: parseInt(process.env.DB_POOL_MAX ?? '10', 10),
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: parseInt(process.env.DB_CONNECT_TIMEOUT_MS ?? '10000', 10),
    });
    pool.on('error', (err) => {
      // Idle client errors (e.g. Postgres restart) — log, don't crash.
      logger.error({ err }, 'Postgres idle client error');
    });
  }
  return pool;
}

const client: DbClient = {
  prepare(sql: string): PreparedStatement {
    const text = toPgPlaceholders(sql);
    return {
      async get(...params) {
        const r = await getPool().query(text, params);
        return r.rows[0];
      },
      async all(...params) {
        const r = await getPool().query(text, params);
        return r.rows;
      },
      async run(...params) {
        const r = await getPool().query(text, params);
        return { changes: r.rowCount ?? 0 };
      },
    };
  },
  async exec(sql: string): Promise<void> {
    // Multi-statement DDL is fine over a single query call in node-postgres.
    await getPool().query(sql);
  },
};

/** Return the async DB client. The pool connects lazily on first query. */
export function getDb(): DbClient {
  return client;
}

/** Raw pooled query — used by the migration runner and data-migration script. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function rawQuery(text: string, params: any[] = []): Promise<pg.QueryResult> {
  return getPool().query(text, params);
}

/**
 * Run `fn` against a single checked-out client wrapped in a transaction.
 * Commits on success, rolls back on throw. Use for multi-statement units that
 * must run on the same connection (migrations, the merge/purge operations).
 */
export async function withTransaction<T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  const c = await getPool().connect();
  try {
    await c.query('BEGIN');
    const result = await fn(c);
    await c.query('COMMIT');
    return result;
  } catch (err) {
    await c.query('ROLLBACK');
    throw err;
  } finally {
    c.release();
  }
}

/** Verify connectivity (used by readiness checks / startup). */
export async function pingDb(): Promise<void> {
  await getPool().query('SELECT 1');
}

/** Close the pool on graceful shutdown. */
export async function closeDb(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = undefined;
  }
}
