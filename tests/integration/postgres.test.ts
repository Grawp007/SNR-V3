/**
 * Integration tests against a real Postgres. Runs only when TEST_DATABASE_URL is
 * set (CI provides a postgres service); otherwise skipped so `npm test` stays
 * green locally without a database. Exercises migrations and the Postgres-specific
 * SQL the V2→V3 port introduced (jsonb extraction, date_trunc bucketing, ON
 * CONFLICT upserts).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';

const TEST_DB = process.env.TEST_DATABASE_URL;
const suite = TEST_DB ? describe : describe.skip;

suite('postgres integration', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let client: any;

  beforeAll(async () => {
    process.env.DATABASE_URL = TEST_DB;
    client = await import('../../server/db/client.js');
    const { runMigrations } = await import('../../server/db/migrate.js');
    await runMigrations();
  });

  afterAll(async () => {
    if (client) await client.closeDb();
  });

  it('applies all migrations (schema_migrations populated)', async () => {
    const r = await client.rawQuery('SELECT count(*)::int AS c FROM schema_migrations');
    expect(r.rows[0].c).toBeGreaterThanOrEqual(5);
  });

  it('round-trips a session + result and extracts IOCs via jsonb (snr_json_array)', async () => {
    const now = Date.now();
    await client.rawQuery(
      "INSERT INTO teams (id,name,created_at,updated_at) VALUES ('it_t1','IT',$1,$1) ON CONFLICT (id) DO NOTHING",
      [now],
    );
    await client.rawQuery(
      "INSERT INTO sessions (id,name,created_at,updated_at,status,team_id) VALUES ('it_s1','IT session',$1,$1,'complete','it_t1') ON CONFLICT (id) DO NOTHING",
      [now],
    );
    await client.rawQuery(
      'INSERT INTO analysis_results (id,session_id,version,result_json,created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO NOTHING',
      [
        'it_r1',
        'it_s1',
        1,
        JSON.stringify({ iocs: [{ type: 'ipv4', value: '1.2.3.4' }], attack_chain: [{ technique_id: 'T1059' }] }),
        now,
      ],
    );

    const iocs = await client.rawQuery(
      `SELECT ioc.value ->> 'type' AS t
       FROM analysis_results ar JOIN sessions s ON ar.session_id = s.id,
       snr_json_array(ar.result_json, 'iocs') AS ioc(value)
       WHERE s.team_id = 'it_t1'`,
    );
    expect(iocs.rows.map((r: { t: string }) => r.t)).toContain('ipv4');
  });

  it('buckets sessions by day via to_timestamp/to_char (epoch-ms bigint)', async () => {
    const buckets = await client.rawQuery(
      "SELECT to_char(to_timestamp(created_at / 1000), 'YYYY-MM-DD') AS d, COUNT(*) AS c FROM sessions WHERE team_id = 'it_t1' GROUP BY d",
    );
    expect(buckets.rows.length).toBeGreaterThan(0);
    expect(typeof buckets.rows[0].c).toBe('number'); // int8 parsed to Number
  });

  it('ON CONFLICT upsert updates settings in place', async () => {
    const now = Date.now();
    const sql =
      'INSERT INTO settings (key,value,updated_at) VALUES ($1,$2,$3) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at';
    await client.rawQuery(sql, ['it_key', 'v1', now]);
    await client.rawQuery(sql, ['it_key', 'v2', now + 1]);
    const r = await client.rawQuery("SELECT value FROM settings WHERE key = 'it_key'");
    expect(r.rows[0].value).toBe('v2');
  });
});
