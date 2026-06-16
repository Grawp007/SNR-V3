#!/usr/bin/env tsx
/**
 * Read-only diagnostic: list threat-actor attributions, links, and canonical
 * actor records. Ported from the V2 SQLite version to Postgres.
 *
 * Usage: npm run check:actors   (requires DATABASE_URL)
 */
import path from 'path';
import { fileURLToPath } from 'url';
import { config } from 'dotenv';
import { rawQuery, closeDb } from '../server/db/client.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
config({ path: path.resolve(__dirname, '../.env') });

async function main() {
  const attributions = await rawQuery(
    `SELECT ar.session_id,
            (ar.result_json::jsonb -> 'threat_actor' ->> 'name') AS actor_name
     FROM analysis_results ar
     WHERE (ar.result_json::jsonb -> 'threat_actor' ->> 'name') IS NOT NULL
     ORDER BY ar.created_at DESC`,
  );
  console.log('Sessions with threat actors:');
  for (const r of attributions.rows) {
    console.log(`  ${r.session_id} -> ${r.actor_name}`);
  }

  const links = await rawQuery('SELECT COUNT(*)::int AS c FROM session_threat_actors');
  console.log(`\nLinks: ${links.rows[0].c}`);

  const actors = await rawQuery('SELECT id, name FROM threat_actors ORDER BY name');
  console.log(`Actors: ${actors.rows.length}`);
  for (const a of actors.rows) {
    console.log(`  ${a.id} -> ${a.name}`);
  }

  await closeDb();
}

main().catch(async (err) => {
  console.error('check-actors failed:', err instanceof Error ? err.message : err);
  await closeDb().catch(() => {});
  process.exit(1);
});
