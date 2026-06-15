/**
 * Minimal forward-only SQL migration runner.
 *
 * Applies every `*.sql` file in ./migrations in lexical order, once each, inside a
 * transaction, tracking applied files in `schema_migrations`. New migrations are
 * added as higher-numbered files (002_*.sql, 003_*.sql, ...).
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { rawQuery, withTransaction } from './client.js';
import logger from '../lib/logger.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = path.join(__dirname, 'migrations');

export async function runMigrations(): Promise<void> {
  await rawQuery(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      filename TEXT PRIMARY KEY,
      applied_at BIGINT NOT NULL
    )
  `);

  const files = fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  const applied = new Set(
    (await rawQuery('SELECT filename FROM schema_migrations')).rows.map(
      (r: { filename: string }) => r.filename
    )
  );

  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), 'utf8');
    logger.info(`Applying migration ${file}…`);
    try {
      await withTransaction(async (c) => {
        await c.query(sql);
        await c.query('INSERT INTO schema_migrations (filename, applied_at) VALUES ($1, $2)', [
          file,
          Date.now(),
        ]);
      });
    } catch (err) {
      logger.fatal({ err, file }, 'Migration failed');
      throw err;
    }
  }
}
