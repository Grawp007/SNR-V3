#!/usr/bin/env tsx
/**
 * SNR Database Backup Script (Postgres)
 * Usage: npm run db:backup
 * Creates a timestamped pg_dump snapshot in the backups/ directory.
 * Requires DATABASE_URL and the `pg_dump` client binary on PATH.
 */

import path from 'path';
import { fileURLToPath } from 'url';
import { config } from 'dotenv';
import { runBackup } from '../server/lib/backup.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
config({ path: path.resolve(__dirname, '../.env') });

const dest = await runBackup();
if (dest) {
  console.log(`✓ Backup created: ${dest}`);
  process.exit(0);
} else {
  console.error('✗ Backup failed — check DATABASE_URL and that pg_dump is installed.');
  process.exit(1);
}
