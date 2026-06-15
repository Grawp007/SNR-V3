#!/usr/bin/env tsx
/**
 * SNR Database Restore Script (Postgres)
 * Usage: npm run db:restore -- <backup-file.dump>
 * Restores the database from a pg_dump custom-format snapshot via pg_restore.
 * Requires DATABASE_URL and the `pg_restore` client binary on PATH.
 *
 * WARNING: this overwrites existing data (pg_restore --clean). Stop the server
 * first. Take a fresh backup beforehand if in doubt.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { config } from 'dotenv';
import { readSecret } from '../server/lib/secrets.js';

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
config({ path: path.resolve(__dirname, '../.env') });

const backupDir = process.env.BACKUP_DIR
  ? path.resolve(process.env.BACKUP_DIR)
  : path.resolve(__dirname, '../backups');
const databaseUrl = readSecret('DATABASE_URL');

if (!databaseUrl) {
  console.error('✗ DATABASE_URL is not set.');
  process.exit(1);
}

const restoreFile = process.argv[2];

if (!restoreFile) {
  console.error('Usage: npm run db:restore -- <backup-file.dump>');
  console.error('');
  if (fs.existsSync(backupDir)) {
    const backups = fs
      .readdirSync(backupDir)
      .filter((f) => f.startsWith('snr-') && f.endsWith('.dump'))
      .sort()
      .reverse();
    if (backups.length > 0) {
      console.error('Available backups:');
      for (const b of backups) {
        const stat = fs.statSync(path.join(backupDir, b));
        console.error(`  ${b}  (${(stat.size / 1024).toFixed(1)} KB)`);
      }
    } else {
      console.error('No backups found.');
    }
  }
  process.exit(1);
}

// Resolve backup path (try as-is, then in backups dir)
let sourcePath = path.resolve(restoreFile);
if (!fs.existsSync(sourcePath)) {
  sourcePath = path.join(backupDir, restoreFile);
}
if (!fs.existsSync(sourcePath)) {
  console.error(`✗ Backup file not found: ${restoreFile}`);
  process.exit(1);
}

try {
  await execFileAsync(
    'pg_restore',
    ['--clean', '--if-exists', '--no-owner', '-d', databaseUrl, sourcePath],
    { maxBuffer: 64 * 1024 * 1024 }
  );
  console.log(`✓ Database restored from ${path.basename(sourcePath)}`);
  console.log('  Restart the server to apply changes.');
} catch (err) {
  console.error('✗ Restore failed:', err instanceof Error ? err.message : err);
  process.exit(1);
}
