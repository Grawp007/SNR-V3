/**
 * Scheduled database backups for on-prem operation.
 *
 * V3 runs on Postgres, so snapshots are produced with `pg_dump` in the custom
 * (compressed) format. Snapshots are written to a backups directory and pruned to
 * the most recent N. Restore is a manual op: `pg_restore --clean --if-exists -d
 * "$DATABASE_URL" <snapshot>` (see DEPLOYMENT.md).
 *
 * Requires the `pg_dump` client binary on PATH (the container installs
 * postgresql-client; for local use install the Postgres client tools). If absent,
 * backups are skipped with a warning rather than crashing the server.
 */
import fs from 'fs';
import path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { readSecret } from './secrets.js';
import logger from './logger.js';

const execFileAsync = promisify(execFile);

function backupDir(): string {
  if (process.env.BACKUP_DIR) return path.resolve(process.env.BACKUP_DIR);
  return path.resolve('./backups');
}

/** Take a single consistent snapshot via pg_dump. Returns the path, or null on failure. */
export async function runBackup(): Promise<string | null> {
  const databaseUrl = readSecret('DATABASE_URL');
  if (!databaseUrl) {
    logger.warn('Backup skipped — DATABASE_URL is not set');
    return null;
  }
  try {
    const dir = backupDir();
    fs.mkdirSync(dir, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
    const dest = path.join(dir, `snr-${ts}.dump`);
    // -Fc = custom compressed format (restore with pg_restore). --no-owner keeps
    // restores portable across roles.
    await execFileAsync('pg_dump', ['-d', databaseUrl, '-Fc', '--no-owner', '-f', dest], {
      maxBuffer: 64 * 1024 * 1024,
    });
    pruneOldBackups(dir);
    const sizeKb = (fs.statSync(dest).size / 1024).toFixed(1);
    logger.info({ dest, sizeKb }, 'Database backup created');
    return dest;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT') {
      logger.warn('Backup skipped — pg_dump not found on PATH (install postgresql-client)');
    } else {
      logger.error({ err }, 'Database backup failed');
    }
    return null;
  }
}

/** Keep only the newest BACKUP_RETENTION (default 7) snapshots. */
function pruneOldBackups(dir: string): void {
  const retention = parseInt(process.env.BACKUP_RETENTION ?? '7', 10) || 7;
  const snaps = fs
    .readdirSync(dir)
    .filter((f) => /^snr-.*\.dump$/.test(f))
    .sort()
    .reverse();
  for (const stale of snaps.slice(retention)) {
    try {
      fs.unlinkSync(path.join(dir, stale));
    } catch {
      /* best effort */
    }
  }
}

/**
 * Start the periodic backup scheduler. Returns a stop() function (for graceful
 * shutdown). BACKUP_INTERVAL_HOURS=0 disables scheduling entirely.
 */
export function startBackupScheduler(): () => void {
  const hours = parseInt(process.env.BACKUP_INTERVAL_HOURS ?? '24', 10);
  if (!hours || hours <= 0) {
    logger.info('Scheduled backups disabled (BACKUP_INTERVAL_HOURS=0)');
    return () => {};
  }
  logger.info({ intervalHours: hours, dir: backupDir() }, 'Scheduled database backups enabled');
  const timer = setInterval(() => {
    void runBackup();
  }, hours * 60 * 60 * 1000);
  timer.unref?.();
  return () => clearInterval(timer);
}
