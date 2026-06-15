import { Router } from 'express';
import multer from 'multer';
import { getDb, loadMergedSettings } from '../db/database.js';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';
import logger from '../lib/logger.js';

const router = Router();

const logoUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (/^image\/(png|jpeg|svg\+xml|gif|webp)$/.test(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only PNG, JPG, SVG, GIF, and WebP images are allowed'));
    }
  },
});

/** Keys that must never be sent to the frontend */
const SENSITIVE_KEY_PATTERNS = [
  /api_key/i, /api_secret/i, /password/i, /secret/i, /^_/, /token/i,
];

function filterSensitiveSettings(settings: Record<string, string>): Record<string, string> {
  const filtered: Record<string, string> = {};
  for (const [key, value] of Object.entries(settings)) {
    if (SENSITIVE_KEY_PATTERNS.some(p => p.test(key))) {
      // Indicate presence without exposing value
      filtered[key] = value ? '••••••••' : '';
    } else {
      filtered[key] = value;
    }
  }
  return filtered;
}

// GET /api/settings — return all settings as flat object (team-merged if in team context)
// Sensitive keys (api_key, secret, password, etc.) are masked before sending to frontend
router.get('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const settings = await loadMergedSettings(authReq.teamId);
  res.json({ settings: filterSensitiveSettings(settings) });
});

// Upsert SQL (Postgres ON CONFLICT replaces SQLite INSERT OR REPLACE)
const UPSERT_TEAM_SETTING =
  'INSERT INTO team_settings (team_id, key, value, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT (team_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at';
const UPSERT_GLOBAL_SETTING =
  'INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at';

// PATCH /api/settings — update one or many settings
// Team context → writes to team_settings; admin without team → writes to global settings
router.patch('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const updates = req.body as Record<string, string>;
  const now = Date.now();

  // Skip masked values — never persist the '••••••••' placeholder back to the DB
  const MASKED_VALUE = '••••••••';

  if (authReq.teamId) {
    // Team-scoped: write overrides into team_settings
    const stmt = db.prepare(UPSERT_TEAM_SETTING);
    for (const [key, value] of Object.entries(updates)) {
      if (typeof value === 'string' && value !== MASKED_VALUE) await stmt.run(authReq.teamId, key, value, now);
    }
  } else {
    // Admin with no team context: write to global settings
    const stmt = db.prepare(UPSERT_GLOBAL_SETTING);
    for (const [key, value] of Object.entries(updates)) {
      if (typeof value === 'string' && value !== MASKED_VALUE) await stmt.run(key, value, now);
    }
  }

  res.json({ ok: true });
});

// POST /api/settings/logo — upload logo image (max 500KB)
router.post('/logo', logoUpload.single('logo'), async (req: Request, res: Response) => {
  if (!req.file) { res.status(400).json({ error: 'No file uploaded' }); return; }
  const authReq = req as AuthenticatedRequest;
  const b64 = req.file.buffer.toString('base64');
  const dataUri = `data:${req.file.mimetype};base64,${b64}`;
  const db = getDb();

  if (authReq.teamId) {
    await db.prepare(UPSERT_TEAM_SETTING).run(authReq.teamId, 'email_logo_data', dataUri, Date.now());
  } else {
    await db.prepare(UPSERT_GLOBAL_SETTING).run('email_logo_data', dataUri, Date.now());
  }

  res.json({ ok: true, dataUri });
});

// DELETE /api/settings/logo — remove logo
router.delete('/logo', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();

  if (authReq.teamId) {
    await db.prepare(UPSERT_TEAM_SETTING).run(authReq.teamId, 'email_logo_data', '', Date.now());
  } else {
    await db.prepare(UPSERT_GLOBAL_SETTING).run('email_logo_data', '', Date.now());
  }

  res.json({ ok: true });
});

export default router;
