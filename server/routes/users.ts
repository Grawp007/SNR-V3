import { Router } from 'express';
import crypto from 'crypto';
import { getDb, appendAuditLog } from '../db/database.js';
import { hashPassword, validatePasswordStrength } from '../lib/auth-utils.js';
import { requireRole, type AuthenticatedRequest } from '../middleware/auth.js';
import logger from '../lib/logger.js';

const router = Router();

// All routes require admin role (applied at mount level in index.ts,
// but also guarded here for safety)
router.use(requireRole('admin'));

// GET /api/users — list all users
router.get('/', async (_req, res) => {
  const db = getDb();
  const users = (await db.prepare(`
    SELECT id, email, display_name, role, created_at, updated_at, last_login_at, disabled
    FROM users ORDER BY created_at DESC
  `).all()) as Array<{
    id: string; email: string; display_name: string; role: string;
    created_at: number; updated_at: number; last_login_at: number | null; disabled: number;
  }>;

  // Attach team memberships
  const result = [];
  for (const u of users) {
    const teams = (await db.prepare(`
      SELECT t.id, t.name, tm.role as team_role
      FROM teams t JOIN team_members tm ON t.id = tm.team_id
      WHERE tm.user_id = ?
    `).all(u.id)) as Array<{ id: string; name: string; team_role: string }>;
    result.push({
      id: u.id,
      email: u.email,
      displayName: u.display_name,
      role: u.role,
      createdAt: u.created_at,
      updatedAt: u.updated_at,
      lastLoginAt: u.last_login_at,
      disabled: !!u.disabled,
      teams: teams.map(t => ({ id: t.id, name: t.name, role: t.team_role })),
    });
  }

  res.json(result);
});

// POST /api/users — create user
router.post('/', async (req, res) => {
  try {
    const { email, password, displayName, role } = req.body;
    if (!email?.trim() || !password || !displayName?.trim()) {
      res.status(400).json({ error: 'email, password, and displayName are required' });
      return;
    }
    const pwStrength = validatePasswordStrength(password);
    if (!pwStrength.valid) {
      res.status(400).json({ error: pwStrength.errors.join('. ') });
      return;
    }
    const validRoles = ['admin', 'analyst', 'viewer'];
    if (role && !validRoles.includes(role)) {
      res.status(400).json({ error: `Invalid role. Must be one of: ${validRoles.join(', ')}` });
      return;
    }

    const db = getDb();
    const existing = await db.prepare('SELECT id FROM users WHERE LOWER(email) = LOWER(?)').get(email.trim().toLowerCase());
    if (existing) {
      res.status(409).json({ error: 'A user with this email already exists' });
      return;
    }

    const id = crypto.randomUUID();
    const now = Date.now();
    const passwordHash = await hashPassword(password);

    await db.prepare(`
      INSERT INTO users (id, email, password_hash, display_name, role, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, email.trim().toLowerCase(), passwordHash, displayName.trim(), role || 'analyst', now, now);

    res.status(201).json({
      id,
      email: email.trim().toLowerCase(),
      displayName: displayName.trim(),
      role: role || 'analyst',
      createdAt: now,
      disabled: false,
    });
  } catch (err) {
    logger.error('Create user error:', err instanceof Error ? err.message : 'Unknown');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/users/:id — get user detail
router.get('/:id', async (req, res) => {
  const db = getDb();
  const user = (await db.prepare(`
    SELECT id, email, display_name, role, created_at, updated_at, last_login_at, disabled
    FROM users WHERE id = ?
  `).get(req.params.id)) as {
    id: string; email: string; display_name: string; role: string;
    created_at: number; updated_at: number; last_login_at: number | null; disabled: number;
  } | undefined;

  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  const teams = (await db.prepare(`
    SELECT t.id, t.name, tm.role as team_role
    FROM teams t JOIN team_members tm ON t.id = tm.team_id
    WHERE tm.user_id = ?
  `).all(user.id)) as Array<{ id: string; name: string; team_role: string }>;

  res.json({
    id: user.id,
    email: user.email,
    displayName: user.display_name,
    role: user.role,
    createdAt: user.created_at,
    updatedAt: user.updated_at,
    lastLoginAt: user.last_login_at,
    disabled: !!user.disabled,
    teams: teams.map(t => ({ id: t.id, name: t.name, role: t.team_role })),
  });
});

// PATCH /api/users/:id — update user (role, displayName, disabled)
router.patch('/:id', async (req, res) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const user = (await db.prepare('SELECT id, email FROM users WHERE id = ?').get(req.params.id)) as { id: string; email: string } | undefined;
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  const now = Date.now();

  if (req.body.displayName !== undefined) {
    await db.prepare('UPDATE users SET display_name = ?, updated_at = ? WHERE id = ?')
      .run(req.body.displayName.trim(), now, req.params.id);
  }
  if (req.body.role !== undefined) {
    const validRoles = ['admin', 'analyst', 'viewer'];
    if (!validRoles.includes(req.body.role)) {
      res.status(400).json({ error: `Invalid role. Must be one of: ${validRoles.join(', ')}` });
      return;
    }
    await db.prepare('UPDATE users SET role = ?, updated_at = ? WHERE id = ?')
      .run(req.body.role, now, req.params.id);
    appendAuditLog({ analyst_name: authReq.user.displayName, user_id: authReq.user.id, action: 'user_role_changed', details: `Changed ${user.email} role to ${req.body.role}` });
  }
  if (req.body.disabled !== undefined) {
    await db.prepare('UPDATE users SET disabled = ?, updated_at = ? WHERE id = ?')
      .run(req.body.disabled ? 1 : 0, now, req.params.id);
    appendAuditLog({ analyst_name: authReq.user.displayName, user_id: authReq.user.id, action: req.body.disabled ? 'user_disabled' : 'user_enabled', details: `User: ${user.email}` });
  }

  res.json({ ok: true });
});

// PATCH /api/users/:id/password — admin reset password
router.patch('/:id/password', async (req, res) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const { newPassword } = req.body;
    if (!newPassword) {
      res.status(400).json({ error: 'New password is required' });
      return;
    }

    // Enforce password complexity
    const strength = validatePasswordStrength(newPassword);
    if (!strength.valid) {
      res.status(400).json({ error: strength.errors.join('. ') });
      return;
    }

    const db = getDb();
    const user = (await db.prepare('SELECT id, email FROM users WHERE id = ?').get(req.params.id)) as { id: string; email: string } | undefined;
    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    const hash = await hashPassword(newPassword);
    const now = Date.now();
    await db.prepare('UPDATE users SET password_hash = ?, updated_at = ?, password_changed_at = ? WHERE id = ?').run(hash, now, now, req.params.id);

    appendAuditLog({
      analyst_name: authReq.user.displayName,
      user_id: authReq.user.id,
      action: 'admin_password_reset',
      details: `Password reset for ${user.email} by admin ${authReq.user.email}`,
    });

    res.json({ ok: true });
  } catch (err) {
    logger.error('Admin password reset error:', err instanceof Error ? err.message : 'Unknown');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/users/:id — soft-disable (set disabled=1)
router.delete('/:id', async (req, res) => {
  const db = getDb();
  const user = await db.prepare('SELECT id FROM users WHERE id = ?').get(req.params.id);
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  await db.prepare('UPDATE users SET disabled = 1, updated_at = ? WHERE id = ?').run(Date.now(), req.params.id);
  res.json({ ok: true });
});

export default router;
