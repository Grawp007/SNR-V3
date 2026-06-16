import { Router } from 'express';
import crypto from 'crypto';
import { getDb, loadMergedSettings, invalidateSettingsCache } from '../db/database.js';
import { requireRole, requireTeamMember, type AuthenticatedRequest } from '../middleware/auth.js';
import type { Request, Response } from 'express';
import logger from '../lib/logger.js';

const router = Router();

// GET /api/teams — admin sees all, others see their teams
router.get('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();

  let teams;
  if (authReq.user.role === 'admin') {
    teams = await db.prepare(`
      SELECT t.*, (SELECT COUNT(*) FROM team_members WHERE team_id = t.id) as member_count
      FROM teams t ORDER BY t.name
    `).all();
  } else {
    teams = await db.prepare(`
      SELECT t.*, (SELECT COUNT(*) FROM team_members WHERE team_id = t.id) as member_count
      FROM teams t JOIN team_members tm ON t.id = tm.team_id
      WHERE tm.user_id = ? ORDER BY t.name
    `).all(authReq.user.id);
  }

  res.json((teams as Array<{ id: string; name: string; description: string; created_at: number; updated_at: number; member_count: number }>).map(t => ({
    id: t.id,
    name: t.name,
    description: t.description,
    createdAt: t.created_at,
    updatedAt: t.updated_at,
    memberCount: t.member_count,
  })));
});

// POST /api/teams — admin only
router.post('/', requireRole('admin'), async (req: Request, res: Response) => {
  const { name, description } = req.body;
  if (!name?.trim()) {
    res.status(400).json({ error: 'Team name is required' });
    return;
  }

  const db = getDb();
  const id = crypto.randomUUID();
  const now = Date.now();

  await db.prepare('INSERT INTO teams (id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, name.trim(), description?.trim() || '', now, now);

  res.status(201).json({ id, name: name.trim(), description: description?.trim() || '', createdAt: now, memberCount: 0 });
});

// GET /api/teams/:id — team detail + members (members or admin)
router.get('/:id', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const teamId = req.params.id;

  // Check access
  if (authReq.user.role !== 'admin' && !authReq.user.teamIds.includes(teamId)) {
    res.status(403).json({ error: 'Not a member of this team' });
    return;
  }

  const team = (await db.prepare('SELECT * FROM teams WHERE id = ?').get(teamId)) as {
    id: string; name: string; description: string; created_at: number; updated_at: number;
  } | undefined;
  if (!team) {
    res.status(404).json({ error: 'Team not found' });
    return;
  }

  const members = (await db.prepare(`
    SELECT u.id as user_id, u.email, u.display_name, u.role as user_role, tm.role as team_role, tm.joined_at
    FROM team_members tm JOIN users u ON tm.user_id = u.id
    WHERE tm.team_id = ? ORDER BY tm.joined_at
  `).all(teamId)) as Array<{
    user_id: string; email: string; display_name: string; user_role: string; team_role: string; joined_at: number;
  }>;

  res.json({
    id: team.id,
    name: team.name,
    description: team.description,
    createdAt: team.created_at,
    updatedAt: team.updated_at,
    members: members.map(m => ({
      userId: m.user_id,
      email: m.email,
      displayName: m.display_name,
      userRole: m.user_role,
      teamRole: m.team_role,
      joinedAt: m.joined_at,
    })),
  });
});

// PATCH /api/teams/:id — update team (admin or team lead)
router.patch('/:id', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const teamId = req.params.id;

  // Check admin or team lead
  if (authReq.user.role !== 'admin') {
    const membership = (await db.prepare('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?').get(teamId, authReq.user.id)) as { role: string } | undefined;
    if (!membership || membership.role !== 'lead') {
      res.status(403).json({ error: 'Requires admin or team lead role' });
      return;
    }
  }

  const now = Date.now();
  let updated = false;

  if (req.body.name !== undefined) {
    await db.prepare('UPDATE teams SET name = ?, updated_at = ? WHERE id = ?')
      .run(req.body.name.trim(), now, teamId);
    updated = true;
  }
  if (req.body.description !== undefined) {
    await db.prepare('UPDATE teams SET description = ?, updated_at = ? WHERE id = ?')
      .run(req.body.description.trim(), now, teamId);
    updated = true;
  }

  if (!updated) {
    res.status(400).json({ error: 'No valid fields to update' });
    return;
  }

  res.json({ ok: true });
});

// DELETE /api/teams/:id — admin only, must have zero sessions
router.delete('/:id', requireRole('admin'), async (req: Request, res: Response) => {
  const db = getDb();
  const teamId = req.params.id;

  const sessionCount = ((await db.prepare('SELECT COUNT(*) as c FROM sessions WHERE team_id = ?').get(teamId)) as { c: number }).c;
  if (sessionCount > 0) {
    res.status(409).json({ error: `Cannot delete team with ${sessionCount} session(s). Reassign or delete sessions first.` });
    return;
  }

  await db.prepare('DELETE FROM teams WHERE id = ?').run(teamId);
  res.json({ ok: true });
});

// ── Member management ────────────────────────────────────────────────────

// POST /api/teams/:id/members — add member (admin or team lead)
router.post('/:id/members', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const teamId = req.params.id;

  // Check admin or team lead
  if (authReq.user.role !== 'admin') {
    const membership = (await db.prepare('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?').get(teamId, authReq.user.id)) as { role: string } | undefined;
    if (!membership || membership.role !== 'lead') {
      res.status(403).json({ error: 'Requires admin or team lead role' });
      return;
    }
  }

  const { userId, role } = req.body;
  if (!userId) {
    res.status(400).json({ error: 'userId is required' });
    return;
  }

  const validRoles = ['lead', 'member'];
  const teamRole = role || 'member';
  if (!validRoles.includes(teamRole)) {
    res.status(400).json({ error: `Invalid role. Must be one of: ${validRoles.join(', ')}` });
    return;
  }

  // Verify user exists
  const user = await db.prepare('SELECT id FROM users WHERE id = ?').get(userId);
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  // Check if already a member
  const existing = await db.prepare('SELECT user_id FROM team_members WHERE team_id = ? AND user_id = ?').get(teamId, userId);
  if (existing) {
    res.status(409).json({ error: 'User is already a member of this team' });
    return;
  }

  await db.prepare('INSERT INTO team_members (team_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)').run(teamId, userId, teamRole, Date.now());
  res.status(201).json({ ok: true });
});

// PATCH /api/teams/:id/members/:userId — change team role
router.patch('/:id/members/:userId', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const { id: teamId, userId } = req.params;

  if (authReq.user.role !== 'admin') {
    const membership = (await db.prepare('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?').get(teamId, authReq.user.id)) as { role: string } | undefined;
    if (!membership || membership.role !== 'lead') {
      res.status(403).json({ error: 'Requires admin or team lead role' });
      return;
    }
  }

  const { role } = req.body;
  if (!role || !['lead', 'member'].includes(role)) {
    res.status(400).json({ error: 'Role must be "lead" or "member"' });
    return;
  }

  const result = await db.prepare('UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?').run(role, teamId, userId);
  if (result.changes === 0) {
    res.status(404).json({ error: 'Membership not found' });
    return;
  }
  res.json({ ok: true });
});

// DELETE /api/teams/:id/members/:userId — remove member
router.delete('/:id/members/:userId', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const { id: teamId, userId } = req.params;

  if (authReq.user.role !== 'admin') {
    const membership = (await db.prepare('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?').get(teamId, authReq.user.id)) as { role: string } | undefined;
    if (!membership || membership.role !== 'lead') {
      res.status(403).json({ error: 'Requires admin or team lead role' });
      return;
    }
  }

  await db.prepare('DELETE FROM team_members WHERE team_id = ? AND user_id = ?').run(teamId, userId);
  res.json({ ok: true });
});

// ── Team settings ────────────────────────────────────────────────────────

// GET /api/teams/:id/settings — merged settings (global + team overrides)
router.get('/:id/settings', requireTeamMember, async (req: Request, res: Response) => {
  const teamId = req.params.id;
  const merged = await loadMergedSettings(teamId);
  res.json(merged);
});

// PATCH /api/teams/:id/settings — update team-level setting overrides
router.patch('/:id/settings', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const teamId = req.params.id;

  // Check admin or team lead
  if (authReq.user.role !== 'admin') {
    const membership = (await db.prepare('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?').get(teamId, authReq.user.id)) as { role: string } | undefined;
    if (!membership || membership.role !== 'lead') {
      res.status(403).json({ error: 'Requires admin or team lead role' });
      return;
    }
  }

  const updates = req.body as Record<string, string>;
  const now = Date.now();

  for (const [key, value] of Object.entries(updates)) {
    if (typeof value !== 'string') continue;
    await db.prepare('INSERT INTO team_settings (team_id, key, value, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT (team_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at').run(teamId, key, value, now);
  }

  invalidateSettingsCache();
  res.json({ ok: true });
});

export default router;
