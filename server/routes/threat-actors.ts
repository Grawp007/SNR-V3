/**
 * Threat Actor grouping API — list, detail, link/unlink, merge, delete.
 * All endpoints are team-scoped via requireTeamMember middleware.
 */
import { Router } from 'express';
import crypto from 'crypto';
import { getDb, appendAuditLog } from '../db/database.js';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';
import type { AnalysisResult } from '../lib/claude.js';
import logger from '../lib/logger.js';

const router = Router();

// ── POST /api/threat-actors — manually create a new threat actor ────────────

router.post('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const teamId = authReq.teamId;
  const db = getDb();

  const { name, aliases, motivation, attribution_confidence, intrusion_set, campaign_name, malware_families, description } = req.body as {
    name?: string;
    aliases?: string[];
    motivation?: string | null;
    attribution_confidence?: string | null;
    intrusion_set?: string | null;
    campaign_name?: string | null;
    malware_families?: string[];
    description?: string;
  };

  if (!name?.trim()) {
    res.status(400).json({ error: 'name is required' });
    return;
  }

  // Check for duplicate name (case-insensitive) within team
  const existing = (await db.prepare(
    'SELECT id, name FROM threat_actors WHERE LOWER(name) = ? AND team_id = ?'
  ).get(name.trim().toLowerCase(), teamId)) as { id: string; name: string } | undefined;

  if (existing) {
    res.status(409).json({ error: `A threat actor named "${existing.name}" already exists` });
    return;
  }

  // Validate attribution_confidence if provided
  if (attribution_confidence && !['High', 'Medium', 'Low'].includes(attribution_confidence)) {
    res.status(400).json({ error: 'attribution_confidence must be High, Medium, or Low' });
    return;
  }

  const id = crypto.randomUUID();
  const now = Date.now();

  await db.prepare(`
    INSERT INTO threat_actors (id, name, aliases, motivation, attribution_confidence, intrusion_set, campaign_name, malware_families, description, team_id, created_by, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    name.trim(),
    JSON.stringify(aliases ?? []),
    motivation ?? null,
    attribution_confidence ?? null,
    intrusion_set ?? null,
    campaign_name ?? null,
    JSON.stringify(malware_families ?? []),
    description ?? '',
    teamId,
    authReq.user.id,
    now,
    now,
  );

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    action: 'threat_actor_created',
    details: `Manually created threat actor "${name.trim()}" (${id})`,
  });

  logger.info({ actorId: id, name: name.trim(), teamId }, 'Threat actor manually created');

  res.json({
    actor: {
      id,
      name: name.trim(),
      aliases: aliases ?? [],
      motivation: motivation ?? null,
      attribution_confidence: attribution_confidence ?? null,
      intrusion_set: intrusion_set ?? null,
      campaign_name: campaign_name ?? null,
      malware_families: malware_families ?? [],
      description: description ?? '',
      session_count: 0,
      latest_session_at: null,
      created_at: now,
    },
  });
});

// ── GET /api/threat-actors — list actors for the team ─────────────────────────

router.get('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const teamId = authReq.teamId;
  const search = (req.query['search'] as string) || '';
  const limit = Math.min(parseInt(req.query['limit'] as string) || 50, 200);
  const offset = parseInt(req.query['offset'] as string) || 0;

  const db = getDb();

  let whereClause = 'WHERE ta.team_id = ?';
  const params: unknown[] = [teamId];

  if (search.trim()) {
    whereClause += ' AND (LOWER(ta.name) LIKE ? OR LOWER(ta.aliases) LIKE ?)';
    const searchPattern = `%${search.trim().toLowerCase()}%`;
    params.push(searchPattern, searchPattern);
  }

  const countRow = (await db.prepare(
    `SELECT COUNT(*) as total FROM threat_actors ta ${whereClause}`
  ).get(...params)) as { total: number };

  const actors = (await db.prepare(`
    SELECT ta.*,
      COUNT(sta.session_id) as session_count,
      MAX(sta.linked_at) as latest_session_at
    FROM threat_actors ta
    LEFT JOIN session_threat_actors sta ON sta.threat_actor_id = ta.id
    ${whereClause}
    GROUP BY ta.id
    ORDER BY latest_session_at DESC NULLS LAST, ta.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, limit, offset)) as Array<Record<string, unknown>>;

  // Parse JSON fields for the response
  const mapped = actors.map((a) => ({
    id: a.id,
    name: a.name,
    aliases: safeJsonParse(a.aliases as string, []),
    motivation: a.motivation,
    attribution_confidence: a.attribution_confidence,
    intrusion_set: a.intrusion_set,
    campaign_name: a.campaign_name,
    malware_families: safeJsonParse(a.malware_families as string, []),
    description: a.description,
    session_count: a.session_count ?? 0,
    latest_session_at: a.latest_session_at ?? null,
    created_at: a.created_at,
  }));

  res.json({ actors: mapped, total: countRow.total });
});

// ── GET /api/threat-actors/:id — actor detail with aggregated data ────────────

router.get('/:id', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const actorId = req.params['id'];
  const db = getDb();

  const actor = (await db.prepare(
    'SELECT * FROM threat_actors WHERE id = ? AND team_id = ?'
  ).get(actorId, authReq.teamId)) as Record<string, unknown> | undefined;

  if (!actor) {
    res.status(404).json({ error: 'Threat actor not found' });
    return;
  }

  // Linked sessions
  const linkedSessions = (await db.prepare(`
    SELECT s.id, s.name, s.severity, s.audience, s.created_at, sta.link_type
    FROM session_threat_actors sta
    JOIN sessions s ON s.id = sta.session_id
    WHERE sta.threat_actor_id = ? AND s.deleted_at IS NULL
    ORDER BY s.created_at DESC
  `).all(actorId)) as Array<Record<string, unknown>>;

  // Aggregate TTPs and IOCs from linked session results
  const sessionIds = linkedSessions.map((s) => s.id as string);
  const aggregatedTtps = new Map<string, { technique_id: string; technique_name: string; tactic: string; session_count: number; sessions: Array<{ id: string; name: string }> }>();
  const aggregatedIocs = new Map<string, { type: string; value: string; context: string; confidence: string; session_count: number; first_seen: number; last_seen: number }>();

  for (const sid of sessionIds) {
    const row = (await db.prepare(
      'SELECT result_json FROM analysis_results WHERE session_id = ? ORDER BY version DESC LIMIT 1'
    ).get(sid)) as { result_json: string } | undefined;

    if (!row) continue;

    let result: AnalysisResult;
    try {
      result = JSON.parse(row.result_json) as AnalysisResult;
    } catch { continue; }

    const session = linkedSessions.find((s) => s.id === sid);
    const sessionName = (session?.name as string) || 'Unknown';
    const sessionCreatedAt = (session?.created_at as number) || 0;

    // Aggregate TTPs
    if (result.attack_chain) {
      for (const tech of result.attack_chain) {
        const key = tech.sub_technique_id || tech.technique_id;
        const existing = aggregatedTtps.get(key);
        if (existing) {
          existing.session_count++;
          existing.sessions.push({ id: sid, name: sessionName });
        } else {
          aggregatedTtps.set(key, {
            technique_id: key,
            technique_name: tech.sub_technique_name || tech.technique_name,
            tactic: tech.tactic,
            session_count: 1,
            sessions: [{ id: sid, name: sessionName }],
          });
        }
      }
    }

    // Aggregate IOCs
    if (result.iocs) {
      for (const ioc of result.iocs) {
        if (!ioc.type || !ioc.value) continue; // skip malformed entries
        const iocKey = `${ioc.type}::${ioc.value.toLowerCase().trim()}`;
        const existing = aggregatedIocs.get(iocKey);
        if (existing) {
          existing.session_count++;
          existing.first_seen = Math.min(existing.first_seen, sessionCreatedAt);
          existing.last_seen = Math.max(existing.last_seen, sessionCreatedAt);
          // Keep higher confidence
          const confRank: Record<string, number> = { High: 3, Medium: 2, Low: 1 };
          if ((confRank[ioc.confidence] || 0) > (confRank[existing.confidence] || 0)) {
            existing.confidence = ioc.confidence;
          }
        } else {
          aggregatedIocs.set(iocKey, {
            type: ioc.type,
            value: ioc.value,
            context: ioc.context,
            confidence: ioc.confidence,
            session_count: 1,
            first_seen: sessionCreatedAt,
            last_seen: sessionCreatedAt,
          });
        }
      }
    }
  }

  res.json({
    actor: {
      id: actor.id,
      name: actor.name,
      aliases: safeJsonParse(actor.aliases as string, []),
      motivation: actor.motivation,
      attribution_confidence: actor.attribution_confidence,
      intrusion_set: actor.intrusion_set,
      campaign_name: actor.campaign_name,
      malware_families: safeJsonParse(actor.malware_families as string, []),
      description: actor.description,
      session_count: linkedSessions.length,
      latest_session_at: linkedSessions.length > 0 ? linkedSessions[0].created_at : null,
      created_at: actor.created_at,
    },
    sessions: linkedSessions,
    aggregated_ttps: Array.from(aggregatedTtps.values()).sort((a, b) => b.session_count - a.session_count),
    aggregated_iocs: Array.from(aggregatedIocs.values()).sort((a, b) => b.session_count - a.session_count),
  });
});

// ── PATCH /api/threat-actors/:id — update actor metadata ──────────────────────

router.patch('/:id', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const actorId = req.params['id'];
  const db = getDb();

  const actor = (await db.prepare(
    'SELECT * FROM threat_actors WHERE id = ? AND team_id = ?'
  ).get(actorId, authReq.teamId)) as Record<string, unknown> | undefined;

  if (!actor) {
    res.status(404).json({ error: 'Threat actor not found' });
    return;
  }

  const { name, aliases, motivation, attribution_confidence, intrusion_set, campaign_name, malware_families, description } = req.body as {
    name?: string;
    aliases?: string[];
    motivation?: string | null;
    attribution_confidence?: string | null;
    intrusion_set?: string | null;
    campaign_name?: string | null;
    malware_families?: string[];
    description?: string;
  };

  const updates: string[] = [];
  const params: unknown[] = [];

  if (name !== undefined && name.trim()) {
    updates.push('name = ?');
    params.push(name.trim());
  }
  if (aliases !== undefined) {
    updates.push('aliases = ?');
    params.push(JSON.stringify(aliases));
  }
  if (motivation !== undefined) {
    updates.push('motivation = ?');
    params.push(motivation);
  }
  if (attribution_confidence !== undefined) {
    updates.push('attribution_confidence = ?');
    params.push(attribution_confidence);
  }
  if (intrusion_set !== undefined) {
    updates.push('intrusion_set = ?');
    params.push(intrusion_set);
  }
  if (campaign_name !== undefined) {
    updates.push('campaign_name = ?');
    params.push(campaign_name);
  }
  if (malware_families !== undefined) {
    updates.push('malware_families = ?');
    params.push(JSON.stringify(malware_families));
  }
  if (description !== undefined) {
    updates.push('description = ?');
    params.push(description);
  }

  if (updates.length === 0) {
    res.status(400).json({ error: 'No fields to update' });
    return;
  }

  updates.push('updated_at = ?');
  params.push(Date.now());
  params.push(actorId);

  await db.prepare(`UPDATE threat_actors SET ${updates.join(', ')} WHERE id = ?`).run(...params);

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    action: 'threat_actor_update',
    details: `Updated threat actor "${actor.name}" (${actorId})`,
  });

  res.json({ ok: true });
});

// ── POST /api/threat-actors/:id/link — manually link a session ────────────────

router.post('/:id/link', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const actorId = req.params['id'];
  const { session_id } = req.body as { session_id: string };
  const db = getDb();

  if (!session_id) {
    res.status(400).json({ error: 'session_id required' });
    return;
  }

  // Verify actor belongs to team
  const actor = (await db.prepare(
    'SELECT id, name FROM threat_actors WHERE id = ? AND team_id = ?'
  ).get(actorId, authReq.teamId)) as { id: string; name: string } | undefined;

  if (!actor) {
    res.status(404).json({ error: 'Threat actor not found' });
    return;
  }

  // Verify session belongs to team
  const session = (await db.prepare(
    'SELECT id FROM sessions WHERE id = ? AND team_id = ? AND deleted_at IS NULL'
  ).get(session_id, authReq.teamId)) as { id: string } | undefined;

  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }

  // Check for existing link
  const existing = await db.prepare(
    'SELECT session_id FROM session_threat_actors WHERE session_id = ? AND threat_actor_id = ?'
  ).get(session_id, actorId);

  if (existing) {
    res.status(409).json({ error: 'Session already linked to this threat actor' });
    return;
  }

  await db.prepare(
    'INSERT INTO session_threat_actors (session_id, threat_actor_id, link_type, linked_at, linked_by) VALUES (?, ?, ?, ?, ?)'
  ).run(session_id, actorId, 'manual', Date.now(), authReq.user.id);

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    session_id,
    action: 'threat_actor_link',
    details: `Manually linked session to "${actor.name}" (${actorId})`,
  });

  res.json({ ok: true });
});

// ── POST /api/threat-actors/:id/link/bulk — bulk link multiple sessions ──────

router.post('/:id/link/bulk', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const actorId = req.params['id'];
  const { session_ids, remove_existing } = req.body as { session_ids: string[]; remove_existing?: boolean };
  const db = getDb();

  if (!Array.isArray(session_ids) || session_ids.length === 0) {
    res.status(400).json({ error: 'session_ids must be a non-empty array' });
    return;
  }

  if (session_ids.length > 50) {
    res.status(400).json({ error: 'Cannot link more than 50 sessions at once' });
    return;
  }

  // Verify actor belongs to team
  const actor = (await db.prepare(
    'SELECT id, name FROM threat_actors WHERE id = ? AND team_id = ?'
  ).get(actorId, authReq.teamId)) as { id: string; name: string } | undefined;

  if (!actor) {
    res.status(404).json({ error: 'Threat actor not found' });
    return;
  }

  let linked = 0;
  let skipped = 0;
  const now = Date.now();

  for (const sessionId of session_ids) {
    // Verify session belongs to team
    const session = (await db.prepare(
      'SELECT id FROM sessions WHERE id = ? AND team_id = ? AND deleted_at IS NULL'
    ).get(sessionId, authReq.teamId)) as { id: string } | undefined;

    if (!session) {
      skipped++;
      continue;
    }

    // Optionally remove existing actor links for this session (reassignment)
    if (remove_existing) {
      await db.prepare('DELETE FROM session_threat_actors WHERE session_id = ?').run(sessionId);
    }

    // Check for existing link to THIS actor
    const existingLink = await db.prepare(
      'SELECT session_id FROM session_threat_actors WHERE session_id = ? AND threat_actor_id = ?'
    ).get(sessionId, actorId);

    if (existingLink) {
      skipped++;
      continue;
    }

    await db.prepare(
      'INSERT INTO session_threat_actors (session_id, threat_actor_id, link_type, linked_at, linked_by) VALUES (?, ?, ?, ?, ?)'
    ).run(sessionId, actorId, 'manual', now, authReq.user.id);
    linked++;

    appendAuditLog({
      analyst_name: authReq.user.displayName,
      user_id: authReq.user.id,
      session_id: sessionId,
      action: 'threat_actor_link',
      details: `Bulk linked session to "${actor.name}" (${actorId})`,
    });
  }

  logger.info({ actorId, actorName: actor.name, linked, skipped }, 'Bulk link completed');
  res.json({ ok: true, linked, skipped });
});

// ── DELETE /api/threat-actors/:id/link/:sessionId — unlink a session ──────────

router.delete('/:id/link/:sessionId', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const actorId = req.params['id'];
  const sessionId = req.params['sessionId'];
  const db = getDb();

  // Verify actor belongs to team
  const actor = (await db.prepare(
    'SELECT id, name FROM threat_actors WHERE id = ? AND team_id = ?'
  ).get(actorId, authReq.teamId)) as { id: string; name: string } | undefined;

  if (!actor) {
    res.status(404).json({ error: 'Threat actor not found' });
    return;
  }

  const result = await db.prepare(
    'DELETE FROM session_threat_actors WHERE session_id = ? AND threat_actor_id = ?'
  ).run(sessionId, actorId);

  if (result.changes === 0) {
    res.status(404).json({ error: 'Link not found' });
    return;
  }

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    session_id: sessionId,
    action: 'threat_actor_unlink',
    details: `Unlinked session from "${actor.name}" (${actorId})`,
  });

  res.json({ ok: true });
});

// ── POST /api/threat-actors/merge — merge two actors ──────────────────────────

router.post('/merge', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const { source_id, target_id } = req.body as { source_id: string; target_id: string };
  const db = getDb();

  if (!source_id || !target_id) {
    res.status(400).json({ error: 'source_id and target_id required' });
    return;
  }
  if (source_id === target_id) {
    res.status(400).json({ error: 'Cannot merge an actor with itself' });
    return;
  }

  const source = (await db.prepare(
    'SELECT * FROM threat_actors WHERE id = ? AND team_id = ?'
  ).get(source_id, authReq.teamId)) as Record<string, unknown> | undefined;
  const target = (await db.prepare(
    'SELECT * FROM threat_actors WHERE id = ? AND team_id = ?'
  ).get(target_id, authReq.teamId)) as Record<string, unknown> | undefined;

  if (!source || !target) {
    res.status(404).json({ error: 'One or both threat actors not found' });
    return;
  }

  const now = Date.now();

  // Move all links from source to target (ignore duplicates)
  const sourceLinks = (await db.prepare(
    'SELECT session_id, link_type, linked_at, linked_by FROM session_threat_actors WHERE threat_actor_id = ?'
  ).all(source_id)) as Array<{ session_id: string; link_type: string; linked_at: number; linked_by: string }>;

  for (const link of sourceLinks) {
    await db.prepare(
      'INSERT INTO session_threat_actors (session_id, threat_actor_id, link_type, linked_at, linked_by) VALUES (?, ?, ?, ?, ?) ON CONFLICT (session_id, threat_actor_id) DO NOTHING'
    ).run(link.session_id, target_id, link.link_type, link.linked_at, link.linked_by);
  }

  // Merge aliases: target aliases + source aliases + source name (all unique)
  const targetAliases: string[] = safeJsonParse(target.aliases as string, []);
  const sourceAliases: string[] = safeJsonParse(source.aliases as string, []);
  const sourceName = source.name as string;

  const allAliases = [...targetAliases];
  const existingLower = new Set(allAliases.map((a) => a.toLowerCase()));
  existingLower.add((target.name as string).toLowerCase());

  // Add source name as alias (if not already target name or alias)
  if (!existingLower.has(sourceName.toLowerCase())) {
    allAliases.push(sourceName);
    existingLower.add(sourceName.toLowerCase());
  }
  // Add source aliases
  for (const alias of sourceAliases) {
    if (!existingLower.has(alias.toLowerCase())) {
      allAliases.push(alias);
      existingLower.add(alias.toLowerCase());
    }
  }

  // Merge malware families
  const targetMalware: string[] = safeJsonParse(target.malware_families as string, []);
  const sourceMalware: string[] = safeJsonParse(source.malware_families as string, []);
  const mergedMalware = [...new Set([...targetMalware, ...sourceMalware])];

  // Update target with merged data (only fill empty fields from source)
  const updates: string[] = ['aliases = ?', 'malware_families = ?', 'updated_at = ?'];
  const params: unknown[] = [JSON.stringify(allAliases), JSON.stringify(mergedMalware), now];

  if (!target.intrusion_set && source.intrusion_set) {
    updates.push('intrusion_set = ?');
    params.push(source.intrusion_set);
  }
  if (!target.campaign_name && source.campaign_name) {
    updates.push('campaign_name = ?');
    params.push(source.campaign_name);
  }
  if (!target.motivation && source.motivation) {
    updates.push('motivation = ?');
    params.push(source.motivation);
  }
  if (!target.description && source.description) {
    updates.push('description = ?');
    params.push(source.description);
  }

  params.push(target_id);
  await db.prepare(`UPDATE threat_actors SET ${updates.join(', ')} WHERE id = ?`).run(...params);

  // Record the merge for audit
  await db.prepare(
    'INSERT INTO threat_actor_merges (id, source_actor_id, target_actor_id, source_actor_name, merged_by, merged_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(crypto.randomUUID(), source_id, target_id, sourceName, authReq.user.id, now);

  // Delete source links and source actor (CASCADE handles links)
  await db.prepare('DELETE FROM session_threat_actors WHERE threat_actor_id = ?').run(source_id);
  await db.prepare('DELETE FROM threat_actors WHERE id = ?').run(source_id);

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    action: 'threat_actor_merge',
    details: `Merged "${sourceName}" (${source_id}) into "${target.name}" (${target_id})`,
  });

  logger.info({ sourceId: source_id, targetId: target_id, sourceName, targetName: target.name }, 'Threat actors merged');

  res.json({ ok: true, merged_into: target_id });
});

// ── DELETE /api/threat-actors/:id — delete an actor ───────────────────────────

router.delete('/:id', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const actorId = req.params['id'];
  const db = getDb();

  const actor = (await db.prepare(
    'SELECT id, name FROM threat_actors WHERE id = ? AND team_id = ?'
  ).get(actorId, authReq.teamId)) as { id: string; name: string } | undefined;

  if (!actor) {
    res.status(404).json({ error: 'Threat actor not found' });
    return;
  }

  // CASCADE handles session_threat_actors cleanup
  await db.prepare('DELETE FROM threat_actors WHERE id = ?').run(actorId);

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    action: 'threat_actor_delete',
    details: `Deleted threat actor "${actor.name}" (${actorId})`,
  });

  res.json({ ok: true });
});

// ── GET /api/threat-actors/:id/sessions/available — sessions not yet linked ───

router.get('/:id/sessions/available', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const actorId = req.params['id'];
  const search = (req.query['search'] as string) || '';
  const db = getDb();

  // Verify actor belongs to team
  const actor = (await db.prepare(
    'SELECT id FROM threat_actors WHERE id = ? AND team_id = ?'
  ).get(actorId, authReq.teamId)) as { id: string } | undefined;

  if (!actor) {
    res.status(404).json({ error: 'Threat actor not found' });
    return;
  }

  let query = `
    SELECT s.id, s.name, s.severity, s.audience, s.created_at
    FROM sessions s
    WHERE s.team_id = ? AND s.status = 'complete' AND s.deleted_at IS NULL
    AND s.id NOT IN (SELECT session_id FROM session_threat_actors WHERE threat_actor_id = ?)
  `;
  const params: unknown[] = [authReq.teamId, actorId];

  if (search.trim()) {
    query += ' AND LOWER(s.name) LIKE ?';
    params.push(`%${search.trim().toLowerCase()}%`);
  }

  query += ' ORDER BY s.created_at DESC LIMIT 20';

  const sessions = (await db.prepare(query).all(...params)) as Array<Record<string, unknown>>;
  res.json({ sessions });
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function safeJsonParse<T>(json: string | null | undefined, fallback: T): T {
  if (!json) return fallback;
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}

export default router;
