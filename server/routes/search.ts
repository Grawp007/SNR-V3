/**
 * Global intelligence search — searches across IOCs, TTPs, threat actors,
 * session names, and affected assets within a team's sessions.
 *
 * GET /api/search?q=<query>&limit=20
 */
import { Router } from 'express';
import { getDb } from '../db/database.js';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';

const router = Router();

interface SearchHit {
  category: 'ioc' | 'technique' | 'threat_actor' | 'session' | 'asset';
  value: string;
  context: string;
  session_id: string;
  session_name: string;
  /** Extra metadata depending on category */
  meta?: Record<string, string>;
  /** For aggregated results (e.g. techniques) — all sessions containing this hit */
  sessions?: Array<{ id: string; name: string }>;
}

router.get('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const teamId = authReq.teamId;
  const query = ((req.query['q'] as string) || '').trim();
  const limit = Math.min(parseInt(req.query['limit'] as string) || 30, 100);

  if (!query || query.length < 2) {
    res.json({ results: [], query, total: 0 });
    return;
  }

  const db = getDb();
  const pattern = `%${query.toLowerCase()}%`;
  const hits: SearchHit[] = [];

  // ── 1. Session name / title match ────────────────────────────────────────
  const sessionMatches = (await db.prepare(`
    SELECT s.id, s.name, s.severity, s.created_at
    FROM sessions s
    WHERE s.team_id = ? AND s.status = 'complete' AND s.deleted_at IS NULL
      AND LOWER(s.name) LIKE ?
    ORDER BY s.created_at DESC
    LIMIT ?
  `).all(teamId, pattern, limit)) as Array<{ id: string; name: string; severity: string | null; created_at: number }>;

  for (const s of sessionMatches) {
    hits.push({
      category: 'session',
      value: s.name,
      context: s.severity ? `${s.severity} severity` : 'Session',
      session_id: s.id,
      session_name: s.name,
    });
  }

  // ── 2. Threat actor name / alias match ───────────────────────────────────
  const actorMatches = (await db.prepare(`
    SELECT ta.id as actor_id, ta.name, ta.aliases, ta.attribution_confidence,
           COUNT(sta.session_id) as session_count
    FROM threat_actors ta
    LEFT JOIN session_threat_actors sta ON sta.threat_actor_id = ta.id
    WHERE ta.team_id = ?
      AND (LOWER(ta.name) LIKE ? OR LOWER(ta.aliases) LIKE ?)
    GROUP BY ta.id
    ORDER BY session_count DESC
    LIMIT ?
  `).all(teamId, pattern, pattern, limit)) as Array<{
    actor_id: string; name: string; aliases: string;
    attribution_confidence: string | null; session_count: number;
  }>;

  for (const a of actorMatches) {
    hits.push({
      category: 'threat_actor',
      value: a.name,
      context: `${a.session_count} session${a.session_count !== 1 ? 's' : ''}${a.attribution_confidence ? ` · ${a.attribution_confidence} confidence` : ''}`,
      session_id: '',
      session_name: '',
      meta: { actor_id: a.actor_id },
    });
  }

  // ── 3. IOC value match (search inside result_json) ───────────────────────
  // Use json_each to extract IOC values from the stored JSON
  const iocMatches = (await db.prepare(`
    SELECT DISTINCT
      s.id as session_id, s.name as session_name,
      ioc.value ->> 'type' as ioc_type,
      ioc.value ->> 'value' as ioc_value,
      ioc.value ->> 'context' as ioc_context,
      ioc.value ->> 'confidence' as ioc_confidence,
      s.created_at as created_at
    FROM sessions s
    JOIN analysis_results ar ON ar.session_id = s.id
    , snr_json_array(ar.result_json, 'iocs') as ioc(value)
    WHERE s.team_id = ? AND s.status = 'complete' AND s.deleted_at IS NULL
      AND LOWER(ioc.value ->> 'value') LIKE ?
    ORDER BY created_at DESC
    LIMIT ?
  `).all(teamId, pattern, limit)) as Array<{
    session_id: string; session_name: string;
    ioc_type: string; ioc_value: string; ioc_context: string; ioc_confidence: string;
  }>;

  // Aggregate IOCs: group by type+value so each IOC appears once
  const iocMap = new Map<string, SearchHit>();
  for (const m of iocMatches) {
    if (!m.ioc_value) continue;
    const key = `${m.ioc_type}::${m.ioc_value.toLowerCase().trim()}`;
    const existing = iocMap.get(key);
    if (existing) {
      if (!existing.sessions!.some((s) => s.id === m.session_id)) {
        existing.sessions!.push({ id: m.session_id, name: m.session_name });
      }
    } else {
      iocMap.set(key, {
        category: 'ioc',
        value: m.ioc_value,
        context: m.ioc_context || '',
        session_id: m.session_id,
        session_name: m.session_name,
        meta: { type: m.ioc_type, confidence: m.ioc_confidence },
        sessions: [{ id: m.session_id, name: m.session_name }],
      });
    }
  }
  hits.push(...iocMap.values());

  // ── 4. ATT&CK technique match ───────────────────────────────────────────
  const ttpMatches = (await db.prepare(`
    SELECT DISTINCT
      s.id as session_id, s.name as session_name,
      tech.value ->> 'technique_id' as technique_id,
      tech.value ->> 'technique_name' as technique_name,
      tech.value ->> 'sub_technique_id' as sub_id,
      tech.value ->> 'sub_technique_name' as sub_name,
      tech.value ->> 'tactic' as tactic,
      s.created_at as created_at
    FROM sessions s
    JOIN analysis_results ar ON ar.session_id = s.id
    , snr_json_array(ar.result_json, 'attack_chain') as tech(value)
    WHERE s.team_id = ? AND s.status = 'complete' AND s.deleted_at IS NULL
      AND (
        LOWER(tech.value ->> 'technique_id') LIKE ?
        OR LOWER(tech.value ->> 'technique_name') LIKE ?
        OR LOWER(tech.value ->> 'sub_technique_id') LIKE ?
        OR LOWER(tech.value ->> 'sub_technique_name') LIKE ?
        OR LOWER(tech.value ->> 'tactic') LIKE ?
      )
    ORDER BY created_at DESC
    LIMIT ?
  `).all(teamId, pattern, pattern, pattern, pattern, pattern, limit)) as Array<{
    session_id: string; session_name: string;
    technique_id: string; technique_name: string;
    sub_id: string | null; sub_name: string | null; tactic: string;
  }>;

  // Aggregate techniques: group by technique ID so each technique appears once
  const techniqueMap = new Map<string, SearchHit>();
  for (const m of ttpMatches) {
    const id = m.sub_id || m.technique_id;
    const name = m.sub_name || m.technique_name;
    const key = `${id}::${m.tactic}`;
    const existing = techniqueMap.get(key);
    if (existing) {
      // Add session to existing technique entry (avoid duplicates)
      if (!existing.sessions!.some((s) => s.id === m.session_id)) {
        existing.sessions!.push({ id: m.session_id, name: m.session_name });
      }
    } else {
      techniqueMap.set(key, {
        category: 'technique',
        value: `${id} — ${name}`,
        context: m.tactic,
        session_id: m.session_id,
        session_name: m.session_name,
        meta: { technique_id: id, tactic: m.tactic },
        sessions: [{ id: m.session_id, name: m.session_name }],
      });
    }
  }
  hits.push(...techniqueMap.values());

  // ── 5. Affected asset match ──────────────────────────────────────────────
  const assetMatches = (await db.prepare(`
    SELECT DISTINCT
      s.id as session_id, s.name as session_name,
      asset.value ->> 'hostname' as hostname,
      asset.value ->> 'ip' as ip,
      asset.value ->> 'role' as role,
      s.created_at as created_at
    FROM sessions s
    JOIN analysis_results ar ON ar.session_id = s.id
    , snr_json_array(ar.result_json, 'affected_assets') as asset(value)
    WHERE s.team_id = ? AND s.status = 'complete' AND s.deleted_at IS NULL
      AND (
        LOWER(asset.value ->> 'hostname') LIKE ?
        OR LOWER(asset.value ->> 'ip') LIKE ?
      )
    ORDER BY created_at DESC
    LIMIT ?
  `).all(teamId, pattern, pattern, limit)) as Array<{
    session_id: string; session_name: string;
    hostname: string | null; ip: string | null; role: string | null;
  }>;

  // Aggregate assets: group by hostname+ip so each asset appears once
  const assetMap = new Map<string, SearchHit>();
  for (const m of assetMatches) {
    const value = [m.hostname, m.ip].filter(Boolean).join(' / ');
    if (!value) continue;
    const key = value.toLowerCase();
    const existing = assetMap.get(key);
    if (existing) {
      if (!existing.sessions!.some((s) => s.id === m.session_id)) {
        existing.sessions!.push({ id: m.session_id, name: m.session_name });
      }
    } else {
      assetMap.set(key, {
        category: 'asset',
        value,
        context: m.role || 'Asset',
        session_id: m.session_id,
        session_name: m.session_name,
        sessions: [{ id: m.session_id, name: m.session_name }],
      });
    }
  }
  hits.push(...assetMap.values());

  // Deduplicate IOC hits (same value across sessions) — keep unique by value+session
  const seen = new Set<string>();
  const deduped = hits.filter((h) => {
    const key = `${h.category}::${h.value}::${h.session_id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  res.json({ results: deduped.slice(0, limit), query, total: deduped.length });
});

export default router;
