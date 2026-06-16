/**
 * Detection-as-code publishing endpoint (human/JWT auth, team-scoped).
 * Opens/updates a GitHub PR with a session's detection rules + Markdown report.
 */
import { Router } from 'express';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';
import { getDb, loadMergedSettings, appendAuditLog } from '../db/database.js';
import { parseSections } from '../lib/sections.js';
import { buildMarkdownReport } from '../lib/report.js';
import { parseDacConfig, publishSession } from '../lib/publish/github.js';
import type { AnalysisResult } from '../lib/claude.js';
import logger from '../lib/logger.js';

const router = Router();

// GET /api/publish/status — whether detection-as-code is configured for the team.
router.get('/status', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const settings = await loadMergedSettings(authReq.teamId);
  const cfg = parseDacConfig(settings);
  res.json({
    configured: !!cfg,
    repo: cfg ? `${cfg.owner}/${cfg.repo}` : null,
    branch: cfg?.branch ?? null,
  });
});

// POST /api/publish/:sessionId — publish a session's detections to GitHub.
router.post('/:sessionId', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const sessionId = req.params.sessionId;

  const session = (await db
    .prepare('SELECT * FROM sessions WHERE id = ? AND deleted_at IS NULL')
    .get(sessionId)) as Record<string, unknown> | undefined;
  if (!session || (authReq.teamId && session.team_id !== authReq.teamId)) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }

  const row = (await db
    .prepare(
      'SELECT result_json, analyst_overrides FROM analysis_results WHERE session_id = ? ORDER BY version DESC LIMIT 1'
    )
    .get(sessionId)) as { result_json: string; analyst_overrides?: string } | undefined;
  if (!row) {
    res.status(409).json({ error: 'Session has no completed analysis to publish' });
    return;
  }

  let result: AnalysisResult;
  try {
    result = JSON.parse(row.result_json) as AnalysisResult;
  } catch {
    res.status(500).json({ error: 'Stored analysis data is corrupted' });
    return;
  }

  // Respect analyst false-positive IOC exclusions (as in V2 exports).
  try {
    const overrides = row.analyst_overrides ? JSON.parse(row.analyst_overrides) : {};
    const fps: string[] = overrides.ioc_false_positives ?? [];
    if (Array.isArray(fps) && fps.length > 0 && Array.isArray(result.iocs)) {
      const fpSet = new Set(fps);
      result.iocs = result.iocs.filter((i) => !fpSet.has(`${i.type}::${i.value}`));
    }
  } catch { /* ignore */ }

  if (!result.detection_rules || result.detection_rules.length === 0) {
    res.status(422).json({ error: 'This session has no detection rules to publish' });
    return;
  }

  const settings = await loadMergedSettings(authReq.teamId);
  const config = parseDacConfig(settings);
  if (!config) {
    res.status(400).json({ error: 'Detection-as-code is not configured. Set the GitHub repo and token in Settings.' });
    return;
  }

  const sections = parseSections(settings.report_sections || '');
  const markdownReport = buildMarkdownReport(result, sections, {
    analystName: settings.analyst_name || 'CTI Analyst',
    orgName: settings.org_name || 'Security Operations',
    tlp: settings.default_tlp || 'AMBER',
    audience: (session.audience as string) || 'soc',
    template: settings.report_template || undefined,
  });

  try {
    const pub = await publishSession({
      session: { id: sessionId, name: String(session.name ?? 'session') },
      result,
      markdownReport,
      config,
    });
    await db.prepare('UPDATE sessions SET dac_pr_url = ?, updated_at = ? WHERE id = ?').run(pub.prUrl, Date.now(), sessionId);
    appendAuditLog({
      analyst_name: authReq.user.displayName,
      user_id: authReq.user.id,
      session_id: sessionId,
      action: 'detections_published',
      outputs_generated: pub.files,
      details: `${pub.updated ? 'updated' : 'opened'} PR ${pub.prUrl} (${pub.files.length} files)`,
    });
    logger.info({ sessionId, prUrl: pub.prUrl, files: pub.files.length }, 'Detections published');
    res.json({ ok: true, prUrl: pub.prUrl, prNumber: pub.prNumber, branch: pub.branch, files: pub.files, updated: pub.updated });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Publish failed';
    logger.warn({ err, sessionId }, 'Detection-as-code publish failed');
    res.status(502).json({ error: `GitHub publish failed: ${message}` });
  }
});

export default router;
