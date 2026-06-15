import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import archiver from 'archiver';
import { getDb, appendAuditLog, loadMergedSettings } from '../db/database.js';
import { analyzeWithClaude } from '../lib/claude.js';
import { buildStixBundle, buildNavigatorLayer } from '../lib/stix.js';
import { buildEml, buildHtmlBody } from '../lib/eml.js';
import { parseSections } from '../lib/sections.js';
import { buildMarkdownReport } from '../lib/report.js';
import multer from 'multer';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';
import type { AnalysisResult } from '../lib/claude.js';
import logger from '../lib/logger.js';
import { validateAndDeduplicateIOCs } from '../lib/ioc-validator.js';
import { validateAttackFlow } from '../lib/attack-flow.js';
import { buildAfb } from '../lib/afb.js';
import { analysisRunsTotal, analysisDurationSeconds } from '../lib/metrics.js';
import { autoLinkThreatActor } from '../lib/threat-actor-linker.js';

const router = Router();

/**
 * Verify a session belongs to the requesting user's team.
 * Returns the session row or sends 404 and returns null.
 */
async function verifySessionTeam(req: Request, res: Response, sessionId: string): Promise<Record<string, unknown> | null> {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const session = (await db.prepare('SELECT * FROM sessions WHERE id = ? AND deleted_at IS NULL').get(sessionId)) as Record<string, unknown> | undefined;
  if (!session) { res.status(404).json({ error: 'No analysis found' }); return null; }
  if (authReq.teamId && session.team_id !== authReq.teamId) {
    res.status(404).json({ error: 'No analysis found' });
    return null;
  }
  return session;
}

/**
 * Remove analyst-flagged false-positive IOCs from a result before export.
 * FP keys (`type::value`) are stored in analyst_overrides.ioc_false_positives.
 */
function filterFalsePositiveIocs(result: AnalysisResult, overridesJson: string | null | undefined): void {
  if (!overridesJson || !result.iocs?.length) return;
  try {
    const overrides = JSON.parse(overridesJson) as Record<string, string>;
    const fp = JSON.parse(overrides['ioc_false_positives'] || '[]') as string[];
    if (!Array.isArray(fp) || fp.length === 0) return;
    const fpSet = new Set(fp);
    result.iocs = result.iocs.filter((i) => !fpSet.has(`${i.type}::${i.value.toLowerCase().trim()}`));
  } catch { /* malformed overrides — leave IOCs unfiltered */ }
}

// Multer: memory storage, 10 MB limit
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowedExtensions = ['csv', 'txt', 'log', 'json'];
    const allowedMimeTypes = ['text/csv', 'text/plain', 'application/json', 'text/x-log'];
    const ext = file.originalname.split('.').pop()?.toLowerCase();
    if (allowedExtensions.includes(ext ?? '') && allowedMimeTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only .csv, .txt, .log, and .json files with valid MIME types are allowed'));
    }
  },
});

// ── Email preview sample data ─────────────────────────────────────────────────

const SAMPLE_PREVIEW_EMAIL: AnalysisResult['email_content'] = {
  subject: '[TLP:AMBER] [SNR] Ransomware Pre-Staging Activity Detected | SOC',
  severity_badge: 'Critical',
  // Current default brief-section keys (drives {{SECTIONS}} / {{SECTION:key}})
  threat_action: 'A financially motivated actor compromised a Finance endpoint via a phishing email, harvested domain credentials, and staged tooling consistent with pre-ransomware deployment. Immediate containment is required.',
  attack_overview: 'On March 8, 2026 a macro-enabled attachment opened on FINANCE-WS-042 launched an encoded PowerShell command that downloaded a Cobalt Strike beacon. The beacon established HTTPS C2, after which the actor dumped LSASS with Mimikatz and moved laterally over SMB to FINANCE-SRV-01 using stolen domain admin credentials.',
  technical_analysis: 'Initial execution used `powershell.exe -EncodedCommand` to retrieve a beacon from 91.234.56.78. Credential access via **Mimikatz** yielded the DA_finance domain admin account. Lateral movement abused **ADMIN$** shares. Tools were staged in `C:\\ProgramData\\svctemp\\`, a pattern frequently preceding ransomware deployment.',
  impact_assessment: 'Two Finance systems and one domain admin account are confirmed compromised. Data exposure risk is High given file-server access. Without containment, enterprise-wide encryption is a plausible next step.',
  threat_actor_info: 'Activity aligns with a financially motivated intrusion set leveraging Cobalt Strike and Mimikatz. Attribution confidence is Medium pending infrastructure pivoting.',
  behavioral_indicators: 'Encoded PowerShell spawned from an Office process; outbound HTTPS to a newly-registered host; LSASS access by a non-system binary; and ADMIN$ writes from a workstation to a server are the strongest behavioral signals.',
  references: 'Internal SIEM alert SOC-2026-0308-114; MITRE ATT&CK technique pages for the mapped techniques; vendor advisory on Cobalt Strike beacon detection.',
  distribution_info: 'TLP:AMBER — limit to SOC, CIRT, and IT security leadership with operational need-to-know. Do not forward outside the organization without approval.',
  // Auto blocks read these (techniques table + IOC table)
  techniques_table: [
    { technique_id: 'T1566.001', technique_name: 'Phishing: Spearphishing Attachment', evidence: 'Macro-enabled Office document opened by user jsmith@org.com' },
    { technique_id: 'T1059.001', technique_name: 'Command and Scripting: PowerShell', evidence: 'Encoded PS command: -EncodedCommand SQBFAFgA...' },
    { technique_id: 'T1003.001', technique_name: 'OS Credential Dumping: LSASS Memory', evidence: 'mimikatz.exe detected via process creation event' },
    { technique_id: 'T1021.002', technique_name: 'Remote Services: SMB/Windows Admin Shares', evidence: 'ADMIN$ share access from FINANCE-WS-042 to FINANCE-SRV-01' },
  ],
  ioc_table: [
    { type: 'ip', value: '91.234.56.78', context: 'Cobalt Strike C2 beacon over HTTPS' },
    { type: 'domain', value: 'cobalt-staging.ru', context: 'Malicious domain used for C2 communication' },
    { type: 'sha256', value: 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3', context: 'Mimikatz binary dropped to C:\\ProgramData\\svctemp\\' },
    { type: 'filename', value: 'Q1_Finance_Report_FINAL.xlsm', context: 'Phishing macro-enabled Excel document' },
  ],
};

const SAMPLE_PREVIEW_RESULT = {
  attack_chain: SAMPLE_PREVIEW_EMAIL.techniques_table,
  iocs: SAMPLE_PREVIEW_EMAIL.ioc_table,
  email_content: SAMPLE_PREVIEW_EMAIL,
} as unknown as AnalysisResult;

const PREVIEW_TLP_COLORS: Record<string, string> = {
  CLEAR: '#6b7280', GREEN: '#16a34a', AMBER: '#d97706', 'AMBER+STRICT': '#ea580c', RED: '#dc2626',
};
const PREVIEW_SEVERITY_COLORS: Record<string, string> = {
  Critical: '#b91c1c', High: '#dc2626', Medium: '#d97706', Low: '#16a34a', Informational: '#2563eb',
};
const PREVIEW_SEVERITY_BG: Record<string, string> = {
  Critical: '#fef2f2', High: '#fff1f2', Medium: '#fffbeb', Low: '#f0fdf4', Informational: '#eff6ff',
};
const PREVIEW_AUDIENCE_LABELS: Record<string, string> = {
  purple_team: 'Purple Team', soc: 'SOC', red_team: 'Red Team', dr: 'Detection & Response', general: 'General',
};

// GET /api/analyze/email-preview — renders a live template preview with sample data
router.get('/email-preview', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const settings = await loadMergedSettings(authReq.teamId);
  const sections = parseSections(settings.report_sections || '');

  const tlp = (req.query['tlp'] as string) || 'AMBER';
  const audience = (req.query['audience'] as string) || 'soc';
  const tlpColor = PREVIEW_TLP_COLORS[tlp] ?? '#d97706';
  const severityColor = PREVIEW_SEVERITY_COLORS[SAMPLE_PREVIEW_EMAIL.severity_badge] ?? '#374151';
  const severityBg = PREVIEW_SEVERITY_BG[SAMPLE_PREVIEW_EMAIL.severity_badge] ?? '#f9fafb';
  const audienceLabel = PREVIEW_AUDIENCE_LABELS[audience] ?? audience;

  const html = buildHtmlBody({
    email: SAMPLE_PREVIEW_EMAIL,
    audienceLabel,
    tlp,
    tlpColor,
    tlpTextColor: '#ffffff',
    severityColor,
    severityBg,
    result: SAMPLE_PREVIEW_RESULT,
    sections,
    headerText: settings.email_header_text,
    footerText: settings.email_footer_text,
    signature: settings.email_signature,
    customPreamble: settings.email_custom_preamble,
    audienceIntro: settings[`custom_intro_${audience}`],
    primaryColor: sanitizeColor(settings.email_primary_color),
    secondaryColor: sanitizeColor(settings.email_secondary_color),
    logoDataUri: settings.email_logo_data || undefined,
    fontFamily: settings.email_font_family || undefined,
    bodyFontSize: settings.email_body_font_size || undefined,
    template: settings.email_template || undefined,
    orgName: settings.org_name || '',
    analystName: settings.analyst_name || '',
  });

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

// POST /api/analyze/email-preview — live preview with an in-progress template override
router.post('/email-preview', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const settings = await loadMergedSettings(authReq.teamId);
  const sections = parseSections(settings.report_sections || '');

  const { tlp = 'AMBER', audience = 'soc', template } = (req.body ?? {}) as {
    tlp?: string; audience?: string; template?: string;
  };
  const tlpColor = PREVIEW_TLP_COLORS[tlp] ?? '#d97706';
  const severityColor = PREVIEW_SEVERITY_COLORS[SAMPLE_PREVIEW_EMAIL.severity_badge] ?? '#374151';
  const severityBg = PREVIEW_SEVERITY_BG[SAMPLE_PREVIEW_EMAIL.severity_badge] ?? '#f9fafb';
  const audienceLabel = PREVIEW_AUDIENCE_LABELS[audience] ?? audience;

  const html = buildHtmlBody({
    email: SAMPLE_PREVIEW_EMAIL,
    audienceLabel,
    tlp,
    tlpColor,
    tlpTextColor: '#ffffff',
    severityColor,
    severityBg,
    result: SAMPLE_PREVIEW_RESULT,
    sections,
    headerText: settings.email_header_text,
    footerText: settings.email_footer_text,
    signature: settings.email_signature,
    customPreamble: settings.email_custom_preamble,
    audienceIntro: settings[`custom_intro_${audience}`],
    primaryColor: sanitizeColor(settings.email_primary_color),
    secondaryColor: sanitizeColor(settings.email_secondary_color),
    logoDataUri: settings.email_logo_data || undefined,
    fontFamily: settings.email_font_family || undefined,
    bodyFontSize: settings.email_body_font_size || undefined,
    // The in-progress editor template (unsaved); falls back to saved/default
    template: (typeof template === 'string' ? template : settings.email_template) || undefined,
    orgName: settings.org_name || '',
    analystName: settings.analyst_name || '',
  });

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

// POST /api/analyze — main analysis endpoint (SSE streaming)
router.post('/', upload.single('logFile'), async (req: Request, res: Response) => {
  try {
    const { session_id, siem_input, text_input, audience, redacted_strings } = req.body as {
      session_id: string;
      siem_input?: string;
      text_input?: string;
      audience: string;
      redacted_strings?: string;
    };

    if (!session_id) return res.status(400).json({ error: 'session_id required' });
    if (!audience) return res.status(400).json({ error: 'audience required' });
    if (!siem_input && !text_input && !req.file) {
      return res.status(400).json({ error: 'At least one input source required' });
    }

    const db = getDb();

    // Apply redactions client-side data cannot be trusted to be clean here,
    // but we apply an extra server-side mask pass for any patterns provided
    let siemClean = siem_input ?? '';
    let textClean = text_input ?? '';
    let logClean = req.file ? req.file.buffer.toString('utf-8') : '';

    if (redacted_strings) {
      let patterns: string[] = [];
      try {
        patterns = JSON.parse(redacted_strings) as string[];
        if (!Array.isArray(patterns)) patterns = [];
      } catch {
        return res.status(400).json({ error: 'Invalid redacted_strings format' });
      }
      for (const p of patterns) {
        const re = new RegExp(escapeRegex(p), 'gi');
        siemClean = siemClean.replace(re, '[REDACTED]');
        textClean = textClean.replace(re, '[REDACTED]');
        logClean = logClean.replace(re, '[REDACTED]');
      }
    }

    // Compute input hash for audit
    const inputRaw = [siemClean, textClean, logClean].join('||');
    const inputHash = crypto.createHash('sha256').update(inputRaw).digest('hex');

    // Persist inputs (store hash reference, not cleartext in audit)
    const now = Date.now();
    if (siemClean) {
      await db.prepare('INSERT INTO session_inputs (id, session_id, input_type, content, created_at) VALUES (?,?,?,?,?)')
        .run(uuidv4(), session_id, 'siem', siemClean, now);
    }
    if (textClean) {
      await db.prepare('INSERT INTO session_inputs (id, session_id, input_type, content, created_at) VALUES (?,?,?,?,?)')
        .run(uuidv4(), session_id, 'text', textClean, now);
    }
    if (logClean) {
      await db.prepare('INSERT INTO session_inputs (id, session_id, input_type, content, filename, created_at) VALUES (?,?,?,?,?,?)')
        .run(uuidv4(), session_id, 'log', logClean, req.file?.originalname ?? 'upload', now);
    }

    // Update session status
    await db.prepare('UPDATE sessions SET status = ?, updated_at = ?, input_hash = ? WHERE id = ?')
      .run('analyzing', now, inputHash, session_id);

    await runAnalysisPipeline(req, res, {
      sessionId: session_id,
      siemClean,
      textClean,
      logClean,
      audience,
      inputHash,
      auditAction: 'analysis_complete',
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Analysis failed';
    res.write(`event: error\ndata: ${JSON.stringify({ error: message })}\n\n`);
    res.end();
  }
});

/**
 * Shared SSE analysis pipeline — used by POST / (fresh analysis) and
 * POST /rerun/:sessionId (retry / re-analyze from stored inputs).
 * Sets up the SSE stream, runs the two-phase LLM analysis, persists the
 * result as a new version, and updates session status ('complete' on
 * success, 'failed' on error).
 */
async function runAnalysisPipeline(
  req: Request,
  res: Response,
  p: {
    sessionId: string;
    siemClean: string;
    textClean: string;
    logClean: string;
    audience: string;
    inputHash: string;
    auditAction: 'analysis_complete' | 'analysis_rerun';
  },
): Promise<void> {
  const db = getDb();
  const now = Date.now();
  const metricKind = p.auditAction === 'analysis_rerun' ? 'rerun' : 'analyze';
  const startedAt = Date.now();

  // SSE setup for streaming
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const sendEvent = (event: string, data: unknown) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  const authReq = req as AuthenticatedRequest;

  try {
    // Load team-merged settings
    const settings = await loadMergedSettings(authReq.teamId);

    sendEvent('status', { message: 'Phase 1 of 2 — Extracting ATT&CK techniques and IOCs…', phase: 1 });

    const audienceKey = p.audience.replace(/-/g, '_');
    let audiencePromptOverride = settings[`audience_prompt_${audienceKey}`] || undefined;
    let resolvedAudience = p.audience;

    // If no built-in override found, check custom audiences
    if (!audiencePromptOverride && !['purple_team', 'soc', 'red_team', 'dr', 'general'].includes(audienceKey)) {
      try {
        const customList = JSON.parse(settings['custom_audiences'] || '[]') as Array<{ id: string; label: string; prompt: string }>;
        const custom = customList.find((a) => a.id === p.audience);
        if (custom) {
          audiencePromptOverride = custom.prompt || undefined;
          resolvedAudience = custom.label;
        }
      } catch { /* ignore parse error */ }
    }

    const sections = parseSections(settings.report_sections || '');

    const result = await analyzeWithClaude(
      {
        siem: p.siemClean || undefined,
        log: p.logClean || undefined,
        text: p.textClean || undefined,
        audience: resolvedAudience,
        sections,
        orgEvaluationCriteria: settings.org_evaluation_criteria || undefined,
        orgDetectionContext: settings.org_detection_context || undefined,
        audiencePromptOverride,
        systemPromptOverride: settings.system_prompt_override || undefined,
        phase1InstructionsOverride: settings.phase1_instructions_override || undefined,
        phase2TemplateOverride: settings.phase2_template_override || undefined,
        providerSettings: settings,
      },
      (chunk, phase) => {
        if (chunk === '' && phase === 'phase2') {
          sendEvent('status', { message: 'Phase 2 of 2 — Generating stakeholder brief…', phase: 2 });
        } else if (chunk) {
          sendEvent('chunk', { text: chunk, phase });
        }
      }
    );

    // Validate the model returned a usable result
    if (!result.incident_summary?.title || !result.incident_summary?.severity) {
      throw new Error(
        'The model returned an incomplete analysis — missing incident_summary. ' +
        'This usually means the model cannot produce SNR\'s required JSON schema. ' +
        'Try a larger model (33B+) or use the Anthropic API.'
      );
    }

    // Validate IOC formats and deduplicate
    if (result.iocs && result.iocs.length > 0) {
      const before = result.iocs.length;
      result.iocs = validateAndDeduplicateIOCs(result.iocs);
      const invalidCount = result.iocs.filter(i => i.validation && !i.validation.valid).length;
      const deduped = before - result.iocs.length;
      if (deduped > 0 || invalidCount > 0) {
        logger.info(
          { iocsBefore: before, iocsAfter: result.iocs.length, duplicatesRemoved: deduped, invalidCount },
          `IOC validation: ${deduped} duplicates merged, ${invalidCount} invalid flagged`,
        );
      }
    }

    // Validate / repair the Attack Flow causal graph (drops dangling edges,
    // breaks cycles, prunes orphans; falls back to undefined if too sparse)
    result.attack_flow = validateAttackFlow(result.attack_flow, result.attack_chain ?? []);

    // Determine latest version for this session
    const latestVersion = ((await db.prepare('SELECT MAX(version) as v FROM analysis_results WHERE session_id = ?').get(p.sessionId)) as { v: number | null }).v ?? 0;
    const newVersion = latestVersion + 1;

    await db.prepare('INSERT INTO analysis_results (id, session_id, version, result_json, created_at) VALUES (?,?,?,?,?)')
      .run(uuidv4(), p.sessionId, newVersion, JSON.stringify(result), now);

    await db.prepare('UPDATE sessions SET status = ?, updated_at = ?, severity = ?, version = ? WHERE id = ?')
      .run('complete', now, result.incident_summary.severity, newVersion, p.sessionId);

    // Auto-link threat actor (additive, failure-safe)
    try {
      await autoLinkThreatActor(db, p.sessionId, result, authReq.teamId, authReq.user.id);
    } catch (err) {
      logger.warn({ err, session_id: p.sessionId }, 'Threat actor auto-link failed (non-fatal)');
    }

    const techniques = result.attack_chain.map((t) => t.sub_technique_id ?? t.technique_id);

    appendAuditLog({
      analyst_name: authReq.user.displayName,
      user_id: authReq.user.id,
      session_id: p.sessionId,
      action: p.auditAction,
      input_hash: p.inputHash,
      techniques_identified: techniques,
      details: `severity=${result.incident_summary.severity}, audience=${p.audience}`,
    });

    analysisRunsTotal.inc({ result: 'success', kind: metricKind });
    analysisDurationSeconds.observe((Date.now() - startedAt) / 1000);

    sendEvent('complete', { result, version: newVersion });
    res.end();
  } catch (err) {
    // Mark the session failed so it doesn't sit in 'analyzing' forever and
    // the UI can offer a retry.
    try {
      await db.prepare('UPDATE sessions SET status = ?, updated_at = ? WHERE id = ?')
        .run('failed', Date.now(), p.sessionId);
    } catch { /* status update is best-effort */ }
    analysisRunsTotal.inc({ result: 'failed', kind: metricKind });
    analysisDurationSeconds.observe((Date.now() - startedAt) / 1000);
    const message = err instanceof Error ? err.message : 'Analysis failed';
    logger.warn({ err, session_id: p.sessionId }, 'Analysis pipeline failed');
    sendEvent('error', { error: message });
    res.end();
  }
}

// POST /api/analyze/rerun/:sessionId — re-run analysis from stored inputs (SSE)
router.post('/rerun/:sessionId', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const sessionId = req.params['sessionId'];
  const { audience: audienceOverride } = (req.body ?? {}) as { audience?: string };
  const db = getDb();

  const session = await verifySessionTeam(req, res, sessionId);
  if (!session) return;

  // Load stored inputs — saved before the original analysis ran
  const inputs = (await db.prepare(
    'SELECT input_type, content FROM session_inputs WHERE session_id = ? ORDER BY created_at ASC'
  ).all(sessionId)) as Array<{ input_type: string; content: string }>;

  if (inputs.length === 0) {
    res.status(400).json({ error: 'No stored inputs found for this session — run a new analysis instead' });
    return;
  }

  // Use the most recent content per input type (re-runs may have appended duplicates)
  let siemClean = '';
  let textClean = '';
  let logClean = '';
  for (const input of inputs) {
    if (input.input_type === 'siem') siemClean = input.content;
    else if (input.input_type === 'text') textClean = input.content;
    else if (input.input_type === 'log') logClean = input.content;
  }

  const audience = audienceOverride?.trim() || (session.audience as string) || 'soc';
  const now = Date.now();

  // Persist audience change if the analyst switched it for the re-run
  if (audienceOverride && audienceOverride !== session.audience) {
    await db.prepare('UPDATE sessions SET audience = ?, updated_at = ? WHERE id = ?')
      .run(audienceOverride, now, sessionId);
  }

  const inputRaw = [siemClean, textClean, logClean].join('||');
  const inputHash = crypto.createHash('sha256').update(inputRaw).digest('hex');

  await db.prepare('UPDATE sessions SET status = ?, updated_at = ? WHERE id = ?')
    .run('analyzing', now, sessionId);

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    session_id: sessionId,
    action: 'analysis_rerun_started',
    input_hash: inputHash,
    details: `audience=${audience}`,
  });

  await runAnalysisPipeline(req, res, {
    sessionId,
    siemClean,
    textClean,
    logClean,
    audience,
    inputHash,
    auditAction: 'analysis_rerun',
  });
});

// POST /api/analyze/export/stix
router.post('/export/stix', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const { session_id, tlp } = req.body as { session_id: string; tlp: string };
  if (!(await verifySessionTeam(req, res, session_id))) return;
  const db = getDb();
  const row = (await db.prepare('SELECT result_json, analyst_overrides FROM analysis_results WHERE session_id = ? ORDER BY version DESC LIMIT 1').get(session_id)) as { result_json: string; analyst_overrides?: string } | undefined;
  if (!row) return res.status(404).json({ error: 'No analysis found' });

  const settings = await loadMergedSettings(authReq.teamId);
  let result: AnalysisResult;
  let overrides: Record<string, string> | undefined;
  try {
    result = JSON.parse(row.result_json) as AnalysisResult;
    overrides = row.analyst_overrides ? JSON.parse(row.analyst_overrides) as Record<string, string> : undefined;
  } catch {
    res.status(500).json({ error: 'Stored analysis data is corrupted' });
    return;
  }
  filterFalsePositiveIocs(result, row.analyst_overrides);
  const analystName = settings.analyst_name || authReq.user.displayName;
  const orgName = settings.org_name || 'Security Operations';
  const bundle = buildStixBundle(result, session_id, tlp as 'AMBER', analystName, orgName, overrides);
  const date = new Date().toISOString().split('T')[0];
  const filename = `SNR-STIX-${session_id.slice(0, 8)}-${date}.json`;

  appendAuditLog({
    analyst_name: analystName,
    user_id: authReq.user.id,
    session_id,
    action: 'export_stix',
    outputs_generated: [filename],
  });

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.json(bundle);
});

// POST /api/analyze/export/navigator
router.post('/export/navigator', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const { session_id } = req.body as { session_id: string };
  if (!(await verifySessionTeam(req, res, session_id))) return;
  const db = getDb();
  const row = (await db.prepare('SELECT result_json FROM analysis_results WHERE session_id = ? ORDER BY version DESC LIMIT 1').get(session_id)) as { result_json: string } | undefined;
  const session = (await db.prepare('SELECT name FROM sessions WHERE id = ?').get(session_id)) as { name: string } | undefined;
  if (!row) return res.status(404).json({ error: 'No analysis found' });

  let result: AnalysisResult;
  try {
    result = JSON.parse(row.result_json) as AnalysisResult;
  } catch {
    res.status(500).json({ error: 'Stored analysis data is corrupted' });
    return;
  }
  const layer = buildNavigatorLayer(result, session?.name ?? 'Incident');
  const date = new Date().toISOString().split('T')[0];
  const filename = `SNR-Navigator-${session_id.slice(0, 8)}-${date}.json`;

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    session_id,
    action: 'export_navigator',
    outputs_generated: [filename],
  });

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.json(layer);
});

// ── IOC text formatter ─────────────────────────────────────────────────────
// Groups IOCs by type, outputs only the value per line, section headers as "# Type"
const TYPE_LABELS: Record<string, string> = {
  ip: 'IP Address',
  domain: 'Domain',
  url: 'URL',
  hash: 'Hash',
  file: 'File Name',
  email: 'Email Address',
  registry: 'Registry Key',
  mutex: 'Mutex',
  pipe: 'Named Pipe',
  service: 'Service Name',
  useragent: 'User Agent',
};

function formatDetectionRules(rules: AnalysisResult['detection_rules'], sessionName: string, date: string, tlp: string): string {
  const lines: string[] = [
    `# Detection Rules Export — ${sessionName}`,
    `# Generated: ${date} | TLP:${tlp}`,
    `# Source: SNR Signal-to-Noise`,
    `# Rules: ${rules.length} total (${rules.filter(r => r.source === 'extracted').length} extracted, ${rules.filter(r => r.source === 'generated').length} generated)`,
    '',
  ];

  // Group by rule_type
  const groups = new Map<string, typeof rules>();
  for (const rule of rules) {
    const key = rule.rule_type.toLowerCase();
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(rule);
  }

  const typeLabels: Record<string, string> = {
    sigma: 'Sigma Rules',
    yara: 'YARA Rules',
    suricata: 'Suricata Rules',
  };

  for (const [type, typeRules] of groups) {
    const label = typeLabels[type] ?? type.charAt(0).toUpperCase() + type.slice(1);
    lines.push(`${'='.repeat(60)}`);
    lines.push(`# ${label}`);
    lines.push(`${'='.repeat(60)}`);
    lines.push('');

    for (const rule of typeRules) {
      lines.push(`# Rule: ${rule.rule_name}`);
      lines.push(`# Description: ${rule.description}`);
      lines.push(`# Source: ${rule.source} | Confidence: ${rule.confidence}${rule.related_technique ? ` | ATT&CK: ${rule.related_technique}` : ''}`);
      lines.push('');
      lines.push(rule.rule_content);
      lines.push('');
      lines.push(`${'─'.repeat(40)}`);
      lines.push('');
    }
  }

  return lines.join('\n');
}

function formatIocText(iocs: AnalysisResult['iocs'], sessionName: string, date: string, tlp: string): string {
  // Group by type, preserving insertion order of first occurrence
  const groups = new Map<string, string[]>();
  for (const ioc of iocs) {
    const key = ioc.type.toLowerCase();
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(ioc.value);
  }

  const lines: string[] = [
    `# IOC Export — ${sessionName}`,
    `# Generated: ${date} | TLP:${tlp}`,
    `# Source: SNR Signal-to-Noise`,
    '',
  ];

  let first = true;
  for (const [type, values] of groups) {
    if (!first) lines.push('');
    first = false;
    const label = TYPE_LABELS[type] ?? type.charAt(0).toUpperCase() + type.slice(1);
    lines.push(`# ${label}`);
    for (const v of values) lines.push(v);
  }

  return lines.join('\n');
}

// POST /api/analyze/export/eml
router.post('/export/eml', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const { session_id, audience, tlp, attach_stix, attach_navigator, attach_iocs, attach_detection_rules, diagram_jpg_b64, email_content_overrides } = req.body as {
    session_id: string;
    audience: string;
    tlp: string;
    attach_stix?: boolean;
    attach_navigator?: boolean;
    attach_iocs?: boolean;
    attach_detection_rules?: boolean;
    diagram_jpg_b64?: string;
    email_content_overrides?: Partial<AnalysisResult['email_content']>;
  };

  if (!(await verifySessionTeam(req, res, session_id))) return;
  const db = getDb();
  const row = (await db.prepare('SELECT result_json, analyst_overrides FROM analysis_results WHERE session_id = ? ORDER BY version DESC LIMIT 1').get(session_id)) as { result_json: string; analyst_overrides?: string } | undefined;
  const session = (await db.prepare('SELECT name FROM sessions WHERE id = ?').get(session_id)) as { name: string } | undefined;
  if (!row) return res.status(404).json({ error: 'No analysis found' });

  const settings = await loadMergedSettings(authReq.teamId);
  const analystName = settings.analyst_name || authReq.user.displayName;
  const analystEmail = settings.analyst_email || authReq.user.email;
  const orgName = settings.org_name || 'Security Operations';

  let result: AnalysisResult;
  let savedOverrides: Record<string, string> | null;
  try {
    result = JSON.parse(row.result_json) as AnalysisResult;
    // Apply saved overrides first, then request overrides on top
    savedOverrides = row.analyst_overrides ? JSON.parse(row.analyst_overrides) as Record<string, string> : null;
  } catch {
    res.status(500).json({ error: 'Stored analysis data is corrupted' });
    return;
  }
  filterFalsePositiveIocs(result, row.analyst_overrides);
  if (savedOverrides) {
    result.email_content = { ...result.email_content, ...savedOverrides };
  }
  if (email_content_overrides) {
    result.email_content = { ...result.email_content, ...email_content_overrides };
  }

  // Ensure subject line reflects the current severity_badge.
  // Subject format: TLP:{LEVEL} | {Severity} | {Category} | {Date}
  const subjectStr = (result.email_content.subject as string) ?? '';
  const subjectParts = subjectStr.split('|').map((s: string) => s.trim());
  if (subjectParts.length >= 2) {
    const currentSev = (result.email_content.severity_badge as string) ?? '';
    if (currentSev && subjectParts[1] !== currentSev) {
      subjectParts[1] = currentSev;
      result.email_content.subject = subjectParts.join(' | ');
    }
  }

  const attachments: Array<{ filename: string; content: Buffer; contentType: string }> = [];
  const date = new Date().toISOString().split('T')[0];

  if (attach_stix) {
    const overrides = row.analyst_overrides ? JSON.parse(row.analyst_overrides) as Record<string, string> : undefined;
    const bundle = buildStixBundle(result, session_id, tlp as 'AMBER', analystName, orgName, overrides);
    attachments.push({
      filename: `SNR-STIX-${session_id.slice(0, 8)}-${date}.json`,
      content: Buffer.from(JSON.stringify(bundle, null, 2)),
      contentType: 'application/json',
    });
  }

  if (attach_navigator) {
    const layer = buildNavigatorLayer(result, session?.name ?? 'Incident');
    attachments.push({
      filename: `SNR-Navigator-${session_id.slice(0, 8)}-${date}.json`,
      content: Buffer.from(JSON.stringify(layer, null, 2)),
      contentType: 'application/json',
    });
  }

  if (attach_iocs && result.iocs.length > 0) {
    attachments.push({
      filename: `SNR-IOCs-${session_id.slice(0, 8)}-${date}.txt`,
      content: Buffer.from(formatIocText(result.iocs, session?.name ?? 'Incident', date, tlp), 'utf-8'),
      contentType: 'text/plain',
    });
  }

  if (attach_detection_rules && result.detection_rules && result.detection_rules.length > 0) {
    attachments.push({
      filename: `SNR-Detection-Rules-${session_id.slice(0, 8)}-${date}.txt`,
      content: Buffer.from(formatDetectionRules(result.detection_rules, session?.name ?? 'Incident', date, tlp), 'utf-8'),
      contentType: 'text/plain',
    });
  }

  if (diagram_jpg_b64) {
    try {
      const imgBuf = Buffer.from(diagram_jpg_b64, 'base64');
      // Detect PNG by magic bytes (89 50 4E 47) or default to JPEG
      const isPng = imgBuf.length > 4 && imgBuf[0] === 0x89 && imgBuf[1] === 0x50 && imgBuf[2] === 0x4E && imgBuf[3] === 0x47;
      attachments.push({
        filename: `SNR-AttackChain-${session_id.slice(0, 8)}-${date}.${isPng ? 'png' : 'jpg'}`,
        content: imgBuf,
        contentType: isPng ? 'image/png' : 'image/jpeg',
      });
    } catch { /* invalid base64 — skip silently */ }
  }

  const emlSections = parseSections(settings.report_sections || '');

  const eml = buildEml({
    result,
    audience,
    tlp: tlp as 'AMBER',
    analystEmail,
    analystName,
    ccMap: buildCcMap(settings),
    attachments,
    sections: emlSections,
    headerText: settings.email_header_text,
    footerText: settings.email_footer_text,
    signature: settings.email_signature,
    customPreamble: settings.email_custom_preamble,
    audienceIntro: settings[`custom_intro_${audience}`],
    primaryColor: sanitizeColor(settings.email_primary_color),
    secondaryColor: sanitizeColor(settings.email_secondary_color),
    logoDataUri: settings.email_logo_data || undefined,
    fontFamily: settings.email_font_family || undefined,
    bodyFontSize: settings.email_body_font_size || undefined,
    template: settings.email_template || undefined,
    orgName,
  });

  const filename = `SNR-Brief-${audience}-${session_id.slice(0, 8)}-${date}.eml`;

  appendAuditLog({
    analyst_name: analystName,
    user_id: authReq.user.id,
    session_id,
    action: 'export_eml',
    outputs_generated: [filename],
    details: `audience=${audience}, tlp=${tlp}`,
  });

  res.setHeader('Content-Type', 'message/rfc822');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(eml);
});

// POST /api/analyze/export/zip — Export All
router.post('/export/zip', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const { session_id, audience, tlp, attach_iocs, diagram_jpg_b64, email_content_overrides } = req.body as {
    session_id: string;
    audience: string;
    tlp: string;
    attach_iocs?: boolean;
    diagram_jpg_b64?: string;
    email_content_overrides?: Partial<AnalysisResult['email_content']>;
  };
  if (!(await verifySessionTeam(req, res, session_id))) return;
  const db = getDb();
  const row = (await db.prepare('SELECT result_json, analyst_overrides FROM analysis_results WHERE session_id = ? ORDER BY version DESC LIMIT 1').get(session_id)) as { result_json: string; analyst_overrides?: string } | undefined;
  const session = (await db.prepare('SELECT name FROM sessions WHERE id = ?').get(session_id)) as { name: string } | undefined;
  if (!row) return res.status(404).json({ error: 'No analysis found' });

  const settings = await loadMergedSettings(authReq.teamId);
  const analystName = settings.analyst_name || authReq.user.displayName;
  const analystEmail = settings.analyst_email || authReq.user.email;
  const orgName = settings.org_name || 'Security Operations';

  let result: AnalysisResult;
  let zipSavedOverrides: Record<string, string> | null;
  let overrides: Record<string, string> | undefined;
  try {
    result = JSON.parse(row.result_json) as AnalysisResult;
    // Apply saved overrides first, then request overrides on top
    zipSavedOverrides = row.analyst_overrides ? JSON.parse(row.analyst_overrides) as Record<string, string> : null;
    overrides = row.analyst_overrides ? JSON.parse(row.analyst_overrides) as Record<string, string> : undefined;
  } catch {
    res.status(500).json({ error: 'Stored analysis data is corrupted' });
    return;
  }
  filterFalsePositiveIocs(result, row.analyst_overrides);
  if (zipSavedOverrides) {
    result.email_content = { ...result.email_content, ...zipSavedOverrides };
  }
  if (email_content_overrides) {
    result.email_content = { ...result.email_content, ...email_content_overrides };
  }

  // Ensure subject line reflects the current severity_badge
  const zipSubject = (result.email_content.subject as string) ?? '';
  const zipSubjectParts = zipSubject.split('|').map((s: string) => s.trim());
  if (zipSubjectParts.length >= 2) {
    const zipSev = (result.email_content.severity_badge as string) ?? '';
    if (zipSev && zipSubjectParts[1] !== zipSev) {
      zipSubjectParts[1] = zipSev;
      result.email_content.subject = zipSubjectParts.join(' | ');
    }
  }

  const date = new Date().toISOString().split('T')[0];
  const shortId = session_id.slice(0, 8);

  const bundle = buildStixBundle(result, session_id, tlp as 'AMBER', analystName, orgName, overrides);
  const layer = buildNavigatorLayer(result, session?.name ?? 'Incident');
  const zipAttachments: Array<{ filename: string; content: Buffer; contentType: string }> = [
    { filename: `SNR-STIX-${shortId}-${date}.json`, content: Buffer.from(JSON.stringify(bundle, null, 2)), contentType: 'application/json' },
  ];

  if (attach_iocs && result.iocs.length > 0) {
    zipAttachments.push({
      filename: `SNR-IOCs-${shortId}-${date}.txt`,
      content: Buffer.from(formatIocText(result.iocs, session?.name ?? 'Incident', date, tlp), 'utf-8'),
      contentType: 'text/plain',
    });
  }

  // Always include detection rules in zip if they exist
  if (result.detection_rules && result.detection_rules.length > 0) {
    zipAttachments.push({
      filename: `SNR-Detection-Rules-${shortId}-${date}.txt`,
      content: Buffer.from(formatDetectionRules(result.detection_rules, session?.name ?? 'Incident', date, tlp), 'utf-8'),
      contentType: 'text/plain',
    });
  }

  if (diagram_jpg_b64) {
    try {
      const imgBuf = Buffer.from(diagram_jpg_b64, 'base64');
      const isPng = imgBuf.length > 4 && imgBuf[0] === 0x89 && imgBuf[1] === 0x50 && imgBuf[2] === 0x4E && imgBuf[3] === 0x47;
      zipAttachments.push({
        filename: `SNR-AttackChain-${shortId}-${date}.${isPng ? 'png' : 'jpg'}`,
        content: imgBuf,
        contentType: isPng ? 'image/png' : 'image/jpeg',
      });
    } catch { /* invalid base64 — skip */ }
  }

  const zipSections = parseSections(settings.report_sections || '');

  const eml = buildEml({
    result,
    audience,
    tlp: tlp as 'AMBER',
    analystEmail,
    analystName,
    ccMap: buildCcMap(settings),
    attachments: zipAttachments,
    sections: zipSections,
    headerText: settings.email_header_text,
    footerText: settings.email_footer_text,
    signature: settings.email_signature,
    customPreamble: settings.email_custom_preamble,
    audienceIntro: settings[`custom_intro_${audience}`],
    primaryColor: sanitizeColor(settings.email_primary_color),
    secondaryColor: sanitizeColor(settings.email_secondary_color),
    logoDataUri: settings.email_logo_data || undefined,
    fontFamily: settings.email_font_family || undefined,
    bodyFontSize: settings.email_body_font_size || undefined,
    template: settings.email_template || undefined,
    orgName,
  });

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="SNR-Export-${shortId}-${date}.zip"`);

  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.pipe(res);
  archive.append(Buffer.from(JSON.stringify(bundle, null, 2)), { name: `SNR-STIX-${shortId}-${date}.json` });
  archive.append(Buffer.from(JSON.stringify(layer, null, 2)), { name: `SNR-Navigator-${shortId}-${date}.json` });
  archive.append(Buffer.from(eml), { name: `SNR-Brief-${audience}-${shortId}-${date}.eml` });
  archive.append(Buffer.from(JSON.stringify(result, null, 2)), { name: `SNR-Analysis-${shortId}-${date}.json` });
  if (attach_iocs && result.iocs.length > 0) {
    const iocTxt = zipAttachments.find(a => a.filename.endsWith('.txt'));
    if (iocTxt) archive.append(iocTxt.content, { name: iocTxt.filename });
  }
  if (diagram_jpg_b64) {
    const diagramAtt = zipAttachments.find(a => a.filename.endsWith('.jpg') || a.filename.endsWith('.png'));
    if (diagramAtt) archive.append(diagramAtt.content, { name: diagramAtt.filename });
  }
  await archive.finalize();

  appendAuditLog({
    analyst_name: analystName,
    user_id: authReq.user.id,
    session_id,
    action: 'export_zip',
    outputs_generated: [`SNR-Export-${shortId}-${date}.zip`],
  });
});

// POST /api/analyze/report-preview — Return rendered markdown as text (no download header)
router.post('/report-preview', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const { session_id, audience = 'general', tlp = 'AMBER', email_content_overrides } = req.body as {
    session_id: string;
    audience?: string;
    tlp?: string;
    email_content_overrides?: Partial<AnalysisResult['email_content']>;
  };
  if (!session_id) { res.status(400).json({ error: 'session_id required' }); return; }
  if (!(await verifySessionTeam(req, res, session_id))) return;

  const db = getDb();
  const row = (await db.prepare('SELECT result_json, analyst_overrides FROM analysis_results WHERE session_id = ? ORDER BY version DESC LIMIT 1').get(session_id)) as { result_json: string; analyst_overrides?: string } | undefined;
  if (!row) { res.status(404).json({ error: 'No analysis found' }); return; }

  let result: AnalysisResult;
  let savedOverrides: Record<string, string> | null;
  try {
    result = JSON.parse(row.result_json) as AnalysisResult;
    savedOverrides = row.analyst_overrides ? JSON.parse(row.analyst_overrides) as Record<string, string> : null;
  } catch {
    res.status(500).json({ error: 'Stored analysis data is corrupted' });
    return;
  }
  filterFalsePositiveIocs(result, row.analyst_overrides);
  if (savedOverrides) {
    result.email_content = { ...result.email_content, ...savedOverrides };
  }
  if (email_content_overrides) {
    result.email_content = { ...result.email_content, ...email_content_overrides };
  }
  const settings = await loadMergedSettings(authReq.teamId);
  const analystName = settings.analyst_name || 'CTI Analyst';
  const orgName = settings.org_name || '';
  const sections = parseSections(settings.report_sections || '');

  const markdown = buildMarkdownReport(result, sections, { analystName, orgName, tlp, audience, template: settings.report_template || undefined });

  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.send(markdown);
});

// POST /api/analyze/export/report — Download Markdown CTI Report
router.post('/export/report', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const { session_id, audience, tlp, email_content_overrides } = req.body as {
    session_id: string;
    audience: string;
    tlp: string;
    email_content_overrides?: Partial<AnalysisResult['email_content']>;
  };

  if (!session_id) {
    res.status(400).json({ error: 'session_id required' });
    return;
  }
  if (!(await verifySessionTeam(req, res, session_id))) return;

  const db = getDb();
  const row = (await db.prepare('SELECT result_json, analyst_overrides FROM analysis_results WHERE session_id = ? ORDER BY version DESC LIMIT 1').get(session_id)) as
    { result_json: string; analyst_overrides?: string } | undefined;
  const session = (await db.prepare('SELECT name, status FROM sessions WHERE id = ?').get(session_id)) as
    { name: string; status: string } | undefined;

  if (!row) {
    res.status(404).json({ error: 'No analysis found for this session' });
    return;
  }

  let result: AnalysisResult;
  let savedOverrides: Record<string, string> | null;
  try {
    result = JSON.parse(row.result_json) as AnalysisResult;
    savedOverrides = row.analyst_overrides ? JSON.parse(row.analyst_overrides) as Record<string, string> : null;
  } catch {
    res.status(500).json({ error: 'Stored analysis data is corrupted' });
    return;
  }
  filterFalsePositiveIocs(result, row.analyst_overrides);
  if (savedOverrides) {
    result.email_content = { ...result.email_content, ...savedOverrides };
  }
  if (email_content_overrides) {
    result.email_content = { ...result.email_content, ...email_content_overrides };
  }
  const settings = await loadMergedSettings(authReq.teamId);

  const analystName = settings.analyst_name || 'CTI Analyst';
  const orgName     = settings.org_name     || '';
  const sections    = parseSections(settings.report_sections || '');

  const markdown = buildMarkdownReport(result, sections, {
    analystName,
    orgName,
    tlp: tlp || 'AMBER',
    audience: audience || 'general',
    template: settings.report_template || undefined,
  });

  const date     = new Date().toISOString().split('T')[0];
  const shortId  = session_id.slice(0, 8);
  const filename = `SNR-CTI-Report-${shortId}-${date}.md`;

  appendAuditLog({
    analyst_name: analystName,
    user_id: authReq.user.id,
    session_id,
    action: 'export_report',
    outputs_generated: [filename],
    details: `tlp=${tlp}, audience=${audience}`,
  });

  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(markdown);
});

// POST /api/analyze/export/detection-rules — Download detection rules as .txt
router.post('/export/detection-rules', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const { session_id, tlp } = req.body as { session_id: string; tlp?: string };

  if (!session_id) {
    res.status(400).json({ error: 'session_id required' });
    return;
  }
  if (!(await verifySessionTeam(req, res, session_id))) return;

  const db = getDb();
  const row = (await db.prepare('SELECT result_json FROM analysis_results WHERE session_id = ? ORDER BY version DESC LIMIT 1').get(session_id)) as { result_json: string } | undefined;
  const session = (await db.prepare('SELECT name FROM sessions WHERE id = ?').get(session_id)) as { name: string } | undefined;

  if (!row) {
    res.status(404).json({ error: 'No analysis found' });
    return;
  }

  let result: AnalysisResult;
  try {
    result = JSON.parse(row.result_json) as AnalysisResult;
  } catch {
    res.status(500).json({ error: 'Stored analysis data is corrupted' });
    return;
  }

  const rules = result.detection_rules ?? [];
  if (rules.length === 0) {
    res.status(404).json({ error: 'No detection rules found in this analysis' });
    return;
  }

  const date = new Date().toISOString().split('T')[0];
  const shortId = session_id.slice(0, 8);
  const filename = `SNR-Detection-Rules-${shortId}-${date}.txt`;
  const text = formatDetectionRules(rules, session?.name ?? 'Incident', date, tlp ?? 'AMBER');

  const settings = await loadMergedSettings(authReq.teamId);
  const analystName = settings.analyst_name || authReq.user.displayName;

  appendAuditLog({
    analyst_name: analystName,
    user_id: authReq.user.id,
    session_id,
    action: 'export_detection_rules',
    outputs_generated: [filename],
    details: `rules=${rules.length}`,
  });

  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(text);
});

// POST /api/analyze/export/attack-flow — Download MITRE Attack Flow Builder (.afb)
router.post('/export/attack-flow', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const { session_id } = req.body as { session_id: string };

  if (!session_id) {
    res.status(400).json({ error: 'session_id required' });
    return;
  }
  if (!(await verifySessionTeam(req, res, session_id))) return;

  const db = getDb();
  const row = (await db.prepare('SELECT result_json FROM analysis_results WHERE session_id = ? ORDER BY version DESC LIMIT 1').get(session_id)) as { result_json: string } | undefined;
  if (!row) {
    res.status(404).json({ error: 'No analysis found' });
    return;
  }

  let result: AnalysisResult;
  try {
    result = JSON.parse(row.result_json) as AnalysisResult;
  } catch {
    res.status(500).json({ error: 'Stored analysis data is corrupted' });
    return;
  }

  if (!result.attack_flow || result.attack_flow.nodes.length === 0) {
    res.status(404).json({ error: 'No attack flow available for this session. Re-analyze to generate one.' });
    return;
  }

  const afb = buildAfb(result);
  const date = new Date().toISOString().split('T')[0];
  const shortId = session_id.slice(0, 8);
  const filename = `SNR-AttackFlow-${shortId}-${date}.afb`;

  const settings = await loadMergedSettings(authReq.teamId);
  const analystName = settings.analyst_name || authReq.user.displayName;

  appendAuditLog({
    analyst_name: analystName,
    user_id: authReq.user.id,
    session_id,
    action: 'export_attack_flow',
    outputs_generated: [filename],
    details: `nodes=${result.attack_flow.nodes.length}, edges=${result.attack_flow.edges.length}`,
  });

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(JSON.stringify(afb, null, 2));
});

// POST /api/analyze/export/iocs-csv — Download IOCs as CSV
router.post('/export/iocs-csv', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const { session_id, tlp } = req.body as { session_id: string; tlp?: string };

  if (!session_id) {
    res.status(400).json({ error: 'session_id required' });
    return;
  }
  if (!(await verifySessionTeam(req, res, session_id))) return;

  const db = getDb();
  const row = (await db.prepare('SELECT result_json, analyst_overrides FROM analysis_results WHERE session_id = ? ORDER BY version DESC LIMIT 1').get(session_id)) as { result_json: string; analyst_overrides?: string } | undefined;
  if (!row) return res.status(404).json({ error: 'No analysis found' });

  let result: AnalysisResult;
  try {
    result = JSON.parse(row.result_json) as AnalysisResult;
  } catch {
    res.status(500).json({ error: 'Stored analysis data is corrupted' });
    return;
  }
  filterFalsePositiveIocs(result, row.analyst_overrides);

  const iocs = result.iocs ?? [];
  if (iocs.length === 0) {
    res.status(404).json({ error: 'No IOCs found in this analysis' });
    return;
  }

  const resolvedTlp = tlp ?? 'AMBER';
  const csvLines: string[] = ['type,value,context,confidence,tlp'];
  for (const ioc of iocs) {
    const escapeCsv = (s: string) => `"${s.replace(/"/g, '""')}"`;
    csvLines.push([
      escapeCsv(ioc.type),
      escapeCsv(ioc.value),
      escapeCsv(ioc.context),
      escapeCsv((ioc as Record<string, unknown>).confidence as string ?? ''),
      escapeCsv(resolvedTlp),
    ].join(','));
  }
  const csv = csvLines.join('\n');

  const date = new Date().toISOString().split('T')[0];
  const shortId = session_id.slice(0, 8);
  const filename = `SNR-IOCs-${shortId}-${date}.csv`;

  const settings = await loadMergedSettings(authReq.teamId);
  const analystName = settings.analyst_name || authReq.user.displayName;

  appendAuditLog({
    analyst_name: analystName,
    user_id: authReq.user.id,
    session_id,
    action: 'export_iocs_csv',
    outputs_generated: [filename],
    details: `iocs=${iocs.length}, tlp=${resolvedTlp}`,
  });

  logger.info(`IOC CSV export: ${filename} (${iocs.length} indicators)`);

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(csv);
});

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ── Settings helpers ──────────────────────────────────────────────────────────

/** Validate CSS color value (hex only) to prevent CSS injection */
function sanitizeColor(value: string | undefined): string | undefined {
  if (!value) return undefined;
  return /^#[0-9a-fA-F]{3,6}$/.test(value) ? value : undefined;
}

function buildCcMap(settings: Record<string, string>): Record<string, string[]> {
  const audiences = ['purple_team', 'soc', 'red_team', 'dr', 'general'];
  const map: Record<string, string[]> = {};
  for (const aud of audiences) {
    const raw = settings[`cc_${aud}`] ?? '';
    if (raw.trim()) {
      map[aud] = raw.split(',').map((e) => e.trim()).filter(Boolean);
    }
  }
  return map;
}

export default router;
