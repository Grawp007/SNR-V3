import type { AnalysisResult, Session, ThreatActorSummary } from '../types';

const BASE = '/api';

/**
 * Authenticated fetch wrapper — injects Authorization + X-Team-Id headers.
 * Falls back to regular fetch if no token is stored.
 */
export async function authFetch(url: string, init?: RequestInit): Promise<Response> {
  const token = localStorage.getItem('snr_token');
  const teamId = localStorage.getItem('snr_active_team');
  const headers = new Headers(init?.headers);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (teamId) headers.set('X-Team-Id', teamId);

  const res = await fetch(url, { ...init, headers });

  // If 401 and we have a refresh token, try to refresh
  if (res.status === 401 && token) {
    const refreshToken = localStorage.getItem('snr_refresh_token');
    if (refreshToken) {
      const refreshRes = await fetch(`${BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken }),
      });
      if (refreshRes.ok) {
        const data = await refreshRes.json() as { token: string; refreshToken: string };
        localStorage.setItem('snr_token', data.token);
        localStorage.setItem('snr_refresh_token', data.refreshToken);
        headers.set('Authorization', `Bearer ${data.token}`);
        return fetch(url, { ...init, headers });
      } else {
        // Refresh failed — clear tokens, redirect to login
        localStorage.removeItem('snr_token');
        localStorage.removeItem('snr_refresh_token');
        localStorage.removeItem('snr_active_team');
        window.location.reload();
      }
    }
  }

  return res;
}

export async function fetchSessions(filters?: {
  search?: string;
  severity?: string;
  audience?: string;
  tags?: string;
}): Promise<Session[]> {
  const params = new URLSearchParams();
  if (filters?.search) params.set('search', filters.search);
  if (filters?.severity) params.set('severity', filters.severity);
  if (filters?.audience) params.set('audience', filters.audience);
  if (filters?.tags) params.set('tags', filters.tags);
  const qs = params.toString();
  const res = await authFetch(`${BASE}/sessions${qs ? `?${qs}` : ''}`);
  if (!res.ok) throw new Error('Failed to load sessions');
  const data = await res.json() as { sessions: Array<Session & { tags?: string | string[] }> };
  // Backend stores tags as JSON string — parse if needed
  return data.sessions.map((s) => ({
    ...s,
    tags: typeof s.tags === 'string' ? JSON.parse(s.tags || '[]') : (s.tags ?? []),
  }));
}

export async function fetchAllSessions(limit = 100, offset = 0): Promise<{ sessions: Session[]; total: number }> {
  const res = await authFetch(`${BASE}/sessions?limit=${limit}&offset=${offset}`);
  if (!res.ok) throw new Error('Failed to load sessions');
  const data = await res.json() as { sessions: Session[]; total: number };
  return { sessions: data.sessions, total: data.total };
}

export interface AuditLogEntry {
  id: number;
  timestamp: number;
  analyst_name: string;
  session_id: string | null;
  action: string;
  input_hash: string | null;
  outputs_generated: string | null;
  techniques_identified: string | null;
  details: string | null;
}

export interface TechniqueSession {
  id: string;
  name: string;
  severity: string | null;
  created_at: number;
}

export interface TechniqueEntry {
  technique_id: string;
  technique_name: string;
  tactic: string;
  sessions: TechniqueSession[];
}

export interface AnalyticsData {
  sessionsOverTime: { date: string; count: number }[];
  severityDistribution: { severity: string; count: number }[];
  audienceBreakdown: { audience: string; count: number }[];
  exportActivity: { export_type: string; count: number }[];
  iocDistribution: { ioc_type: string; count: number }[];
  techniqueMap: TechniqueEntry[];
}

export async function fetchAnalytics(days: number): Promise<AnalyticsData> {
  const res = await authFetch(`${BASE}/analytics?days=${days}`);
  if (!res.ok) throw new Error('Failed to load analytics');
  return res.json() as Promise<AnalyticsData>;
}

export async function fetchAuditLog(): Promise<AuditLogEntry[]> {
  const res = await authFetch(`${BASE}/sessions/audit/log`);
  if (!res.ok) throw new Error('Failed to load audit log');
  const data = await res.json() as { rows: AuditLogEntry[] };
  return data.rows;
}

export async function fetchSession(id: string): Promise<{
  session: Session;
  result: AnalysisResult | null;
  analystOverrides: Record<string, string>;
  inputs: Array<{ input_type: string; content: string; filename?: string }>;
  note: string;
  linked_threat_actor: { id: string; name: string } | null;
}> {
  const res = await authFetch(`${BASE}/sessions/${id}`);
  if (!res.ok) throw new Error('Failed to load session');
  const data = await res.json();
  // Parse tags JSON string to array (backend stores as JSON string in SQLite)
  if (data.session) {
    const t = data.session.tags;
    data.session.tags = typeof t === 'string' ? JSON.parse(t || '[]') : (t ?? []);
  }
  return data;
}

export async function createSession(data: {
  name: string;
  incident_id?: string;
  audience: string;
}): Promise<string> {
  const res = await authFetch(`${BASE}/sessions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to create session');
  const j = await res.json() as { id: string };
  return j.id;
}

export async function saveNote(sessionId: string, content: string): Promise<void> {
  await authFetch(`${BASE}/sessions/${sessionId}/note`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content }),
  });
}

export async function updateSessionName(sessionId: string, name: string): Promise<void> {
  await authFetch(`${BASE}/sessions/${sessionId}/name`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
}

export async function saveOverrides(sessionId: string, overrides: Record<string, string>): Promise<void> {
  await authFetch(`${BASE}/sessions/${sessionId}/overrides`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ overrides }),
  });
}

export async function streamAnalysis(
  params: {
    session_id: string;
    siem_input?: string;
    text_input?: string;
    logFile?: File;
    audience: string;
    redacted_strings?: string[];
  },
  onChunk: (text: string) => void,
  onComplete: (result: AnalysisResult) => void,
  onError: (err: string) => void,
  onStatus?: (msg: string, phase: number) => void
): Promise<void> {
  const formData = new FormData();
  formData.append('session_id', params.session_id);
  formData.append('audience', params.audience);
  if (params.siem_input) formData.append('siem_input', params.siem_input);
  if (params.text_input) formData.append('text_input', params.text_input);
  if (params.logFile) formData.append('logFile', params.logFile);
  if (params.redacted_strings?.length) {
    formData.append('redacted_strings', JSON.stringify(params.redacted_strings));
  }

  const res = await authFetch(`${BASE}/analyze`, { method: 'POST', body: formData });
  if (!res.ok || !res.body) {
    onError(`HTTP ${res.status}`);
    return;
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';

    for (const line of lines) {
      if (line.startsWith('event: chunk')) continue;
      if (line.startsWith('data: ')) {
        const data = line.slice(6);
        try {
          const parsed = JSON.parse(data) as { text?: string; result?: AnalysisResult; error?: string; message?: string; phase?: number };
          if (parsed.text) onChunk(parsed.text);
          else if (parsed.result) onComplete(parsed.result);
          else if (parsed.error) onError(parsed.error);
          else if (parsed.message && onStatus) onStatus(parsed.message, parsed.phase ?? 1);
        } catch {
          // partial event, continue
        }
      }
    }
  }
}

/** Re-run analysis on an existing session using its stored inputs (SSE). */
export async function streamReanalysis(
  sessionId: string,
  audience: string | undefined,
  onChunk: (text: string) => void,
  onComplete: (result: AnalysisResult) => void,
  onError: (err: string) => void,
  onStatus?: (msg: string, phase: number) => void
): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/rerun/${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(audience ? { audience } : {}),
  });
  if (!res.ok || !res.body) {
    // Non-SSE failure (e.g. no stored inputs) returns JSON
    const d = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    onError(d.error || `HTTP ${res.status}`);
    return;
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';

    for (const line of lines) {
      if (line.startsWith('event: chunk')) continue;
      if (line.startsWith('data: ')) {
        const data = line.slice(6);
        try {
          const parsed = JSON.parse(data) as { text?: string; result?: AnalysisResult; error?: string; message?: string; phase?: number };
          if (parsed.text) onChunk(parsed.text);
          else if (parsed.result) onComplete(parsed.result);
          else if (parsed.error) onError(parsed.error);
          else if (parsed.message && onStatus) onStatus(parsed.message, parsed.phase ?? 1);
        } catch {
          // partial event, continue
        }
      }
    }
  }
}

export async function fetchEmailPreview(params: {
  showObservations?: boolean;
  showTechniques?: boolean;
  showAffectedAssets?: boolean;
  showActions?: boolean;
  showIocs?: boolean;
  showNextSteps?: boolean;
  audience?: string;
  tlp?: string;
}): Promise<string> {
  const qs = new URLSearchParams();
  if (params.showObservations   === false) qs.set('show_observations',    'false');
  if (params.showTechniques     === false) qs.set('show_techniques',      'false');
  if (params.showAffectedAssets === false) qs.set('show_affected_assets', 'false');
  if (params.showActions        === false) qs.set('show_actions',         'false');
  if (params.showIocs           === false) qs.set('show_iocs',            'false');
  if (params.showNextSteps      === false) qs.set('show_next_steps',      'false');
  if (params.audience) qs.set('audience', params.audience);
  if (params.tlp)      qs.set('tlp', params.tlp);
  const res = await authFetch(`${BASE}/analyze/email-preview?${qs.toString()}`);
  if (!res.ok) throw new Error('Failed to load email preview');
  return res.text();
}

/** Preview the email rendered through an in-progress (unsaved) body template. */
export async function fetchEmailTemplatePreview(params: {
  template: string;
  audience?: string;
  tlp?: string;
}): Promise<string> {
  const res = await authFetch(`${BASE}/analyze/email-preview`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ template: params.template, audience: params.audience ?? 'soc', tlp: params.tlp ?? 'AMBER' }),
  });
  if (!res.ok) throw new Error('Failed to load email preview');
  return res.text();
}

export async function exportStix(sessionId: string, tlp: string): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/stix`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, tlp }),
  });
  if (!res.ok) throw new Error('STIX export failed');
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'stix.json'));
}

export async function exportNavigator(sessionId: string): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/navigator`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId }),
  });
  if (!res.ok) throw new Error('Navigator export failed');
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'navigator.json'));
}

export async function exportDetectionRules(sessionId: string, tlp: string): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/detection-rules`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, tlp }),
  });
  if (!res.ok) throw new Error('Detection rules export failed');
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'detection-rules.txt'));
}

export async function exportAttackFlow(sessionId: string): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/attack-flow`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Attack Flow export failed' }));
    throw new Error(d.error || 'Attack Flow export failed');
  }
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'attack-flow.afb'));
}

export async function exportIocsCsv(sessionId: string, tlp: string): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/iocs-csv`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, tlp }),
  });
  if (!res.ok) throw new Error('IOC CSV export failed');
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'iocs.csv'));
}

export async function deleteSession(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/sessions/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete session');
}

/** Undo a soft delete — sessions are recoverable for 7 days after deletion. */
export async function restoreSession(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/sessions/${id}/restore`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to restore session');
}

export async function bulkDeleteSessions(sessionIds: string[]): Promise<{ deleted: number; errors: string[] }> {
  const res = await authFetch(`${BASE}/sessions/bulk-delete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_ids: sessionIds }),
  });
  if (!res.ok) throw new Error('Failed to bulk delete sessions');
  return res.json();
}

export async function exportEml(params: {
  session_id: string;
  audience: string;
  tlp: string;
  attach_stix?: boolean;
  attach_navigator?: boolean;
  attach_iocs?: boolean;
  attach_detection_rules?: boolean;
  diagram_jpg_b64?: string;
  email_content_overrides?: Partial<AnalysisResult['email_content']>;
}): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/eml`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(`Email export failed: ${errText || res.statusText}`);
  }
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'brief.eml'));
}

export async function fetchReportPreview(params: {
  session_id: string;
  audience: string;
  tlp: string;
  email_content_overrides?: Partial<AnalysisResult['email_content']>;
}): Promise<string> {
  const res = await authFetch(`${BASE}/analyze/report-preview`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) throw new Error('Failed to load report preview');
  return res.text();
}

export async function exportReport(params: {
  session_id: string;
  audience: string;
  tlp: string;
  email_content_overrides?: Partial<AnalysisResult['email_content']>;
}): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) throw new Error('Report export failed');
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'cti-report.md'));
}

export async function fetchSettings(): Promise<Record<string, string>> {
  const res = await authFetch(`${BASE}/settings`);
  if (!res.ok) throw new Error('Failed to load settings');
  const data = await res.json() as { settings: Record<string, string> };
  return data.settings;
}

export async function saveSettings(updates: Record<string, string>): Promise<void> {
  await authFetch(`${BASE}/settings`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  });
}

export async function uploadLogo(file: File): Promise<string> {
  const form = new FormData();
  form.append('logo', file);
  const res = await authFetch(`${BASE}/settings/logo`, { method: 'POST', body: form });
  if (!res.ok) throw new Error('Logo upload failed');
  const data = await res.json() as { dataUri: string };
  return data.dataUri;
}

export async function deleteLogo(): Promise<void> {
  await authFetch(`${BASE}/settings/logo`, { method: 'DELETE' });
}

export async function exportZip(params: {
  session_id: string;
  audience: string;
  tlp: string;
  attach_iocs?: boolean;
  diagram_jpg_b64?: string;
  email_content_overrides?: Partial<AnalysisResult['email_content']>;
}): Promise<void> {
  const res = await authFetch(`${BASE}/analyze/export/zip`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) throw new Error('Zip export failed');
  const blob = await res.blob();
  downloadBlob(blob, getFilenameFromResponse(res, 'export.zip'));
}

// ── Auth API ──────────────────────────────────────────────────────────────────

export async function login(email: string, password: string): Promise<{
  token: string;
  refreshToken: string;
  user: { id: string; email: string; displayName: string; role: string };
  teams: Array<{ id: string; name: string; role: string }>;
}> {
  const res = await fetch(`${BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({ error: 'Login failed' }));
    throw new Error(data.error || 'Login failed');
  }
  return res.json();
}

export async function fetchMe(): Promise<{
  user: { id: string; email: string; displayName: string; role: string };
  teams: Array<{ id: string; name: string; role: string }>;
}> {
  const res = await authFetch(`${BASE}/auth/me`);
  if (!res.ok) throw new Error('Not authenticated');
  return res.json();
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  const res = await authFetch(`${BASE}/auth/me/password`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ currentPassword, newPassword }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({ error: 'Password change failed' }));
    throw new Error(data.error || 'Password change failed');
  }
}

// ── Users API (admin) ─────────────────────────────────────────────────────────

export async function fetchUsers(): Promise<Array<{
  id: string; email: string; displayName: string; role: string;
  createdAt: number; lastLoginAt: number | null; disabled: boolean;
  teams: Array<{ id: string; name: string; role: string }>;
}>> {
  const res = await authFetch(`${BASE}/users`);
  if (!res.ok) throw new Error('Failed to load users');
  return res.json();
}

export async function createUser(data: {
  email: string; password: string; displayName: string; role?: string;
}): Promise<{ id: string }> {
  const res = await authFetch(`${BASE}/users`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Failed to create user' }));
    throw new Error(d.error);
  }
  return res.json();
}

export async function updateUser(id: string, data: {
  displayName?: string; role?: string; disabled?: boolean;
}): Promise<void> {
  const res = await authFetch(`${BASE}/users/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Failed to update user' }));
    throw new Error(d.error);
  }
}

export async function resetUserPassword(id: string, newPassword: string): Promise<void> {
  const res = await authFetch(`${BASE}/users/${id}/password`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ newPassword }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Password reset failed' }));
    throw new Error(d.error);
  }
}

export async function disableUser(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/users/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to disable user');
}

// ── Teams API ─────────────────────────────────────────────────────────────────

export async function fetchTeams(): Promise<Array<{
  id: string; name: string; description: string; createdAt: number; memberCount: number;
}>> {
  const res = await authFetch(`${BASE}/teams`);
  if (!res.ok) throw new Error('Failed to load teams');
  return res.json();
}

export async function createTeam(data: { name: string; description?: string }): Promise<{ id: string }> {
  const res = await authFetch(`${BASE}/teams`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Failed to create team' }));
    throw new Error(d.error);
  }
  return res.json();
}

export async function fetchTeamDetail(id: string): Promise<{
  id: string; name: string; description: string;
  members: Array<{ userId: string; email: string; displayName: string; userRole: string; teamRole: string; joinedAt: number }>;
}> {
  const res = await authFetch(`${BASE}/teams/${id}`);
  if (!res.ok) throw new Error('Failed to load team');
  return res.json();
}

export async function updateTeam(id: string, data: { name?: string; description?: string }): Promise<void> {
  const res = await authFetch(`${BASE}/teams/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update team');
}

export async function deleteTeam(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/teams/${id}`, { method: 'DELETE' });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Failed to delete team' }));
    throw new Error(d.error);
  }
}

export async function addTeamMember(teamId: string, userId: string, role?: string): Promise<void> {
  const res = await authFetch(`${BASE}/teams/${teamId}/members`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId, role: role || 'member' }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Failed to add member' }));
    throw new Error(d.error);
  }
}

export async function updateTeamMemberRole(teamId: string, userId: string, role: string): Promise<void> {
  const res = await authFetch(`${BASE}/teams/${teamId}/members/${userId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role }),
  });
  if (!res.ok) throw new Error('Failed to update member role');
}

export async function removeTeamMember(teamId: string, userId: string): Promise<void> {
  const res = await authFetch(`${BASE}/teams/${teamId}/members/${userId}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to remove member');
}

// ── Threat Actors API ────────────────────────────────────────────────────────

export async function fetchThreatActors(filters?: { search?: string }): Promise<{
  actors: Array<{
    id: string; name: string; aliases: string[]; motivation: string | null;
    attribution_confidence: string | null; intrusion_set: string | null;
    campaign_name: string | null; malware_families: string[];
    description: string; session_count: number; latest_session_at: number | null;
    created_at: number;
  }>;
  total: number;
}> {
  const params = new URLSearchParams();
  if (filters?.search) params.set('search', filters.search);
  const qs = params.toString() ? `?${params.toString()}` : '';
  const res = await authFetch(`${BASE}/threat-actors${qs}`);
  if (!res.ok) throw new Error('Failed to load threat actors');
  return res.json();
}

export async function fetchThreatActorDetail(id: string): Promise<{
  actor: {
    id: string; name: string; aliases: string[]; motivation: string | null;
    attribution_confidence: string | null; intrusion_set: string | null;
    campaign_name: string | null; malware_families: string[];
    description: string; session_count: number; latest_session_at: number | null;
    created_at: number;
  };
  sessions: Array<{
    id: string; name: string; severity: string | null; audience: string | null;
    created_at: number; link_type: 'auto' | 'manual';
  }>;
  aggregated_ttps: Array<{
    technique_id: string; technique_name: string; tactic: string;
    session_count: number; sessions: Array<{ id: string; name: string }>;
  }>;
  aggregated_iocs: Array<{
    type: string; value: string; context: string; confidence: string;
    session_count: number; first_seen: number; last_seen: number;
  }>;
}> {
  const res = await authFetch(`${BASE}/threat-actors/${id}`);
  if (!res.ok) throw new Error('Failed to load threat actor details');
  return res.json();
}

export async function updateThreatActor(id: string, data: Record<string, unknown>): Promise<void> {
  const res = await authFetch(`${BASE}/threat-actors/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Update failed' }));
    throw new Error(d.error || 'Update failed');
  }
}

export async function linkSessionToActor(actorId: string, sessionId: string): Promise<void> {
  const res = await authFetch(`${BASE}/threat-actors/${actorId}/link`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Link failed' }));
    throw new Error(d.error || 'Link failed');
  }
}

export async function unlinkSessionFromActor(actorId: string, sessionId: string): Promise<void> {
  const res = await authFetch(`${BASE}/threat-actors/${actorId}/link/${sessionId}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error('Unlink failed');
}

export async function mergeThreatActors(sourceId: string, targetId: string): Promise<void> {
  const res = await authFetch(`${BASE}/threat-actors/merge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source_id: sourceId, target_id: targetId }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Merge failed' }));
    throw new Error(d.error || 'Merge failed');
  }
}

export async function deleteThreatActor(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/threat-actors/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete threat actor');
}

export async function fetchAvailableSessions(actorId: string, search?: string): Promise<Array<{
  id: string; name: string; severity: string | null; audience: string | null; created_at: number;
}>> {
  const params = new URLSearchParams();
  if (search) params.set('search', search);
  const qs = params.toString() ? `?${params.toString()}` : '';
  const res = await authFetch(`${BASE}/threat-actors/${actorId}/sessions/available${qs}`);
  if (!res.ok) throw new Error('Failed to load available sessions');
  const data = await res.json() as { sessions: Array<{ id: string; name: string; severity: string | null; audience: string | null; created_at: number }> };
  return data.sessions;
}

// ── Tags ─────────────────────────────────────────────────────────────────────

export async function updateSessionTags(sessionId: string, tags: string[]): Promise<{ tags: string[] }> {
  const res = await authFetch(`${BASE}/sessions/${sessionId}/tags`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tags }),
  });
  if (!res.ok) throw new Error('Failed to update tags');
  return res.json();
}

export async function fetchAllTags(): Promise<string[]> {
  const res = await authFetch(`${BASE}/sessions/tags/all`);
  if (!res.ok) throw new Error('Failed to load tags');
  const data = await res.json() as { tags: string[] };
  return data.tags;
}

// ── Threat Actor Manual Management ──────────────────────────────────────────

export async function createThreatActor(data: {
  name: string;
  aliases?: string[];
  motivation?: string | null;
  attribution_confidence?: string | null;
  intrusion_set?: string | null;
  campaign_name?: string | null;
  malware_families?: string[];
  description?: string;
}): Promise<{ actor: ThreatActorSummary }> {
  const res = await authFetch(`${BASE}/threat-actors`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Failed to create threat actor' }));
    throw new Error(d.error || 'Failed to create threat actor');
  }
  return res.json();
}

export async function assignSessionThreatActor(
  sessionId: string,
  threatActorId: string | null,
): Promise<{ ok: boolean; threat_actor: { id: string; name: string } | null }> {
  const res = await authFetch(`${BASE}/sessions/${sessionId}/threat-actor`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ threat_actor_id: threatActorId }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Failed to assign threat actor' }));
    throw new Error(d.error || 'Failed to assign threat actor');
  }
  return res.json();
}

export async function bulkLinkSessions(
  actorId: string,
  sessionIds: string[],
  removeExisting = false,
): Promise<{ ok: boolean; linked: number; skipped: number }> {
  const res = await authFetch(`${BASE}/threat-actors/${actorId}/link/bulk`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_ids: sessionIds, remove_existing: removeExisting }),
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({ error: 'Bulk link failed' }));
    throw new Error(d.error || 'Bulk link failed');
  }
  return res.json();
}

export async function fetchUngroupedSessions(search?: string): Promise<Array<{
  id: string; name: string; severity: string | null; audience: string | null; created_at: number;
}>> {
  const params = new URLSearchParams();
  if (search) params.set('search', search);
  const qs = params.toString() ? `?${params.toString()}` : '';
  const res = await authFetch(`${BASE}/sessions/ungrouped${qs}`);
  if (!res.ok) throw new Error('Failed to load ungrouped sessions');
  const data = await res.json() as { sessions: Array<{ id: string; name: string; severity: string | null; audience: string | null; created_at: number }> };
  return data.sessions;
}

// ── Global Intelligence Search ───────────────────────────────────────────────

export interface SearchHit {
  category: 'ioc' | 'technique' | 'threat_actor' | 'session' | 'asset';
  value: string;
  context: string;
  session_id: string;
  session_name: string;
  meta?: Record<string, string>;
  /** For aggregated results — all sessions containing this hit */
  sessions?: Array<{ id: string; name: string }>;
}

export async function searchIntelligence(query: string, limit = 30): Promise<{
  results: SearchHit[];
  query: string;
  total: number;
}> {
  const params = new URLSearchParams({ q: query, limit: String(limit) });
  const res = await authFetch(`${BASE}/search?${params.toString()}`);
  if (!res.ok) throw new Error('Search failed');
  return res.json();
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function getFilenameFromResponse(res: Response, fallback: string): string {
  const cd = res.headers.get('content-disposition') ?? '';
  const match = cd.match(/filename="([^"]+)"/);
  return match?.[1] ?? fallback;
}

// ── API key management (admin) ───────────────────────────────────────────────

export interface ServiceAccountRecord {
  id: string;
  name: string;
  team_id: string;
  role: 'analyst' | 'viewer';
  disabled: number;
  active_keys: number;
  created_at: number;
}

export interface ApiKeyRecord {
  id: string;
  name: string;
  prefix: string;
  scopes: string;
  rate_limit_per_min: number;
  created_at: number;
  last_used_at: number | null;
  expires_at: number | null;
  revoked_at: number | null;
}

export async function getApiScopes(): Promise<string[]> {
  const res = await authFetch(`${BASE}/keys/scopes`);
  if (!res.ok) throw new Error('Failed to load scopes');
  return (await res.json()).scopes;
}

export async function listServiceAccounts(): Promise<ServiceAccountRecord[]> {
  const res = await authFetch(`${BASE}/keys/service-accounts`);
  if (!res.ok) throw new Error('Failed to load service accounts');
  return (await res.json()).serviceAccounts;
}

export async function createServiceAccount(name: string, role: 'analyst' | 'viewer'): Promise<{ id: string }> {
  const res = await authFetch(`${BASE}/keys/service-accounts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, role }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to create service account');
  return res.json();
}

export async function setServiceAccountDisabled(id: string, disabled: boolean): Promise<void> {
  const res = await authFetch(`${BASE}/keys/service-accounts/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ disabled }),
  });
  if (!res.ok) throw new Error('Failed to update service account');
}

export async function listApiKeys(accountId: string): Promise<ApiKeyRecord[]> {
  const res = await authFetch(`${BASE}/keys/service-accounts/${accountId}/keys`);
  if (!res.ok) throw new Error('Failed to load keys');
  return (await res.json()).keys;
}

export async function mintApiKey(
  accountId: string,
  body: { name: string; scopes: string[]; rateLimitPerMin?: number },
): Promise<{ id: string; token: string; prefix: string }> {
  const res = await authFetch(`${BASE}/keys/service-accounts/${accountId}/keys`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to mint key');
  return res.json();
}

export async function revokeApiKey(keyId: string): Promise<void> {
  const res = await authFetch(`${BASE}/keys/${keyId}/revoke`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to revoke key');
}

// ── Threat-intel feeds (admin/lead) ──────────────────────────────────────────

export interface FeedRecord {
  id: string;
  name: string;
  type: 'taxii' | 'misp' | 'rss';
  url: string;
  audience: string;
  tags: string;
  cadence_minutes: number;
  max_items: number;
  enabled: number;
  last_polled_at: number | null;
  last_status: string | null;
  has_auth?: boolean;
}

export interface FeedInput {
  name: string;
  type: 'taxii' | 'misp' | 'rss';
  url: string;
  authToken?: string;
  config?: string;
  audience?: string;
  tags?: string[];
  cadenceMinutes?: number;
  maxItems?: number;
}

export async function listFeeds(): Promise<FeedRecord[]> {
  const res = await authFetch(`${BASE}/feeds`);
  if (!res.ok) throw new Error('Failed to load feeds');
  return (await res.json()).feeds;
}

export async function createFeed(body: FeedInput): Promise<{ id: string }> {
  const res = await authFetch(`${BASE}/feeds`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed to create feed');
  return res.json();
}

export async function updateFeed(id: string, body: Partial<FeedInput> & { enabled?: boolean }): Promise<void> {
  const res = await authFetch(`${BASE}/feeds/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error('Failed to update feed');
}

export async function deleteFeed(id: string): Promise<void> {
  const res = await authFetch(`${BASE}/feeds/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete feed');
}

export async function testFeed(id: string): Promise<{ count: number; sample: string[] }> {
  const res = await authFetch(`${BASE}/feeds/${id}/test`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Feed test failed');
  return res.json();
}

export async function pollFeedNow(id: string): Promise<{ fetched: number; ingested: number; skipped: number }> {
  const res = await authFetch(`${BASE}/feeds/${id}/poll`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Feed poll failed');
  return res.json();
}

// ── Detection-as-code publishing ─────────────────────────────────────────────

export async function getPublishStatus(): Promise<{ configured: boolean; repo: string | null; branch: string | null }> {
  const res = await authFetch(`${BASE}/publish/status`);
  if (!res.ok) throw new Error('Failed to load publish status');
  return res.json();
}

export async function publishDetections(sessionId: string): Promise<{ prUrl: string; prNumber: number; files: string[]; updated: boolean }> {
  const res = await authFetch(`${BASE}/publish/${sessionId}`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Publish failed');
  return res.json();
}
