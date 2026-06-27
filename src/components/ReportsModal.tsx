import { useState, useEffect, useCallback } from 'react';
import { X, BarChart2, ChevronLeft, ChevronRight, ExternalLink, Activity, Search, TrendingUp, Trash2, RotateCcw } from 'lucide-react';
import AnalyticsTab from './AnalyticsTab';
import ConfirmDialog from './ConfirmDialog';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from './ui/tabs';
import { cn, formatTimestamp, severityDot } from '@/lib/utils';
import type { Session } from '@/types';
import type { AuditLogEntry } from '@/lib/api';
import * as api from '@/lib/api';

interface Props {
  open: boolean;
  onClose: () => void;
  onSelectSession: (id: string) => void;
  /** Delete a session (soft delete with undo) — reuses the app-level handler/toast. */
  onDeleteSession: (id: string) => Promise<void> | void;
  /** Restore a soft-deleted session — reuses the app-level handler/toast. */
  onRestoreSession: (id: string) => Promise<void> | void;
}

const PAGE_SIZE = 15;

const ACTION_LABELS: Record<string, string> = {
  session_created: 'Session Created',
  analysis_complete: 'Analysis Complete',
  export_stix: 'Export: STIX',
  export_eml: 'Export: Email',
  export_navigator: 'Export: Navigator',
  export_zip: 'Export: ZIP',
};

const ACTION_COLORS: Record<string, string> = {
  session_created: 'text-muted-foreground',
  analysis_complete: 'text-cyan-400',
  export_stix: 'text-orange-400',
  export_eml: 'text-green-400',
  export_navigator: 'text-purple-400',
  export_zip: 'text-yellow-400',
};

export default function ReportsModal({ open, onClose, onSelectSession, onDeleteSession, onRestoreSession }: Props) {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [total, setTotal] = useState(0);
  const [auditLog, setAuditLog] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [auditLoading, setAuditLoading] = useState(false);
  const [page, setPage] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [confirmDelete, setConfirmDelete] = useState<{ id: string; name: string } | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deletedSessions, setDeletedSessions] = useState<Array<Session & { deleted_at: number }>>([]);
  const [deletedLoading, setDeletedLoading] = useState(false);
  const [restoringId, setRestoringId] = useState<string | null>(null);

  const loadSessions = useCallback(async (p: number) => {
    setLoading(true);
    try {
      const { sessions: s, total: t } = await api.fetchAllSessions(PAGE_SIZE, p * PAGE_SIZE);
      setSessions(s);
      setTotal(t);
    } catch {
      // non-critical
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAudit = useCallback(async () => {
    setAuditLoading(true);
    try {
      const rows = await api.fetchAuditLog();
      setAuditLog(rows);
    } catch {
      // non-critical
    } finally {
      setAuditLoading(false);
    }
  }, []);

  const loadDeleted = useCallback(async () => {
    setDeletedLoading(true);
    try {
      setDeletedSessions(await api.fetchDeletedSessions());
    } catch {
      // non-critical
    } finally {
      setDeletedLoading(false);
    }
  }, []);

  const handleConfirmDelete = useCallback(async () => {
    if (!confirmDelete) return;
    setDeleting(true);
    try {
      await onDeleteSession(confirmDelete.id);
      // If we removed the last row on a non-first page, step back one page.
      const nextPage = sessions.length === 1 && page > 0 ? page - 1 : page;
      if (nextPage !== page) setPage(nextPage);
      else await loadSessions(page);
      await loadAudit();
      await loadDeleted();
    } finally {
      setDeleting(false);
      setConfirmDelete(null);
    }
  }, [confirmDelete, onDeleteSession, sessions.length, page, loadSessions, loadAudit, loadDeleted]);

  const handleRestore = useCallback(async (id: string) => {
    setRestoringId(id);
    try {
      await onRestoreSession(id);
      await loadDeleted();
      await loadSessions(page);
    } finally {
      setRestoringId(null);
    }
  }, [onRestoreSession, loadDeleted, loadSessions, page]);

  useEffect(() => {
    if (!open) return;
    loadSessions(0);
    loadAudit();
    loadDeleted();
    setPage(0);
    setSearchQuery('');
  }, [open, loadSessions, loadAudit, loadDeleted]);

  useEffect(() => {
    if (!open) return;
    loadSessions(page);
  }, [page, open, loadSessions]);

  const filteredSessions = searchQuery.trim()
    ? sessions.filter((s) => s.name.toLowerCase().includes(searchQuery.toLowerCase()))
    : sessions;

  const totalPages = Math.ceil(total / PAGE_SIZE);

  // Aggregate stats from audit log (covers ALL sessions, not just current page)
  const analysisEntries = auditLog.filter((e) => e.action === 'analysis_complete');
  const bySeverity: Record<string, number> = {};
  analysisEntries.forEach((e) => {
    // details field contains e.g. "severity=High, audience=soc"
    const match = e.details?.match(/severity=([^,]+)/);
    if (match?.[1]) {
      const sev = match[1].trim();
      bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
    }
  });

  const stats = {
    totalSessions: total,
    analyses: analysisEntries.length,
    exports: auditLog.filter((e) => e.action.startsWith('export_')).length,
    bySeverity,
  };

  if (!open) return null;

  return (
    <>
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-navy-800 border border-border rounded-xl w-full max-w-6xl h-[90vh] flex flex-col shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <BarChart2 className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-foreground">Activity & Reports</h2>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors" aria-label="Close">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Stats bar */}
        <div className="px-5 py-3 border-b border-border bg-secondary/10 flex items-center gap-6 flex-wrap">
          <Stat label="Total Sessions" value={stats.totalSessions} color="text-cyan-400" />
          <Stat label="Analyses Run" value={stats.analyses} color="text-green-400" />
          <Stat label="Exports Generated" value={stats.exports} color="text-orange-400" />
          {Object.entries(stats.bySeverity).map(([sev, count]) => (
            <Stat key={sev} label={sev} value={count} color={
              sev === 'Critical' ? 'text-red-400' :
              sev === 'High' ? 'text-orange-400' :
              sev === 'Medium' ? 'text-yellow-400' :
              sev === 'Low' ? 'text-green-400' : 'text-blue-400'
            } />
          ))}
        </div>

        <div className="flex-1 overflow-hidden min-h-0">
          <Tabs defaultValue="analytics" className="h-full flex flex-col min-h-0">
            <div className="px-5 pt-3">
              <TabsList className="bg-secondary/50 w-auto">
                <TabsTrigger value="analytics" className="text-xs gap-1.5">
                  <TrendingUp className="w-3 h-3" />Analytics
                </TabsTrigger>
                <TabsTrigger value="sessions" className="text-xs gap-1.5">
                  <ExternalLink className="w-3 h-3" />Session History
                </TabsTrigger>
                <TabsTrigger value="deleted" className="text-xs gap-1.5">
                  <RotateCcw className="w-3 h-3" />Recently Deleted
                  {deletedSessions.length > 0 && (
                    <span className="ml-0.5 text-[9px] bg-secondary/80 text-muted-foreground px-1 py-0 rounded-full">{deletedSessions.length}</span>
                  )}
                </TabsTrigger>
                <TabsTrigger value="audit" className="text-xs gap-1.5">
                  <Activity className="w-3 h-3" />Audit Trail
                </TabsTrigger>
              </TabsList>
            </div>

            {/* ── Analytics Tab ── */}
            <TabsContent value="analytics" className="flex-1 overflow-hidden mt-0 relative min-h-0">
              <AnalyticsTab open={open} onSelectSession={onSelectSession} onClose={onClose} />
            </TabsContent>

            {/* ── Sessions Tab ── */}
            <TabsContent value="sessions" className="flex-1 flex flex-col px-5 pb-4 mt-3 overflow-hidden data-[state=inactive]:!hidden">
              {/* Search */}
              <div className="relative mb-3 flex-shrink-0">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/50" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter by session name…"
                  className="w-full bg-secondary/50 border border-border rounded-md pl-8 pr-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                />
              </div>

              <div className="flex-1 overflow-y-auto">
                {loading ? (
                  <div className="text-center text-muted-foreground text-xs py-12">Loading sessions…</div>
                ) : filteredSessions.length === 0 ? (
                  <div className="text-center text-muted-foreground text-xs py-12">
                    {searchQuery ? 'No sessions match your search.' : 'No sessions recorded yet.'}
                  </div>
                ) : (
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-navy-800">
                      <tr className="border-b border-border text-muted-foreground text-[10px] uppercase tracking-wide">
                        <th className="text-left py-2 pr-3 font-medium">Session Name</th>
                        <th className="text-left py-2 pr-3 font-medium w-28">Date</th>
                        <th className="text-left py-2 pr-3 font-medium w-24">Severity</th>
                        <th className="text-left py-2 pr-3 font-medium w-28">Audience</th>
                        <th className="text-left py-2 pr-3 font-medium w-20">Status</th>
                        <th className="w-10"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredSessions.map((s) => (
                        <tr
                          key={s.id}
                          className="border-b border-border/50 hover:bg-secondary/20 transition-colors cursor-pointer"
                          onClick={() => { onSelectSession(s.id); onClose(); }}
                        >
                          <td className="py-2.5 pr-3 font-medium text-foreground">{s.name}</td>
                          <td className="py-2.5 pr-3 text-muted-foreground">{formatTimestamp(s.created_at)}</td>
                          <td className="py-2.5 pr-3">
                            {s.severity ? (
                              <div className="flex items-center gap-1.5">
                                <div className={cn('w-1.5 h-1.5 rounded-full', severityDot(s.severity))} />
                                <span className="text-muted-foreground">{s.severity}</span>
                              </div>
                            ) : <span className="text-muted-foreground/40">—</span>}
                          </td>
                          <td className="py-2.5 pr-3">
                            {s.audience ? (
                              <Badge variant="secondary" className="text-[9px] px-1.5 py-0 h-4">
                                {s.audience.replace(/_/g, ' ').toUpperCase()}
                              </Badge>
                            ) : <span className="text-muted-foreground/40">—</span>}
                          </td>
                          <td className="py-2.5 pr-3">
                            <span className={cn('text-[10px]',
                              s.status === 'complete' ? 'text-green-400' :
                              s.status === 'analyzing' ? 'text-cyan-400 animate-pulse' :
                              s.status === 'error' ? 'text-red-400' : 'text-muted-foreground'
                            )}>{s.status}</span>
                          </td>
                          <td className="py-2.5 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <ExternalLink className="w-3 h-3 text-muted-foreground/40 hover:text-cyan-400 transition-colors inline-block" />
                              <button
                                onClick={(e) => { e.stopPropagation(); setConfirmDelete({ id: s.id, name: s.name }); }}
                                className="text-muted-foreground/40 hover:text-red-400 transition-colors"
                                title="Delete session"
                                aria-label={`Delete session ${s.name}`}
                              >
                                <Trash2 className="w-3 h-3" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              {/* Pagination */}
              {!searchQuery && totalPages > 1 && (
                <div className="flex items-center justify-between pt-3 border-t border-border flex-shrink-0">
                  <span className="text-[10px] text-muted-foreground">
                    Page {page + 1} of {totalPages} · {total} sessions total
                  </span>
                  <div className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 w-7 p-0"
                      disabled={page === 0}
                      onClick={() => setPage((p) => Math.max(0, p - 1))}
                    >
                      <ChevronLeft className="w-3.5 h-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 w-7 p-0"
                      disabled={page >= totalPages - 1}
                      onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                    >
                      <ChevronRight className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </div>
              )}
            </TabsContent>

            {/* ── Recently Deleted Tab ── */}
            <TabsContent value="deleted" className="flex-1 flex flex-col px-5 pb-4 mt-3 overflow-hidden data-[state=inactive]:!hidden">
              <p className="text-[11px] text-muted-foreground mb-3 flex-shrink-0">
                Sessions are soft-deleted and recoverable here for <strong className="text-foreground/70">7 days</strong>, after which they're permanently purged.
              </p>
              <div className="flex-1 overflow-y-auto">
                {deletedLoading ? (
                  <div className="text-center text-muted-foreground text-xs py-12">Loading…</div>
                ) : deletedSessions.length === 0 ? (
                  <div className="text-center text-muted-foreground text-xs py-12">No recently deleted sessions.</div>
                ) : (
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-navy-800">
                      <tr className="border-b border-border text-muted-foreground text-[10px] uppercase tracking-wide">
                        <th className="text-left py-2 pr-3 font-medium">Session Name</th>
                        <th className="text-left py-2 pr-3 font-medium w-28">Deleted</th>
                        <th className="text-left py-2 pr-3 font-medium w-24">Severity</th>
                        <th className="text-right py-2 font-medium w-24">Restore</th>
                      </tr>
                    </thead>
                    <tbody>
                      {deletedSessions.map((s) => (
                        <tr key={s.id} className="border-b border-border/50 hover:bg-secondary/20 transition-colors">
                          <td className="py-2.5 pr-3 font-medium text-foreground">{s.name}</td>
                          <td className="py-2.5 pr-3 text-muted-foreground">{formatTimestamp(s.deleted_at)}</td>
                          <td className="py-2.5 pr-3">
                            {s.severity ? (
                              <div className="flex items-center gap-1.5">
                                <div className={cn('w-1.5 h-1.5 rounded-full', severityDot(s.severity))} />
                                <span className="text-muted-foreground">{s.severity}</span>
                              </div>
                            ) : <span className="text-muted-foreground/40">—</span>}
                          </td>
                          <td className="py-2.5 text-right">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 text-[10px] gap-1 text-cyan-400 hover:text-cyan-300"
                              disabled={restoringId === s.id}
                              onClick={() => handleRestore(s.id)}
                            >
                              <RotateCcw className="w-3 h-3" />{restoringId === s.id ? 'Restoring…' : 'Restore'}
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </TabsContent>

            {/* ── Audit Trail Tab ── */}
            <TabsContent value="audit" className="flex-1 overflow-y-auto px-5 pb-4 mt-3">
              {auditLoading ? (
                <div className="text-center text-muted-foreground text-xs py-12">Loading audit log…</div>
              ) : auditLog.length === 0 ? (
                <div className="text-center text-muted-foreground text-xs py-12">No audit entries recorded yet.</div>
              ) : (
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-navy-800">
                    <tr className="border-b border-border text-muted-foreground text-[10px] uppercase tracking-wide">
                      <th className="text-left py-2 pr-3 font-medium w-36">Timestamp</th>
                      <th className="text-left py-2 pr-3 font-medium w-44">Action</th>
                      <th className="text-left py-2 pr-3 font-medium">Analyst</th>
                      <th className="text-left py-2 pr-3 font-medium">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLog.map((entry) => (
                      <tr key={entry.id} className="border-b border-border/50">
                        <td className="py-2 pr-3 text-muted-foreground font-mono text-[10px]">
                          {new Date(entry.timestamp).toLocaleString('en-US', {
                            month: 'short', day: 'numeric',
                            hour: '2-digit', minute: '2-digit',
                          })}
                        </td>
                        <td className="py-2 pr-3">
                          <span className={cn('font-medium', ACTION_COLORS[entry.action] ?? 'text-foreground')}>
                            {ACTION_LABELS[entry.action] ?? entry.action}
                          </span>
                        </td>
                        <td className="py-2 pr-3 text-muted-foreground">{entry.analyst_name}</td>
                        <td className="py-2 pr-3 text-muted-foreground/70 text-[10px]">
                          {entry.details ?? entry.outputs_generated ?? ''}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>

      <ConfirmDialog
        open={!!confirmDelete}
        title="Delete session?"
        message={`Delete "${confirmDelete?.name ?? ''}"? You can Undo right after, or restore it from the Recently Deleted tab for 7 days.`}
        confirmLabel={deleting ? 'Deleting…' : 'Delete'}
        danger
        onConfirm={handleConfirmDelete}
        onCancel={() => { if (!deleting) setConfirmDelete(null); }}
      />
    </>
  );
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="flex flex-col">
      <span className={cn('text-lg font-bold font-mono leading-none', color)}>{value}</span>
      <span className="text-[9px] text-muted-foreground/60 uppercase tracking-wide mt-0.5">{label}</span>
    </div>
  );
}
