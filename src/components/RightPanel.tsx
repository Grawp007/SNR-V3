import { useState, useEffect } from 'react';
import { Download, Package, Mail, Map, Shield, Pencil, Eye, RotateCcw, ChevronLeft, ChevronRight, FileText, Radar, GitPullRequest } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip';
import { Button } from './ui/button';
import { Tabs, TabsList, TabsTrigger, TabsContent } from './ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { cn } from '@/lib/utils';
import { TLP_BAND_COLORS, SEVERITY_BAND } from '@/lib/constants';
import type { AnalysisResult, AudienceType, TLPLevel, EmailContent } from '@/types';
import { AUDIENCE_LABELS } from '@/types';
import * as api from '@/lib/api';
import { exportPdf } from '@/lib/pdf-export';

const TLP_OPTIONS: TLPLevel[] = ['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED'];
const TLP_COLORS: Record<TLPLevel, string> = {
  CLEAR: 'text-white',
  GREEN: 'text-green-400',
  AMBER: 'text-yellow-400',
  'AMBER+STRICT': 'text-orange-400',
  RED: 'text-red-400',
};

interface Props {
  sessionId: string | null;
  result: AnalysisResult | null;
  audience: string;
  onAudienceChange: (a: string) => void;
  onShowToast?: (message: string, type?: 'success' | 'error' | 'info') => void;
  captureAttackChain?: () => Promise<string | null>;
  collapsed: boolean;
  onToggleCollapse: () => void;
}

export default function RightPanel({ sessionId, result, audience, onAudienceChange, onShowToast, captureAttackChain, collapsed, onToggleCollapse }: Props) {
  const [tlp, setTlp] = useState<TLPLevel>('AMBER');
  const [attachStix, setAttachStix] = useState(false);
  const [attachNav, setAttachNav] = useState(false);
  const [attachIocs, setAttachIocs] = useState(false);
  const [attachRules, setAttachRules] = useState(false);
  const [attachDiagram, setAttachDiagram] = useState(false);
  const [exporting, setExporting] = useState<string | null>(null);

  // Email editing state
  const [isEditingEmail, setIsEditingEmail] = useState(false);
  const [editedEmail, setEditedEmail] = useState<EmailContent | null>(null);

  // Sync editedEmail when result changes (new session or new analysis)
  useEffect(() => {
    if (result?.email_content) {
      setEditedEmail({ ...result.email_content });
      setIsEditingEmail(false);
    } else {
      setEditedEmail(null);
    }
  }, [result]);

  const hasEdits = editedEmail && result?.email_content
    ? JSON.stringify(editedEmail) !== JSON.stringify(result.email_content)
    : false;

  const handleResetEmail = () => {
    if (result?.email_content) setEditedEmail({ ...result.email_content });
  };

  const setEmailField = (key: string, value: string) => {
    setEditedEmail((prev) => prev ? { ...prev, [key]: value } : prev);
  };

  const exportAction = async (action: string, label: string, fn: () => Promise<void>) => {
    setExporting(action);
    try {
      await fn();
      onShowToast?.(`${label} downloaded successfully`, 'success');
    } catch (e) {
      onShowToast?.(`Export failed: ${e instanceof Error ? e.message : 'Unknown error'}`, 'error');
    } finally {
      setExporting(null);
    }
  };

  // Publish detection rules + report to GitHub as a pull request (detection-as-code).
  const publishToGit = async () => {
    setExporting('publish');
    try {
      const r = await api.publishDetections(sessionId!);
      onShowToast?.(`Detections ${r.updated ? 'updated in' : 'published as'} PR #${r.prNumber}`, 'success');
      window.open(r.prUrl, '_blank', 'noopener');
    } catch (e) {
      onShowToast?.(`Publish failed: ${e instanceof Error ? e.message : 'Unknown error'}`, 'error');
    } finally {
      setExporting(null);
    }
  };

  // Build email content overrides: only send fields that differ from original
  const getEmailOverrides = (): EmailContent | undefined => {
    if (!editedEmail || !result?.email_content || !hasEdits) return undefined;
    const orig = result.email_content;
    const overrides: EmailContent = { subject: editedEmail.subject as string, severity_badge: editedEmail.severity_badge as string };
    let changed = false;
    for (const key of Object.keys(editedEmail)) {
      if (editedEmail[key] !== orig[key]) { overrides[key] = editedEmail[key]; changed = true; }
    }
    return changed ? overrides : undefined;
  };

  const getDiagramB64 = async (): Promise<string | undefined> => {
    if (!attachDiagram || !captureAttackChain) return undefined;
    const dataUrl = await captureAttackChain();
    if (!dataUrl) return undefined;
    return dataUrl.replace(/^data:image\/[^;]+;base64,/, '');
  };

  const disabled = !sessionId || !result;
  const displayEmail = editedEmail ?? result?.email_content;

  // ── Collapsed icon strip ──────────────────────────────────────────────────
  if (collapsed) {
    return (
      <aside className="w-10 flex-shrink-0 bg-navy-900 border-l border-border flex flex-col h-full items-center py-2 gap-1">
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              onClick={onToggleCollapse}
              className="w-7 h-7 rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors"
              aria-label="Expand output panel"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>
          </TooltipTrigger>
          <TooltipContent side="left">Expand output panel</TooltipContent>
        </Tooltip>
        <div
          className="mt-4 text-[9px] text-muted-foreground/50 uppercase tracking-widest select-none"
          style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)' }}
        >
          Output
        </div>
        {result && (
          <div className="mt-auto mb-2 flex flex-col items-center gap-1.5">
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="w-1.5 h-1.5 rounded-full bg-green-400" />
              </TooltipTrigger>
              <TooltipContent side="left">Analysis ready</TooltipContent>
            </Tooltip>
          </div>
        )}
      </aside>
    );
  }

  return (
    <aside className="w-96 flex-shrink-0 bg-navy-900 border-l border-border flex flex-col h-full">
      {/* Controls */}
      <div className="p-3 border-b border-border space-y-2">
        <div className="flex items-center justify-between mb-1">
          <div className="text-[10px] uppercase tracking-widest text-muted-foreground/60">Output Configuration</div>
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                onClick={onToggleCollapse}
                className="text-muted-foreground/50 hover:text-foreground transition-colors p-0.5 rounded hover:bg-secondary/50"
                aria-label="Collapse output panel"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </TooltipTrigger>
            <TooltipContent side="left">Collapse output panel</TooltipContent>
          </Tooltip>
        </div>
        <div className="flex gap-2">
          <div className="flex-1">
            <div className="text-[10px] text-muted-foreground mb-1">Audience</div>
            <Select value={audience} onValueChange={onAudienceChange}>
              <SelectTrigger className="h-8 text-xs bg-secondary/50 border-border">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.entries(AUDIENCE_LABELS) as [AudienceType, string][]).map(([k, v]) => (
                  <SelectItem key={k} value={k} className="text-xs">{v}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex-1">
            <div className="text-[10px] text-muted-foreground mb-1">TLP Level</div>
            <Select value={tlp} onValueChange={(v) => setTlp(v as TLPLevel)}>
              <SelectTrigger className="h-8 text-xs bg-secondary/50 border-border">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TLP_OPTIONS.map((t) => (
                  <SelectItem key={t} value={t} className={cn('text-xs', TLP_COLORS[t])}>TLP:{t}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>

      {/* Output Tabs */}
      <div className="flex-1 overflow-y-auto">
        <Tabs defaultValue="email" className="h-full flex flex-col">
          <div className="px-3 pt-3">
            <TabsList className="w-full bg-secondary/50 grid grid-cols-5">
              <TabsTrigger value="email" className="text-xs gap-1"><Mail className="w-3 h-3" />Email</TabsTrigger>
              <TabsTrigger value="report" className="text-xs gap-1"><FileText className="w-3 h-3" />Report</TabsTrigger>
              <TabsTrigger value="rules" className="text-xs gap-1"><Radar className="w-3 h-3" />Rules</TabsTrigger>
              <TabsTrigger value="stix" className="text-xs gap-1"><Shield className="w-3 h-3" />STIX</TabsTrigger>
              <TabsTrigger value="navigator" className="text-xs gap-1"><Map className="w-3 h-3" />Nav</TabsTrigger>
            </TabsList>
          </div>

          {/* Email Tab */}
          <TabsContent value="email" className="flex-1 flex flex-col px-3 pb-3 mt-2">
            {/* Edit / Preview toolbar */}
            {!disabled && (
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-1">
                  {hasEdits && (
                    <span className="text-[9px] text-yellow-400 border border-yellow-400/30 rounded px-1.5 py-0.5">
                      Edited
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-1">
                  {hasEdits && !isEditingEmail && (
                    <button
                      onClick={handleResetEmail}
                      className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground transition-colors px-1.5 py-0.5 rounded hover:bg-secondary/50"
                      title="Reset to AI output"
                    >
                      <RotateCcw className="w-2.5 h-2.5" />Reset
                    </button>
                  )}
                  <button
                    onClick={() => setIsEditingEmail(!isEditingEmail)}
                    className={cn(
                      'flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border transition-colors',
                      isEditingEmail
                        ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
                        : 'border-border text-muted-foreground hover:text-foreground hover:bg-secondary/50'
                    )}
                  >
                    {isEditingEmail
                      ? <><Eye className="w-2.5 h-2.5" />Preview</>
                      : <><Pencil className="w-2.5 h-2.5" />Edit</>
                    }
                  </button>
                </div>
              </div>
            )}

            {disabled ? (
              <EmptyState message="Run an analysis to generate stakeholder emails." />
            ) : isEditingEmail && editedEmail ? (
              <EmailEditor email={editedEmail} onChange={setEmailField} audience={audience} tlp={tlp} />
            ) : displayEmail ? (
              <EmailPreview email={displayEmail} audience={audience} tlp={tlp} />
            ) : (
              <EmptyState message="No email content generated yet." />
            )}

            <div className="mt-3 space-y-2">
              {/* Attachment toggles */}
              <div className="flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-muted-foreground">
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input type="checkbox" checked={attachStix} onChange={(e) => setAttachStix(e.target.checked)}
                    className="rounded border-border" />
                  Attach STIX
                </label>
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input type="checkbox" checked={attachNav} onChange={(e) => setAttachNav(e.target.checked)}
                    className="rounded border-border" />
                  Attach Navigator
                </label>
                {result?.iocs && result.iocs.length > 0 && (
                  <label className="flex items-center gap-1.5 cursor-pointer">
                    <input type="checkbox" checked={attachIocs} onChange={(e) => setAttachIocs(e.target.checked)}
                      className="rounded border-border" />
                    Attach IOC list (.txt)
                  </label>
                )}
                {result?.detection_rules && result.detection_rules.length > 0 && (
                  <label className="flex items-center gap-1.5 cursor-pointer">
                    <input type="checkbox" checked={attachRules} onChange={(e) => setAttachRules(e.target.checked)}
                      className="rounded border-border" />
                    Attach detection rules (.txt)
                  </label>
                )}
                {captureAttackChain && result?.attack_chain && result.attack_chain.length > 0 && (
                  <label className="flex items-center gap-1.5 cursor-pointer">
                    <input type="checkbox" checked={attachDiagram} onChange={(e) => setAttachDiagram(e.target.checked)}
                      className="rounded border-border" />
                    Attach chain diagram (.png)
                  </label>
                )}
              </div>
              <Button
                variant="outline"
                className="w-full text-xs h-8 gap-1.5"
                disabled={disabled || !!exporting}
                onClick={() => exportAction('eml', 'Email brief (.eml)', async () => {
                  const diagramB64 = await getDiagramB64();
                  await api.exportEml({
                    session_id: sessionId!,
                    audience,
                    tlp,
                    attach_stix: attachStix,
                    attach_navigator: attachNav,
                    attach_iocs: attachIocs || undefined,
                    attach_detection_rules: attachRules || undefined,
                    diagram_jpg_b64: diagramB64,
                    email_content_overrides: getEmailOverrides(),
                  });
                })}
              >
                <Download className="w-3.5 h-3.5" />
                {exporting === 'eml' ? 'Exporting…' : 'Download .eml'}
              </Button>
            </div>
          </TabsContent>

          {/* Detection Rules Tab */}
          <TabsContent value="rules" className="flex-1 flex flex-col px-3 pb-3 mt-2">
            {disabled ? (
              <EmptyState message="Run an analysis to extract & generate detection rules." />
            ) : !result!.detection_rules || result!.detection_rules.length === 0 ? (
              <EmptyState message="No detection rules found in this analysis." />
            ) : (
              <DetectionRulesPreview result={result!} />
            )}
            <Button
              variant="outline"
              className="w-full text-xs h-8 mt-3 gap-1.5"
              disabled={disabled || !!exporting || !result?.detection_rules?.length}
              onClick={() => exportAction('rules', 'Detection rules', () => api.exportDetectionRules(sessionId!, tlp))}
            >
              <Download className="w-3.5 h-3.5" />
              {exporting === 'rules' ? 'Exporting…' : 'Download Rules (.txt)'}
            </Button>
            <Button
              variant="outline"
              className="w-full text-xs h-8 mt-2 gap-1.5"
              disabled={disabled || !!exporting || !result?.detection_rules?.length}
              onClick={publishToGit}
              title="Open/update a GitHub pull request with these rules + report (configure in Settings → Detection-as-Code)"
            >
              <GitPullRequest className="w-3.5 h-3.5" />
              {exporting === 'publish' ? 'Publishing…' : 'Publish to Git (PR)'}
            </Button>
          </TabsContent>

          {/* STIX Tab */}
          <TabsContent value="stix" className="flex-1 flex flex-col px-3 pb-3 mt-2">
            {disabled ? (
              <EmptyState message="Run an analysis to generate STIX 2.1 bundle." />
            ) : (
              <StixPreview result={result!} />
            )}
            <div className="flex gap-2 mt-3">
              <Button
                variant="outline"
                className="flex-1 text-xs h-8 gap-1.5"
                disabled={disabled || !!exporting}
                onClick={() => exportAction('stix', 'STIX bundle', () => api.exportStix(sessionId!, tlp))}
              >
                <Download className="w-3.5 h-3.5" />
                {exporting === 'stix' ? 'Exporting…' : 'Download STIX Bundle'}
              </Button>
              {result?.iocs && result.iocs.length > 0 && (
                <Button
                  variant="outline"
                  className="text-xs h-8 gap-1.5"
                  disabled={disabled || !!exporting}
                  onClick={() => exportAction('iocs-csv', 'IOCs (.csv)', () => api.exportIocsCsv(sessionId!, tlp))}
                >
                  <Download className="w-3.5 h-3.5" />
                  {exporting === 'iocs-csv' ? 'Exporting…' : 'IOCs CSV'}
                </Button>
              )}
            </div>
          </TabsContent>

          {/* Report Tab */}
          <TabsContent value="report" className="flex-1 flex flex-col px-3 pb-3 mt-2 gap-3">
            {disabled ? (
              <EmptyState message="Run an analysis to generate a CTI report." />
            ) : (
              <div className="flex-1 space-y-3 text-xs text-muted-foreground">
                <p className="leading-relaxed">
                  Downloads a <span className="text-foreground font-medium">Markdown (.md)</span> CTI
                  report populated from the analysis data — IOC tables, ATT&amp;CK mapping, threat actor,
                  timeline, and behavioral indicators.
                </p>
                <div className="bg-secondary/40 border border-border/50 rounded p-3 space-y-1 font-mono text-[10px] text-muted-foreground/70 leading-relaxed">
                  <div># Cyber Threat Intelligence Report</div>
                  <div>## Technical Analysis → ATT&amp;CK chain</div>
                  <div>## IOC Table (all types)</div>
                  <div>## MITRE ATT&amp;CK Mapping</div>
                  <div>## Behavioral Indicators</div>
                  <div className="text-muted-foreground/40">… and more sections</div>
                </div>
                <p className="text-[10px] text-muted-foreground/60">
                  Template customizable in{' '}
                  <span className="text-cyan-400/80">Settings → CTI Report Template</span>
                  {' '}using <code className="font-mono">{'{field}'}</code> and <code className="font-mono">{'{{BLOCK}}'}</code> tokens.
                </p>
              </div>
            )}
            <Button
              variant="outline"
              className="w-full text-xs h-8 mt-auto gap-1.5"
              disabled={disabled || !!exporting}
              onClick={() => exportAction('report', 'CTI Report (.md)', () =>
                api.exportReport({ session_id: sessionId!, audience, tlp, email_content_overrides: getEmailOverrides() })
              )}
            >
              <Download className="w-3.5 h-3.5" />
              {exporting === 'report' ? 'Generating…' : 'Download CTI Report (.md)'}
            </Button>
            <Button
              variant="outline"
              className="w-full text-xs h-8 mt-1.5 gap-1.5"
              disabled={disabled}
              onClick={() => { if (result) exportPdf(result, tlp, editedEmail ?? undefined); }}
            >
              <Download className="w-3.5 h-3.5" />
              Download PDF
            </Button>
          </TabsContent>

          {/* Navigator Tab */}
          <TabsContent value="navigator" className="flex-1 flex flex-col px-3 pb-3 mt-2">
            {disabled ? (
              <EmptyState message="Run an analysis to generate ATT&CK Navigator layer." />
            ) : (
              <NavigatorPreview result={result!} />
            )}
            <Button
              variant="outline"
              className="w-full text-xs h-8 mt-3 gap-1.5"
              disabled={disabled || !!exporting}
              onClick={() => exportAction('navigator', 'Navigator layer', () => api.exportNavigator(sessionId!))}
            >
              <Download className="w-3.5 h-3.5" />
              {exporting === 'navigator' ? 'Exporting…' : 'Download Layer JSON'}
            </Button>
          </TabsContent>
        </Tabs>
      </div>

      {/* Export All */}
      <div className="p-3 border-t border-border">
        <Button
          variant="cyan"
          className="w-full text-xs h-9 gap-1.5"
          disabled={disabled || !!exporting}
          onClick={() => exportAction('zip', 'Export package (.zip)', async () => {
            const diagramB64 = await getDiagramB64();
            await api.exportZip({
              session_id: sessionId!,
              audience,
              tlp,
              attach_iocs: attachIocs || undefined,
              diagram_jpg_b64: diagramB64,
              email_content_overrides: getEmailOverrides(),
            });
          })}
        >
          <Package className="w-3.5 h-3.5" />
          {exporting === 'zip' ? 'Packaging…' : 'Export All (.zip)'}
        </Button>
      </div>
    </aside>
  );
}

// ── Email Editor ─────────────────────────────────────────────────────────────

function EmailEditor({
  email,
  onChange,
  audience,
  tlp,
}: {
  email: EmailContent;
  onChange: (key: string, value: string) => void;
  audience: string;
  tlp: TLPLevel;
}) {
  const TLP_BAND_COLORS: Record<string, string> = {
    CLEAR: 'bg-gray-200 text-gray-900',
    GREEN: 'bg-green-600 text-white',
    AMBER: 'bg-yellow-500 text-white',
    'AMBER+STRICT': 'bg-orange-500 text-white',
    RED: 'bg-red-600 text-white',
  };

  return (
    <div className="flex-1 min-h-0 overflow-y-auto rounded-lg border border-cyan-500/30 bg-navy-950 text-xs">
      <div className={cn('py-1 text-center text-[10px] font-bold tracking-widest', TLP_BAND_COLORS[tlp])}>
        TLP:{tlp}
      </div>
      <div className="px-2 py-2 bg-navy-800 border-b border-border text-[9px] text-muted-foreground flex items-center justify-between">
        <span className="text-cyan-400 font-medium">✏ Edit Mode — changes apply to exported .eml and .zip</span>
        <span>FOR: {AUDIENCE_LABELS[audience as AudienceType] ?? audience}</span>
      </div>
      <div className="p-3 space-y-3">
        <EditField label="Subject">
          <input
            type="text"
            value={email.subject as string ?? ''}
            onChange={(e) => onChange('subject', e.target.value)}
            className="w-full bg-secondary/30 border border-border rounded px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
          />
        </EditField>
        <p className="text-[9px] text-muted-foreground/60 pb-1">
          Additional fields are dynamically rendered based on your configured brief sections.
        </p>
      </div>
    </div>
  );
}

function EditField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <div className="text-[9px] uppercase tracking-wide text-cyan-400/70 font-medium">{label}</div>
      {children}
    </div>
  );
}

// ── Email Preview ─────────────────────────────────────────────────────────────

function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex-1 flex items-center justify-center text-center text-muted-foreground text-xs p-4 border border-dashed border-border rounded-lg">
      {message}
    </div>
  );
}


function EmailPreview({ email, audience, tlp }: {
  email: AnalysisResult['email_content'];
  audience: string;
  tlp: TLPLevel;
}) {
  return (
    <div className="flex-1 min-h-0 overflow-y-auto rounded-lg border border-border bg-navy-950 text-xs">
      <div className={cn('py-1 text-center text-[10px] font-bold tracking-widest', TLP_BAND_COLORS[tlp],
        tlp === 'CLEAR' ? 'text-gray-900' : 'text-white')}>
        TLP:{tlp}
      </div>
      <div className="px-3 py-2.5 bg-navy-800 border-b border-border">
        <div className="flex items-start justify-between gap-2">
          <div>
            <div className="text-[9px] text-muted-foreground uppercase tracking-wide">Subject</div>
            <div className="text-xs text-foreground font-medium leading-tight mt-0.5">{email.subject as string}</div>
          </div>
          <div className={cn('text-[10px] px-2 py-0.5 rounded font-bold flex-shrink-0', SEVERITY_BAND[email.severity_badge as string])}>
            {email.severity_badge as string}
          </div>
        </div>
        <div className="mt-1.5 text-[9px] text-muted-foreground">
          FOR: {AUDIENCE_LABELS[audience as AudienceType] ?? audience}
        </div>
      </div>
      <div className="p-3 space-y-3 text-xs text-muted-foreground">
        Content rendered from configured brief sections.
      </div>
    </div>
  );
}

function StixPreview({ result }: { result: AnalysisResult }) {
  return (
    <div className="flex-1 min-h-0 overflow-y-auto rounded-lg border border-border bg-navy-950 p-3 space-y-2 text-xs">
      <div className="text-[9px] text-muted-foreground uppercase tracking-wide">Bundle Contents</div>
      <StixRow label="Attack Patterns" count={result.attack_chain.length} color="text-cyan-400" />
      <StixRow label="Indicators (IOCs)" count={result.iocs.length} color="text-orange-400" />
      <StixRow label="Affected Assets" count={result.affected_assets.length} color="text-yellow-400" />
      {result.threat_actor?.name && (
        <StixRow label="Threat Actor" count={1} color="text-red-400" extra={result.threat_actor.name} />
      )}
      <div className="mt-2 pt-2 border-t border-border">
        <div className="text-[9px] text-muted-foreground">STIX 2.1 compliant · Will be validated on download</div>
      </div>
    </div>
  );
}

function StixRow({ label, count, color, extra }: { label: string; count: number; color: string; extra?: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{label}</span>
      <div className="flex items-center gap-2">
        {extra && <span className="text-muted-foreground/60 text-[10px]">{extra}</span>}
        <span className={cn('font-mono font-semibold', color)}>{count}</span>
      </div>
    </div>
  );
}

function DetectionRulesPreview({ result }: { result: AnalysisResult }) {
  const rules = result.detection_rules ?? [];
  const byType: Record<string, number> = {};
  for (const r of rules) {
    byType[r.rule_type] = (byType[r.rule_type] ?? 0) + 1;
  }
  const extracted = rules.filter(r => r.source === 'extracted').length;
  const generated = rules.filter(r => r.source === 'generated').length;

  const TYPE_COLORS: Record<string, string> = {
    sigma: 'text-purple-400',
    yara: 'text-orange-400',
    suricata: 'text-cyan-400',
  };

  return (
    <div className="flex-1 min-h-0 overflow-y-auto rounded-lg border border-border bg-navy-950 p-3 space-y-2 text-xs">
      <div className="text-[9px] text-muted-foreground uppercase tracking-wide">Detection Rules</div>
      <div className="text-muted-foreground text-[10px]">
        {rules.length} rules ({extracted} extracted, {generated} AI-generated)
      </div>
      <div className="space-y-1">
        {Object.entries(byType).map(([type, count]) => (
          <div key={type} className="flex items-center gap-2">
            <div className={cn('flex-1 text-[10px] font-medium uppercase', TYPE_COLORS[type] ?? 'text-foreground/70')}>{type}</div>
            <div className="text-[10px] font-mono text-cyan-400">{count} rule{count !== 1 ? 's' : ''}</div>
          </div>
        ))}
      </div>
      <div className="mt-2 pt-2 border-t border-border text-[9px] text-muted-foreground">
        Includes Sigma, YARA, and Suricata rules · Extracted from input and AI-generated
      </div>
    </div>
  );
}

function NavigatorPreview({ result }: { result: AnalysisResult }) {
  const byTactic: Record<string, number> = {};
  for (const t of result.attack_chain) {
    byTactic[t.tactic] = (byTactic[t.tactic] ?? 0) + 1;
  }
  return (
    <div className="flex-1 min-h-0 overflow-y-auto rounded-lg border border-border bg-navy-950 p-3 space-y-2 text-xs">
      <div className="text-[9px] text-muted-foreground uppercase tracking-wide">Layer Preview</div>
      <div className="text-muted-foreground text-[10px]">{result.attack_chain.length} techniques across {Object.keys(byTactic).length} tactics</div>
      <div className="space-y-1">
        {Object.entries(byTactic).map(([tactic, count]) => (
          <div key={tactic} className="flex items-center gap-2">
            <div className="flex-1 text-[10px] text-foreground/70">{tactic}</div>
            <div className="text-[10px] font-mono text-cyan-400">{count} technique{count !== 1 ? 's' : ''}</div>
          </div>
        ))}
      </div>
      <div className="mt-2 pt-2 border-t border-border text-[9px] text-muted-foreground">
        Color-coded by confidence · Compatible with ATT&CK Navigator v4.9
      </div>
    </div>
  );
}
