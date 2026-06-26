import { useState, useEffect, useRef, useCallback } from 'react';
import { X, Mail, Save, Loader2, LayoutTemplate, Palette, ListChecks, FileText, Upload, Trash2, Download, Sparkles, Plus, Copy, Star, FileUp, FileDown } from 'lucide-react';
import { cn } from '@/lib/utils';
import * as api from '@/lib/api';
import type { BrandProfile, EmailThemeOverrides, EmailSenderOverrides } from '@/lib/api';
import { parseSections } from '@/lib/sections';
import EmailTemplateEditor from './EmailTemplateEditor';
import RichTextEditor from './RichTextEditor';
import { Button } from './ui/button';
import { AUDIENCE_LABELS } from '@/types';
import type { AnalysisResult, AudienceType, EmailContent, TLPLevel, BriefSection } from '@/types';

// Team-level branding keys edited in the Studio (custom_intro_<audience> added at runtime).
const BRANDING_KEYS = [
  'email_header_text',
  'email_footer_text',
  'email_signature',
  'email_custom_preamble',
  'email_primary_color',
  'email_secondary_color',
  'email_font_family',
  'email_body_font_size',
  'email_logo_data',
] as const;

type StudioTab = 'content' | 'layout' | 'brand' | 'defaults' | 'sections';

type ThemeDraft = Partial<EmailThemeOverrides>;
type SenderDraft = Partial<EmailSenderOverrides>;

interface Props {
  open: boolean;
  onClose: () => void;
  sessionId: string;
  result: AnalysisResult;
  audience: string;
  tlp: TLPLevel;
  /** Shared per-session email content (RightPanel's editedEmail). */
  email: EmailContent;
  onContentChange: (key: string, value: string) => void;
  onShowToast?: (message: string, type?: 'success' | 'error' | 'info') => void;
}

function readFileAsDataUri(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result as string);
    r.onerror = () => reject(new Error('read failed'));
    r.readAsDataURL(file);
  });
}

export default function EmailStudio({ open, onClose, sessionId, result, audience, tlp, email, onContentChange, onShowToast }: Props) {
  const [tab, setTab] = useState<StudioTab>('content');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Team-level drafts (template / branding / section enablement)
  const [templateDraft, setTemplateDraft] = useState('');
  const [branding, setBranding] = useState<Record<string, string>>({});
  const [sections, setSections] = useState<BriefSection[]>([]);

  // Brand profiles (per-team, per-session selection) + the active profile's drafts.
  const [profiles, setProfiles] = useState<BrandProfile[]>([]);
  const [activeProfileId, setActiveProfileId] = useState<string | null>(null);
  const [profileName, setProfileName] = useState('');
  const [themeDraft, setThemeDraft] = useState<ThemeDraft>({});
  const [senderDraft, setSenderDraft] = useState<SenderDraft>({});

  const [previewHtml, setPreviewHtml] = useState('');
  const [previewLoading, setPreviewLoading] = useState(false);
  const previewTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const importInput = useRef<HTMLInputElement | null>(null);

  const introKey = `custom_intro_${audience}`;

  // Load team settings + brand profiles + the session's resolved brand when opened.
  useEffect(() => {
    if (!open) return;
    setLoading(true);
    Promise.all([
      api.fetchSettings(),
      api.listBrandProfiles().catch(() => [] as BrandProfile[]),
      api.fetchSessionBrand(sessionId).catch(() => null),
    ])
      .then(([s, profs, brand]) => {
        setTemplateDraft(s.email_template ?? '');
        const b: Record<string, string> = {};
        for (const k of BRANDING_KEYS) b[k] = s[k] ?? '';
        b[introKey] = s[introKey] ?? '';
        setBranding(b);
        setSections(parseSections(s.report_sections ?? ''));

        setProfiles(profs);
        const activeId = brand?.profileId ?? null;
        setActiveProfileId(activeId);
        const active = activeId ? profs.find((p) => p.id === activeId) : undefined;
        setProfileName(active?.name ?? '');
        setThemeDraft(active?.theme ?? {});
        setSenderDraft(active?.sender ?? {});

        setLoading(false);
      })
      .catch(() => { setLoading(false); onShowToast?.('Failed to load email settings', 'error'); });
  }, [open, sessionId, introKey, onShowToast]);

  // Debounced live preview of the REAL session email with all in-progress edits.
  const refreshPreview = useCallback(() => {
    if (previewTimer.current) clearTimeout(previewTimer.current);
    previewTimer.current = setTimeout(async () => {
      setPreviewLoading(true);
      try {
        const html = await api.fetchEmailStudioPreview({
          session_id: sessionId,
          audience,
          tlp,
          template: templateDraft,
          branding,
          reportSections: JSON.stringify(sections),
          emailContentOverrides: email as unknown as Record<string, string>,
          theme: themeDraft,
          sender: senderDraft,
        });
        setPreviewHtml(html);
      } catch (e) {
        onShowToast?.(e instanceof Error ? e.message : 'Preview failed', 'error');
      } finally {
        setPreviewLoading(false);
      }
    }, 250);
  }, [sessionId, audience, tlp, templateDraft, branding, sections, email, themeDraft, senderDraft, onShowToast]);

  useEffect(() => {
    if (open && !loading) refreshPreview();
    return () => { if (previewTimer.current) clearTimeout(previewTimer.current); };
  }, [open, loading, refreshPreview]);

  const setBrandingField = (key: string, value: string) => setBranding((b) => ({ ...b, [key]: value }));
  const setTheme = (key: keyof EmailThemeOverrides, value: string | number | boolean) =>
    setThemeDraft((t) => ({ ...t, [key]: value }));
  const setSender = (key: keyof EmailSenderOverrides, value: string) =>
    setSenderDraft((s) => ({ ...s, [key]: value }));

  const toggleSection = (key: string) =>
    setSections((arr) => arr.map((s) => (s.key === key ? { ...s, enabled: !s.enabled } : s)));

  // ── Brand profile actions ────────────────────────────────────────────────
  function selectProfile(id: string | null) {
    setActiveProfileId(id);
    const p = id ? profiles.find((x) => x.id === id) : undefined;
    setProfileName(p?.name ?? '');
    setThemeDraft(p?.theme ?? {});
    setSenderDraft(p?.sender ?? {});
  }

  async function reloadProfiles(selectId?: string | null) {
    const profs = await api.listBrandProfiles().catch(() => profiles);
    setProfiles(profs);
    if (selectId !== undefined) {
      const p = selectId ? profs.find((x) => x.id === selectId) : undefined;
      setActiveProfileId(selectId);
      setProfileName(p?.name ?? '');
      setThemeDraft(p?.theme ?? {});
      setSenderDraft(p?.sender ?? {});
    }
  }

  async function handleNewProfile() {
    const name = window.prompt('New brand profile name:', 'New Brand')?.trim();
    if (!name) return;
    try {
      const id = await api.createBrandProfile({ name, theme: {}, sender: {} });
      await reloadProfiles(id);
      onShowToast?.(`Created "${name}"`, 'success');
    } catch (e) { onShowToast?.(e instanceof Error ? e.message : 'Create failed', 'error'); }
  }

  async function handleCloneProfile() {
    const base = activeProfileId ? profileName : 'SNR default';
    const name = window.prompt('Clone as:', `${base} copy`)?.trim();
    if (!name) return;
    try {
      const id = await api.createBrandProfile({ name, theme: themeDraft, sender: senderDraft });
      await reloadProfiles(id);
      onShowToast?.(`Cloned to "${name}"`, 'success');
    } catch (e) { onShowToast?.(e instanceof Error ? e.message : 'Clone failed', 'error'); }
  }

  async function handleDeleteProfile() {
    if (!activeProfileId) return;
    if (!window.confirm(`Delete brand profile "${profileName}"? This cannot be undone.`)) return;
    try {
      await api.deleteBrandProfile(activeProfileId);
      await reloadProfiles(null);
      onShowToast?.('Brand profile deleted', 'success');
    } catch (e) { onShowToast?.(e instanceof Error ? e.message : 'Delete failed', 'error'); }
  }

  async function handleSetDefault() {
    if (!activeProfileId) return;
    try {
      await api.updateBrandProfile(activeProfileId, { isDefault: true });
      await reloadProfiles(activeProfileId);
      onShowToast?.('Set as team default brand', 'success');
    } catch (e) { onShowToast?.(e instanceof Error ? e.message : 'Failed to set default', 'error'); }
  }

  function handleExportKit() {
    const kit = { name: profileName || 'SNR default', theme: themeDraft, sender: senderDraft };
    const blob = new Blob([JSON.stringify(kit, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${(profileName || 'snr-default').replace(/[^a-z0-9]+/gi, '-').toLowerCase()}-brand-kit.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function handleImportKit(file: File) {
    try {
      const parsed = JSON.parse(await file.text()) as { name?: string; theme?: ThemeDraft; sender?: SenderDraft };
      if (parsed.theme) setThemeDraft(parsed.theme);
      if (parsed.sender) setSenderDraft(parsed.sender);
      if (parsed.name && !activeProfileId) setProfileName(parsed.name);
      onShowToast?.('Brand kit imported into the editor — Save to persist', 'info');
    } catch { onShowToast?.('Invalid brand-kit JSON', 'error'); }
  }

  async function handleProfileLogoUpload(file: File) {
    try { setTheme('logoDataUri', await readFileAsDataUri(file)); }
    catch { onShowToast?.('Logo read failed', 'error'); }
  }

  async function handleLogoUpload(file: File) {
    try {
      const dataUri = await api.uploadLogo(file);
      setBrandingField('email_logo_data', dataUri);
      onShowToast?.('Logo uploaded', 'success');
    } catch { onShowToast?.('Logo upload failed', 'error'); }
  }

  async function handleLogoRemove() {
    try { await api.deleteLogo(); setBrandingField('email_logo_data', ''); }
    catch { onShowToast?.('Failed to remove logo', 'error'); }
  }

  // Persist: content → per-session overrides; template/branding/sections → team
  // settings; active brand profile → its theme+sender, and the session's selection.
  async function handleSave() {
    setSaving(true);
    try {
      const current = (await api.fetchSession(sessionId)).analystOverrides ?? {};
      const overrides: Record<string, string> = { ...current };
      const contentKeys = ['subject', ...sections.map((s) => s.key)];
      for (const k of contentKeys) {
        const edited = email[k] as string | undefined;
        const original = result.email_content[k] as string | undefined;
        if (edited !== undefined && edited !== original) overrides[k] = edited;
        else if (k in overrides && edited === original) delete overrides[k];
      }
      await api.saveOverrides(sessionId, overrides);

      await api.saveSettings({
        email_template: templateDraft,
        report_sections: JSON.stringify(sections),
        ...branding,
      });

      // Persist the active brand profile's theme/sender, then the session selection.
      if (activeProfileId) {
        await api.updateBrandProfile(activeProfileId, {
          name: profileName.trim() || undefined,
          theme: themeDraft,
          sender: senderDraft,
        });
      }
      await api.setSessionBrandProfile(sessionId, activeProfileId);

      onShowToast?.('Email saved', 'success');
    } catch (e) {
      onShowToast?.(e instanceof Error ? e.message : 'Save failed', 'error');
    } finally {
      setSaving(false);
    }
  }

  async function handleDownloadEml() {
    try {
      const overrides: Record<string, string> = {};
      const contentKeys = ['subject', 'severity_badge', ...sections.map((s) => s.key)];
      for (const k of contentKeys) {
        const v = email[k] as string | undefined;
        if (v !== undefined) overrides[k] = v;
      }
      await api.exportEml({ session_id: sessionId, audience, tlp, email_content_overrides: overrides });
    } catch (e) {
      onShowToast?.(e instanceof Error ? e.message : 'Download failed', 'error');
    }
  }

  if (!open) return null;

  const editableSections = sections.filter((s) => s.type === 'text' || s.type === 'bullets' || s.type === 'numbered');
  const activeProfile = activeProfileId ? profiles.find((p) => p.id === activeProfileId) : undefined;

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-navy-950">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <Mail className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-semibold text-foreground">Email Studio</h2>
          <span className="text-[11px] text-muted-foreground">
            {AUDIENCE_LABELS[audience as AudienceType] ?? audience} · TLP:{tlp}
          </span>
          {previewLoading && <Loader2 className="w-3 h-3 animate-spin text-muted-foreground" />}
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" className="text-xs h-7 gap-1.5" onClick={handleDownloadEml}>
            <Download className="w-3.5 h-3.5" /> Download .eml
          </Button>
          <Button variant="cyan" size="sm" className="text-xs h-7 gap-1.5" onClick={handleSave} disabled={saving || loading}>
            {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />} Save
          </Button>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors ml-1" aria-label="Close">
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Brand profile bar — the per-session white-label selection. */}
      <div className="flex items-center gap-2 px-4 py-1.5 border-b border-border bg-navy-900/30 flex-shrink-0">
        <Sparkles className="w-3.5 h-3.5 text-cyan-400/70 flex-shrink-0" />
        <span className="text-[10px] uppercase tracking-wide text-cyan-400/70 font-medium">Brand</span>
        <select
          value={activeProfileId ?? ''}
          onChange={(e) => selectProfile(e.target.value || null)}
          className="bg-secondary/40 border border-border rounded px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50 max-w-[240px]"
        >
          <option value="">SNR (default theme)</option>
          {profiles.map((p) => (
            <option key={p.id} value={p.id}>{p.name}{p.isDefault ? ' ★' : ''}</option>
          ))}
        </select>
        <button onClick={handleNewProfile} className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-cyan-300" title="New brand profile"><Plus className="w-3 h-3" />New</button>
        <button onClick={handleCloneProfile} className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-cyan-300" title="Clone current editor state into a new profile"><Copy className="w-3 h-3" />Clone</button>
        {activeProfileId && (
          <>
            <button onClick={handleSetDefault} className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-cyan-300" title="Set as the team default brand"><Star className="w-3 h-3" />{activeProfile?.isDefault ? 'Default' : 'Make default'}</button>
            <button onClick={handleDeleteProfile} className="flex items-center gap-1 text-[10px] text-red-400/70 hover:text-red-400" title="Delete this profile"><Trash2 className="w-3 h-3" />Delete</button>
          </>
        )}
        <div className="ml-auto flex items-center gap-2">
          <button onClick={() => importInput.current?.click()} className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-cyan-300" title="Import a brand-kit JSON into the editor"><FileUp className="w-3 h-3" />Import</button>
          <button onClick={handleExportKit} className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-cyan-300" title="Export the current theme + sender as JSON"><FileDown className="w-3 h-3" />Export</button>
          <input ref={importInput} type="file" accept="application/json,.json" className="hidden" onChange={(e) => e.target.files?.[0] && handleImportKit(e.target.files[0])} />
        </div>
      </div>

      {/* Split body */}
      <div className="flex-1 flex min-h-0">
        {/* Live preview */}
        <div className="flex-1 min-w-0 bg-[#eef0f3] overflow-hidden">
          {previewHtml ? (
            <iframe title="Email preview" srcDoc={previewHtml} sandbox="" className="w-full h-full border-0 bg-white" />
          ) : (
            <div className="w-full h-full flex items-center justify-center text-muted-foreground text-xs">
              {loading ? 'Loading…' : 'Rendering preview…'}
            </div>
          )}
        </div>

        {/* Editor */}
        <div className="w-[440px] flex-shrink-0 border-l border-border flex flex-col bg-navy-900/40">
          {/* Tabs */}
          <div className="grid grid-cols-5 border-b border-border flex-shrink-0">
            {([
              ['content', 'Content', FileText],
              ['layout', 'Layout', LayoutTemplate],
              ['brand', 'Brand Kit', Sparkles],
              ['defaults', 'Defaults', Palette],
              ['sections', 'Sections', ListChecks],
            ] as const).map(([id, label, Icon]) => (
              <button
                key={id}
                onClick={() => setTab(id)}
                className={cn(
                  'flex items-center justify-center gap-1 py-2 text-[11px] transition-colors',
                  tab === id ? 'text-cyan-300 border-b-2 border-cyan-500 bg-cyan-500/5' : 'text-muted-foreground hover:text-foreground'
                )}
              >
                <Icon className="w-3 h-3" />{label}
              </button>
            ))}
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-4">
            {loading ? (
              <div className="flex items-center justify-center py-12 text-muted-foreground"><Loader2 className="w-5 h-5 animate-spin" /></div>
            ) : tab === 'content' ? (
              <>
                <Field label="Subject">
                  <input
                    type="text"
                    value={(email.subject as string) ?? ''}
                    onChange={(e) => onContentChange('subject', e.target.value)}
                    className="w-full bg-secondary/40 border border-border rounded px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                  />
                </Field>
                {editableSections.map((s) => (
                  <Field key={s.key} label={s.label} hint={!s.enabled ? 'hidden in current sections' : undefined}>
                    <RichTextEditor value={(email[s.key] as string) ?? ''} onChange={(v) => onContentChange(s.key, v)} />
                  </Field>
                ))}
                <p className="text-[10px] text-muted-foreground/60">
                  Techniques & IOC tables are auto-generated from the analysis and rendered by their section blocks.
                </p>
              </>
            ) : tab === 'layout' ? (
              <>
                <p className="text-[11px] text-muted-foreground">
                  Body layout (team-wide). Use <code className="font-mono">{'{{BLOCK}}'}</code> tokens for generated content and{' '}
                  <code className="font-mono">{'{field}'}</code> for inline values. Empty = default layout.
                </p>
                <EmailTemplateEditor value={templateDraft} onChange={setTemplateDraft} sections={sections} />
              </>
            ) : tab === 'brand' ? (
              !activeProfileId ? (
                <div className="text-[11px] text-muted-foreground space-y-3 py-2">
                  <p>
                    This session uses the <span className="text-foreground font-medium">SNR default theme</span> (or the team's
                    default brand). Create a brand profile to white-label colors, logo, chrome, and the sender identity for a
                    specific client or tenant.
                  </p>
                  <Button variant="cyan" size="sm" className="text-xs h-7 gap-1.5" onClick={handleNewProfile}>
                    <Plus className="w-3.5 h-3.5" /> New brand profile
                  </Button>
                  <p className="text-[10px] text-muted-foreground/60">You can also Clone the current look or Import a brand-kit JSON from the bar above.</p>
                </div>
              ) : (
                <>
                  <Field label="Profile Name">
                    <TextInput value={profileName} onChange={setProfileName} placeholder="Acme Corp" />
                  </Field>

                  <SectionLabel>Colors</SectionLabel>
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="Primary"><ColorInput value={themeDraft.primary || '#1d4ed8'} onChange={(v) => setTheme('primary', v)} /></Field>
                    <Field label="Header / Accent"><ColorInput value={themeDraft.secondary || '#0a0f1e'} onChange={(v) => setTheme('secondary', v)} /></Field>
                    <Field label="Page Background"><ColorInput value={themeDraft.pageBg || '#eef0f3'} onChange={(v) => setTheme('pageBg', v)} /></Field>
                    <Field label="Body Text"><ColorInput value={themeDraft.bodyText || '#374151'} onChange={(v) => setTheme('bodyText', v)} /></Field>
                    <Field label="Table Header BG"><ColorInput value={themeDraft.tableHeaderBg || '#1e3a5f'} onChange={(v) => setTheme('tableHeaderBg', v)} /></Field>
                    <Field label="Table Header Text"><ColorInput value={themeDraft.tableHeaderText || '#bfdbfe'} onChange={(v) => setTheme('tableHeaderText', v)} /></Field>
                  </div>

                  <SectionLabel>Logo</SectionLabel>
                  <Field label="Logo Image (per profile)">
                    <div className="flex items-center gap-2">
                      {themeDraft.logoDataUri ? (
                        <img src={themeDraft.logoDataUri} alt="logo" className="h-8 max-w-[120px] object-contain bg-navy-800 rounded border border-border" />
                      ) : <span className="text-[10px] text-muted-foreground">No logo</span>}
                      <label className="flex items-center gap-1 text-[10px] text-cyan-400 hover:text-cyan-300 cursor-pointer">
                        <Upload className="w-3 h-3" /> Upload
                        <input type="file" accept="image/*" className="hidden" onChange={(e) => e.target.files?.[0] && handleProfileLogoUpload(e.target.files[0])} />
                      </label>
                      {themeDraft.logoDataUri && (
                        <button onClick={() => setTheme('logoDataUri', '')} className="flex items-center gap-1 text-[10px] text-red-400/70 hover:text-red-400"><Trash2 className="w-3 h-3" />Remove</button>
                      )}
                    </div>
                  </Field>
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="Logo Alt Text"><TextInput value={themeDraft.logoAlt} onChange={(v) => setTheme('logoAlt', v)} placeholder="Acme Corp" /></Field>
                    <Field label="Logo Link"><TextInput value={themeDraft.logoLink} onChange={(v) => setTheme('logoLink', v)} placeholder="https://acme.example" /></Field>
                    <Field label="Logo Max Width (px)"><TextInput value={themeDraft.logoMaxWidth?.toString()} onChange={(v) => setTheme('logoMaxWidth', parseInt(v, 10) || 0)} placeholder="240" /></Field>
                    <Field label="Logo Max Height (px)"><TextInput value={themeDraft.logoMaxHeight?.toString()} onChange={(v) => setTheme('logoMaxHeight', parseInt(v, 10) || 0)} placeholder="80" /></Field>
                  </div>

                  <SectionLabel>Chrome &amp; Type</SectionLabel>
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="Header Title"><TextInput value={themeDraft.headerTitle} onChange={(v) => setTheme('headerTitle', v)} placeholder="SIGNAL TO NOISE" /></Field>
                    <Field label="Header Subtitle"><TextInput value={themeDraft.headerSubtitle} onChange={(v) => setTheme('headerSubtitle', v)} placeholder="Security Intelligence Brief" /></Field>
                    <Field label="Font Family"><TextInput value={themeDraft.fontFamily} onChange={(v) => setTheme('fontFamily', v)} placeholder="Arial" /></Field>
                    <Field label="Body Font Size"><TextInput value={themeDraft.bodyFontSize} onChange={(v) => setTheme('bodyFontSize', v)} placeholder="14" /></Field>
                  </div>
                  <Field label="Footer Text"><TextArea value={themeDraft.footerText} onChange={(v) => setTheme('footerText', v)} placeholder="Leave blank for the default footer" /></Field>
                  <label className="flex items-center gap-2 text-xs text-foreground py-1 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={themeDraft.showVendorAttribution !== false}
                      onChange={(e) => setTheme('showVendorAttribution', e.target.checked)}
                      className="accent-cyan-500"
                    />
                    <span>Show “Generated by SNR” vendor attribution in the default footer</span>
                  </label>

                  <SectionLabel>Sender Identity</SectionLabel>
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="From Name"><TextInput value={senderDraft.fromName} onChange={(v) => setSender('fromName', v)} placeholder="(analyst name)" /></Field>
                    <Field label="From Email"><TextInput value={senderDraft.fromEmail} onChange={(v) => setSender('fromEmail', v)} placeholder="(analyst email)" /></Field>
                  </div>
                  <Field label="Reply-To"><TextInput value={senderDraft.replyTo} onChange={(v) => setSender('replyTo', v)} placeholder="soc@acme.example" /></Field>
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="CC"><TextInput value={senderDraft.cc} onChange={(v) => setSender('cc', v)} placeholder="comma,separated" /></Field>
                    <Field label="BCC"><TextInput value={senderDraft.bcc} onChange={(v) => setSender('bcc', v)} placeholder="comma,separated" /></Field>
                  </div>
                  <Field label="Preheader" hint="inbox preview text"><TextInput value={senderDraft.preheader} onChange={(v) => setSender('preheader', v)} placeholder="One-line summary shown in the inbox" /></Field>
                  <Field label="Subject Template" hint="tokens: {date} {tlp} {severity} {audience} {org_name} {incident_title} {threat_actor_name} {confidence}">
                    <TextInput value={senderDraft.subjectTemplate} onChange={(v) => setSender('subjectTemplate', v)} placeholder="[TLP:{tlp}] {incident_title} — {severity}" />
                  </Field>

                  <p className="text-[10px] text-muted-foreground/60 pt-1">
                    Theme &amp; sender apply to this profile across all sessions that select it. Click <span className="text-foreground">Save</span> to persist.
                  </p>
                </>
              )
            ) : tab === 'defaults' ? (
              <>
                <p className="text-[11px] text-muted-foreground">
                  Team-wide defaults (used when a session has no brand profile, and as the base a profile overrides).
                </p>
                <Field label="Header Title">
                  <TextInput value={branding.email_header_text} onChange={(v) => setBrandingField('email_header_text', v)} placeholder="SIGNAL TO NOISE" />
                </Field>
                <div className="grid grid-cols-2 gap-2">
                  <Field label="Primary Color"><ColorInput value={branding.email_primary_color || '#1d4ed8'} onChange={(v) => setBrandingField('email_primary_color', v)} /></Field>
                  <Field label="Header / Accent"><ColorInput value={branding.email_secondary_color || '#0a0f1e'} onChange={(v) => setBrandingField('email_secondary_color', v)} /></Field>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <Field label="Font Family"><TextInput value={branding.email_font_family} onChange={(v) => setBrandingField('email_font_family', v)} placeholder="Arial" /></Field>
                  <Field label="Body Font Size"><TextInput value={branding.email_body_font_size} onChange={(v) => setBrandingField('email_body_font_size', v)} placeholder="14" /></Field>
                </div>
                <Field label="Logo">
                  <div className="flex items-center gap-2">
                    {branding.email_logo_data ? (
                      <img src={branding.email_logo_data} alt="logo" className="h-8 max-w-[120px] object-contain bg-navy-800 rounded border border-border" />
                    ) : <span className="text-[10px] text-muted-foreground">No logo</span>}
                    <label className="flex items-center gap-1 text-[10px] text-cyan-400 hover:text-cyan-300 cursor-pointer">
                      <Upload className="w-3 h-3" /> Upload
                      <input type="file" accept="image/*" className="hidden" onChange={(e) => e.target.files?.[0] && handleLogoUpload(e.target.files[0])} />
                    </label>
                    {branding.email_logo_data && (
                      <button onClick={handleLogoRemove} className="flex items-center gap-1 text-[10px] text-red-400/70 hover:text-red-400"><Trash2 className="w-3 h-3" />Remove</button>
                    )}
                  </div>
                </Field>
                <Field label={`Audience Intro (${AUDIENCE_LABELS[audience as AudienceType] ?? audience})`}>
                  <TextArea value={branding[introKey]} onChange={(v) => setBrandingField(introKey, v)} placeholder="Optional fixed opening paragraph for this audience" />
                </Field>
                <Field label="Custom Preamble"><TextArea value={branding.email_custom_preamble} onChange={(v) => setBrandingField('email_custom_preamble', v)} /></Field>
                <Field label="Signature"><TextArea value={branding.email_signature} onChange={(v) => setBrandingField('email_signature', v)} /></Field>
                <Field label="Footer Text"><TextArea value={branding.email_footer_text} onChange={(v) => setBrandingField('email_footer_text', v)} /></Field>
              </>
            ) : (
              <>
                <p className="text-[11px] text-muted-foreground">
                  Which sections appear (team-wide; affects the brief, report, and email). Order/inclusion can also be controlled in the Layout template.
                </p>
                {sections.map((s) => (
                  <label key={s.key} className="flex items-center gap-2 text-xs text-foreground py-1 cursor-pointer">
                    <input type="checkbox" checked={!!s.enabled} onChange={() => toggleSection(s.key)} className="accent-cyan-500" />
                    <span className="flex-1">{s.label}</span>
                    <span className="text-[9px] uppercase text-muted-foreground">{s.type}</span>
                  </label>
                ))}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between gap-2">
        <div className="text-[10px] uppercase tracking-wide text-cyan-400/70 font-medium">{label}</div>
        {hint && <span className="text-[9px] text-yellow-400/70 text-right">{hint}</span>}
      </div>
      {children}
    </div>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground border-b border-border/50 pb-1 pt-2">
      {children}
    </div>
  );
}

function TextInput({ value, onChange, placeholder }: { value?: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <input
      type="text"
      value={value ?? ''}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      className="w-full bg-secondary/40 border border-border rounded px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
    />
  );
}

function TextArea({ value, onChange, placeholder }: { value?: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <textarea
      value={value ?? ''}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      rows={2}
      className="w-full bg-secondary/40 border border-border rounded px-2 py-1.5 text-xs text-foreground resize-y focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
    />
  );
}

function ColorInput({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div className="flex items-center gap-2">
      <input type="color" value={value} onChange={(e) => onChange(e.target.value)} className="h-7 w-9 bg-transparent border border-border rounded cursor-pointer" />
      <input type="text" value={value} onChange={(e) => onChange(e.target.value)} className="flex-1 bg-secondary/40 border border-border rounded px-2 py-1 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50" />
    </div>
  );
}
