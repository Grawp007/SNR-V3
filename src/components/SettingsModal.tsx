import { useState, useEffect, useRef } from 'react';
import { X, Save, Settings, Mail, User, Building2, ChevronDown, ChevronRight, Info, Brain, Users, Eye, Code2, Pencil, Plus, Trash2, FileText, LayoutList, Server, GitPullRequest, Sparkles } from 'lucide-react';
import ReportTemplateEditor from './ReportTemplateEditor';
import SectionsEditor from './SectionsEditor';
import ConfirmDialog from './ConfirmDialog';
import { Button } from './ui/button';
import { cn } from '@/lib/utils';
import * as api from '@/lib/api';
import type { CustomAudience, BriefSection } from '@/types';
import { parseSections } from '@/lib/sections';

interface Props {
  open: boolean;
  onClose: () => void;
  /** Launch the standalone Email Studio (team branding/templates/brand profiles). */
  onOpenEmailStudio?: () => void;
}

type Section = 'llm_provider' | 'identity' | 'brief_sections' | 'cc_lists' | 'audience_intros' | 'audience_prompts' | 'report_template' | 'detection_as_code';

const AUDIENCE_KEYS = [
  { key: 'purple_team', label: 'Purple Team' },
  { key: 'soc', label: 'SOC' },
  { key: 'red_team', label: 'Red Team' },
  { key: 'dr', label: 'Detection & Response' },
  { key: 'general', label: 'General' },
];

const TLP_OPTIONS = ['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED'];

const AUDIENCE_PROMPT_DEFAULTS: Record<string, string> = {
  purple_team: 'Focus on the full TTP chain, detection coverage gaps, and emulation recommendations. Include technique-level hunting hypotheses.',
  soc: 'Lead with containment priority and triage steps. Include a watchlist-ready IOC table. Minimize attribution discussion.',
  red_team: 'Frame findings as adversary behavior patterns. Emphasize tooling, C2 infrastructure, and exploitation paths that warrant validation exercises.',
  dr: 'Lead with detection gaps. For each undetected technique, recommend specific log sources, Sigma rule logic, and YARA/Snort signatures where applicable.',
  general: 'Lead with a plain-language threat narrative suitable for broad cybersecurity staff distribution. Avoid deep technical jargon. Summarize business impact clearly and provide a short prioritized action list.',
};

// ── Prompt preview constants (mirrors server/lib/claude.ts) ─────────────────

const CLAUDE_SYSTEM_PROMPT = `You are a senior cyber threat intelligence analyst with deep expertise in the MITRE ATT&CK framework, STIX 2.1, and enterprise security operations. You support Purple Team, SOC, Red Team, Detection & Response, and General cybersecurity staff.

When analyzing security data, you:
  1. Extract observable behaviors and map them to ATT&CK techniques with specific evidence citations
  2. Assign confidence levels (High/Medium/Low) based on evidence directness
  3. Extract and structure all IOCs
  4. Assess detection coverage — only when you have grounded evidence to do so
  5. Generate audience-appropriate communications

Never hallucinate technique IDs — if uncertain, use Low confidence and note the ambiguity.
Be concise: evidence citations ≤ 120 characters, detection recommendations ≤ 200 characters, IOC context ≤ 80 characters.`;

// Anthropic models offered in the model selector. Phase-1 wall-clock time scales
// with model speed, so this is the main lever for analysis latency.
const ANTHROPIC_MODELS: { id: string; label: string }[] = [
  { id: 'claude-sonnet-4-6',           label: 'Sonnet 4.6 — balanced (default)' },
  { id: 'claude-sonnet-4-5',           label: 'Sonnet 4.5 — previous balanced' },
  { id: 'claude-haiku-4-5-20251001',   label: 'Haiku 4.5 — fastest' },
  { id: 'claude-opus-4-8',             label: 'Opus 4.8 — most capable' },
];
const DEFAULT_ANTHROPIC_MODEL = 'claude-sonnet-4-6';

const PHASE1_PROMPT = `Analyze the following security data and produce a structured technical intelligence assessment.
Date: [YYYY-MM-DD]

SECURITY DATA:
[SIEM ALERT]
{your SIEM / alert data}

[LOG DATA]
{uploaded log file content}

[ANALYST NOTES / THREAT INTEL]
{your freeform notes and intel}

[ORGANIZATIONAL CONTEXT]      ← if set in AI Guidance settings
{org evaluation criteria}

[DETECTION STACK]             ← if set in AI Guidance settings
{detection tools description}

Analysis rules:
- Map techniques ONLY to behaviors explicitly evidenced in the input — do not invent
- Extract IOC values as exact strings from the input
- Sort attack_chain by ATT&CK tactic order (Reconnaissance first, Impact last)
- Set all threat_actor fields to null when attribution is not possible
- Truncate evidence strings to ≤ 120 characters with … if needed

Detection coverage rules — applied STRICTLY, no guessing:
- "Likely Detected": ONLY when a SIEM alert directly shows the technique was caught
- "Detection Gap": ONLY when a Detection Stack is provided AND a specific tool clearly misses it
- "Unknown": DEFAULT — used when detection context is absent`;

const phase2PromptBefore = (audienceLabel: string, today: string) =>
  `Draft an intelligence brief for a ${audienceLabel} audience.\nDate: ${today}\nAudience guidance: `;

const phase2PromptAfter = (_audienceLabel: string) =>
  `\n\nTechnical findings to communicate:
- Incident: [incident title] | Severity: [Critical / High / Medium / Low]
- Description: [2-3 sentence description from Phase 1]
- ATT&CK techniques: [e.g. T1059.001 (Execution), T1055 (Defense Evasion), …]
- IOCs: [up to 20 indicators extracted in Phase 1]
- Affected assets: [hostnames / IPs from Phase 1]
- Threat actor: [actor name or Unknown]
[If org context configured: Organizational context for tailoring: {org context}]

Subject line format: TLP:{LEVEL} | {Severity} | {ThreatCategory} | {Date}
Structure the brief as an intelligence document with Threat Action, Threat Summary (Attack Overview / Technical Analysis / Impact Assessment), Threat Actor / Malware Family, MITRE ATT&CK Mapping, Behavioral Indicators, References, and Distribution Information.`;

const BUILT_IN_PHASE1_RULES = `Analysis rules:
- Map techniques ONLY to behaviors explicitly evidenced in the input — do not invent
- Extract IOC values as exact strings from the input
- Sort attack_chain by ATT&CK tactic order (Reconnaissance first, Impact last)
- Set all threat_actor fields to null when attribution is not possible
- Truncate evidence strings to ≤ 120 characters with … if needed

Detection coverage rules — apply STRICTLY, do not guess:
- "Likely Detected": ONLY when SIEM alert or log data directly shows an existing rule caught this technique (the alert firing IS the evidence).
- "Detection Gap": ONLY when a [DETECTION STACK] is provided AND a specific tool clearly misses this technique.
- "Unknown": DEFAULT for all other cases — when detection context is absent or a grounded assessment is not possible.`;

const DEFAULT_PHASE2_TEMPLATE = `Draft an intelligence brief for a {audience} audience.
Date: {date}
Audience guidance: {audience_guidance}

{technical_findings}

{section_guidance}

Subject line format: TLP:{LEVEL} | {Severity} | {ThreatCategory} | {date}

Structure the brief as an intelligence document:
- Threat Action: a brief 1-2 sentence summary of what happened and why it matters
- Threat Summary contains three subsections in order: Attack Overview, Technical Analysis, and Impact Assessment
- For MITRE ATT&CK Mapping: list each T-code with a brief statement explaining how it was specifically applied in this incident
- Behavioral Indicators: describe observable patterns and anomalies in 1-3 paragraphs
- References: cite all source reports, feeds, and CVEs used
- Distribution Information: state TLP handling and authorized recipients`;

export default function SettingsModal({ open, onClose, onOpenEmailStudio }: Props) {
  const [settings, setSettings] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [openSection, setOpenSection] = useState<Section | null>('identity');
  const [showFullPrompt, setShowFullPrompt] = useState<string | null>(null);
  const [editingFields, setEditingFields] = useState<Set<string>>(new Set());
  const [addingAudience, setAddingAudience] = useState(false);
  const [newAudienceName, setNewAudienceName] = useState('');
  const [newAudiencePrompt, setNewAudiencePrompt] = useState('');
  const [ollamaModels, setOllamaModels] = useState<string[]>([]);
  const [ollamaModelsLoading, setOllamaModelsLoading] = useState(false);
  // Anthropic model selector: true when the saved model is a custom (non-preset) id.
  const [customAnthropicModel, setCustomAnthropicModel] = useState(false);
  const today = new Date().toISOString().split('T')[0];

  useEffect(() => {
    if (!open) return;
    setLoading(true);
    setSaveError(null);
    setEditingFields(new Set());
    setAddingAudience(false);
    setNewAudienceName('');
    setNewAudiencePrompt('');
    api.fetchSettings()
      .then((s) => {
        setSettings(s);
        const m = s['model_name']?.trim() ?? '';
        setCustomAnthropicModel(m !== '' && !ANTHROPIC_MODELS.some((opt) => opt.id === m));
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [open]);

  // Fetch available models from OpenAI-compatible endpoint
  useEffect(() => {
    if (settings['llm_provider'] !== 'openai-compatible') { setOllamaModels([]); return; }
    const baseUrl = settings['api_base_url']?.trim();
    if (!baseUrl) { setOllamaModels([]); return; }
    setOllamaModelsLoading(true);
    const url = baseUrl.replace(/\/+$/, '') + '/models';
    fetch(url)
      .then((r) => r.json())
      .then((data: { data?: { id: string }[] }) => {
        const ids = (data.data ?? []).map((m) => m.id).sort();
        setOllamaModels(ids);
        // Auto-select first model if none is set
        if (ids.length > 0 && !settings['model_name']?.trim()) {
          setSettings((prev) => ({ ...prev, model_name: ids[0] }));
        }
      })
      .catch(() => setOllamaModels([]))
      .finally(() => setOllamaModelsLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings['llm_provider'], settings['api_base_url']]);

  const set = (key: string, value: string) =>
    setSettings((prev) => ({ ...prev, [key]: value }));

  const toggle = (id: Section) =>
    setOpenSection((prev) => (prev === id ? null : id));

  const toggleEdit = (key: string) =>
    setEditingFields((prev) => {
      const s = new Set(prev);
      s.has(key) ? s.delete(key) : s.add(key);
      return s;
    });

  // ── Brief sections helpers ──────────────────────────────────────────────
  const briefSections: BriefSection[] = parseSections(settings['report_sections'] || '');

  const setBriefSections = (sections: BriefSection[]) =>
    set('report_sections', JSON.stringify(sections));

  // ── Custom audience helpers ─────────────────────────────────────────────
  const customAudiences: CustomAudience[] = (() => {
    try { return JSON.parse(settings['custom_audiences'] || '[]'); }
    catch { return []; }
  })();

  const setCustomAudiences = (list: CustomAudience[]) =>
    set('custom_audiences', JSON.stringify(list));

  const addCustomAudience = () => {
    const label = newAudienceName.trim();
    if (!label) return;
    const id = `custom_${label.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '')}_${Date.now().toString(36)}`;
    setCustomAudiences([...customAudiences, { id, label, prompt: newAudiencePrompt.trim() }]);
    setAddingAudience(false);
    setNewAudienceName('');
    setNewAudiencePrompt('');
  };

  const updateCustomAudiencePrompt = (id: string, prompt: string) =>
    setCustomAudiences(customAudiences.map((a) => a.id === id ? { ...a, prompt } : a));

  const deleteCustomAudience = (id: string) =>
    setCustomAudiences(customAudiences.filter((a) => a.id !== id));

  const [confirmDeleteAudience, setConfirmDeleteAudience] = useState<{ id: string; label: string } | null>(null);

  const handleSave = async () => {
    setSaving(true);
    setSaveError(null);
    try {
      // Filter out masked sensitive values — never send '••••••••' back to the server
      const filtered = Object.fromEntries(
        Object.entries(settings).filter(([, v]) => v !== '••••••••'),
      );
      await api.saveSettings(filtered);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : 'Save failed — check server connection');
    } finally {
      setSaving(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-navy-800 border border-border rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <Settings className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-foreground">Settings</h2>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors" aria-label="Close">
            <X className="w-4 h-4" />
          </button>
        </div>

        {loading ? (
          <div className="flex-1 flex items-center justify-center text-muted-foreground text-sm">Loading settings…</div>
        ) : (
          <div className="flex-1 overflow-y-auto p-5 space-y-3">

            {/* ── LLM Provider ── */}
            <Accordion
              id="llm_provider"
              label="LLM Provider"
              icon={<Server className="w-3.5 h-3.5" />}
              open={openSection === 'llm_provider'}
              onToggle={() => toggle('llm_provider')}
            >
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1">Provider</label>
                  <select
                    className="w-full bg-navy-900 border border-border rounded px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                    value={settings['llm_provider'] ?? 'anthropic'}
                    onChange={(e) => {
                      set('llm_provider', e.target.value);
                      // Clear model/connection settings when switching providers
                      if (e.target.value === 'anthropic') {
                        set('model_name', '');
                        set('api_base_url', '');
                        set('api_key', '');
                        setCustomAnthropicModel(false);
                      }
                    }}
                  >
                    <option value="anthropic">Anthropic (Claude)</option>
                    <option value="openai-compatible">OpenAI-Compatible (Ollama, LM Studio, vLLM, etc.)</option>
                  </select>
                </div>

                {settings['llm_provider'] === 'openai-compatible' && (
                  <>
                    <EditableField
                      label="API Base URL"
                      help="OpenAI-compatible endpoint (e.g. http://localhost:11434/v1 for Ollama)"
                      value={settings['api_base_url'] ?? ''}
                      onChange={(v) => set('api_base_url', v)}
                      isEditing={editingFields.has('api_base_url')}
                      onToggleEdit={() => toggleEdit('api_base_url')}
                      placeholder="http://localhost:11434/v1"
                      singleLine
                    />
                    <EditableField
                      label="API Key"
                      help="API key for authentication (use 'ollama' for Ollama, 'lm-studio' for LM Studio)"
                      value={settings['api_key'] ?? ''}
                      onChange={(v) => set('api_key', v)}
                      isEditing={editingFields.has('api_key')}
                      onToggleEdit={() => toggleEdit('api_key')}
                      placeholder="ollama"
                      singleLine
                    />
                    {ollamaModels.length > 0 ? (
                      <div>
                        <label className="block text-xs font-medium text-muted-foreground mb-1">Model</label>
                        <select
                          className="w-full bg-navy-900 border border-border rounded px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                          value={settings['model_name'] ?? ''}
                          onChange={(e) => set('model_name', e.target.value)}
                        >
                          {ollamaModels.map((m) => (
                            <option key={m} value={m}>{m}</option>
                          ))}
                        </select>
                        <p className="text-[10px] text-muted-foreground mt-1">{ollamaModels.length} model{ollamaModels.length !== 1 ? 's' : ''} detected from endpoint</p>
                      </div>
                    ) : (
                      <EditableField
                        label="Model Name"
                        help={ollamaModelsLoading ? 'Detecting models…' : 'Model identifier (e.g. llama3.2, mistral-nemo, deepseek-r1)'}
                        value={settings['model_name'] ?? ''}
                        onChange={(v) => set('model_name', v)}
                        isEditing={editingFields.has('model_name')}
                        onToggleEdit={() => toggleEdit('model_name')}
                        placeholder="llama3.2"
                        singleLine
                      />
                    )}
                    <div>
                      <label className="block text-xs font-medium text-muted-foreground mb-1">Context Window</label>
                      <select
                        className="w-full bg-navy-900 border border-border rounded px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                        value={settings['context_window'] ?? '32768'}
                        onChange={(e) => set('context_window', e.target.value)}
                      >
                        <option value="8192">8K tokens</option>
                        <option value="16384">16K tokens</option>
                        <option value="32768">32K tokens (recommended)</option>
                        <option value="65536">64K tokens</option>
                        <option value="131072">128K tokens</option>
                      </select>
                      <p className="text-[10px] text-muted-foreground mt-1">Larger context uses more VRAM/RAM. SNR prompts need ~16K minimum.</p>
                    </div>
                    <div className="flex items-start gap-1.5 text-[10px] text-muted-foreground bg-navy-900/50 rounded p-2 border border-border/50">
                      <Info className="w-3 h-3 mt-0.5 flex-shrink-0 text-cyan-500/70" />
                      <span>On-prem models don't stream partial JSON. Analysis will show a spinner until the full result is ready. JSON output quality depends on the model — larger models (70B+) produce more reliable structured output.</span>
                    </div>
                  </>
                )}

                {settings['llm_provider'] !== 'openai-compatible' && (
                  <>
                    <div>
                      <label className="block text-xs font-medium text-muted-foreground mb-1">Model</label>
                      <select
                        className="w-full bg-navy-900 border border-border rounded px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                        value={customAnthropicModel ? '__custom__' : (settings['model_name']?.trim() || DEFAULT_ANTHROPIC_MODEL)}
                        onChange={(e) => {
                          if (e.target.value === '__custom__') {
                            setCustomAnthropicModel(true);
                            set('model_name', '');
                          } else {
                            setCustomAnthropicModel(false);
                            set('model_name', e.target.value);
                          }
                        }}
                      >
                        {ANTHROPIC_MODELS.map((m) => (
                          <option key={m.id} value={m.id}>{m.label}</option>
                        ))}
                        <option value="__custom__">Custom…</option>
                      </select>
                      <p className="text-[10px] text-muted-foreground mt-1">Faster models reduce analysis time; more capable models add depth. Phase 1 latency scales with model speed.</p>
                    </div>

                    {customAnthropicModel && (
                      <div>
                        <label className="block text-xs font-medium text-muted-foreground mb-1">Custom Model ID</label>
                        <input
                          type="text"
                          className="w-full bg-navy-900 border border-border rounded px-2.5 py-1.5 text-xs text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                          value={settings['model_name'] ?? ''}
                          onChange={(e) => set('model_name', e.target.value)}
                          placeholder="claude-sonnet-4-6"
                        />
                      </div>
                    )}

                    <div className="flex items-start gap-1.5 text-[10px] text-muted-foreground bg-navy-900/50 rounded p-2 border border-border/50">
                      <Info className="w-3 h-3 mt-0.5 flex-shrink-0 text-cyan-500/70" />
                      <span>Anthropic API key is read from the <code className="text-cyan-400/80">.env</code> file. Leaving the model at the default uses <code className="text-cyan-400/80">claude-sonnet-4-6</code> (or the <code className="text-cyan-400/80">CLAUDE_MODEL</code> env var if set).</span>
                    </div>
                  </>
                )}
              </div>
            </Accordion>

            {/* ── Analyst Identity ── */}
            <Accordion
              id="identity"
              label="Analyst Identity"
              icon={<User className="w-3.5 h-3.5" />}
              open={openSection === 'identity'}
              onToggle={() => toggle('identity')}
            >
              <div className="grid grid-cols-2 gap-3">
                <EditableField
                  label="Analyst Name"
                  help="Appears in STIX bundles and email From: field"
                  value={settings['analyst_name'] ?? ''}
                  onChange={(v) => set('analyst_name', v)}
                  isEditing={editingFields.has('analyst_name')}
                  onToggleEdit={() => toggleEdit('analyst_name')}
                  placeholder="CTI Analyst"
                  singleLine
                />
                <EditableField
                  label="Analyst Email"
                  help="Used as the From: address in generated .eml files"
                  value={settings['analyst_email'] ?? ''}
                  onChange={(v) => set('analyst_email', v)}
                  isEditing={editingFields.has('analyst_email')}
                  onToggleEdit={() => toggleEdit('analyst_email')}
                  placeholder="cti@org.com"
                  singleLine
                />
                <EditableField
                  label="Organization Name"
                  help="Appears in email headers and STIX identity objects"
                  value={settings['org_name'] ?? ''}
                  onChange={(v) => set('org_name', v)}
                  isEditing={editingFields.has('org_name')}
                  onToggleEdit={() => toggleEdit('org_name')}
                  placeholder="Security Operations"
                  singleLine
                />
                <EditableField
                  label="Default TLP Level"
                  help="Pre-selected TLP when generating exports"
                  value={settings['default_tlp'] ?? 'AMBER'}
                  onChange={(v) => set('default_tlp', v)}
                  isEditing={editingFields.has('default_tlp')}
                  onToggleEdit={() => toggleEdit('default_tlp')}
                  singleLine
                  renderEdit={
                    <select
                      value={settings['default_tlp'] ?? 'AMBER'}
                      onChange={(e) => set('default_tlp', e.target.value)}
                      className="w-full bg-secondary/50 border border-border rounded-md px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
                    >
                      {TLP_OPTIONS.map((t) => <option key={t} value={t}>TLP:{t}</option>)}
                    </select>
                  }
                />
              </div>
            </Accordion>

            {/* ── Email design → moved to Email Studio ── */}
            <SectionCard icon={<Sparkles className="w-3.5 h-3.5" />} label="Email Branding & Templates">
              <p className="text-xs text-muted-foreground mb-3">Email design for reports lives in Email Studio</p>
              <ul className="text-xs text-muted-foreground/80 space-y-1.5 mb-3 list-disc pl-4">
                <li><strong className="text-foreground/70">Colors, fonts &amp; logo</strong>, header title/subtitle, preamble, signature &amp; footer</li>
                <li><strong className="text-foreground/70">Body layout</strong> — the section template with <span className="font-mono text-[10px]">{'{{BLOCK}}'}</span>/<span className="font-mono text-[10px]">{'{field}'}</span> tokens</li>
                <li><strong className="text-foreground/70">Brand profiles</strong> — reusable per-client white-label themes + sender identity (From / Reply-To / CC / BCC / preheader / subject), selectable per session</li>
              </ul>
              <div className="flex items-start gap-1.5 text-[10px] text-muted-foreground bg-navy-900/50 rounded p-2 border border-border/50 mb-3">
                <Info className="w-3 h-3 mt-0.5 flex-shrink-0 text-cyan-500/70" />
                <span>Open it here to set up team branding before your first analysis, or from the <strong className="text-foreground/70">Email</strong> tab of any analyzed session (where you also edit that session's content and download the .eml). Changes save to the same team-wide defaults.</span>
              </div>
              {onOpenEmailStudio && (
                <Button variant="cyan" size="sm" className="text-xs h-7 gap-1.5" onClick={onOpenEmailStudio}>
                  <Sparkles className="w-3.5 h-3.5" /> Open Email Studio
                </Button>
              )}
            </SectionCard>

            {/* ── AI Guidance (always visible) ── */}
            <SectionCard icon={<Brain className="w-3.5 h-3.5" />} label="AI Guidance">
              <p className="text-xs text-muted-foreground mb-4">
                Help Claude produce more relevant assessments by describing your organization and detection environment.
                These fields are injected into every analysis as context.
              </p>
              <div className="space-y-4">
                <EditableField
                  label="Organizational Context"
                  help="Describe your org's environment, critical assets, regulatory requirements, or threat profile. Claude will prioritize findings relevant to this context."
                  value={settings['org_evaluation_criteria'] ?? ''}
                  onChange={(v) => set('org_evaluation_criteria', v)}
                  isEditing={editingFields.has('org_evaluation_criteria')}
                  onToggleEdit={() => toggleEdit('org_evaluation_criteria')}
                  placeholder="e.g. We are a financial services firm. Critical assets include payment processing servers (PCI-DSS scope), Active Directory, and core banking systems. We are most concerned about ransomware, insider threats, and supply chain attacks."
                  rows={4}
                />
                <EditableField
                  label="Detection Stack"
                  help="List your SIEM, EDR, NDR, and other detection tools. Claude uses this to identify specific detection gaps — without it, coverage assessments default to 'Unknown'."
                  value={settings['org_detection_context'] ?? ''}
                  onChange={(v) => set('org_detection_context', v)}
                  isEditing={editingFields.has('org_detection_context')}
                  onToggleEdit={() => toggleEdit('org_detection_context')}
                  placeholder="e.g. Splunk Enterprise SIEM with ESCU (Splunk Security Essentials), CrowdStrike Falcon EDR on all Windows/macOS endpoints, Palo Alto NGFW with IDS, Windows Event Log forwarding (Security, System, PowerShell), Zeek network sensors on core segments."
                  rows={4}
                />
              </div>
            </SectionCard>

            {/* ── Prompt Engineering (always visible) ── */}
            <SectionCard icon={<Code2 className="w-3.5 h-3.5" />} label="Prompt Engineering">
              <p className="text-xs text-muted-foreground mb-4">
                Override the default prompts sent to Claude. Click <strong className="text-foreground/70">Edit</strong> to customize — the built-in default is pre-loaded so you can make minor tweaks.
                {' '}<strong className="text-yellow-400/80">Advanced — changes here affect all analyses.</strong>
              </p>
              <div className="mb-4 p-3 rounded-lg bg-navy-950 border border-border text-[10px] text-muted-foreground leading-relaxed">
                <div className="text-cyan-400/80 font-semibold uppercase tracking-widest text-[9px] mb-2">Prompt → Output Variable Mapping</div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
                  <div>
                    <div className="text-foreground/70 font-semibold mb-1">Phase 1 (Technical Analysis) generates:</div>
                    <div className="space-y-0.5 font-mono text-[9px]">
                      <div><span className="text-cyan-400">incident_summary</span> → title, severity, confidence</div>
                      <div><span className="text-cyan-400">attack_chain[]</span> → {'{{ATTACK_CHAIN}}'}, {'{{ATTACK_TABLE}}'}</div>
                      <div><span className="text-cyan-400">iocs[]</span> → {'{{IOC_TABLE}}'}, {'{{EMAIL_IOCS}}'}</div>
                      <div><span className="text-cyan-400">threat_actor</span> → {'{{THREAT_ACTOR}}'}</div>
                      <div><span className="text-cyan-400">affected_assets[]</span> → {'{{AFFECTED_ASSETS_TABLE}}'}</div>
                    </div>
                  </div>
                  <div>
                    <div className="text-foreground/70 font-semibold mb-1">Phase 2 (Stakeholder Brief) generates:</div>
                    <div className="space-y-0.5 font-mono text-[9px]">
                      <div><span className="text-orange-400">email_content.subject</span> → Email subject line</div>
                      <div><span className="text-orange-400">email_content.severity_badge</span> → Severity</div>
                      <div><span className="text-orange-400">email_content.summary</span> → "Summary" section</div>
                      <div><span className="text-orange-400">email_content.observations</span> → "Key Observations"</div>
                      <div><span className="text-orange-400">email_content.recommended_actions</span> → "Recommended Actions"</div>
                      <div><span className="text-orange-400">email_content.next_steps</span> → "Next Steps"</div>
                    </div>
                  </div>
                </div>
                <div className="mt-2 pt-2 border-t border-border/40 text-muted-foreground/80">
                  To change what Claude writes for a section (e.g. "Summary"), edit the <strong className="text-foreground/60">Phase 2 template</strong> and/or the <strong className="text-foreground/60">audience prompt</strong>.
                  Section names/order are configured in <strong className="text-foreground/60">Brief Sections</strong>.
                </div>
              </div>
              <p className="text-[10px] text-yellow-400/60 border border-yellow-400/20 rounded px-2 py-1.5 mb-4 bg-yellow-400/5">
                Changes to prompts apply to <strong>new analyses only</strong>. Re-run an analysis to regenerate content with updated prompts.
              </p>
              <div className="space-y-4">
                <EditableField
                  label="System Prompt"
                  help="The system-level context that frames Claude's role and expertise. Sent on both API calls (Phase 1 + Phase 2)."
                  value={settings['system_prompt_override'] ?? ''}
                  defaultValue={CLAUDE_SYSTEM_PROMPT}
                  onChange={(v) => set('system_prompt_override', v)}
                  isEditing={editingFields.has('system_prompt_override')}
                  onToggleEdit={() => toggleEdit('system_prompt_override')}
                  rows={6}
                />
                <EditableField
                  label="Technical Extraction Instructions"
                  help="Rules given to Claude in Phase 1 (ATT&CK mapping, IOC extraction, detection coverage). Controls: incident_summary, attack_chain, iocs, threat_actor, affected_assets."
                  value={settings['phase1_instructions_override'] ?? ''}
                  defaultValue={BUILT_IN_PHASE1_RULES}
                  onChange={(v) => set('phase1_instructions_override', v)}
                  isEditing={editingFields.has('phase1_instructions_override')}
                  onToggleEdit={() => toggleEdit('phase1_instructions_override')}
                  rows={8}
                />
                <EditableField
                  label="Stakeholder Brief Template"
                  help="The Phase 2 prompt that generates the email narrative. Controls: email_content (subject, severity_badge, + all enabled brief sections). Supports template variables shown below."
                  value={settings['phase2_template_override'] ?? ''}
                  defaultValue={DEFAULT_PHASE2_TEMPLATE}
                  onChange={(v) => set('phase2_template_override', v)}
                  isEditing={editingFields.has('phase2_template_override')}
                  onToggleEdit={() => toggleEdit('phase2_template_override')}
                  rows={8}
                  footer={
                    <div className="mt-1.5 text-[10px] text-muted-foreground/60 leading-relaxed">
                      <span className="text-cyan-400/70 font-mono">Variables: </span>
                      {['{audience}', '{date}', '{audience_guidance}', '{technical_findings}'].map((v) => (
                        <span key={v} className="font-mono bg-navy-950 border border-border/60 rounded px-1 py-0.5 mr-1">{v}</span>
                      ))}
                    </div>
                  }
                />
              </div>
            </SectionCard>

            {/* ── Brief Sections ── */}
            <Accordion
              id="brief_sections"
              label="Brief Sections"
              icon={<LayoutList className="w-3.5 h-3.5" />}
              open={openSection === 'brief_sections'}
              onToggle={() => toggle('brief_sections')}
            >
              <SectionsEditor sections={briefSections} onChange={setBriefSections} />
            </Accordion>

            {/* ── CC Lists ── */}
            <Accordion
              id="cc_lists"
              label="CC / BCC Lists per Audience"
              icon={<Building2 className="w-3.5 h-3.5" />}
              open={openSection === 'cc_lists'}
              onToggle={() => toggle('cc_lists')}
            >
              <p className="text-xs text-muted-foreground mb-3">Comma-separated email addresses. Embedded in the .eml CC: header when that audience is selected.</p>
              <div className="space-y-2">
                {AUDIENCE_KEYS.map(({ key, label }) => (
                  <EditableField
                    key={key}
                    label={`CC — ${label}`}
                    help={`Always CC these addresses when exporting to ${label}`}
                    value={settings[`cc_${key}`] ?? ''}
                    onChange={(v) => set(`cc_${key}`, v)}
                    isEditing={editingFields.has(`cc_${key}`)}
                    onToggleEdit={() => toggleEdit(`cc_${key}`)}
                    placeholder="soc-lead@org.com, shift-manager@org.com"
                    singleLine
                  />
                ))}
              </div>
            </Accordion>

            {/* ── Audience Prompts ── */}
            <Accordion
              id="audience_prompts"
              label="Audience Analysis Prompts"
              icon={<Users className="w-3.5 h-3.5" />}
              open={openSection === 'audience_prompts'}
              onToggle={() => toggle('audience_prompts')}
            >
              <p className="text-xs text-muted-foreground mb-3">
                Customize the instructions Claude receives when generating stakeholder briefs for each audience.
                Click <strong className="text-foreground/80">Edit</strong> to customize — the default is pre-loaded for easy tweaking.
              </p>
              <div className="space-y-5">
                {/* ── Built-in audiences ── */}
                {AUDIENCE_KEYS.map(({ key, label }) => {
                  const effectivePrompt = settings[`audience_prompt_${key}`]?.trim() || AUDIENCE_PROMPT_DEFAULTS[key];
                  const isExpanded = showFullPrompt === key;
                  const previewSystemPrompt = settings['system_prompt_override']?.trim() || CLAUDE_SYSTEM_PROMPT;
                  const previewPhase1 = settings['phase1_instructions_override']?.trim() || PHASE1_PROMPT;
                  const phase2TemplateOverride = settings['phase2_template_override']?.trim() || '';
                  return (
                    <EditableField
                      key={key}
                      label={label}
                      help={`Controls how Claude frames the email brief for ${label} recipients.`}
                      value={settings[`audience_prompt_${key}`] ?? ''}
                      defaultValue={AUDIENCE_PROMPT_DEFAULTS[key]}
                      onChange={(v) => set(`audience_prompt_${key}`, v)}
                      isEditing={editingFields.has(`audience_prompt_${key}`)}
                      onToggleEdit={() => toggleEdit(`audience_prompt_${key}`)}
                      rows={3}
                      footer={
                        <>
                          <button
                            onClick={() => setShowFullPrompt(isExpanded ? null : key)}
                            className="flex items-center gap-1 text-[10px] text-cyan-500/70 hover:text-cyan-400 transition-colors mt-1"
                          >
                            <Eye className="w-3 h-3" />
                            {isExpanded ? 'Hide full prompt' : 'View full prompt sent to Claude'}
                          </button>

                          {isExpanded && (
                            <div className="mt-2 border border-cyan-500/20 rounded-lg overflow-hidden bg-navy-950 text-[10px] font-mono">
                              <div className="border-b border-border/60">
                                <div className="flex items-center gap-2 px-3 py-1.5 bg-navy-800/60 border-b border-border/40">
                                  <span className="text-[9px] uppercase tracking-widest text-muted-foreground/50 font-sans font-medium">System Prompt</span>
                                  <span className="text-[9px] text-muted-foreground/30 font-sans">— sent on both API calls</span>
                                  {settings['system_prompt_override']?.trim() && (
                                    <span className="text-[9px] text-cyan-400/70 font-sans ml-auto">✎ custom</span>
                                  )}
                                </div>
                                <pre className="px-3 py-2.5 text-muted-foreground/50 whitespace-pre-wrap leading-relaxed overflow-x-auto">
                                  {previewSystemPrompt}
                                </pre>
                              </div>
                              <div className="border-b border-border/60">
                                <div className="flex items-center gap-2 px-3 py-1.5 bg-navy-800/60 border-b border-border/40">
                                  <span className="text-[9px] uppercase tracking-widest text-muted-foreground/50 font-sans font-medium">Phase 1 · Technical Extraction</span>
                                  <span className="text-[9px] text-yellow-500/60 font-sans">— audience prompt not used here</span>
                                  {settings['phase1_instructions_override']?.trim() && (
                                    <span className="text-[9px] text-cyan-400/70 font-sans ml-auto">✎ custom</span>
                                  )}
                                </div>
                                <pre className="px-3 py-2.5 text-muted-foreground/40 whitespace-pre-wrap leading-relaxed overflow-x-auto">
                                  {previewPhase1}
                                </pre>
                              </div>
                              <div>
                                <div className="flex items-center gap-2 px-3 py-1.5 bg-navy-800/60 border-b border-border/40">
                                  <span className="text-[9px] uppercase tracking-widest text-muted-foreground/50 font-sans font-medium">Phase 2 · Stakeholder Brief</span>
                                  <span className="text-[9px] text-cyan-400/70 font-sans">— your audience prompt is injected here</span>
                                  {phase2TemplateOverride && (
                                    <span className="text-[9px] text-cyan-400/70 font-sans ml-auto">✎ custom template</span>
                                  )}
                                </div>
                                <div className="px-3 py-2.5 leading-relaxed overflow-x-auto">
                                  {phase2TemplateOverride ? (() => {
                                    const processed = phase2TemplateOverride
                                      .replace(/\{audience\}/g, label)
                                      .replace(/\{date\}/g, today)
                                      .replace(/\{technical_findings\}/g, '[auto-generated from Phase 1 results]');
                                    const parts = processed.split('{audience_guidance}');
                                    if (parts.length === 2) {
                                      return (
                                        <>
                                          <span className="text-muted-foreground/50 whitespace-pre-wrap">{parts[0]}</span>
                                          <span className="text-cyan-300 bg-cyan-500/10 rounded px-0.5 whitespace-pre-wrap border-l-2 border-cyan-500/40 pl-1">{effectivePrompt}</span>
                                          <span className="text-muted-foreground/50 whitespace-pre-wrap">{parts[1]}</span>
                                        </>
                                      );
                                    }
                                    return <span className="text-muted-foreground/50 whitespace-pre-wrap">{processed}</span>;
                                  })() : (
                                    <>
                                      <span className="text-muted-foreground/50 whitespace-pre-wrap">{phase2PromptBefore(label, today)}</span>
                                      <span className="text-cyan-300 bg-cyan-500/10 rounded px-0.5 whitespace-pre-wrap border-l-2 border-cyan-500/40 pl-1">{effectivePrompt}</span>
                                      <span className="text-muted-foreground/50 whitespace-pre-wrap">{phase2PromptAfter(label)}</span>
                                    </>
                                  )}
                                </div>
                              </div>
                            </div>
                          )}
                        </>
                      }
                    />
                  );
                })}
                {/* ── Custom audiences ── */}
                {customAudiences.length > 0 && (
                  <div className="border-t border-border/60 pt-4 space-y-4">
                    <div className="text-[10px] uppercase tracking-widest text-muted-foreground/50 flex items-center gap-1.5">
                      <span>Custom Audiences</span>
                      <span className="text-[9px] bg-cyan-500/10 text-cyan-400/70 px-1.5 py-0.5 rounded-full">{customAudiences.length}</span>
                    </div>
                    {customAudiences.map((ca) => (
                      <div key={ca.id} className="space-y-1.5">
                        <div className="flex items-center gap-1.5">
                          <span className="text-xs font-medium text-foreground/80">{ca.label}</span>
                          <span className="text-[9px] bg-cyan-500/15 text-cyan-400 px-1.5 py-0.5 rounded-full border border-cyan-500/20">Custom</span>
                          <button
                            onClick={() => setConfirmDeleteAudience({ id: ca.id, label: ca.label })}
                            className="ml-auto p-0.5 text-muted-foreground/30 hover:text-red-400 transition-colors rounded"
                            title="Delete audience"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                        <EditableField
                          label="Prompt"
                          value={ca.prompt}
                          onChange={(v) => updateCustomAudiencePrompt(ca.id, v)}
                          isEditing={editingFields.has(ca.id)}
                          onToggleEdit={() => toggleEdit(ca.id)}
                          placeholder="Describe how Claude should frame the brief for this audience…"
                          rows={3}
                        />
                      </div>
                    ))}
                  </div>
                )}

                {/* ── Add audience form / button ── */}
                <div className="border-t border-border/60 pt-3">
                  {addingAudience ? (
                    <div className="space-y-3">
                      <div className="text-[10px] uppercase tracking-widest text-muted-foreground/50">New Custom Audience</div>
                      <div className="space-y-1.5">
                        <label className="text-xs font-medium text-foreground/80">Audience Name</label>
                        <input
                          value={newAudienceName}
                          onChange={(e) => setNewAudienceName(e.target.value)}
                          onKeyDown={(e) => e.key === 'Enter' && addCustomAudience()}
                          placeholder="e.g. Legal Team, IT Operations, C-Suite"
                          autoFocus
                          className="w-full bg-secondary/50 border border-cyan-500/40 rounded-md px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-xs font-medium text-foreground/80">Analysis Prompt</label>
                        <textarea
                          value={newAudiencePrompt}
                          onChange={(e) => setNewAudiencePrompt(e.target.value)}
                          placeholder="Describe how Claude should frame the brief for this audience…"
                          rows={3}
                          className="w-full bg-secondary/50 border border-border rounded-md px-3 py-2 text-xs text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none"
                        />
                      </div>
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => { setAddingAudience(false); setNewAudienceName(''); setNewAudiencePrompt(''); }}
                          className="text-xs text-muted-foreground hover:text-foreground px-3 py-1.5 rounded-md hover:bg-secondary/50 transition-colors"
                        >
                          Cancel
                        </button>
                        <Button
                          variant="cyan"
                          size="sm"
                          onClick={addCustomAudience}
                          disabled={!newAudienceName.trim()}
                        >
                          <Plus className="w-3 h-3" />Add Audience
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <button
                      onClick={() => setAddingAudience(true)}
                      className="flex items-center gap-1.5 text-xs text-cyan-500/70 hover:text-cyan-400 transition-colors"
                    >
                      <Plus className="w-3.5 h-3.5" />Add Custom Audience
                    </button>
                  )}
                </div>
              </div>
            </Accordion>

            {/* ── Audience Intros ── */}
            <Accordion
              id="audience_intros"
              label="Audience-Specific Preambles"
              icon={<Mail className="w-3.5 h-3.5" />}
              open={openSection === 'audience_intros'}
              onToggle={() => toggle('audience_intros')}
            >
              <p className="text-xs text-muted-foreground mb-3">Optional opening paragraph inserted before the AI summary, specific to each audience. Use for routing instructions or standard context.</p>
              <div className="space-y-3">
                {AUDIENCE_KEYS.map(({ key, label }) => (
                  <EditableField
                    key={key}
                    label={label}
                    help={`Shown only when audience = ${label}`}
                    value={settings[`custom_intro_${key}`] ?? ''}
                    onChange={(v) => set(`custom_intro_${key}`, v)}
                    isEditing={editingFields.has(`custom_intro_${key}`)}
                    onToggleEdit={() => toggleEdit(`custom_intro_${key}`)}
                    placeholder={`e.g. Please review and update detection rules accordingly. Route responses to #${key.replace('_', '-')}.`}
                    rows={2}
                  />
                ))}
              </div>
            </Accordion>

            {/* ── CTI Report Template ── */}
            <Accordion
              id="report_template"
              label="CTI Report Template"
              icon={<FileText className="w-3.5 h-3.5" />}
              open={openSection === 'report_template'}
              onToggle={() => toggle('report_template')}
            >
              <p className="text-xs text-muted-foreground mb-3">
                Markdown template for the <strong className="text-foreground/70">CTI Report (.md)</strong> export.
                Tokens are highlighted as colored chips — use{' '}
                <strong className="text-foreground/70">Insert Token</strong> to place them at the cursor.
              </p>
              <ReportTemplateEditor
                value={settings['report_template'] ?? ''}
                onChange={(v) => set('report_template', v)}
                sections={briefSections}
              />
            </Accordion>

            {/* ── Detection-as-Code (GitHub) ── */}
            <Accordion
              id="detection_as_code"
              label="Detection-as-Code (GitHub)"
              icon={<GitPullRequest className="w-3.5 h-3.5" />}
              open={openSection === 'detection_as_code'}
              onToggle={() => toggle('detection_as_code')}
            >
              <p className="text-xs text-muted-foreground mb-3">
                Publish a session's Sigma/YARA/Suricata rules and report to a Git repo as a
                pull request. Set a GitHub repo and a personal access token with <strong className="text-foreground/70">repo</strong> scope.
              </p>
              <div className="grid grid-cols-2 gap-3">
                <EditableField
                  label="GitHub Repository"
                  help="owner/repo, e.g. acme-soc/detections"
                  value={settings['dac_github_repo'] ?? ''}
                  onChange={(v) => set('dac_github_repo', v)}
                  isEditing={editingFields.has('dac_github_repo')}
                  onToggleEdit={() => toggleEdit('dac_github_repo')}
                  placeholder="owner/repo"
                  singleLine
                />
                <EditableField
                  label="Base Branch"
                  help="PRs target this branch (default: main)"
                  value={settings['dac_github_branch'] ?? ''}
                  onChange={(v) => set('dac_github_branch', v)}
                  isEditing={editingFields.has('dac_github_branch')}
                  onToggleEdit={() => toggleEdit('dac_github_branch')}
                  placeholder="main"
                  singleLine
                />
                <EditableField
                  label="GitHub Token"
                  help="PAT with repo scope — stored server-side, never shown again"
                  value={settings['dac_github_token'] ?? ''}
                  onChange={(v) => set('dac_github_token', v)}
                  isEditing={editingFields.has('dac_github_token')}
                  onToggleEdit={() => toggleEdit('dac_github_token')}
                  placeholder="ghp_…"
                  singleLine
                />
                <EditableField
                  label="Path Prefix"
                  help="Folder root for rules/reports (default: detections)"
                  value={settings['dac_path_prefix'] ?? ''}
                  onChange={(v) => set('dac_path_prefix', v)}
                  isEditing={editingFields.has('dac_path_prefix')}
                  onToggleEdit={() => toggleEdit('dac_path_prefix')}
                  placeholder="detections"
                  singleLine
                />
              </div>
            </Accordion>

          </div>
        )}

        {/* Footer */}
        <div className="px-5 py-3 border-t border-border flex items-center justify-between gap-2">
          {saveError ? (
            <span className="text-xs text-red-400 flex items-center gap-1.5 min-w-0">
              <X className="w-3.5 h-3.5 flex-shrink-0" />
              <span className="truncate">{saveError}</span>
            </span>
          ) : <span />}
          <div className="flex gap-2 flex-shrink-0">
            <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
            <Button variant="cyan" size="sm" onClick={handleSave} disabled={saving || loading}>
              {saving ? (
                <><span className="w-3 h-3 border-2 border-navy-950/30 border-t-navy-950 rounded-full animate-spin" />Saving…</>
              ) : saved ? (
                <>✓ Saved</>
              ) : (
                <><Save className="w-3.5 h-3.5" />Save Settings</>
              )}
            </Button>
          </div>
        </div>
      </div>

      <ConfirmDialog
        open={!!confirmDeleteAudience}
        title="Delete custom audience?"
        message={`Delete audience "${confirmDeleteAudience?.label ?? ''}"? This cannot be undone.`}
        confirmLabel="Delete"
        danger
        onConfirm={() => {
          if (confirmDeleteAudience) deleteCustomAudience(confirmDeleteAudience.id);
          setConfirmDeleteAudience(null);
        }}
        onCancel={() => setConfirmDeleteAudience(null)}
      />
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SectionCard({ icon, label, children }: { icon: React.ReactNode; label: string; children: React.ReactNode }) {
  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 text-sm font-medium bg-secondary/20 border-b border-border text-foreground">
        <span className="text-muted-foreground">{icon}</span>
        <span>{label}</span>
      </div>
      <div className="px-4 pb-4 pt-3 bg-navy-900/40">
        {children}
      </div>
    </div>
  );
}

function EditableField({
  label, help, value, defaultValue, placeholder, rows = 4,
  singleLine = false, renderEdit,
  isEditing, onToggleEdit, onChange, footer,
}: {
  label: string;
  help?: string;
  value: string;
  defaultValue?: string;
  placeholder?: string;
  rows?: number;
  singleLine?: boolean;
  renderEdit?: React.ReactNode;
  isEditing: boolean;
  onToggleEdit: () => void;
  onChange: (v: string) => void;
  footer?: React.ReactNode;
}) {
  // Local buffer so we can pre-populate with defaultValue on entering edit mode
  const [editBuf, setEditBuf] = useState('');
  const prevIsEditing = useRef(false);

  useEffect(() => {
    // When entering edit mode: init buffer from current value or built-in default
    if (isEditing && !prevIsEditing.current) {
      setEditBuf(value !== '' ? value : (defaultValue ?? ''));
    }
    prevIsEditing.current = isEditing;
  });

  const handleChange = (v: string) => {
    setEditBuf(v);
    onChange(v);
  };

  const handleReset = () => {
    setEditBuf(defaultValue ?? '');
    onChange('');
  };

  const isCustomized = !!value.trim();
  const hasDefault = defaultValue !== undefined;
  const previewContent = isCustomized ? value : (defaultValue ?? '');

  return (
    <div className="space-y-1.5">
      {/* Label row */}
      <div className="flex items-center gap-1.5 min-w-0">
        <span className="text-xs font-medium text-foreground/80 truncate">{label}</span>
        {help && (
          <div className="group relative flex-shrink-0">
            <Info className="w-3 h-3 text-muted-foreground/50 cursor-help" />
            <div className="absolute left-0 bottom-full mb-1.5 w-64 bg-navy-950 border border-border rounded-md px-2.5 py-1.5 text-xs text-muted-foreground hidden group-hover:block z-10 shadow-lg">
              {help}
            </div>
          </div>
        )}
        {hasDefault ? (
          isCustomized
            ? <span className="text-[9px] bg-cyan-500/15 text-cyan-400 px-1.5 py-0.5 rounded-full border border-cyan-500/20 flex-shrink-0">Custom</span>
            : <span className="text-[9px] bg-secondary/80 text-muted-foreground/50 px-1.5 py-0.5 rounded-full flex-shrink-0">Built-in</span>
        ) : (
          isCustomized && <span className="text-[9px] bg-cyan-500/15 text-cyan-400 px-1.5 py-0.5 rounded-full border border-cyan-500/20 flex-shrink-0">Set</span>
        )}
        <button
          onClick={onToggleEdit}
          className="ml-auto flex items-center gap-1 text-[10px] text-cyan-500/70 hover:text-cyan-400 transition-colors flex-shrink-0"
        >
          {isEditing ? (
            <><Eye className="w-3 h-3" />Preview</>
          ) : (
            <><Pencil className="w-3 h-3" />Edit</>
          )}
        </button>
      </div>

      {/* Edit mode */}
      {isEditing ? (
        <div>
          {renderEdit ? (
            renderEdit
          ) : singleLine ? (
            <input
              type="text"
              value={editBuf}
              onChange={(e) => handleChange(e.target.value)}
              placeholder={placeholder ?? defaultValue ?? ''}
              autoFocus
              className="w-full bg-secondary/50 border border-cyan-500/40 rounded-md px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            />
          ) : (
            <textarea
              value={editBuf}
              onChange={(e) => handleChange(e.target.value)}
              placeholder={placeholder ?? defaultValue ?? ''}
              rows={rows}
              autoFocus
              className="w-full bg-secondary/50 border border-cyan-500/40 rounded-md px-3 py-2 text-xs text-foreground placeholder:text-muted-foreground/30 focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none font-mono leading-relaxed"
            />
          )}
          {!renderEdit && (
            <div className="flex items-center gap-3 mt-1">
              {isCustomized && (
                <button
                  onClick={handleReset}
                  className="text-[10px] text-muted-foreground hover:text-red-400 transition-colors"
                >
                  ↩ Reset to {hasDefault ? 'built-in default' : 'empty'}
                </button>
              )}
            </div>
          )}
          {footer && <div className="mt-1">{footer}</div>}
        </div>
      ) : (
        /* Preview mode */
        <div>
          <div
            className={cn(
              'rounded-md border px-3 py-2 text-xs leading-relaxed bg-navy-950 overflow-y-auto',
              singleLine ? 'truncate' : 'whitespace-pre-wrap',
              previewContent
                ? (isCustomized
                    ? 'border-cyan-500/20 text-cyan-200/80 font-mono'
                    : hasDefault
                      ? 'border-border/40 text-muted-foreground/50 font-mono'
                      : 'border-border/40 text-foreground/70')
                : 'border-border/30 text-muted-foreground/30 italic font-sans'
            )}
            style={{ maxHeight: singleLine ? undefined : 180 }}
          >
            {previewContent || (hasDefault ? '(Using built-in default — click Edit to customize)' : '(Not set — click Edit to add)')}
          </div>
          {footer && <div className="mt-1">{footer}</div>}
        </div>
      )}
    </div>
  );
}

function Accordion({ id, label, icon, open, onToggle, children }: {
  id: string; label: string; icon: React.ReactNode; open: boolean;
  onToggle: () => void; children: React.ReactNode;
}) {
  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <button
        onClick={onToggle}
        className={cn(
          'w-full flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors text-left',
          open ? 'bg-cyan-500/10 text-cyan-300' : 'bg-secondary/20 text-foreground hover:bg-secondary/40'
        )}
        aria-expanded={open}
        aria-controls={`accordion-${id}`}
      >
        <span className={open ? 'text-cyan-400' : 'text-muted-foreground'}>{icon}</span>
        <span className="flex-1">{label}</span>
        {open ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" /> : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />}
      </button>
      {open && (
        <div id={`accordion-${id}`} className="px-4 pb-4 pt-3 bg-navy-900/40">
          {children}
        </div>
      )}
    </div>
  );
}
