[← Analyst Guide](./03-analyst-guide.md) · [Manual index](./README.md) · Next: [Reference →](./05-reference.md)

# 4. Administrator Guide

For administrators and team leads: identity, access, and all of Settings.

- [4.1 Roles & permissions](#41-roles--permissions)
- [4.2 User management](#42-user-management)
- [4.3 Teams & workspaces](#43-teams--workspaces)
- [4.4 Settings reference](#44-settings-reference)
- [4.5 Audit & compliance](#45-audit--compliance)
- [4.6 Operations](#46-operations)

---

## 4.1 Roles & permissions

SNR has **system roles** (on the user) and a **team role** (per team membership).

| Capability | Admin | Analyst | Viewer | Team Lead* |
|---|:--:|:--:|:--:|:--:|
| Run analyses, export, edit briefs | ✓ | ✓ | — | ✓ |
| Tag / group sessions, assign threat actors | ✓ | ✓ | — | ✓ |
| View sessions & reports in their team | ✓ | ✓ | ✓ | ✓ |
| Delete sessions | own/any | own | — | any in team |
| Manage team members | ✓ | — | — | ✓ (their team) |
| Create / delete teams | ✓ | — | — | — |
| Manage users (create, role, disable, reset pw) | ✓ | — | — | — |
| Org-wide analytics across teams | ✓ | — | — | — |

\* **Team Lead** is a per-team elevation (set on a member), not a system role. **Viewer**
is read-only. **Analyst** is the default for new users.

**Multi-tenancy:** all data is **team-scoped** — analysts only see their team's sessions,
threat actors, tags, and settings. Admins operating without a team context can see
org-wide views.

## 4.2 User management

**Admin Panel → Users** (admin only):

- **Create user** — email, display name, temporary password (complexity enforced), and role (`admin` / `analyst` / `viewer`).
- **Edit** — change display name, role, or disable the account.
- **Reset password** — set a new password for a user.
- **Disable** — deletes are soft-disables (the account is retained for audit integrity).

Replace the bootstrap admin's shared credentials with individual accounts as soon as possible.

## 4.3 Teams & workspaces

**Admin Panel → Teams:**

- **Create / delete teams** (admin). A team is an isolated workspace with its own sessions and settings. Only teams with zero sessions can be deleted.
- **Members & leads** — add/remove members; promote a member to **lead** to grant in-team delete and member-management rights.
- **Per-team settings** — most Settings (below) are stored per team, so different teams can have different branding, sections, prompts, and even LLM providers.

## 4.4 Settings reference

Open **Settings** (gear icon). Sections:

| Section | What it controls |
|---|---|
| **LLM Provider** | Choose Anthropic or an OpenAI-compatible endpoint. For OpenAI-compatible, set **API Base URL**, **API Key**, and **Model Name** (Ollama, LM Studio, vLLM, Azure OpenAI). |
| **Analyst Identity** | **Analyst Name**, **Analyst Email**, **Organization Name**, and **Default TLP Level** — these populate export headers and report metadata. |
| **AI Guidance** | **Organizational Context** (your environment, crown jewels, industry) and **Detection Stack** (your SIEM/EDR/firewall) — injected into every analysis. Detection-gap analysis only works when the Detection Stack is filled in. Be specific. |
| **Brief Sections** | The blocks of the Phase 2 brief. Reorder (↑/↓), enable/disable, edit each section's Claude instructions, or **Add Section** (label, type, unique snake_case key, instructions). Types: `text`, `bullets`, `numbered`, and auto `techniques` / `iocs` (read-only, filled from Phase 1). |
| **Audience Analysis Prompts** | Override each built-in audience's framing prompt, and **add custom audiences** (appear in the analysis dropdown). |
| **Audience-Specific Preambles** | A fixed opening paragraph per audience (boilerplate disclaimers, mandatory headers). |
| **Email Template** | The **body layout** of the email brief, edited as a token document: `{{SECTIONS}}` / `{{SECTION:key}}`, `{{TECHNIQUES_TABLE}}`, `{{IOCS_TABLE}}`, `{{PREAMBLE}}`, `{{AUDIENCE_INTRO}}`, `{{SIGNATURE}}`, plus inline `{field}` tokens. Empty = built-in default layout. Live preview included. |
| **Email Branding** | The visual wrapper: **Email Header Title**, **Footer Text**, **Signature Block**, **Custom Preamble**, colors, logo, and font family/size. Live preview included. |
| **CTI Report Template** | The Markdown report layout, using `{field}` and `{{BLOCK}}` tokens (`{{SECTIONS}}`, `{{ATTACK_TABLE}}`, `{{ATTACK_CHAIN}}`, `{{IOC_TABLE}}`, `{{EMAIL_IOCS}}`, `{{AFFECTED_ASSETS_TABLE}}`, `{{THREAT_ACTOR}}`, `{{CAMPAIGN_TIMELINE}}`). Empty = built-in structured report. |
| **CC / BCC Lists per Audience** | Comma-separated recipient lists per audience, written into the exported `.eml`. |
| **Prompt Engineering** | Advanced overrides: **System Prompt**, **Technical Extraction Instructions** (Phase 1), and **Stakeholder Brief Template** (Phase 2, supports `{audience}`, `{date}`, `{audience_guidance}`, `{section_guidance}`, `{technical_findings}`). |
| **Detection-as-Code (GitHub)** | GitHub **repo**, **base branch**, **token** (PAT with repo scope, masked), and **path prefix** for publishing rules + reports as pull requests. See [8. Detection-as-Code](./08-detection-as-code.md). |

> **Email Template vs. Email Branding:** *Template* controls the body **layout/content
> order** (tokens); *Branding* controls the **look** (colors, logo, fonts, header/footer).
> Both have live previews. Leaving a template empty uses the built-in default.

> **Re-run after section/prompt changes.** Stored results use the schema/prompt that was
> active at analysis time. Run a new analysis (or **Re-analyze**) to pick up changes.

## 4.5 Audit & compliance

- **Audit trail** (Activity Log → Audit) records logins, analyses, exports, edits, deletes, restores, threat-actor changes, etc. It is append-only.
- **Retention** — deleted sessions are soft-deleted and purged after 7 days; backups run on a schedule (see DEPLOYMENT.md).
- **Redaction** — analysts can mask sensitive strings before analysis; enforced client- and server-side.
- **TLP** — set a default in Analyst Identity; per-session overrides apply to exports.
- **Logs** are structured JSON with secrets redacted — forward to your SIEM.

Full control set: [SECURITY.md](../SECURITY.md).

## 4.6 Integration, feeds & detection-as-code

Two admin-panel tabs and one settings section extend SNR into an enterprise stack:

- **Admin Panel → API Keys** — create service accounts and mint scoped API keys so
  other systems can submit/fetch analyses. See [7. Integration API](./07-integration-api.md).
- **Admin Panel → Threat Feeds** — add TAXII/MISP/RSS sources that are polled on a
  cadence and auto-analyzed. See [7.4 Threat-intel feeds](./07-integration-api.md#74-threat-intel-feeds).
- **Settings → Detection-as-Code** — publish a session's rules + report to GitHub as a
  pull request. See [8. Detection-as-Code](./08-detection-as-code.md).

## 4.7 Operations

Installation, Postgres, the background worker, TLS, scheduled `pg_dump` backups &
restore, Prometheus `/metrics` (+ Grafana dashboard), secrets (`*_FILE`), scaling,
and the hardening checklist live in the **[Deployment Guide](../DEPLOYMENT.md)**.
Programmatic access is documented in the **[API Reference](../API.md)**.

---

Next: [Reference →](./05-reference.md)
