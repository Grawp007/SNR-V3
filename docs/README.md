# SNR — User Manual

**Signal to Noise (SNR)** — AI-powered Cyber Threat Intelligence workbench.
This manual explains how to operate SNR end to end, for analysts and administrators.

> Version: 3.0 · Applies to SNR V3 · Last reviewed against the shipping build.

---

## Who should read what

| You are… | Start here |
|---|---|
| **New to SNR** | [1. Overview](./01-overview.md) → [2. Getting Started](./02-getting-started.md) |
| **An analyst** (running analyses, producing intel) | [3. Analyst Guide](./03-analyst-guide.md) |
| **An administrator** (users, teams, settings, templates) | [4. Administrator Guide](./04-administrator-guide.md) |
| **Integrating other systems** (API keys, feeds, detection-as-code) | [7. Integration API](./07-integration-api.md) · [8. Detection-as-Code](./08-detection-as-code.md) |
| **Looking something up** | [5. Reference](./05-reference.md) · [6. Troubleshooting & FAQ](./06-troubleshooting.md) |
| **Installing / operating the server** | [DEPLOYMENT.md](../DEPLOYMENT.md) |
| **Integrating via API** | [API.md](../API.md) |
| **Reviewing security posture** | [SECURITY.md](../SECURITY.md) |

## Contents

1. [Overview & Concepts](./01-overview.md) — what SNR does, the two-phase pipeline, terminology, data handling
2. [Getting Started](./02-getting-started.md) — sign in, the workspace, your first analysis, keyboard shortcuts
3. [Analyst Guide](./03-analyst-guide.md) — create, review, refine, export, and organize intelligence
4. [Administrator Guide](./04-administrator-guide.md) — roles, users, teams, and every Settings section
5. [Reference](./05-reference.md) — glossary, shortcuts, export formats, audiences, template tokens, env vars
6. [Troubleshooting & FAQ](./06-troubleshooting.md) — common issues and answers
7. [Integration API & Feeds](./07-integration-api.md) — API keys, programmatic submit/fetch, webhooks, threat-intel feeds
8. [Detection-as-Code](./08-detection-as-code.md) — publish rules + reports to GitHub as pull requests

## Related documentation

- [Deployment Guide](../DEPLOYMENT.md) — on-prem install, TLS, backups, metrics, hardening
- [API Reference](../API.md) — REST endpoints
- [Security](../SECURITY.md) — controls and posture
- [`.env.example`](../.env.example) — complete configuration reference

> **Tip:** The application also has built-in help — press **`?`** or click **Help** in the
> sidebar for a quick in-app version of the most common topics.
