[← Integration API](./07-integration-api.md) · [Manual index](./README.md)

# 8. Detection-as-Code

Publish a session's generated detection rules and its report to a Git repository as
a **pull request**, so detections enter your version-controlled detection-as-code
pipeline for review and deployment.

- [8.1 Configure the GitHub target](#81-configure-the-github-target)
- [8.2 Publish a session](#82-publish-a-session)
- [8.3 What gets published](#83-what-gets-published)

---

## 8.1 Configure the GitHub target

In **Settings → Detection-as-Code (GitHub)** (per team):

| Field | Meaning |
|---|---|
| **GitHub Repository** | `owner/repo` the PRs are opened against |
| **Base Branch** | Branch PRs target (default `main`) |
| **GitHub Token** | A personal access token with **repo** scope — stored server-side, never shown again |
| **Path Prefix** | Folder root for the published files (default `detections`) |

Use a token scoped to just the target repo. A fine-grained PAT with
**Contents: read & write** and **Pull requests: read & write** on that repo is sufficient.

## 8.2 Publish a session

Open an analyzed session, go to the **Rules** tab in the right panel, and click
**Publish to Git (PR)**. SNR opens (or updates) a pull request and opens it in a new
tab. The PR URL is recorded on the session.

Publishing is **idempotent**: each session uses a stable branch
(`snr/<session>-<id>`). Re-publishing after edits pushes to that same branch and
updates the **same open PR** rather than creating duplicates.

> Analyst-flagged false-positive IOCs are excluded from the published report, just
> like other exports.

## 8.3 What gets published

Files are committed under your path prefix, foldered by rule type:

```
detections/
├── sigma/<rule-name>.yml
├── yara/<rule-name>.yar
├── suricata/<rule-name>.rules
└── reports/<session>-<id>.md      # the full Markdown CTI report
```

The PR description links back to the SNR session and lists the files. Review,
adjust, and merge through your normal Git workflow; from there your CI/CD deploys
the rules to your detection stack.

---

[Manual index](./README.md)
