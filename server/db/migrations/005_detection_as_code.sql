-- SNR V3 Phase 5 — detection-as-code publishing.
-- Records the pull request opened for a session's published detections.

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS dac_pr_url TEXT;
