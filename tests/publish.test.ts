import { describe, it, expect } from 'vitest';
import { buildFiles, parseDacConfig } from '../server/lib/publish/github.js';
import type { AnalysisResult } from '../server/lib/claude.js';

const rule = (rule_type: string, rule_name: string, rule_content: string) => ({
  rule_type, rule_name, rule_content, description: 'desc', source: 'generated', confidence: 'High', related_technique: null,
});

const result = {
  detection_rules: [
    rule('sigma', 'Cobalt Strike Beacon', 'title: cs'),
    rule('yara', 'Mimikatz Loader', 'rule m {}'),
    rule('suricata', 'C2 Beacon', 'alert tcp any any -> any any (msg:"c2";)'),
    rule('sigma', 'Cobalt Strike Beacon', 'title: cs duplicate name'), // filename collision
    rule('unknown', 'Ignored', 'whatever'), // unsupported type -> skipped
    rule('sigma', 'Empty', '   '), // empty content -> skipped
  ],
} as unknown as AnalysisResult;

describe('detection-as-code: parseDacConfig', () => {
  it('returns null when unconfigured or incomplete', () => {
    expect(parseDacConfig({})).toBeNull();
    expect(parseDacConfig({ dac_github_repo: 'owner/repo' })).toBeNull(); // no token
    expect(parseDacConfig({ dac_github_token: 't' })).toBeNull(); // no repo
    expect(parseDacConfig({ dac_github_repo: 'noslash', dac_github_token: 't' })).toBeNull();
  });

  it('parses repo/branch/prefix with defaults', () => {
    const c = parseDacConfig({ dac_github_repo: 'acme/detections', dac_github_token: 'ghp_x' });
    expect(c).toMatchObject({ owner: 'acme', repo: 'detections', branch: 'main', pathPrefix: 'detections' });
    const c2 = parseDacConfig({ dac_github_repo: 'a/b', dac_github_token: 't', dac_github_branch: 'develop', dac_path_prefix: '/rules/' });
    expect(c2).toMatchObject({ branch: 'develop', pathPrefix: 'rules' });
  });
});

describe('detection-as-code: buildFiles', () => {
  const files = buildFiles(result, '# report body', 'my-session', 'abc12345', 'detections');
  const paths = files.map((f) => f.path);

  it('folders rules by type with correct extensions', () => {
    expect(paths).toContain('detections/sigma/cobalt-strike-beacon.yml');
    expect(paths).toContain('detections/yara/mimikatz-loader.yar');
    expect(paths).toContain('detections/suricata/c2-beacon.rules');
  });

  it('dedupes colliding filenames', () => {
    expect(paths).toContain('detections/sigma/cobalt-strike-beacon-2.yml');
  });

  it('includes the markdown report', () => {
    const report = files.find((f) => f.path === 'detections/reports/my-session-abc12345.md');
    expect(report?.content).toContain('# report body');
  });

  it('skips unsupported types and empty rules', () => {
    expect(paths.some((p) => p.includes('ignored'))).toBe(false);
    expect(paths.some((p) => p.includes('empty'))).toBe(false);
  });
});
