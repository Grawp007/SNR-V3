#!/usr/bin/env tsx
/**
 * Async-pipeline load test. Submits N analyses concurrently through the
 * integration API and reports enqueue latency and end-to-end throughput. Use it
 * to tune ANALYSIS_WORKER_CONCURRENCY and DB_POOL_MAX for your hardware/LLM.
 *
 * Usage:
 *   SNR_BASE_URL=http://localhost:3001 SNR_API_KEY=snr_... \
 *     npm run loadtest -- [count] [--wait]
 *
 * Each submission consumes one LLM analysis — keep `count` modest against paid
 * providers. `--wait` polls every job to completion to measure throughput.
 */
const BASE = (process.env.SNR_BASE_URL || 'http://localhost:3001').replace(/\/+$/, '');
const KEY = process.env.SNR_API_KEY;
const COUNT = parseInt(process.argv[2] || '10', 10);
const WAIT = process.argv.includes('--wait');

if (!KEY) {
  console.error('Set SNR_API_KEY (an snr_… key with analyze:write + sessions:read).');
  process.exit(1);
}
const H = { Authorization: `Bearer ${KEY}`, 'content-type': 'application/json' };

const SAMPLE =
  'EventID=4625 repeated failed logons from 203.0.113.7, then EventID=4624 RDP success user=svcadmin, ' +
  'followed by mimikatz lsass access and a new scheduled task for persistence.';

async function submit(i: number): Promise<{ ok: boolean; ms: number; sessionId?: string }> {
  const t0 = Date.now();
  try {
    const res = await fetch(`${BASE}/api/v1/analyze`, {
      method: 'POST',
      headers: H,
      body: JSON.stringify({ name: `loadtest ${i}`, audience: 'soc', siem: SAMPLE }),
    });
    const ms = Date.now() - t0;
    if (!res.ok) return { ok: false, ms };
    const j = (await res.json()) as { sessionId: string };
    return { ok: true, ms, sessionId: j.sessionId };
  } catch {
    return { ok: false, ms: Date.now() - t0 };
  }
}

async function waitFor(sessionId: string): Promise<string> {
  for (let i = 0; i < 120; i++) {
    const r = await fetch(`${BASE}/api/v1/analyses/${sessionId}`, { headers: H });
    if (r.ok) {
      const j = (await r.json()) as { status: string };
      if (j.status === 'complete' || j.status === 'failed') return j.status;
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  return 'timeout';
}

async function main() {
  console.log(`Load test: ${COUNT} concurrent submissions to ${BASE}${WAIT ? ' (waiting for completion)' : ''}`);
  const start = Date.now();
  const results = await Promise.all(Array.from({ length: COUNT }, (_, i) => submit(i)));
  const oken = results.filter((r) => r.ok);
  const lat = oken.map((r) => r.ms).sort((a, b) => a - b);
  const p = (q: number) => (lat.length ? lat[Math.min(lat.length - 1, Math.floor(q * lat.length))] : 0);
  console.log(`\nEnqueue: ${oken.length}/${COUNT} accepted in ${Date.now() - start}ms`);
  console.log(`  latency  p50=${p(0.5)}ms  p95=${p(0.95)}ms  max=${lat.at(-1) ?? 0}ms`);

  if (WAIT) {
    const ids = oken.map((r) => r.sessionId!).filter(Boolean);
    const wStart = Date.now();
    const statuses = await Promise.all(ids.map(waitFor));
    const done = statuses.filter((s) => s === 'complete').length;
    const secs = (Date.now() - wStart) / 1000;
    console.log(`\nProcessing: ${done}/${ids.length} completed in ${secs.toFixed(1)}s`);
    console.log(`  throughput ≈ ${(done / secs).toFixed(2)} analyses/sec (raise ANALYSIS_WORKER_CONCURRENCY to increase)`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
