import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';

const image = process.argv[2];
const commit = process.argv[3];
if (!image || !/^[a-f0-9]{40}$/.test(commit ?? '')) throw new Error('Image and full commit required');
const docker = (...args) => execFileSync('docker', args, { encoding: 'utf8', timeout: 120_000 }).trim();
const metadata = JSON.parse(docker('image', 'inspect', image))[0];
assert.equal(metadata.Os, 'linux'); assert.equal(metadata.Architecture, 'amd64');
assert.equal(metadata.Config.Labels['com.silmaril.firewall-mcp.commit'], commit);
assert.equal(metadata.Config.Labels['com.silmaril.firewall-mcp.mode'], 'customer_hosted');
const name = `customer-mcp-${randomUUID()}`;
try {
  docker('run', '--detach', '--name', name, '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--publish', '127.0.0.1::3000', image);
  const container = JSON.parse(docker('inspect', name))[0];
  const port = container.NetworkSettings.Ports['3000/tcp'][0].HostPort;
  assert.match(port, /^[0-9]+$/);
  const base = `http://127.0.0.1:${port}`;
  let healthy = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    try { healthy = (await fetch(`${base}/healthz`, { signal: AbortSignal.timeout(2000) })).status === 200; } catch { /* Startup is bounded below. */ }
    if (healthy) break;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  assert.equal(healthy, true, 'Container must become live');
  assert.equal((await fetch(`${base}/readyz`, { signal: AbortSignal.timeout(5000) })).status, 503, 'Unconfigured image must not claim customer readiness');
  docker('exec', name, 'node', '-e', `
    const fs = require('node:fs');
    if (process.getuid() !== 1000) throw new Error('Expected installation UID');
    for (const dir of ['/tmp', '/app/.next/cache']) {
      const path = dir + '/writable-probe'; fs.writeFileSync(path, 'ok'); fs.unlinkSync(path);
    }
    let blocked = false;
    try { fs.writeFileSync('/app/root-write-probe', 'unexpected'); }
    catch (error) { if (!['EROFS', 'EACCES'].includes(error.code)) throw error; blocked = true; }
    if (!blocked) throw new Error('Application root must be read-only');
  `);
} finally {
  try { docker('logs', name); } finally { docker('rm', '--force', '--volumes', name); }
}
