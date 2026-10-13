// End-to-end: paste fixtures -> parsers -> engine.  node scripts/test-e2e.mjs
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { parseInput } from '../extension/src/parsers/index.js';
import { buildRuleSet, ROOT } from './lib/node-loader.mjs';

const dir = path.join(ROOT, 'tests', 'fixtures', 'paste');
const rs = await buildRuleSet({});
let fail = 0;
for (const f of readdirSync(dir).sort()) {
  const { requests, format, errors } = parseInput(readFileSync(path.join(dir, f), 'utf8'));
  const lines = requests.map((r) => {
    const res = rs.evaluate(r);
    const hits = res.matches.filter((m) => m.log && !m.isMeta).map((m) => `${m.id}@PL${m.pl}`);
    return `    ${r.method} ${r.url.slice(0, 70)} ${r.httpVersion} -> ${res.blocked ? 'BLOCKED(' + res.interruption.ruleId + ')' : 'pass'} PL1..4=${Object.values(res.inbound.cumulative).join('/')} ${hits.join(' ')}`;
  });
  console.log(`${f} [${format}] ${requests.length} request(s)${errors.length ? ' errors: ' + errors.join('; ') : ''}\n${lines.join('\n')}`);
  if (!requests.length) fail++;
}
// The two PowerShell examples from the user must parse to HTTP/2 requests and pass at PL1.
const ps = parseInput(readFileSync(path.join(dir, 'powershell-copy-all.txt'), 'utf8')).requests;
assert.equal(ps.length, 2);
for (const r of ps) {
  assert.equal(r.httpVersion, 'HTTP/2.0');
  assert.equal(rs.evaluate(r).blocked, false);
}
console.log(fail ? `${fail} fixture(s) produced no request` : 'e2e OK');
process.exit(fail ? 1 : 0);
