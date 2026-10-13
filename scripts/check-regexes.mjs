// Parses every rule file of every bundled CRS version and compiles all @rx patterns
// (and regex variable keys) with the PCRE -> JS translator. Reports failures/warnings.
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseConfig, parseOperator, parseVariables } from '../extension/src/engine/seclang.js';
import { compilePcre } from '../extension/src/engine/pcre.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RS = path.join(ROOT, 'extension', 'rulesets');
const index = JSON.parse(readFileSync(path.join(RS, 'index.json'), 'utf8'));
let bad = 0;
const sets = [...index.rulesets.map((r) => ({ v: r.version, dir: path.join(RS, r.path, 'rules'), files: r.files })),
  { v: 'modsecurity', dir: path.join(RS, 'modsecurity'), files: ['modsecurity.conf-recommended'] }];
for (const { v, dir, files } of sets) {
  let total = 0, warnCount = 0;
  const warnKinds = {};
  for (const f of files) {
    const text = readFileSync(path.join(dir, f), 'latin1');
    const { directives, errors } = parseConfig(text, f);
    for (const e of errors) console.log(v, 'PARSE', e);
    for (const d of directives) {
      if (d.name !== 'SecRule' && d.name !== 'SecRuleUpdateTargetById') continue;
      const pats = [];
      if (d.name === 'SecRule') {
        const op = parseOperator(d.args[1] ?? '');
        if (op.name === 'rx') pats.push(op.param);
        for (const vv of parseVariables(d.args[0])) if (vv.keyRegex) pats.push(vv.keyRegex);
      } else {
        for (const vv of parseVariables(d.args[1])) if (vv.keyRegex) pats.push(vv.keyRegex);
      }
      for (const p of pats) {
        total++;
        const r = compilePcre(p);
        if (!r.re) {
          bad++;
          console.log(`${v} ${f}:${d.line} ERROR ${r.error}\n   ${p.slice(0, 200)}`);
        } else if (r.warnings.length) {
          warnCount++;
          for (const w of r.warnings) warnKinds[w] = (warnKinds[w] || 0) + 1;
        }
      }
    }
  }
  console.log(`${v}: ${total} regexes, ${warnCount} with warnings`, warnKinds);
}
process.exit(bad ? 1 : 0);
