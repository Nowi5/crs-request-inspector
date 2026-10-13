#!/usr/bin/env node
// Downloads the development-only test data into vendor/ (git-ignored):
//  - libinjection v4.0.0 sources, unit tests and sample data (scripts/test-libinjection.mjs,
//    scripts/gen-libinjection-data.mjs)
//  - OWASP CRS regression tests + ModSecurity v2 overrides (scripts/run-crs-tests.mjs)
//  - ModSecurity unicode.mapping (scripts/gen-unicode-map.mjs)
//
//   node scripts/fetch-test-data.mjs [--crs v4.30.0] [--skip-crs]
import { mkdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VENDOR = path.join(ROOT, 'vendor');
const LIBINJECTION_TAG = 'v4.0.0';
const args = process.argv.slice(2);
const crsTag = args.includes('--crs') ? args[args.indexOf('--crs') + 1] : 'v4.30.0';

const headers = { 'User-Agent': 'crs-request-inspector-dev' };
if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
const getJson = async (u) => {
  const r = await fetch(u, { headers });
  if (!r.ok) throw new Error(`${u}: HTTP ${r.status}`);
  return r.json();
};
const getBuf = async (u) => {
  const r = await fetch(u, { headers });
  if (!r.ok) throw new Error(`${u}: HTTP ${r.status}`);
  return Buffer.from(await r.arrayBuffer());
};

async function fetchTree(repo, tag, filter, destDir, mapPath = (p) => p) {
  const tree = await getJson(`https://api.github.com/repos/${repo}/git/trees/${tag}?recursive=1`);
  const files = tree.tree.filter((e) => e.type === 'blob' && filter(e));
  let ok = 0;
  for (let i = 0; i < files.length; i += 16) {
    await Promise.all(
      files.slice(i, i + 16).map(async (e) => {
        try {
          const buf = await getBuf(`https://raw.githubusercontent.com/${repo}/${tag}/${e.path}`);
          const dest = path.join(destDir, mapPath(e.path));
          await mkdir(path.dirname(dest), { recursive: true });
          await writeFile(dest, buf);
          ok++;
        } catch (err) {
          console.warn(`  ! ${e.path}: ${err.message}`);
        }
      })
    );
  }
  return `${ok}/${files.length}`;
}

console.log(`libinjection ${LIBINJECTION_TAG} …`);
const libDir = path.join(VENDOR, 'libinjection');
const n = await fetchTree(
  'libinjection/libinjection',
  LIBINJECTION_TAG,
  (e) => (/^src\/libinjection[\w-]*\.(c|h)$/.test(e.path) || /^tests\/test-.*\.txt$/.test(e.path) || (/^data\//.test(e.path) && e.size < 2_000_000) || e.path === 'COPYING'),
  libDir
);
console.log(`  ${n} files -> vendor/libinjection`);

console.log('ModSecurity unicode.mapping …');
await writeFile(path.join(VENDOR, 'unicode.mapping'), await getBuf('https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v2/master/unicode.mapping'));

if (!args.includes('--skip-crs')) {
  console.log(`CRS ${crsTag} regression tests …`);
  const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'fetch-crs.mjs'), '--tests', crsTag], { stdio: 'inherit' });
  if (r.status !== 0) process.exitCode = 1;
  await writeFile(path.join(VENDOR, 'httpd-overrides.yaml'), await getBuf(`https://raw.githubusercontent.com/coreruleset/coreruleset/${crsTag}/tests/regression/httpd-overrides.yaml`));
}
console.log(existsSync(path.join(libDir, 'tests')) ? 'Done.' : 'Done (libinjection tests missing – check warnings).');
