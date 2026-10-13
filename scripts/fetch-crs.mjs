#!/usr/bin/env node
// Downloads OWASP CRS rule files (rules/*.conf, rules/*.data, crs-setup.conf.example)
// for the requested release tags into extension/rulesets/<tag>/ and writes
// extension/rulesets/index.json, which the extension uses to discover rule sets.
//
// Files are fetched one by one (instead of the release tarball) because antivirus
// products tend to quarantine the whole tarball: CRS ships web-shell signatures and
// attack payloads as test data. If an individual file cannot be written, it is
// skipped and reported; the engine reports rules whose data file is missing.
//
// Usage: node scripts/fetch-crs.mjs [tag ...]
//        node scripts/fetch-crs.mjs              -> latest v4 release, the v4.25 LTS line and latest v3.3
//        node scripts/fetch-crs.mjs --tests v4.30.0  -> also fetch regression tests into vendor/ (dev only)

import { mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'extension', 'rulesets');
const REPO = 'coreruleset/coreruleset';
const MODSEC_RECOMMENDED =
  'https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended';

const headers = { 'User-Agent': 'crs-request-inspector-build' };
if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

async function getJson(url) {
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return res.json();
}

async function getText(url) {
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return res.text();
}

async function pickDefaultTags() {
  const releases = await getJson(`https://api.github.com/repos/${REPO}/releases?per_page=50`);
  const tags = releases.filter((r) => !r.prerelease && !r.draft).map((r) => r.tag_name);
  const parse = (t) => t.replace(/^v/, '').split('.').map(Number);
  const cmp = (a, b) => {
    const x = parse(a), y = parse(b);
    for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (y[i] || 0) - (x[i] || 0);
    return 0;
  };
  tags.sort(cmp);
  const latest4 = tags.find((t) => t.startsWith('v4.'));
  const lts = tags.find((t) => t.startsWith('v4.25.'));
  const latest3 = tags.find((t) => t.startsWith('v3.3.'));
  return [...new Set([latest4, lts, latest3].filter(Boolean))];
}

async function fetchTag(tag, withTests) {
  const tree = await getJson(`https://api.github.com/repos/${REPO}/git/trees/${tag}?recursive=1`);
  const wanted = tree.tree.filter(
    (e) =>
      e.type === 'blob' &&
      ((e.path.startsWith('rules/') && /\.(conf|data)$/.test(e.path)) ||
        e.path === 'crs-setup.conf.example' ||
        e.path === 'LICENSE')
  );
  const dir = path.join(OUT, tag);
  await rm(dir, { recursive: true, force: true });
  await mkdir(path.join(dir, 'rules'), { recursive: true });
  const ok = [], failed = [];
  await Promise.all(
    wanted.map(async (e) => {
      try {
        const text = await getText(`https://raw.githubusercontent.com/${REPO}/${tag}/${e.path}`);
        await writeFile(path.join(dir, e.path), text);
        ok.push(e.path);
      } catch (err) {
        failed.push(`${e.path}: ${err.message}`);
      }
    })
  );
  // Verify files still exist: antivirus scanners (e.g. Windows Defender) may quarantine files
  // containing attack signatures a few seconds after they are written.
  await new Promise((r) => setTimeout(r, 5000));
  const present = ok.filter((p) => existsSync(path.join(dir, p))).sort();
  for (const p of ok) if (!present.includes(p)) failed.push(`${p}: removed after download (antivirus?)`);

  if (withTests) {
    const testFiles = tree.tree.filter((e) => e.type === 'blob' && e.path.startsWith('tests/regression/tests/'));
    const tdir = path.join(ROOT, 'vendor', `tests-${tag}`);
    let n = 0;
    for (let i = 0; i < testFiles.length; i += 20) {
      await Promise.all(
        testFiles.slice(i, i + 20).map(async (e) => {
          try {
            const text = await getText(`https://raw.githubusercontent.com/${REPO}/${tag}/${e.path}`);
            const p = path.join(tdir, e.path.replace('tests/regression/tests/', ''));
            await mkdir(path.dirname(p), { recursive: true });
            await writeFile(p, text);
            n++;
          } catch {}
        })
      );
    }
    console.log(`  tests: ${n}/${testFiles.length} files -> ${path.relative(ROOT, tdir)}`);
  }

  return {
    version: tag,
    path: tag,
    files: present.filter((p) => p.endsWith('.conf')).map((p) => p.replace(/^rules\//, '')),
    dataFiles: present.filter((p) => p.endsWith('.data')).map((p) => p.replace(/^rules\//, '')),
    missing: failed,
    fetchedAt: new Date().toISOString(),
  };
}

async function main() {
  const args = process.argv.slice(2);
  const withTests = args.includes('--tests');
  let tags = args.filter((a) => !a.startsWith('--'));
  if (!tags.length) tags = await pickDefaultTags();
  await mkdir(OUT, { recursive: true });

  const indexPath = path.join(OUT, 'index.json');
  let index = { rulesets: [] };
  if (existsSync(indexPath)) index = JSON.parse(await readFile(indexPath, 'utf8'));

  for (const tag of tags) {
    console.log(`Fetching CRS ${tag} ...`);
    const entry = await fetchTag(tag, withTests);
    console.log(`  ${entry.files.length} rule files, ${entry.dataFiles.length} data files`);
    for (const m of entry.missing) console.warn(`  ! ${m}`);
    index.rulesets = index.rulesets.filter((r) => r.version !== tag);
    index.rulesets.push(entry);
  }
  const ver = (t) => t.replace(/^v/, '').split('.').map(Number);
  index.rulesets.sort((a, b) => {
    const x = ver(a.version), y = ver(b.version);
    for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return y[i] - x[i];
    return 0;
  });
  index.default = index.rulesets[0]?.version;

  try {
    const rec = await getText(MODSEC_RECOMMENDED);
    await mkdir(path.join(OUT, 'modsecurity'), { recursive: true });
    await writeFile(path.join(OUT, 'modsecurity', 'modsecurity.conf-recommended'), rec);
    console.log('Fetched modsecurity.conf-recommended');
  } catch (e) {
    console.warn('! Could not fetch modsecurity.conf-recommended:', e.message);
  }

  await writeFile(indexPath, JSON.stringify(index, null, 2) + '\n');
  console.log(`Wrote ${path.relative(ROOT, indexPath)} (default ${index.default})`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
