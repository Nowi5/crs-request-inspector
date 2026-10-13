// Node helpers to build a RuleSet from the bundled rule files.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRuleSet } from '../../extension/src/engine/loader.js';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const RULESETS = path.join(ROOT, 'extension', 'rulesets');

export function readIndex() {
  return JSON.parse(readFileSync(path.join(RULESETS, 'index.json'), 'utf8'));
}

export async function buildRuleSet(settings = {}) {
  const index = readIndex();
  const readText = async (p) => readFileSync(path.join(RULESETS, p), 'latin1');
  return loadRuleSet({ readText, index, settings });
}
