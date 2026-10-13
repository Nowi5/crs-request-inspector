// Analysis worker: loads the CRS rule set and evaluates requests off the UI thread.
// Messages in:  {type:'init', settings, generation}
//               {type:'analyze', id, request, generation}
// Messages out: {type:'ready', info, generation} | {type:'init-error', error, generation}
//               {type:'result', id, result, generation} | {type:'error', id, error, generation}

import { loadRuleSet, fetchReader, DEFAULT_SETTINGS } from './loader.js';
import { loadAzureRuleSet, evaluateAzure } from '../azure/simulate.js';

const RULESETS = new URL('../../rulesets/', import.meta.url);
let ruleSet = null;
let settings = null;
let azure = null; // { rs, policy, profile, info } when simulating an Azure WAF policy
let generation = 0;

async function init(s, gen) {
  const index = await (await fetch(new URL('index.json', RULESETS))).json();
  const t0 = performance.now();
  azure = null;
  if (s.wafProfile === 'azure') {
    azure = await loadAzureRuleSet({ readText: fetchReader(RULESETS), index, settings: { ...DEFAULT_SETTINGS, ...s } });
    ruleSet = azure.rs;
    settings = { ...DEFAULT_SETTINGS, ...s };
  } else {
    ruleSet = await loadRuleSet({ readText: fetchReader(RULESETS), index, settings: s });
    settings = ruleSet.meta.settings;
  }
  generation = gen;
  return {
    versions: index.rulesets.map((r) => r.version),
    defaultVersion: index.default,
    version: ruleSet.meta.version,
    rules: ruleSet.ruleCount,
    loadMs: Math.round(performance.now() - t0),
    warnings: ruleSet.warnings.slice(0, 200),
    errors: ruleSet.errors.slice(0, 200),
    missingFiles: ruleSet.meta.missing,
    azure: azure ? azure.info : null,
    config: {
      requestBodyNoFilesLimit: ruleSet.config.requestBodyNoFilesLimit,
      requestBodyLimit: ruleSet.config.requestBodyLimit,
      responseBodyMimeTypes: ruleSet.config.responseBodyMimeTypes,
    },
  };
}

self.onmessage = async ({ data }) => {
  if (data.type === 'init') {
    try {
      const info = await init(data.settings || {}, data.generation);
      self.postMessage({ type: 'ready', info, generation: data.generation });
    } catch (e) {
      self.postMessage({ type: 'init-error', error: String(e?.stack || e), generation: data.generation });
    }
    return;
  }
  if (data.type === 'analyze') {
    if (!ruleSet) {
      self.postMessage({ type: 'error', id: data.id, error: 'rule set not loaded', generation: data.generation });
      return;
    }
    try {
      const req = { ...data.request };
      if (settings.protocolOverride) req.httpVersion = settings.protocolOverride;
      const result = azure
        ? evaluateAzure(azure, req, settings)
        : ruleSet.evaluate(req, {
            continueAfterInterruption: settings.continueAfterBlock !== false,
            evaluateResponse: settings.evaluateResponses !== false,
            txConfig: { remoteAddr: settings.remoteAddr },
          });
      self.postMessage({ type: 'result', id: data.id, result, generation });
    } catch (e) {
      self.postMessage({ type: 'error', id: data.id, error: String(e?.stack || e), generation });
    }
  }
};
