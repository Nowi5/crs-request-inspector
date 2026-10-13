// Mock host for design review and local testing (panel.html?mock=1).
//
// Starts with the precomputed sample entries from mock-data.json. Pasting, HAR import and
// settings changes use the real parsers + rule engine (loaded lazily from ../parsers and
// ../engine), so the mock behaves like the real panel minus live capture.
//
// Extra URL parameters (mock mode only):
//   stress=N   clone the samples into N entries (list performance testing)
//   live=1     keep adding a sample entry every 1.5 s while recording (simulated traffic)
//   empty=1    start with an empty list
//   data=demo  use demo-data.json (the "Example Shop" scenario used for README screenshots)

const MOCK_URL = new URL(
  typeof location !== 'undefined' && new URLSearchParams(location.search).get('data') === 'demo' ? './demo-data.json' : './mock-data.json',
  import.meta.url
);
const RULESETS_URL = new URL('../../rulesets/', import.meta.url);

const DEFAULT_SETTINGS = {
  version: null,
  blockingParanoiaLevel: 1,
  detectionParanoiaLevel: 4,
  inboundThreshold: 5,
  outboundThreshold: 4,
  earlyBlocking: false,
  includeModsecRecommended: true,
  evaluateResponses: true,
  continueAfterBlock: true,
  remoteAddr: '203.0.113.10',
  protocolOverride: '',
  customRulesBefore: '',
  customRulesAfter: '',
};

export function createHost(opts = {}) {
  const params = new URLSearchParams(globalThis.location ? location.search : '');
  const mode = opts.mode || 'mock';
  const listeners = new Set();
  let entries = [];
  let seq = 0;
  let settings = { ...DEFAULT_SETTINGS };
  let samples = [];
  let rulesetMeta = { version: 'v4.30.0', rules: 0 };
  let index = null;
  let ruleSet = null; // { rs, key }
  let ruleSetPromise = null;
  let ruleSetError = null;
  let loading = false;
  let generation = 0;

  const emit = () => {
    const list = entries.slice();
    for (const cb of listeners) {
      try {
        cb(list);
      } catch (e) {
        console.error(e);
      }
    }
  };

  // Parsers are small: preload so detectFormat() can be synchronous.
  let parsers = null;
  const parsersReady = import('../parsers/index.js').then((m) => (parsers = m)).catch((e) => {
    console.warn('[mock-host] parsers unavailable:', e);
    return null;
  });

  fetch(new URL('index.json', RULESETS_URL)).then((r) => (r.ok ? r.json() : null)).then((j) => { index = j; emit(); }).catch(() => {});

  // ---------------------------------------------------------------- samples
  const ready = (params.has('empty') && mode === 'mock') || mode === 'standalone'
    ? Promise.resolve()
    : fetch(MOCK_URL)
      .then((r) => r.json())
      .then((data) => {
        rulesetMeta = data.ruleset || rulesetMeta;
        samples = data.entries || [];
        const n = Math.max(0, parseInt(params.get('stress') || '0', 10));
        if (n > 0) {
          for (let i = 0; i < n; i++) entries.push(cloneSample(samples[i % samples.length], i));
        } else {
          entries = samples.map((e) => ({ ...e, status: e.status || (e.result ? 'done' : 'pending') }));
          seq = entries.length;
        }
        emit();
      })
      .catch((e) => console.error('[mock-host] could not load mock-data.json', e));

  function cloneSample(e, i) {
    const startedAt = (e.startedAt || Date.now()) + i * 250;
    const url = i < samples.length ? e.request.url : e.request.url.replace(/(\?|$)/, (m) => (m === '?' ? `?n=${i}&` : `?n=${i}`));
    return { ...e, id: `s${++seq}`, startedAt, status: 'done', request: { ...e.request, url } };
  }

  // Simulated live traffic.
  let liveTimer = 0;
  const startLive = () => {
    if (mode !== 'mock' || !params.has('live') || liveTimer) return;
    liveTimer = setInterval(() => {
      if (!host.recording || !samples.length) return;
      entries.push(cloneSample(samples[Math.floor(Math.random() * samples.length)], entries.length));
      emit();
    }, 1500);
  };

  // ---------------------------------------------------------------- engine
  async function getRuleSet() {
    const key = JSON.stringify(settings);
    if (ruleSet && ruleSet.key === key) return ruleSet.rs;
    if (ruleSetPromise && ruleSetPromise.key === key) return ruleSetPromise.promise;
    loading = true;
    const promise = (async () => {
      const [{ loadRuleSet, fetchReader }] = await Promise.all([import('../engine/loader.js')]);
      if (!index) index = await (await fetch(new URL('index.json', RULESETS_URL))).json();
      const rs = await loadRuleSet({ readText: fetchReader(RULESETS_URL), index, settings });
      ruleSet = { rs, key };
      ruleSetError = null;
      rulesetMeta = { version: rs.meta.version, rules: rs.ruleCount, settings: rs.meta.settings };
      return rs;
    })();
    ruleSetPromise = { key, promise };
    try {
      return await promise;
    } catch (e) {
      ruleSetError = e;
      throw e;
    } finally {
      loading = false;
    }
  }

  function evaluateEntry(rs, entry) {
    try {
      const result = rs.evaluate(entry.request, {
        evaluateResponse: settings.evaluateResponses,
        continueAfterInterruption: settings.continueAfterBlock,
      });
      return { ...entry, status: 'done', result, error: undefined };
    } catch (e) {
      return { ...entry, status: 'error', result: null, error: String(e && e.message ? e.message : e) };
    }
  }

  /** Evaluate pending entries in small chunks so the UI stays responsive. */
  async function analyzePending() {
    const gen = generation;
    let rs;
    try {
      rs = await getRuleSet();
    } catch (e) {
      entries = entries.map((x) => (x.status === 'pending' ? { ...x, status: 'error', error: `Rule set failed to load: ${e.message}` } : x));
      emit();
      return;
    }
    const t0 = performance.now();
    for (let i = 0; i < entries.length; i++) {
      if (gen !== generation) return; // superseded by a newer settings change
      if (entries[i].status !== 'pending') continue;
      entries[i] = evaluateEntry(rs, entries[i]);
      if (performance.now() - t0 > 30) {
        emit();
        await new Promise((r) => setTimeout(r, 0));
        return analyzePending();
      }
    }
    emit();
  }

  function addRequests(requests, format) {
    const added = [];
    for (const req of requests) {
      const entry = {
        id: `p${++seq}`,
        source: `paste:${format}`,
        resourceType: req.resourceType || 'fetch',
        startedAt: req.startedAt || Date.now(),
        status: 'pending',
        request: req,
        result: null,
      };
      entries.push(entry);
      added.push(entry);
    }
    emit();
    analyzePending();
    return added;
  }

  // ------------------------------------------------------------------ host
  const host = {
    mode,
    recording: mode !== 'standalone',
    preserveLog: false,
    ready,

    onEntries(cb) {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    getEntries: () => entries.slice(),

    detectFormat(text) {
      if (parsers) return parsers.detectFormat(text);
      const t = String(text || '').trim();
      if (/^\{[\s\S]*"log"\s*:/.test(t)) return 'har';
      if (/^curl\b/i.test(t)) return 'curl';
      if (/^(?:await\s+)?fetch\s*\(/.test(t)) return 'fetch';
      if (/Invoke-(?:WebRequest|RestMethod)|^\$session/i.test(t)) return 'powershell';
      if (/^[A-Z]+ \S+ HTTP\/\d/m.test(t)) return 'raw';
      return 'unknown';
    },

    async analyzeText(text) {
      await parsersReady;
      if (!parsers) return { added: 0, format: 'unknown', errors: ['Parsers could not be loaded.'] };
      const { requests, format, errors } = parsers.parseInput(text);
      const added = addRequests(requests, format);
      return { added: added.length, format, errors, ids: added.map((e) => e.id) };
    },

    async importHarFile(file) {
      await parsersReady;
      if (!parsers) return { added: 0, errors: ['Parsers could not be loaded.'] };
      const text = await file.text();
      const { requests, errors } = parsers.parseInput(text, { format: 'har' });
      const added = addRequests(requests, 'har');
      return { added: added.length, errors, ids: added.map((e) => e.id) };
    },

    clear() {
      entries = [];
      emit();
    },

    getSettings: () => ({ ...settings }),

    async setSettings(partial) {
      settings = { ...settings, ...partial };
      generation++;
      entries = entries.map((e) => ({ ...e, status: 'pending' }));
      emit();
      try {
        await getRuleSet();
      } catch (e) {
        console.error('[mock-host] rule set error', e);
      }
      await analyzePending();
    },

    getRulesetInfo() {
      const rs = ruleSet && ruleSet.rs;
      return {
        versions: index ? index.rulesets.map((r) => r.version) : [rulesetMeta.version],
        defaultVersion: index ? index.default : rulesetMeta.version,
        version: rs ? rs.meta.version : rulesetMeta.version,
        rules: rs ? rs.ruleCount : rulesetMeta.rules,
        warnings: rs ? rs.warnings.slice() : [],
        errors: rs ? rs.errors.slice() : ruleSetError ? [{ file: '', line: 0, message: String(ruleSetError.message || ruleSetError) }] : [],
        loading,
      };
    },

    setRecording(on) {
      host.recording = !!on;
      if (on) startLive();
    },
    setPreserveLog(on) {
      host.preserveLog = !!on;
    },

    // Optional: theme. DevTools: chrome.devtools.panels.themeName ('default' | 'dark').
    themeName: null,
  };

  ready.then(startLive);
  return host;
}
