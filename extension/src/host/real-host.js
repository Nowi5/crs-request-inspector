// Real host for the UI: owns the entry list, the analysis worker, settings and the
// DevTools network capture. See src/ui/mock-host.js for the interface.

import { parseInput, detectFormat as detectFormatImpl, fromHarEntry } from '../parsers/index.js';
import { harToRequests } from '../parsers/har.js';
import { DEFAULT_SETTINGS } from '../engine/loader.js';

const SETTINGS_KEY = 'crsInspectorSettings';
const MAX_ENTRIES = 3000;
const ANALYZE_TIMEOUT_MS = 15000;
const RESPONSE_BODY_MAX = 1024 * 1024;

const hasChromeStorage = () => typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local;

async function loadSettings() {
  try {
    if (hasChromeStorage()) {
      const r = await chrome.storage.local.get(SETTINGS_KEY);
      return { ...DEFAULT_SETTINGS, ...(r[SETTINGS_KEY] || {}) };
    }
    const raw = localStorage.getItem(SETTINGS_KEY);
    return { ...DEFAULT_SETTINGS, ...(raw ? JSON.parse(raw) : {}) };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

async function saveSettings(s) {
  try {
    if (hasChromeStorage()) await chrome.storage.local.set({ [SETTINGS_KEY]: s });
    else localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
  } catch {
    /* settings just won't persist */
  }
}

/** Wait for the bridge object that devtools.js puts on this panel window. */
function waitForBridge() {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const check = () => {
      if (window.__crsDevtoolsBridge) return resolve(window.__crsDevtoolsBridge);
      setTimeout(check, Date.now() - t0 < 5000 ? 50 : 1000);
    };
    check();
  });
}

export function createHost({ mode } = {}) {
  const params = new URLSearchParams(location.search);
  const inDevtools = typeof chrome !== 'undefined' && !!chrome.devtools && !params.has('standalone');
  mode = mode || (inDevtools ? 'devtools' : 'standalone');

  let entries = [];
  const byId = new Map();
  const listeners = new Set();
  let seq = 0;
  let settings = { ...DEFAULT_SETTINGS };
  let rulesetInfo = null;
  let rulesetError = null;
  const infoListeners = new Set();

  // ---- change notification (batched) ----
  let emitScheduled = false;
  const emit = () => {
    if (emitScheduled) return;
    emitScheduled = true;
    setTimeout(() => {
      emitScheduled = false;
      const snapshot = entries.slice();
      for (const cb of listeners) {
        try {
          cb(snapshot);
        } catch (e) {
          console.error(e);
        }
      }
    }, 30);
  };
  const emitInfo = () => {
    for (const cb of infoListeners) {
      try {
        cb(host.getRulesetInfo());
      } catch (e) {
        console.error(e);
      }
    }
  };

  // ---- worker management ----
  let worker = null;
  let workerReady = false;
  let generation = 0;
  const queue = [];
  let inflight = null; // { id, timer }

  function startWorker() {
    if (worker) worker.terminate();
    workerReady = false;
    generation++;
    worker = new Worker(new URL('../engine/worker.js', import.meta.url), { type: 'module' });
    worker.onmessage = onWorkerMessage;
    worker.onerror = (e) => {
      rulesetError = `Worker error: ${e.message || e}`;
      emitInfo();
    };
    worker.postMessage({ type: 'init', settings, generation });
  }

  function onWorkerMessage({ data }) {
    if (data.generation !== generation) return; // stale worker/settings
    if (data.type === 'ready') {
      workerReady = true;
      rulesetInfo = data.info;
      rulesetError = null;
      emitInfo();
      emit(); // lets the UI refresh status/ruleset info even without entry changes
      pump();
      return;
    }
    if (data.type === 'init-error') {
      rulesetError = data.error;
      emitInfo();
      return;
    }
    if (data.type === 'result' || data.type === 'error') {
      if (!inflight || inflight.id !== data.id) return;
      clearTimeout(inflight.timer);
      inflight = null;
      const e = byId.get(data.id);
      if (e) {
        if (data.type === 'result') {
          e.result = data.result;
          e.status = 'done';
          e.error = null;
        } else {
          e.status = 'error';
          e.error = data.error;
        }
        emit();
      }
      pump();
    }
  }

  function pump() {
    if (!workerReady || inflight) return;
    let id;
    while ((id = queue.shift()) !== undefined) {
      if (byId.has(id)) break;
    }
    if (id === undefined) return;
    const e = byId.get(id);
    const timer = setTimeout(() => {
      // Probably catastrophic regex backtracking: kill the worker and continue.
      e.status = 'error';
      e.error = `Analysis timed out after ${ANALYZE_TIMEOUT_MS / 1000}s (a rule regex may be backtracking catastrophically on this input).`;
      inflight = null;
      emit();
      startWorker();
    }, ANALYZE_TIMEOUT_MS);
    inflight = { id, timer };
    worker.postMessage({ type: 'analyze', id, request: e.request, generation });
  }

  function enqueue(entry) {
    entry.status = 'pending';
    queue.push(entry.id);
    pump();
  }

  function addEntry(request, { source, resourceType, startedAt }) {
    const entry = {
      id: `e${++seq}`,
      source,
      resourceType: resourceType || request.resourceType || (source === 'devtools' ? 'other' : 'paste'),
      startedAt: startedAt || request.startedAt || Date.now(),
      status: 'pending',
      error: null,
      request,
      result: null,
    };
    // Keep the list in request start order (response bodies are fetched asynchronously).
    let at = entries.length;
    while (at > 0 && (entries[at - 1].startedAt || 0) > entry.startedAt) at--;
    entries.splice(at, 0, entry);
    byId.set(entry.id, entry);
    if (entries.length > MAX_ENTRIES) {
      const removed = entries.splice(0, entries.length - MAX_ENTRIES);
      for (const r of removed) byId.delete(r.id);
    }
    enqueue(entry);
    emit();
    return entry;
  }

  // ---- DevTools capture ----
  let recording = true;
  let preserveLog = false;
  let bridge = null;
  let navGeneration = 0;

  function shouldFetchBody(req) {
    const mime = String(req.response?.content?.mimeType || '').toLowerCase().split(';')[0].trim();
    const allowed = rulesetInfo?.config?.responseBodyMimeTypes || ['text/plain', 'text/html', 'text/xml'];
    const size = req.response?.content?.size ?? 0;
    return settings.evaluateResponses && allowed.includes(mime) && size <= RESPONSE_BODY_MAX;
  }

  const stats = { received: 0, converted: 0, added: 0, dropped: { recording: 0, nonHttp: 0, error: 0, navigation: 0 } };
  // Requests already handled, so the getHAR() fallback below does not add them twice.
  const seen = new Set();
  const harKey = (e) => `${e.startedDateTime}|${e.request?.method}|${e.request?.url}`;

  async function onHarRequest(req) {
    stats.received++;
    const key = harKey(req);
    if (seen.has(key)) return;
    seen.add(key);
    if (seen.size > 20000) seen.clear();
    if (!recording) return void stats.dropped.recording++;
    const gen = navGeneration;
    let parsed;
    try {
      parsed = fromHarEntry(req, { source: 'devtools' });
    } catch (e) {
      console.warn('CRS inspector: could not convert request', e);
      stats.dropped.error++;
      return;
    }
    if (!parsed) return void stats.dropped.nonHttp++;
    stats.converted++;
    if (parsed.response && shouldFetchBody(req) && typeof req.getContent === 'function') {
      try {
        const [content, encoding] = await new Promise((resolve) => req.getContent((c, enc) => resolve([c, enc])));
        if (content != null) {
          parsed.response.body = content;
          parsed.response.bodyEncoding = encoding === 'base64' ? 'base64' : 'text';
        }
      } catch {
        /* response body unavailable */
      }
    }
    // The page navigated while the body was being fetched: drop it like the Network panel does.
    if (gen !== navGeneration && !preserveLog) return void stats.dropped.navigation++;
    stats.added++;
    addEntry(parsed, { source: 'devtools', resourceType: req._resourceType, startedAt: Date.parse(req.startedDateTime) || Date.now() });
  }

  async function attachDevtools() {
    bridge = await waitForBridge();
    if (!bridge) return;
    bridge.setSink(onHarRequest);
    for (const r of bridge.drain()) onHarRequest(r);
    // Fallback: Chrome does not fire onRequestFinished for every request (e.g. fetches whose
    // response body the page never reads). Pick those up from the Network log periodically.
    const network = typeof chrome !== 'undefined' ? chrome.devtools?.network : null;
    if (network?.getHAR) {
      const sweep = () => {
        if (!recording) return;
        try {
          network.getHAR((har) => {
            for (const e of har?.entries || []) {
              if (e.response && e.response.status > 0 && !seen.has(harKey(e))) {
                stats.fromHar = (stats.fromHar || 0) + 1;
                onHarRequest(e);
              }
            }
          });
        } catch {
          /* DevTools closed */
        }
      };
      setInterval(sweep, 2000);
    }
    // If this panel document goes away (reload), let the DevTools page buffer again.
    window.addEventListener('pagehide', () => {
      bridge.setSink(null);
      bridge.setNavigationSink(null);
    });
    bridge.setNavigationSink(() => {
      navGeneration++;
      if (preserveLog) return;
      entries = entries.filter((e) => e.source !== 'devtools');
      for (const id of [...byId.keys()]) if (!entries.some((e) => e.id === id)) byId.delete(id);
      emit();
    });
  }

  const host = {
    get mode() {
      return mode;
    },
    get themeName() {
      try {
        if (inDevtools) return chrome.devtools.panels.themeName || null;
      } catch {}
      return null;
    },
    onThemeChange(cb) {
      try {
        if (inDevtools && chrome.devtools.panels.setThemeChangeHandler) chrome.devtools.panels.setThemeChangeHandler(cb);
      } catch {}
    },
    ready: null,
    onEntries(cb) {
      listeners.add(cb);
      cb(entries.slice());
      return () => listeners.delete(cb);
    },
    onRulesetInfo(cb) {
      infoListeners.add(cb);
      cb(host.getRulesetInfo());
      return () => infoListeners.delete(cb);
    },
    getEntries() {
      return entries.slice();
    },
    detectFormat(text) {
      try {
        return detectFormatImpl(text);
      } catch {
        return 'unknown';
      }
    },
    async analyzeText(text) {
      const { requests, format, errors } = parseInput(text);
      const ids = [];
      for (const r of requests) ids.push(addEntry(r, { source: `paste:${format}`, resourceType: r.resourceType || 'paste' }).id);
      return { added: requests.length, format, errors: errors || [], ids };
    },
    async importHarFile(file) {
      const text = await file.text();
      let requests, errors = [];
      try {
        const r = harToRequests(text);
        requests = r.requests || [];
        errors = [...(r.errors || [])];
        if (r.skipped) errors.push(`${r.skipped} entr${r.skipped === 1 ? 'y' : 'ies'} skipped (non-HTTP URLs such as data: or blob:)`);
      } catch (e) {
        return { added: 0, errors: [String(e.message || e)], ids: [] };
      }
      const ids = [];
      for (const r of requests) if (r) ids.push(addEntry(r, { source: 'har', resourceType: r.resourceType }).id);
      return { added: ids.length, errors, ids };
    },
    clear() {
      entries = [];
      byId.clear();
      queue.length = 0;
      emit();
    },
    removeEntry(id) {
      entries = entries.filter((e) => e.id !== id);
      byId.delete(id);
      emit();
    },
    reanalyze(id) {
      const e = byId.get(id);
      if (e) {
        enqueue(e);
        emit();
      }
    },
    getSettings() {
      return { ...settings };
    },
    async setSettings(partial) {
      if (host.ready) await host.ready; // never overwrite stored settings before they were loaded
      settings = { ...settings, ...partial };
      await saveSettings(settings);
      rulesetInfo = null;
      emitInfo();
      if (inflight) {
        clearTimeout(inflight.timer);
        inflight = null;
      }
      queue.length = 0;
      startWorker();
      for (const e of entries) enqueue(e);
      emit();
    },
    getRulesetInfo() {
      return rulesetInfo
        ? { ...rulesetInfo, loading: false, error: rulesetError }
        : { loading: !rulesetError, error: rulesetError, versions: [], version: settings.version, rules: 0, warnings: [], errors: [] };
    },
    get recording() {
      return recording;
    },
    setRecording(v) {
      recording = !!v;
    },
    get preserveLog() {
      return preserveLog;
    },
    setPreserveLog(v) {
      preserveLog = !!v;
    },
    get canCapture() {
      return mode === 'devtools';
    },
  };

  // Debug aid (DevTools console of the panel: __crsInspector.stats, __crsInspector.host.getEntries()).
  try {
    window.__crsInspector = { host, stats };
  } catch {}

  host.ready = (async () => {
    settings = await loadSettings();
    startWorker();
    if (mode === 'devtools') attachDevtools();
  })();

  return host;
}
