// CRS Request Inspector — panel UI entry point.
//   panel.html?mock=1        mock host with sample data (design review in a normal browser)
//   panel.html?standalone=1  standalone tab (paste / import only)
//   panel.html               DevTools panel
// Optional: &theme=dark|light to force a theme.

import { h, icon, iconButton, clear, append, toast, loadPref, savePref, nextFrame } from './dom.js';
import {
  summarizeEntry, compareBy, splitUrl, typeGroup, TYPE_GROUPS, FORMAT_LABELS,
} from './format.js';
import { createRequestList } from './components/request-list.js';
import { createDetails } from './components/details.js';
import { createPasteDialog, MOD_KEY } from './components/paste-dialog.js';
import { createReportDialog } from './components/report-dialog.js';
import { createSettingsDrawer } from './components/settings-drawer.js';

const params = new URLSearchParams(location.search);

async function loadHost() {
  const mod = params.has('mock') ? await import('./mock-host.js') : await import('./host.js');
  return mod.createHost({ standalone: params.has('standalone'), mock: params.has('mock') });
}

/* ------------------------------------------------------------------ theme */
function applyTheme(name) {
  const forced = params.get('theme');
  const t = forced || name;
  if (t === 'dark') document.documentElement.dataset.theme = 'dark';
  else if (t === 'light' || t === 'default') document.documentElement.dataset.theme = 'light';
  else delete document.documentElement.dataset.theme;
}

/* ------------------------------------------------------------------ state */
const state = {
  entries: [],
  view: [],
  selectedId: null,
  sort: loadPref('sort', { col: 'time', dir: 1 }),
  filter: { text: '', quick: 'all', types: new Set(), host: '' },
  showInternal: loadPref('showInternal', false),
  settings: {},
  info: {},
};

const summaryCache = new WeakMap(); // entry -> { result, status, summary }
function summary(entry) {
  const c = summaryCache.get(entry);
  if (c && c.result === entry.result && c.status === entry.status) return c.summary;
  const s = summarizeEntry(entry);
  summaryCache.set(entry, { result: entry.result, status: entry.status, summary: s });
  return s;
}
const searchCache = new WeakMap();
function searchText(entry) {
  const c = searchCache.get(entry);
  if (c && c.result === entry.result) return c.text;
  const s = summary(entry);
  const text = `${entry.request?.method || ''} ${entry.request?.url || ''} ${s.rules.map((r) => r.id).join(' ')} ${entry.source || ''}`.toLowerCase();
  searchCache.set(entry, { result: entry.result, text });
  return text;
}

/* -------------------------------------------------------------------- main */
async function main() {
  const host = await loadHost();
  applyTheme(host.themeName);
  if (typeof host.onThemeChange === 'function') host.onThemeChange(applyTheme);

  const mode = host.mode || 'devtools';
  if (mode === 'mock') window.__crsInspector = { host, state }; // debugging aid in mock mode only
  document.documentElement.dataset.mode = mode;
  const live = mode === 'devtools' || mode === 'mock';
  state.settings = safe(() => host.getSettings(), {});
  state.info = safe(() => host.getRulesetInfo(), {});

  const app = document.getElementById('app');
  clear(app);

  // ------------------------------------------------------------- toolbar
  const recordBtn = h('button.icon-btn.record-btn', {
    type: 'button',
    on: { click: () => { host.setRecording(!host.recording); syncToolbar(); } },
  }, icon('record'));
  const clearBtn = iconButton('clear', 'Clear', () => { host.clear(); select(null); });
  const preserve = h('input', { type: 'checkbox', id: 'preserve-log', on: { change: (e) => host.setPreserveLog(e.target.checked) } });
  const preserveLabel = h('label.tb-check', { title: 'Do not clear the list on page reload / navigation' }, preserve, h('span', 'Preserve log'));

  const pasteBtn = h('button.btn.btn-primary.btn-tb', { type: 'button', title: `Paste a request to analyze (${MOD_KEY}+V anywhere in the panel)`, on: { click: () => paste.open() } }, icon('paste'), h('span', 'Paste request'));
  const fileInput = h('input', { type: 'file', accept: '.har,.json,application/json', hidden: true, on: { change: (e) => { const f = e.target.files[0]; e.target.value = ''; if (f) importFile(f); } } });
  const importBtn = h('button.btn.btn-tb', { type: 'button', title: 'Import a HAR file', on: { click: () => fileInput.click() } }, icon('upload'), h('span.hide-narrow', 'Import HAR'));

  const plGroup = h('div.pl-select', { role: 'radiogroup', 'aria-label': 'Blocking paranoia level', title: 'Blocking paranoia level of the simulated WAF' });
  const plButtons = [1, 2, 3, 4].map((n) => {
    const b = h('button.pl-btn', { type: 'button', role: 'radio', 'aria-checked': 'false', title: `Blocking paranoia level ${n}`, on: { click: () => applySettings({ blockingParanoiaLevel: n, detectionParanoiaLevel: Math.max(n, Number(state.settings.detectionParanoiaLevel) || 4) }) } }, String(n));
    plGroup.appendChild(b);
    return b;
  });
  const thresholdInput = h('input.input.input-num.tb-threshold', {
    type: 'number', min: '1', max: '999', 'aria-label': 'Inbound anomaly score threshold', title: 'Inbound anomaly score threshold',
    on: {
      change: (e) => { const v = Math.max(1, Number(e.target.value) || 5); if (v !== Number(state.settings.inboundThreshold)) applySettings({ inboundThreshold: v }); },
      keydown: (e) => { if (e.key === 'Enter') e.target.blur(); },
    },
  });
  const gearBtn = iconButton('gear', 'Settings', () => (drawer.isOpen ? closeDrawer() : openDrawer()));
  const plLabel = h('span.tb-label', { 'aria-hidden': 'true' }, 'PL');
  const thresholdLabel = h('label.tb-label', { title: 'Inbound anomaly score threshold' }, h('span.hide-narrow', 'Threshold'), thresholdInput);
  const azureChip = h('button.btn.btn-tb.azure-chip', { type: 'button', hidden: true, title: 'Simulating an imported Azure WAF policy – click to change', on: { click: () => openDrawer() } });
  const reportBtn = h('button.btn.btn-tb', { type: 'button', title: 'All findings grouped by rule, with recommendations for developers and the WAF owner', on: { click: () => report.open() } }, icon('shield'), h('span.hide-narrow', 'Issues report'));

  const toolbar = h('div.toolbar', { role: 'toolbar', 'aria-label': 'Main toolbar' },
    live ? recordBtn : null,
    clearBtn,
    live ? h('span.tb-sep') : null,
    live ? preserveLabel : null,
    h('span.tb-sep'),
    pasteBtn,
    importBtn,
    fileInput,
    h('span.tb-sep'),
    plLabel,
    plGroup,
    thresholdLabel,
    azureChip,
    h('span.tb-sep'),
    reportBtn,
    h('span.spacer'),
    h('span.brand.hide-narrow', { title: 'OWASP Core Rule Set request inspector' }, icon('shield'), h('span', 'CRS Inspector')),
    gearBtn);

  // ----------------------------------------------------------- filter bar
  const filterInput = h('input.input.filter-input', {
    type: 'search', placeholder: 'Filter (URL, method, rule id)', 'aria-label': 'Filter requests', spellcheck: false,
    on: { input: (e) => { state.filter.text = e.target.value; refreshView(); } },
  });
  const quickChips = [['all', 'All'], ['blocked', 'Blocked'], ['hits', 'Hits'], ['clean', 'Clean']].map(([id, label]) => h('button.chip', {
    type: 'button', 'aria-pressed': 'false', dataset: { quick: id },
    title: { all: 'Show all requests', blocked: 'Requests that would be blocked', hits: 'Requests with rule hits that are not blocked (below threshold or only at higher PLs)', clean: 'Requests without any rule hit' }[id],
    on: { click: () => { state.filter.quick = id; syncFilterBar(); refreshView(); } },
  }, label, h('span.chip-count')));
  const typeChips = TYPE_GROUPS.map((t) => h('button.chip', {
    type: 'button', 'aria-pressed': 'false', dataset: { type: t.id },
    on: {
      click: (e) => {
        const multi = e.ctrlKey || e.metaKey;
        if (!multi) {
          const only = state.filter.types.size === 1 && state.filter.types.has(t.id);
          state.filter.types = only ? new Set() : new Set([t.id]);
        } else if (state.filter.types.has(t.id)) state.filter.types.delete(t.id);
        else state.filter.types.add(t.id);
        syncFilterBar();
        refreshView();
      },
    },
    title: `Show only ${t.label} (${MOD_KEY}+click to select several)`,
  }, t.label));
  const hostSelect = h('select.select.host-select', { 'aria-label': 'Filter by host', on: { change: (e) => { state.filter.host = e.target.value; refreshView(); } } });

  const filterbar = h('div.filterbar', { role: 'toolbar', 'aria-label': 'Filters' },
    h('div.filter-box', icon('filter'), filterInput),
    h('div.chip-group', { role: 'group', 'aria-label': 'Verdict filter' }, quickChips),
    h('span.tb-sep'),
    h('div.chip-group', { role: 'group', 'aria-label': 'Resource type filter' }, typeChips),
    h('span.tb-sep'),
    hostSelect);

  // ----------------------------------------------------------------- main
  const list = createRequestList({
    summary,
    onSelect: (id) => select(id),
    onSort: (col) => {
      state.sort = state.sort.col === col ? { col, dir: -state.sort.dir } : { col, dir: col === 'score' || col === 'rules' || col === 'status' ? (col === 'status' ? 1 : -1) : 1 };
      savePref('sort', state.sort);
      list.setSort(state.sort);
      refreshView();
    },
    onActivate: () => details.focus(),
  });
  list.setSort(state.sort);

  const details = createDetails({
    initialTab: params.get('tab') || loadPref('tab', 'findings'),
    onTabChange: (id) => savePref('tab', id),
    onClose: () => { select(null); list.focus(); },
    getExtra: () => ({
      settings: state.settings,
      version: state.info.version,
      showInternal: state.showInternal,
      onToggleInternal: (on) => { state.showInternal = on; savePref('showInternal', on); details.rerender(); },
      onSetPL: (pl) => applySettings({ blockingParanoiaLevel: pl, detectionParanoiaLevel: Math.max(pl, Number(state.settings.detectionParanoiaLevel) || 4) }),
      onRule: (id) => details.scrollToRule(id),
    }),
  });

  const splitter = h('div.splitter', { role: 'separator', tabindex: '0', 'aria-label': 'Resize request list', title: 'Drag to resize' });
  const listPane = h('section.list-pane', { 'aria-label': 'Requests' }, list.el);
  const detailsPane = h('section.details-pane', details.el);
  const mainEl = h('main.main.no-selection', listPane, splitter, detailsPane);

  // ----------------------------------------------------------- status bar
  const statusLeft = h('span.sb-left');
  const statusRight = h('span.sb-right');
  const statusbar = h('footer.statusbar', { role: 'status', 'aria-live': 'off' }, statusLeft, h('span.spacer'), statusRight);

  const drawer = createSettingsDrawer({
    host,
    onApply: (partial) => applySettings(partial),
    onClose: () => closeDrawer(),
  });
  const paste = createPasteDialog({ host, onAdded: (res) => onAdded(res) });
  const report = createReportDialog({
    getEntries: () => state.entries,
    getSettings: () => state.settings,
    getVersion: () => state.info?.version || '',
    onSelect: (id) => select(id),
  });
  const dropOverlay = h('div.drop-overlay', { hidden: true }, h('div.drop-box', icon('upload'), h('strong', 'Drop to analyze'), h('span', 'HAR files, or text copied as PowerShell / cURL / fetch / raw HTTP')));

  app.append(toolbar, filterbar, mainEl, statusbar, drawer.el, paste.el, report.el, dropOverlay);

  // ------------------------------------------------------------ splitter
  let orientation = null;
  const applySplit = () => {
    const key = orientation === 'h' ? 'splitH' : 'splitV';
    const frac = Math.min(0.85, Math.max(0.15, Number(loadPref(key, orientation === 'h' ? 0.42 : 0.4)) || 0.4));
    mainEl.style.setProperty('--split', `${(frac * 100).toFixed(2)}%`);
  };
  new ResizeObserver(() => {
    const w = mainEl.clientWidth;
    const o = w >= 980 ? 'h' : 'v';
    if (o !== orientation) {
      orientation = o;
      mainEl.classList.toggle('split-h', o === 'h');
      mainEl.classList.toggle('split-v', o === 'v');
      splitter.setAttribute('aria-orientation', o === 'h' ? 'vertical' : 'horizontal');
      applySplit();
    }
  }).observe(mainEl);
  splitter.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    splitter.setPointerCapture(e.pointerId);
    mainEl.classList.add('resizing');
    const rect = mainEl.getBoundingClientRect();
    const move = (ev) => {
      const frac = orientation === 'h' ? (ev.clientX - rect.left) / rect.width : (ev.clientY - rect.top) / rect.height;
      const f = Math.min(0.85, Math.max(0.15, frac));
      mainEl.style.setProperty('--split', `${(f * 100).toFixed(2)}%`);
      savePref(orientation === 'h' ? 'splitH' : 'splitV', f);
    };
    const up = () => {
      mainEl.classList.remove('resizing');
      splitter.removeEventListener('pointermove', move);
      splitter.removeEventListener('pointerup', up);
      splitter.removeEventListener('pointercancel', up);
    };
    splitter.addEventListener('pointermove', move);
    splitter.addEventListener('pointerup', up);
    splitter.addEventListener('pointercancel', up);
  });
  splitter.addEventListener('keydown', (e) => {
    const key = orientation === 'h' ? 'splitH' : 'splitV';
    const dec = orientation === 'h' ? 'ArrowLeft' : 'ArrowUp';
    const inc = orientation === 'h' ? 'ArrowRight' : 'ArrowDown';
    if (e.key !== dec && e.key !== inc) return;
    e.preventDefault();
    const cur = Number(loadPref(key, 0.42)) || 0.42;
    savePref(key, Math.min(0.85, Math.max(0.15, cur + (e.key === inc ? 0.03 : -0.03))));
    applySplit();
  });

  // ------------------------------------------------------------ behaviour
  function syncToolbar() {
    recordBtn.classList.toggle('on', !!host.recording);
    recordBtn.setAttribute('aria-pressed', String(!!host.recording));
    const recLabel = host.recording ? 'Stop recording requests' : 'Record requests';
    recordBtn.title = recLabel;
    recordBtn.setAttribute('aria-label', recLabel);
    preserve.checked = !!host.preserveLog;
    const pl = Number(state.settings.blockingParanoiaLevel) || 1;
    plButtons.forEach((b, i) => {
      const on = i + 1 === pl;
      b.classList.toggle('on', on);
      b.setAttribute('aria-checked', String(on));
    });
    if (document.activeElement !== thresholdInput) thresholdInput.value = String(state.settings.inboundThreshold ?? 5);
    const azure = state.settings.wafProfile === 'azure';
    plGroup.hidden = azure;
    plLabel.hidden = azure;
    thresholdLabel.hidden = azure;
    azureChip.hidden = !azure;
    if (azure) {
      const sm = state.info?.azure?.summary;
      azureChip.textContent = sm ? `Azure WAF: ${sm.name} · ${sm.enabled ? sm.mode : 'disabled'}` : 'Azure WAF: no policy loaded';
      azureChip.classList.toggle('chip-warn', !sm || sm.mode !== 'Prevention' || !sm.enabled);
    }
  }

  function syncFilterBar() {
    for (const c of quickChips) c.setAttribute('aria-pressed', String(c.dataset.quick === state.filter.quick));
    for (const c of typeChips) c.setAttribute('aria-pressed', String(state.filter.types.has(c.dataset.type)));
  }

  function syncHosts() {
    const hosts = new Map();
    for (const e of state.entries) {
      const hst = splitUrl(e.request?.url).host;
      if (hst) hosts.set(hst, (hosts.get(hst) || 0) + 1);
    }
    const sig = [...hosts.keys()].sort().join('|');
    if (hostSelect.dataset.sig === sig) return;
    hostSelect.dataset.sig = sig;
    if (state.filter.host && !hosts.has(state.filter.host)) state.filter.host = '';
    hostSelect.replaceChildren(h('option', { value: '' }, 'All hosts'), ...[...hosts.keys()].sort().map((x) => h('option', { value: x, selected: x === state.filter.host }, x)));
    hostSelect.hidden = hosts.size < 1;
  }

  function quickMatch(st, q) {
    if (q === 'all') return true;
    if (q === 'blocked') return st === 'blocked';
    if (q === 'hits') return st === 'warn' || st === 'latent';
    if (q === 'clean') return st === 'clean';
    return true;
  }

  function refreshView() {
    const f = state.filter;
    const text = f.text.trim().toLowerCase();
    const terms = text ? text.split(/\s+/) : [];
    const counts = { all: 0, blocked: 0, hits: 0, clean: 0 };
    const view = [];
    for (const e of state.entries) {
      if (f.types.size && !f.types.has(typeGroup(e.resourceType))) continue;
      if (f.host && splitUrl(e.request?.url).host !== f.host) continue;
      if (terms.length) {
        const s = searchText(e);
        if (!terms.every((t) => (t.startsWith('-') && t.length > 1 ? !s.includes(t.slice(1)) : s.includes(t)))) continue;
      }
      const st = summary(e).status;
      counts.all++;
      if (st === 'blocked') counts.blocked++;
      else if (st === 'warn' || st === 'latent') counts.hits++;
      else if (st === 'clean') counts.clean++;
      if (quickMatch(st, f.quick)) view.push(e);
    }
    for (const c of quickChips) c.querySelector('.chip-count').textContent = counts[c.dataset.quick] ? String(counts[c.dataset.quick]) : '';
    const { col, dir } = state.sort;
    if (col !== 'time' || dir !== 1) {
      const cmp = compareBy(col, summary);
      const byTime = compareBy('time', summary);
      view.sort((a, b) => dir * cmp(a, b) || byTime(a, b));
    }
    state.view = view;
    list.setItems(view, emptyState());
    renderStatus(view.length);
  }

  function emptyState() {
    if (state.view.length) return null;
    if (state.entries.length) {
      return h('div.empty', h('div.empty-title', 'No requests match the current filters.'),
        h('button.btn', { type: 'button', on: { click: resetFilters } }, 'Clear filters'));
    }
    const lines = mode === 'devtools'
      ? [host.recording ? 'Recording network activity…' : 'Recording is paused.', 'Reload the page to capture requests, or paste one copied from the Network panel.']
      : ['Paste a request copied from Chrome DevTools (Copy as PowerShell / cURL / fetch), raw HTTP text, or import a HAR file.'];
    return h('div.empty',
      h('div.empty-logo', icon('shield')),
      h('div.empty-title', 'Would the OWASP Core Rule Set block it?'),
      lines.map((l) => h('p', l)),
      h('div.empty-actions',
        h('button.btn.btn-primary', { type: 'button', on: { click: () => paste.open() } }, icon('paste'), h('span', 'Paste a request')),
        h('button.btn', { type: 'button', on: { click: () => fileInput.click() } }, icon('upload'), h('span', 'Import HAR'))),
      h('p.muted.empty-hint', `Tip: press ${MOD_KEY}+V anywhere in this panel, or drop a .har file here.`));
  }

  function resetFilters() {
    state.filter = { text: '', quick: 'all', types: new Set(), host: '' };
    filterInput.value = '';
    hostSelect.value = '';
    syncFilterBar();
    refreshView();
  }

  function renderStatus(shown) {
    const total = state.entries.length;
    let blocked = 0;
    let pending = 0;
    let hits = 0;
    for (const e of state.entries) {
      const st = summary(e).status;
      if (st === 'blocked') blocked++;
      else if (st === 'pending') pending++;
      else if (st === 'warn' || st === 'latent') hits++;
    }
    const parts = [`${total} request${total === 1 ? '' : 's'}`];
    if (shown !== total) parts.unshift(`${shown} / ${total} shown`);
    parts.push(`${blocked} would be blocked`);
    if (hits) parts.push(`${hits} with hits below threshold`);
    append(clear(statusLeft), [
      pending ? h('span.sb-busy', h('span.spinner'), `Analyzing ${pending}…`) : null,
      h('span', parts.join(" · "))]);
    const s = state.settings;
    const info = state.info || {};
    const azSm = s.wafProfile === 'azure' ? info.azure?.summary : null;
    append(clear(statusRight), [
      s.wafProfile === 'azure' ? h('button.sb-link', { type: 'button', title: 'Simulated Azure WAF policy', on: { click: openDrawer } }, azSm ? `Azure ${azSm.name} · ${azSm.mode} · ${azSm.ruleSet}` : 'Azure profile · no policy') : null,
      s.wafProfile === 'azure' ? h('span.sb-dot', '·') : null,
      h('span', { title: `${info.rules ?? '?'} rules loaded` }, `CRS ${info.version || '—'}`),
      h('span.sb-dot', '·'),
      s.wafProfile === 'azure' ? null : h('button.sb-link', { type: 'button', title: 'Open settings', on: { click: openDrawer } },
        `PL${s.blockingParanoiaLevel ?? 1} / threshold ${s.inboundThreshold ?? 5}${Number(s.detectionParanoiaLevel) > Number(s.blockingParanoiaLevel) ? ` · detecting to PL${s.detectionParanoiaLevel}` : ''}`),
      (info.errors || []).length ? h('button.sb-link.sb-error', { type: 'button', on: { click: openDrawer } }, `${info.errors.length} rule error${info.errors.length === 1 ? '' : 's'}`) : null]);
  }

  function select(id, { scroll = true } = {}) {
    state.selectedId = id;
    list.setSelected(id, { scroll });
    mainEl.classList.toggle('no-selection', !id);
    const entry = id ? state.entries.find((e) => e.id === id) : null;
    details.show(entry || null);
  }

  let pendingSelect = null; // ids just added via paste/import
  function onEntries(entries) {
    state.entries = entries;
    state.info = safe(() => host.getRulesetInfo(), state.info);
    state.settings = safe(() => host.getSettings(), state.settings);
    syncHosts();
    refreshView();
    syncToolbar();
    if (pendingSelect) {
      const ids = pendingSelect;
      const found = entries.find((e) => ids.includes(e.id));
      if (found) {
        pendingSelect = null;
        if (!state.view.some((e) => e.id === found.id)) resetFilters();
        select(found.id);
      }
    }
    if (state.selectedId) {
      const entry = entries.find((e) => e.id === state.selectedId);
      if (!entry) select(null);
      else details.show(entry);
    }
    drawer.refreshInfo();
  }

  let rafPending = false;
  host.onEntries((entries) => {
    // Coalesce bursts of updates into one frame.
    state.nextEntries = entries;
    if (rafPending) return;
    rafPending = true;
    nextFrame(() => {
      rafPending = false;
      onEntries(state.nextEntries);
    });
  });

  async function applySettings(partial) {
    state.settings = { ...state.settings, ...partial };
    syncToolbar();
    renderStatus(state.view.length);
    try {
      await host.setSettings(partial);
    } catch (e) {
      toast(`Could not apply settings: ${e && e.message ? e.message : e}`, 'error', 4000);
      throw e;
    } finally {
      state.settings = safe(() => host.getSettings(), state.settings);
      state.info = safe(() => host.getRulesetInfo(), state.info);
      syncToolbar();
      renderStatus(state.view.length);
      drawer.rebase(state.settings);
      drawer.refreshInfo();
    }
  }

  function onAdded(res) {
    const before = new Set(state.entries.map((e) => e.id));
    const ids = res.ids && res.ids.length ? res.ids : null;
    if (ids) pendingSelect = ids;
    else {
      // Host did not report ids: pick the first new entry on the next update.
      const current = safe(() => host.getEntries(), []);
      const fresh = current.filter((e) => !before.has(e.id));
      pendingSelect = fresh.length ? fresh.map((e) => e.id) : null;
    }
    const fmt = res.format ? FORMAT_LABELS[res.format] || res.format : null;
    const msg = `Added ${res.added} request${res.added === 1 ? '' : 's'}${fmt ? ` from ${fmt}` : ''}`;
    if (res.errors && res.errors.length) toast(`${msg} · ${res.errors.length} warning${res.errors.length === 1 ? '' : 's'}: ${res.errors[0]}`, 'warn', 5000);
    else toast(msg);
    onEntries(safe(() => host.getEntries(), state.entries));
  }

  async function importFile(file) {
    try {
      const res = await host.importHarFile(file);
      if (!res || !res.added) {
        toast(`Nothing imported${res?.errors?.length ? `: ${res.errors[0]}` : ''}`, 'error', 5000);
        return;
      }
      onAdded({ ...res, format: 'har' });
    } catch (e) {
      toast(`Import failed: ${e && e.message ? e.message : e}`, 'error', 5000);
    }
  }

  function openDrawer() {
    drawer.open();
    gearBtn.setAttribute('aria-expanded', 'true');
  }
  function closeDrawer() {
    drawer.close();
    gearBtn.setAttribute('aria-expanded', 'false');
    gearBtn.focus();
  }

  // ------------------------------------------------------------- keyboard
  const isEditable = (el) => el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (paste.isOpen || document.querySelector('dialog[open]')) return; // the open <dialog> handles Escape itself
      if (drawer.isOpen) { e.preventDefault(); closeDrawer(); return; }
      if (state.selectedId && !isEditable(document.activeElement)) { select(null); list.focus(); }
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f' && !paste.isOpen) {
      e.preventDefault();
      filterInput.focus();
      filterInput.select();
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k' && !paste.isOpen) {
      e.preventDefault();
      paste.open();
    }
  });
  document.addEventListener('paste', (e) => {
    if (paste.isOpen || isEditable(document.activeElement)) return;
    const text = e.clipboardData && e.clipboardData.getData('text');
    if (!text || !text.trim()) return;
    e.preventDefault();
    paste.open(text);
  });

  // ---------------------------------------------------------------- drop
  let dragDepth = 0;
  const hasDroppable = (e) => [...(e.dataTransfer?.types || [])].some((t) => t === 'Files' || t === 'text/plain');
  document.addEventListener('dragenter', (e) => {
    if (!hasDroppable(e) || paste.isOpen) return;
    dragDepth++;
    dropOverlay.hidden = false;
  });
  document.addEventListener('dragleave', () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) dropOverlay.hidden = true;
  });
  document.addEventListener('dragover', (e) => {
    if (hasDroppable(e)) e.preventDefault();
  });
  document.addEventListener('drop', async (e) => {
    dragDepth = 0;
    dropOverlay.hidden = true;
    if (!e.dataTransfer || paste.isOpen) return;
    e.preventDefault();
    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) {
      if (/\.(har|json)$/i.test(file.name) || /json/.test(file.type)) {
        const text = await file.text();
        if (safe(() => host.detectFormat(text), 'unknown') === 'har') importFile(file);
        else paste.open(text);
      } else if (file.size < 5 * 1024 * 1024) {
        paste.open(await file.text());
      } else toast('File too large to paste', 'error');
      return;
    }
    const text = e.dataTransfer.getData('text/plain');
    if (text && text.trim()) paste.open(text);
  });

  // ---------------------------------------------------------------- start
  syncToolbar();
  syncFilterBar();
  if (host.ready && typeof host.ready.then === 'function') await host.ready.catch(() => {});
  onEntries(safe(() => host.getEntries(), []));
  if (params.has('select')) select(params.get('select'));
  if (params.has('paste')) paste.open();
  if (params.has('settings')) openDrawer();
  if (params.has('report')) report.open();
  if (state.entries.length) list.focus();
}

function safe(fn, fallback) {
  try {
    const v = fn();
    return v === undefined ? fallback : v;
  } catch {
    return fallback;
  }
}

main().catch((e) => {
  console.error(e);
  const app = document.getElementById('app');
  if (app) app.replaceChildren(h('div.fatal', h('strong', 'CRS Request Inspector failed to start'), h('pre.mono', String(e && e.stack ? e.stack : e))));
});

