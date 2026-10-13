// Virtualised request list (Network-panel style).

import { h, clear, icon, statusIcon, nextFrame } from '../dom.js';
import { splitUrl, typeLabel, sourceInfo, STATUS_LABELS } from '../format.js';

export const ROW_HEIGHT = 22;
const OVERSCAN = 12;

export const COLUMNS = [
  { id: 'status', label: '', title: 'Verdict', cls: 'c-status', sortable: true },
  { id: 'method', label: 'Method', cls: 'c-method', sortable: true },
  { id: 'name', label: 'Name', cls: 'c-name', sortable: true },
  { id: 'type', label: 'Type', cls: 'c-type', sortable: true },
  { id: 'score', label: 'Score', title: 'Inbound anomaly score at the configured paranoia level / threshold. Bar: PL1–PL4 (red = would block at that level)', cls: 'c-score', sortable: true },
  { id: 'rules', label: 'Top rules', cls: 'c-rules', sortable: true },
  { id: 'source', label: 'Source', cls: 'c-source', sortable: true },
];

/**
 * @param {{ onSelect(id: string, opts?: {focusDetails?: boolean}): void, onSort(col: string): void, summary(entry): object, onActivate?(id): void }} cb
 */
export function createRequestList(cb) {
  const header = h('div.list-header', { role: 'row' });
  const spacer = h('div.list-spacer');
  const layer = h('div.list-rows', { role: 'presentation' });
  const scroller = h('div.list-scroller', { tabindex: '0', role: 'grid', 'aria-label': 'Requests', 'aria-rowcount': '0' }, spacer, layer);
  const empty = h('div.list-empty');
  const el = h('div.request-list', header, scroller, empty);

  let items = [];
  let selectedId = null;
  let sort = { col: 'time', dir: 1 };
  let rowCache = new Map(); // id -> { entry, summary, selected, index, el }
  let raf = 0;

  // ---------------------------------------------------------------- header
  function renderHeader() {
    clear(header);
    for (const c of COLUMNS) {
      const active = sort.col === c.id;
      const cell = h(`div.cell.${c.cls}`, {
        role: 'columnheader',
        title: c.title || (c.sortable ? `Sort by ${c.label}` : ''),
        'aria-sort': active ? (sort.dir > 0 ? 'ascending' : 'descending') : 'none',
      });
      const btn = h('button.th', { type: 'button', on: { click: () => cb.onSort(c.id) } },
        c.id === 'status' ? icon('shield', 'th-icon') : h('span.th-label', c.label),
        active ? h('span.sort-ind', sort.dir > 0 ? '▲' : '▼') : null);
      if (c.id === 'status') btn.setAttribute('aria-label', 'Sort by verdict');
      cell.appendChild(btn);
      header.appendChild(cell);
    }
  }
  renderHeader();

  // ------------------------------------------------------------------ rows
  function buildRow(entry, sum, index, selected) {
    const req = entry.request || {};
    const u = splitUrl(req.url);
    const src = sourceInfo(entry.source);
    const row = h(`div.row${selected ? '.selected' : ''}${index % 2 ? '.odd' : ''}.st-${sum.status}`, {
      role: 'row',
      'aria-selected': selected ? 'true' : 'false',
      'aria-rowindex': String(index + 1),
      dataset: { id: entry.id },
      style: { transform: `translateY(${index * ROW_HEIGHT}px)` },
    });
    const statusTitle = STATUS_LABELS[sum.status] + (entry.error ? `: ${entry.error}` : '');
    row.append(
      h('div.cell.c-status', { role: 'gridcell' }, statusIcon(sum.status, statusTitle)),
      h('div.cell.c-method', { role: 'gridcell' }, h('span.method', { class: `m-${String(req.method || '').toLowerCase()}` }, req.method || '')),
      h('div.cell.c-name', { role: 'gridcell', title: req.url || '' },
        h('span.path', u.pathAndQuery),
        u.host ? h('span.host', u.host) : null),
      h('div.cell.c-type', { role: 'gridcell' }, typeLabel(entry.resourceType)),
      h('div.cell.c-score', { role: 'gridcell' }, scoreCell(sum)),
      h('div.cell.c-rules', { role: 'gridcell' }, rulesCell(sum)),
      h('div.cell.c-source', { role: 'gridcell', title: src.long }, h(`span.src.src-${src.kind}`, src.short)),
    );
    return row;
  }

  function scoreCell(sum) {
    if (sum.score == null) return h('span.muted', sum.status === 'pending' ? '…' : '—');
    const cls = sum.status === 'blocked' ? 'blocked' : sum.score > 0 ? 'warn' : 'zero';
    const tip = sum.matrix.map((c) => `PL${c.pl}: ${c.evaluated ? c.inbound + (c.outbound ? ` (+${c.outbound} out)` : '') + (c.blocked ? ' — block' : '') : 'not evaluated'}`).join('\n');
    const bar = h('span.plbar', { title: tip + (sum.blockAt ? `\nWould block from PL${sum.blockAt}` : '\nNever blocks at PL1–4') });
    for (const c of sum.matrix) {
      bar.appendChild(h(`span.seg${c.blocked ? '.seg-block' : c.hits ? '.seg-hit' : ''}${c.current ? '.seg-current' : ''}${c.evaluated ? '' : '.seg-off'}`));
    }
    return [h(`span.score.score-${cls}`, String(sum.score)), h('span.threshold', `/ ${sum.threshold}`), sum.outScore ? h('span.out-score', { title: `Outbound (response) score ${sum.outScore} / threshold ${sum.outThreshold}` }, `out ${sum.outScore}`) : null, bar];
  }

  function rulesCell(sum) {
    if (!sum.rules.length) return null;
    // Up to 3 pills on wide lists, 2 on narrow ones (CSS toggles .pill-3 and the two "+N" variants).
    const out = sum.rules.slice(0, 3).map((r, i) => h(`span.pill${r.active ? '.pill-active' : '.pill-higher'}${i === 2 ? '.pill-3' : ''}`, { title: `${r.id} — ${r.msg || ''}${r.active ? '' : ` (only at PL${r.pl}+)`}` }, String(r.id)));
    const all = sum.rules.map((r) => r.id).join(', ');
    if (sum.rules.length > 3) out.push(h('span.pill-more.more-wide', { title: all }, `+${sum.rules.length - 3}`));
    if (sum.rules.length > 2) out.push(h('span.pill-more.more-narrow', { title: all }, `+${sum.rules.length - 2}`));
    return out;
  }

  function render() {
    raf = 0;
    const n = items.length;
    spacer.style.height = `${n * ROW_HEIGHT}px`;
    scroller.setAttribute('aria-rowcount', String(n));
    const top = scroller.scrollTop;
    const height = scroller.clientHeight || 400;
    const start = Math.max(0, Math.floor(top / ROW_HEIGHT) - OVERSCAN);
    const end = Math.min(n, Math.ceil((top + height) / ROW_HEIGHT) + OVERSCAN);
    const next = new Map();
    const frag = [];
    for (let i = start; i < end; i++) {
      const entry = items[i];
      const sum = cb.summary(entry);
      const selected = entry.id === selectedId;
      const cached = rowCache.get(entry.id);
      let row;
      if (cached && cached.entry === entry && cached.summary === sum && cached.selected === selected && cached.index === i) row = cached.el;
      else row = buildRow(entry, sum, i, selected);
      next.set(entry.id, { entry, summary: sum, selected, index: i, el: row });
      frag.push(row);
    }
    // Replace children only when they differ.
    const current = Array.from(layer.children);
    if (current.length !== frag.length || current.some((c, i) => c !== frag[i])) {
      layer.replaceChildren(...frag);
    }
    rowCache = next;
  }

  const schedule = () => {
    if (!raf) raf = nextFrame(render);
  };
  scroller.addEventListener('scroll', schedule, { passive: true });
  new ResizeObserver(schedule).observe(scroller);

  // ------------------------------------------------------------ interaction
  layer.addEventListener('click', (e) => {
    const row = e.target.closest('.row');
    if (!row) return;
    cb.onSelect(row.dataset.id);
    scroller.focus({ preventScroll: true });
  });
  layer.addEventListener('dblclick', (e) => {
    const row = e.target.closest('.row');
    if (row && cb.onActivate) cb.onActivate(row.dataset.id);
  });

  scroller.addEventListener('keydown', (e) => {
    if (!items.length) return;
    const idx = items.findIndex((x) => x.id === selectedId);
    const page = Math.max(1, Math.floor(scroller.clientHeight / ROW_HEIGHT) - 1);
    let next = null;
    switch (e.key) {
      case 'ArrowDown': next = idx < 0 ? 0 : Math.min(items.length - 1, idx + 1); break;
      case 'ArrowUp': next = idx < 0 ? 0 : Math.max(0, idx - 1); break;
      case 'PageDown': next = Math.min(items.length - 1, (idx < 0 ? 0 : idx) + page); break;
      case 'PageUp': next = Math.max(0, (idx < 0 ? 0 : idx) - page); break;
      case 'Home': next = 0; break;
      case 'End': next = items.length - 1; break;
      case 'Enter':
        if (idx >= 0 && cb.onActivate) cb.onActivate(items[idx].id);
        e.preventDefault();
        return;
      default: return;
    }
    e.preventDefault();
    if (next != null && items[next]) cb.onSelect(items[next].id);
  });

  function ensureVisible(id) {
    const i = items.findIndex((x) => x.id === id);
    if (i < 0) return;
    const top = i * ROW_HEIGHT;
    const bottom = top + ROW_HEIGHT;
    if (top < scroller.scrollTop) scroller.scrollTop = top;
    else if (bottom > scroller.scrollTop + scroller.clientHeight) scroller.scrollTop = bottom - scroller.clientHeight;
  }

  return {
    el,
    scroller,
    setItems(list, emptyContent) {
      const wasAtBottom = scroller.scrollTop + scroller.clientHeight >= scroller.scrollHeight - ROW_HEIGHT;
      const grew = list.length > items.length;
      items = list;
      el.classList.toggle('is-empty', !list.length);
      if (emptyContent !== undefined) {
        clear(empty);
        if (emptyContent) empty.appendChild(emptyContent);
      }
      render();
      // Follow new rows like the Network panel when scrolled to the bottom (time order).
      if (grew && wasAtBottom && sort.col === 'time' && sort.dir > 0) scroller.scrollTop = scroller.scrollHeight;
    },
    setSelected(id, { scroll = true } = {}) {
      selectedId = id;
      if (scroll && id) ensureVisible(id);
      schedule();
    },
    setSort(s) {
      sort = s;
      renderHeader();
    },
    focus() {
      scroller.focus({ preventScroll: true });
    },
    refresh: schedule,
  };
}
