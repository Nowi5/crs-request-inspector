// Details pane: tab bar + Findings / Request / Response / All rules.

import { h, icon, clear, statusIcon } from '../dom.js';
import { splitUrl, entryStatus, STATUS_LABELS } from '../format.js';
import { renderFindings, buildContext } from './findings.js';
import { renderRequest, renderResponse } from './request-view.js';
import { renderAllRules } from './all-rules.js';

const TABS = [
  { id: 'findings', label: 'Findings' },
  { id: 'request', label: 'Request' },
  { id: 'response', label: 'Response' },
  { id: 'all', label: 'All rules' },
];

/**
 * @param {{ onClose(): void, getExtra(): object, initialTab?: string, onTabChange?(id): void }} cb
 */
export function createDetails(cb) {
  const tabbar = h('div.tabbar', { role: 'tablist', 'aria-label': 'Request details' });
  const content = h('div.details-content', { role: 'tabpanel', tabindex: '-1' });
  const title = h('div.details-title');
  const el = h('section.details', tabbar, title, content);
  let tab = cb.initialTab || 'findings';
  let current = null; // { entry, result, status, response, key }

  const closeBtn = h('button.icon-btn.tab-close', { type: 'button', title: 'Close details (Esc)', 'aria-label': 'Close details', on: { click: () => cb.onClose() } }, icon('close'));
  const tabButtons = new Map();
  tabbar.appendChild(closeBtn);
  for (const t of TABS) {
    const b = h('button.tab', { type: 'button', role: 'tab', id: `tab-${t.id}`, 'aria-selected': 'false', on: { click: () => setTab(t.id) } }, t.label);
    tabButtons.set(t.id, b);
    tabbar.appendChild(b);
  }
  tabbar.addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    const visible = TABS.filter((t) => !tabButtons.get(t.id).hidden).map((t) => t.id);
    const i = visible.indexOf(tab);
    const next = visible[(i + (e.key === 'ArrowRight' ? 1 : visible.length - 1)) % visible.length];
    setTab(next);
    tabButtons.get(next).focus();
  });

  function setTab(id) {
    if (id === tab) return;
    tab = id;
    cb.onTabChange?.(id);
    render(true);
  }

  function updateTabs(entry) {
    const hasResponse = !!entry?.request?.response;
    tabButtons.get('response').hidden = !hasResponse;
    if (tab === 'response' && !hasResponse) tab = 'findings';
    for (const [id, b] of tabButtons) {
      b.setAttribute('aria-selected', String(id === tab));
      b.tabIndex = id === tab ? 0 : -1;
      b.classList.toggle('active', id === tab);
    }
    const count = entry?.result ? (entry.result.matches || []).filter((m) => !m.isMeta).length : 0;
    const fb = tabButtons.get('findings');
    fb.replaceChildren('Findings', count ? h('span.tab-count', String(count)) : '');
  }

  function renderTitle(entry) {
    clear(title);
    if (!entry) return;
    const req = entry.request || {};
    const u = splitUrl(req.url);
    const st = entryStatus(entry);
    title.append(statusIcon(st, STATUS_LABELS[st]), h('span.dt-method', req.method || ''), h('span.dt-path', { title: req.url || '' }, u.pathAndQuery), h('span.dt-host', u.host));
  }

  function render(keepScroll = false) {
    const entry = current?.entry;
    updateTabs(entry);
    renderTitle(entry);
    const scroll = content.scrollTop;
    clear(content);
    if (!entry) return;
    if (entry.status === 'pending' && !entry.result) {
      content.appendChild(h('div.placeholder', h('span.spinner'), ' Analyzing request…'));
      return;
    }
    if (entry.status === 'error' || !entry.result) {
      if (tab === 'request' && entry.request) {
        content.appendChild(renderRequest(buildContext(entry, cb.getExtra())));
        return;
      }
      content.appendChild(h('div.placeholder.placeholder-error', icon('error'), h('div', h('strong', 'Analysis failed'), h('p', entry.error || 'No result available.'))));
      return;
    }
    const ctx = buildContext(entry, cb.getExtra());
    let view;
    try {
      if (tab === 'request') view = renderRequest(ctx);
      else if (tab === 'response') view = renderResponse(ctx);
      else if (tab === 'all') view = renderAllRules(ctx);
      else view = renderFindings(ctx);
    } catch (e) {
      console.error(e);
      view = h('div.placeholder.placeholder-error', icon('error'), h('div', h('strong', 'Could not render this view'), h('p.mono', String(e && e.message ? e.message : e))));
    }
    if (entry.status === 'pending') content.appendChild(h('div.stale-banner', h('span.spinner'), 'Re-analyzing with new settings…'));
    content.appendChild(view);
    content.scrollTop = keepScroll ? scroll : 0;
  }

  return {
    el,
    /** Show an entry; re-renders only if the entry (or its result) changed, or when forced. */
    show(entry, { force = false } = {}) {
      const key = entry ? { id: entry.id, status: entry.status, result: entry.result, response: entry.request?.response } : null;
      const same = current && key && current.key.id === key.id && current.key.status === key.status && current.key.result === key.result && current.key.response === key.response;
      if (same && !force) return;
      const sameId = current && key && current.key.id === key.id;
      current = entry ? { entry, key } : null;
      render(sameId);
    },
    rerender() {
      render(true);
    },
    get tab() {
      return tab;
    },
    setTab,
    focus() {
      content.focus({ preventScroll: true });
    },
    scrollToRule(id) {
      if (tab !== 'findings') setTab('findings');
      const card = content.querySelector(`.card[data-rule="${CSS.escape(String(id))}"]`);
      if (!card) return;
      if (!card.classList.contains('open')) card.querySelector('.card-head')?.click();
      card.scrollIntoView({ block: 'start', behavior: 'smooth' });
      card.classList.add('flash');
      setTimeout(() => card.classList.remove('flash'), 1200);
    },
  };
}
