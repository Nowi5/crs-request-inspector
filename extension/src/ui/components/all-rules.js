// "All rules" tab: compact table of every matched rule (power users).

import { h, icon } from '../dom.js';
import { isDetection, matchScore, matchPL, severityClass, ruleSourceUrl, truncate } from '../format.js';
import { renderSecLang } from './seclang-view.js';

export function renderAllRules(ctx) {
  const r = ctx.result;
  const all = r.matches || [];
  const list = ctx.showInternal ? all : all.filter(isDetection);
  const root = h('div.allrules');
  root.appendChild(h('div.view-toolbar',
    h('span.muted', `${all.length} rule${all.length === 1 ? '' : 's'} matched (${all.filter(isDetection).length} detections) · ${r.evaluatedRules ?? '?'} evaluated · ${r.elapsedMs ?? '?'} ms · phases ${(r.phasesRun || []).join(', ') || '—'}`),
    h('span.spacer'),
    h('label.toggle', h('input', { type: 'checkbox', checked: ctx.showInternal, on: { change: (e) => ctx.onToggleInternal?.(e.target.checked) } }), h('span', 'Show internal rules'))));

  const tbody = h('tbody');
  for (const m of list) {
    const det = isDetection(m);
    const pl = matchPL(m);
    const higher = det && pl != null && pl > ctx.blockingPL;
    const vars = (m.links || []).flatMap((l) => (l.matches || []).map((x) => x.var)).filter(Boolean);
    const score = matchScore(m);
    const url = ruleSourceUrl(m, ctx.version);
    const tr = h(`tr.ar-row${det ? '' : '.ar-meta'}${higher ? '.ar-higher' : ''}${m.disruptive && m.disruptive !== 'pass' ? '.ar-disruptive' : ''}`, { tabindex: '0', 'aria-expanded': 'false' },
      h('td.ar-chev', icon('chevronRight', 'chev')),
      h('td.mono', url ? h('a', { href: url, target: '_blank', rel: 'noopener noreferrer', on: { click: (e) => e.stopPropagation() } }, String(m.id)) : String(m.id ?? '—')),
      h('td.ar-num', String(m.phase ?? '')),
      h('td.ar-num', pl != null ? `PL${pl}` : ''),
      h('td', m.severity ? h(`span.badge.sev.sev-${severityClass(m.severity)}`, m.severity) : h('span.muted', det ? '' : 'internal')),
      h('td.ar-num', score ? `+${score}` : m.disruptive && m.disruptive !== 'pass' ? m.disruptive : ''),
      h('td.mono.ar-vars', { title: vars.join('\n') }, truncate(vars.join(', '), 120)),
      h('td.ar-msg', { title: m.msg || '' }, m.msg || ''));
    const detail = h('tr.ar-detail', { hidden: true }, h('td', { colspan: '8' }));
    const toggle = () => {
      const open = detail.hidden;
      detail.hidden = !open;
      tr.classList.toggle('open', open);
      tr.setAttribute('aria-expanded', String(open));
      if (open && !detail.firstChild.firstChild) {
        detail.firstChild.append(
          (m.links || []).length ? h('div.ar-links', (m.links || []).map((l, i) => h('div.ar-link',
            h('span.muted', i ? 'chain' : 'rule'),
            h('code.mono', l.vars || ''),
            l.op ? h('code.op-name', `${l.op.negated ? '!' : ''}@${l.op.name}`) : null,
            l.op?.param ? h('code.mono.cond-param', truncate(l.op.param, 160)) : null,
            h('span.muted', `${l.checked ?? 0} checked, ${(l.matches || []).length} matched`)))) : null,
          m.raw ? renderSecLang(m.raw, { file: m.file, line: m.line }) : h('span.muted', 'No source'));
      }
    };
    tr.addEventListener('click', toggle);
    tr.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
    tbody.append(tr, detail);
  }
  root.appendChild(h('div.table-wrap', h('table.artable',
    h('thead', h('tr', h('th', ''), h('th', 'Rule'), h('th', 'Phase'), h('th', 'PL'), h('th', 'Severity'), h('th', 'Score'), h('th', 'Variables'), h('th', 'Message'))),
    tbody)));
  if (!list.length) root.appendChild(h('div.placeholder', 'No detection rules matched. Enable “Show internal rules” to see the plumbing rules.'));
  return root;
}
