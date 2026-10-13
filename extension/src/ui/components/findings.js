// "Findings" tab: verdict banner, PL matrix, one card per detection rule.

import { h, icon, copyButton, highlighted, statusIcon } from '../dom.js';
import {
  verdict, plMatrix, groupFindings, matchScore, matchPL, attackCategory, severityClass, describeVar,
  describeOperator, ruleSourceUrl, isDetection, truncate,
} from '../format.js';
import { buildExclusions } from '../exclusions.js';
import { recommend } from '../recommendations.js';
import { renderSecLang } from './seclang-view.js';

const MAX_MATCHES_SHOWN = 3;

/** Build the context used by all detail renderers. */
export function buildContext(entry, extra = {}) {
  const r = entry.result || {};
  const v = r.variables || {};
  const names = (list) => new Set((list || []).map((x) => x.name));
  return {
    entry,
    result: r,
    blockingPL: r.paranoia?.blocking ?? extra.settings?.blockingParanoiaLevel ?? 1,
    detectionPL: r.paranoia?.detection ?? 4,
    varCtx: { argsGet: names(v.ARGS_GET), argsPost: names(v.ARGS_POST), bodyProcessor: r.bodyProcessor || v.REQBODY_PROCESSOR || null },
    path: v.REQUEST_FILENAME || null,
    ...extra,
  };
}

export function renderFindings(ctx) {
  const { result: r, entry } = ctx;
  const root = h('div.findings');
  root.appendChild(renderVerdict(ctx));
  if (r.azure) root.appendChild(renderAzure(r.azure));

  const notes = [
    ...(entry.request?.notes || []).map((t) => ({ kind: 'info', text: t, src: 'Parser' })),
    ...(r.bodyNotes || []).map((t) => ({ kind: 'info', text: typeof t === 'string' ? t : t.message || JSON.stringify(t), src: 'Body' })),
    ...(r.warnings || []).map((t) => ({ kind: 'warn', text: typeof t === 'string' ? t : t.message || JSON.stringify(t), src: 'Engine' })),
  ];
  if (r.variables?.REQBODY_ERROR_MSG) notes.push({ kind: 'warn', text: `Request body parse error: ${r.variables.REQBODY_ERROR_MSG}`, src: 'Body' });
  if (notes.length) {
    root.appendChild(h('div.notes', notes.map((n) => h(`div.note.note-${n.kind}`, icon(n.kind === 'warn' ? 'error' : 'info'), h('span.note-src', n.src), h('span.note-text', n.text)))));
  }

  const { active, higher } = groupFindings(r.matches || [], ctx.blockingPL);
  const sectionActions = h('div.section-actions',
    h('label.toggle', { title: 'Show internal rules (initialisation, paranoia-level gating, score evaluation)' },
      h('input', { type: 'checkbox', checked: ctx.showInternal, on: { change: (e) => ctx.onToggleInternal?.(e.target.checked) } }),
      h('span', 'Show internal rules')));

  if (!active.length && !higher.length) {
    root.appendChild(h('div.section-head', h('h3', 'Findings'), sectionActions));
    root.appendChild(h('div.findings-empty', icon('shield'), h('div',
      h('strong', 'No detection rule matched.'),
      h('p', `All ${r.evaluatedRules ?? ''} evaluated rules passed up to paranoia level ${ctx.detectionPL}.`))));
  }

  if (active.length) {
    const inSum = active.reduce((s, m) => s + matchScore(m, 'inbound'), 0);
    const outSum = active.reduce((s, m) => s + matchScore(m, 'outbound'), 0);
    const sums = [inSum || !outSum ? `+${inSum} inbound` : null, outSum ? `+${outSum} outbound` : null].filter(Boolean).join(', ');
    root.appendChild(h('div.section-head',
      h('h3', `Counted at PL${ctx.blockingPL}`),
      h('span.section-meta', `${active.length} rule${active.length === 1 ? '' : 's'} · ${sums}`),
      sectionActions));
    for (const m of active) root.appendChild(renderCard(m, ctx, { higher: false, open: true }));
  }
  if (higher.length) {
    const firstPL = Math.min(...higher.map((m) => matchPL(m) ?? 4));
    root.appendChild(h('div.section-head.section-head-higher',
      h('h3', 'Only at higher paranoia levels'),
      h('span.section-meta', `${higher.length} rule${higher.length === 1 ? '' : 's'} · not counted at PL${ctx.blockingPL}; would count from PL${firstPL}`),
      active.length ? null : sectionActions));
    const openHigher = !active.length && higher.length <= 3;
    for (const m of higher) root.appendChild(renderCard(m, ctx, { higher: true, open: openHigher }));
  }

  if (ctx.showInternal) {
    const internal = (r.matches || []).filter((m) => !isDetection(m));
    root.appendChild(h('div.section-head', h('h3', 'Internal rules'), h('span.section-meta', `${internal.length} matched · initialisation, PL gating, score evaluation`)));
    root.appendChild(h('div.internal-list', internal.map((m) => h('div.internal-row',
      ruleIdLink(m, ctx), h('span.muted', `phase ${m.phase}`),
      h('span.internal-vars.mono', (m.links || []).map((l) => l.matches.map((x) => x.var).join(', ')).filter(Boolean).join(' ; ') || '—'),
      h('span.internal-msg', m.msg || (m.disruptive && m.disruptive !== 'pass' ? m.disruptive : ''))))));
  }
  return root;
}

/* ------------------------------------------------------------------ azure */

function renderAzure(az) {
  const d = az.decidedBy;
  let decision;
  if (!az.enabled) decision = 'Policy disabled';
  else if (d?.type === 'custom') decision = `Decided by custom rule “${d.name}” (priority ${d.priority}) → ${d.action}${az.managedSkipped ? ' · managed rules not evaluated' : ''}`;
  else if (d?.type === 'managed') decision = `Managed rules: anomaly score ${az.managedScore} ≥ ${az.threshold} → ${az.action}`;
  else decision = `No custom rule ended evaluation · managed rules score ${az.managedScore} < ${az.threshold}`;
  const statusOf = (r) => {
    if (!r.enabled) return ['disabled', 'Disabled'];
    if (!r.evaluated) return ['skipped', 'Not reached'];
    if (r.rateLimited) return ['rate', 'Counts toward rate limit'];
    if (r.matched) return ['match', String(r.action).toLowerCase() === 'log' ? 'Matched → Log' : `Matched → ${r.action}`];
    if (r.uncertain) return ['unknown', 'Unknown'];
    return ['nomatch', 'No match'];
  };
  const rows = az.customRules.map((r) => {
    const [cls, label] = statusOf(r);
    const conds = r.conditions.map((c) => h(`div.az-cond${c.matched ? '.az-cond-hit' : ''}`,
      h('span.az-cond-mark', c.status !== 'ok' ? '?' : c.matched ? '✓' : '✗'),
      h('code.mono', `${c.variable}${c.selector ? `[${c.selector}]` : ''}`),
      h('span.az-op', `${c.negate ? 'NOT ' : ''}${c.operator}`),
      h('span.az-expected.mono', (c.transforms?.length ? `[${c.transforms.join(' → ')}] ` : '') + truncateList(c.expected)),
      h('span.az-actual', c.note ? c.note : c.matchedValue != null ? `matched “${c.matchedValue}”` : c.values?.length ? `saw “${c.values[0]}”${c.values.length > 1 ? ` +${c.values.length - 1}` : ''}` : '')));
    return h(`details.az-rule.az-${cls}`, { open: r.matched || r.uncertain },
      h('summary.az-rule-head',
        h('span.az-prio.mono', String(r.priority)),
        h('span.az-name', r.name),
        h('span.az-type', /ratelimit/i.test(r.ruleType) ? 'rate limit' : ''),
        h('span.az-action', r.action),
        h(`span.az-status.az-status-${cls}`, label)),
      h('div.az-conds', conds.length ? conds : h('div.muted', 'No match conditions')),
      r.note ? h('div.az-note.muted', r.note) : null);
  });
  return h('section.azure-panel',
    h('div.az-head',
      h('strong', 'Azure WAF'),
      h('span.muted', `${az.policyName || 'policy'} · ${az.kind === 'appgw' ? 'Application Gateway' : 'Front Door'} · ${az.mode}${az.ruleSet ? ` · ${az.ruleSet}` : ''}${az.ruleSetAction ? ` (${az.ruleSetAction})` : ''}`)),
    h('div.az-decision', decision),
    az.note ? h('div.az-note', az.note) : null,
    az.customLogged?.length ? h('div.az-note', `Logged by custom rule(s): ${az.customLogged.join(', ')}`) : null,
    rows.length ? h('details.az-rules', { open: true }, h('summary', `Custom rules (${rows.length}) – evaluated in priority order`), ...rows) : h('div.muted.az-none', 'The policy has no custom rules.'));
}

function truncateList(list) {
  const l = (list || []).map(String);
  const s = l.slice(0, 4).join(', ');
  return l.length > 4 ? `${s}, … (+${l.length - 4})` : s;
}

/* ----------------------------------------------------------------- verdict */

function renderVerdict(ctx) {
  const r = ctx.result;
  const v = verdict(r);
  const st = v.kind === 'off' ? 'none' : v.kind;
  const banner = h(`section.verdict.verdict-${v.kind}`, { 'aria-label': 'Verdict' });
  const text = h('div.verdict-text',
    h('div.verdict-title', statusIcon(st === 'off' ? 'none' : st), h('span', v.title)),
    h('div.verdict-detail', v.detail),
    v.hint ? h('div.verdict-hint', icon('arrowUp'), v.hint) : null);
  if (r.blocked && r.interruption) {
    const it = r.interruption;
    const evalRule = (r.matches || []).find((m) => m.id === it.ruleId);
    text.appendChild(h('div.verdict-rule',
      evalRule ? ruleIdLink(evalRule, ctx) : h('span.mono', String(it.ruleId)),
      h('span.badge.badge-action', `${it.action || 'deny'}${it.status ? ' ' + it.status : ''}`),
      h('span.muted', `phase ${it.phase}`),
      it.msg ? h('span.verdict-msg', it.msg) : null));
    if ((r.interruptions || []).length > 1) {
      text.appendChild(h('div.verdict-more.muted', `+${r.interruptions.length - 1} more interruption(s): ${r.interruptions.slice(1).map((x) => x.ruleId).join(', ')}`));
    }
  }
  banner.append(text, renderMatrix(ctx));
  return banner;
}

function renderMatrix(ctx) {
  const r = ctx.result;
  const cells = plMatrix(r);
  const showOut = cells.some((c) => c.outbound > 0) || !!r.responseInspected;
  const grid = h('div.plmatrix', { role: 'group', 'aria-label': 'Score per paranoia level' });
  for (const c of cells) {
    const state = !c.evaluated ? 'off' : c.blocked ? 'block' : c.hits ? 'hit' : 'pass';
    const label = !c.evaluated ? 'not run' : c.blocked ? 'block' : 'pass';
    const title = !c.evaluated
      ? `PL${c.pl} was not evaluated (detection paranoia level is ${ctx.detectionPL})`
      : `At PL${c.pl}: inbound score ${c.inbound} ${c.inboundBlocked ? '≥' : '<'} ${r.inbound?.threshold}${showOut ? `, outbound ${c.outbound} ${c.outboundBlocked ? '≥' : '<'} ${r.outbound?.threshold}` : ''} → ${c.blocked ? 'blocked' : 'passes'}${c.current ? ' (configured level)' : `. Click to set blocking PL${c.pl}.`}`;
    const cell = h(`button.plcell.pl-${state}${c.current ? '.pl-current' : ''}`, {
      type: 'button',
      title,
      'aria-pressed': c.current ? 'true' : 'false',
      on: { click: () => !c.current && ctx.onSetPL?.(c.pl) },
    },
    h('span.pl-name', `PL${c.pl}`),
    h('span.pl-score', c.evaluated ? String(c.inbound) : '–'),
    showOut && c.evaluated ? h('span.pl-out', `out ${c.outbound}`) : null,
    h('span.pl-state', label));
    grid.appendChild(cell);
  }
  return h('div.plmatrix-wrap',
    grid,
    h('div.plmatrix-caption', `Cumulative inbound score · threshold ${r.inbound?.threshold ?? 5}${showOut ? ` · outbound threshold ${r.outbound?.threshold ?? 4}` : ''}`));
}

/* -------------------------------------------------------------------- cards */

function ruleIdLink(m, ctx) {
  const url = ruleSourceUrl(m, ctx.version);
  const label = String(m.id ?? '—');
  if (!url) return h('span.rule-id', label);
  return h('a.rule-id', { href: url, target: '_blank', rel: 'noopener noreferrer', title: `Open ${m.file}:${m.line} on GitHub` , on: { click: (e) => e.stopPropagation() } }, label);
}

export function renderCard(m, ctx, { higher, open }) {
  const sev = severityClass(m.severity);
  const pl = matchPL(m);
  const score = matchScore(m);
  const category = attackCategory(m.tags, m.file);
  const body = h('div.card-body');
  const card = h(`article.card.sev-${sev}${higher ? '.card-higher' : ''}${open ? '.open' : ''}`, { dataset: { rule: String(m.id) } });

  const toggle = () => {
    const isOpen = card.classList.toggle('open');
    head.setAttribute('aria-expanded', String(isOpen));
    if (isOpen && !body.firstChild) fillBody();
  };
  const head = h('div.card-head', {
    role: 'button', tabindex: '0', 'aria-expanded': String(!!open),
    on: { click: toggle, keydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } } },
  },
  icon('chevronRight', 'chev'),
  ruleIdLink(m, ctx),
  m.severity ? h(`span.badge.sev.sev-${sev}`, m.severity) : null,
  pl != null ? h(`span.badge.pl${higher ? '.pl-higher' : ''}`, { title: `Paranoia level ${pl}` }, `PL${pl}`) : null,
  score ? h(`span.delta${higher ? '.delta-higher' : ''}`, { title: `Adds ${score} to the anomaly score${higher ? ` at PL${pl}+` : ''}` }, `+${score}`) : null,
  category ? h('span.category', category) : null,
  m.override ? h('span.badge.badge-override', { title: `Rule action overridden in the Azure WAF policy: ${m.override}${m.suppressedScores?.length ? ` – its +${m.suppressedScores.reduce((a, x) => a + x.delta, 0)} is not counted` : ''}` }, `Azure: ${m.override}`) : null,
  h('span.card-msg', { title: m.msg || '' }, m.msg || ''),
  higher ? h('span.only-at', `only at PL${pl}+`) : null);
  card.append(head, body);

  function fillBody() {
    body.appendChild(renderRecommendation(m, ctx));
    const links = m.links || [];
    const first = links[0];
    if (first) body.appendChild(renderLink(first, m, ctx, true));
    for (const l of links.slice(1)) body.appendChild(renderCondition(l));
    if (m.logdata) body.appendChild(kv('Log data', h('div.logdata.mono', m.logdata)));
    body.appendChild(renderCardActions(m, ctx));
  }
  if (open) fillBody();
  return card;
}

function kv(label, value, cls = '') {
  return h(`div.kv${cls ? '.' + cls : ''}`, h('div.k', label), h('div.v', value));
}

function renderLink(link, m, ctx, isFirst) {
  const frag = h('div.link');
  const matches = (link.matches || []).filter((x) => x);
  const op = describeOperator(link.op, matches[0]);
  if (op.note && matches[0] && op.note === matches[0].detail) op.note = null;
  const showMatches = (list) => list.map((x, i) => renderMatch(x, ctx, i, op.kind));
  const shown = matches.slice(0, MAX_MATCHES_SHOWN);
  const list = h('div.matches', showMatches(shown));
  frag.appendChild(list);
  const more = matches.length - shown.length + (link.moreMatches || 0);
  if (more > 0) {
    const btn = h('button.link-btn', { type: 'button', on: { click: () => { list.replaceChildren(...showMatches(matches)); btn.remove(); } } },
      `Show ${matches.length - shown.length} more match${matches.length - shown.length === 1 ? '' : 'es'}${link.moreMatches ? ` (${link.moreMatches} not recorded)` : ''}`);
    if (matches.length > shown.length) frag.appendChild(btn);
    else frag.appendChild(h('div.muted', `${link.moreMatches} more matches not recorded`));
  }
  frag.appendChild(kv('Transforms', renderTfns(link.tfns)));
  frag.appendChild(kv('Operator', renderOperator(op)));
  if (isFirst && link.vars) frag.appendChild(kv('Inspects', h('div.inspects.mono', { title: 'Variables this rule inspects' }, link.vars)));
  return frag;
}

function renderMatch(x, ctx, i, opKind) {
  const info = describeVar(x, ctx.varCtx);
  const t = x.transformed || {};
  const wrap = h(`div.match${i ? '.match-next' : ''}`);
  wrap.appendChild(kv('Where', h('div.where',
    h(`span.where-chip.where-${info.kind}`, info.label),
    h('code.rawvar', { title: 'ModSecurity variable' }, x.var),
    copyButton(x.var, 'Copy variable name', { iconOnly: true, title: 'Copy variable name' }))));
  const valueBox = h('div.value-wrap');
  if (t.match || t.before || t.after) {
    valueBox.appendChild(highlighted(t.before, t.match, t.after, 'value mono'));
  } else {
    valueBox.appendChild(h('div.value.mono', x.value ?? ''));
  }
  const meta = [];
  if (x.transformedDiffers) meta.push(h('span.tag-transformed', { title: 'The highlighted value is shown after transformations' }, 'after transformations'));
  if (x.valueLength > 4000 || t.truncated) meta.push(h('span.muted', `${x.valueLength} bytes${t.truncated ? ', excerpt' : ''}`));
  if (x.detail && opKind !== 'libinjection') meta.push(h('span.match-detail', x.detail));
  if (meta.length) valueBox.appendChild(h('div.value-meta', meta));
  if (x.transformedDiffers) {
    valueBox.appendChild(h('details.original', h('summary', 'Original value'), h('div.value.mono', x.value ?? '')));
  }
  wrap.appendChild(kv(t.match ? 'Matched' : 'Value', valueBox));
  if (x.captures && x.captures.length > 1) {
    wrap.appendChild(kv('Captures', h('div.captures', x.captures.slice(0, 6).map((c, ci) => h('span.capture', h('span.cap-i', `${ci}`), h('span.mono', truncate(c, 80)))))));
  }
  return wrap;
}

function renderTfns(tfns) {
  if (!tfns || !tfns.length) return h('span.muted', 'none');
  const out = h('div.tfns');
  tfns.forEach((t, i) => {
    if (i) out.appendChild(h('span.tfn-arrow', '→'));
    out.appendChild(h('span.tfn', t));
  });
  return out;
}

function renderOperator(op) {
  const head = h('div.op-head', h('code.op-name', `${op.text.startsWith('!') ? '!' : ''}@${op.name}`), h('span.op-label', op.label));
  const out = h('div.op', head);
  if (op.param) {
    const long = op.param.length > 90 || op.kind === 'regex';
    const param = h(`code.op-param${long ? '.collapsed' : ''}`, op.param);
    out.appendChild(h('div.op-param-row', param,
      long && op.param.length > 90 ? h('button.link-btn', { type: 'button', on: { click: (e) => { const c = param.classList.toggle('collapsed'); e.target.textContent = c ? 'Expand' : 'Collapse'; } } }, 'Expand') : null,
      copyButton(op.param, 'Copy', { iconOnly: true, title: op.kind === 'regex' ? 'Copy regex' : 'Copy operator argument' })));
  }
  if (op.note) out.appendChild(h('div.op-note', op.note));
  return out;
}

function renderCondition(link) {
  const x = (link.matches || [])[0];
  const op = describeOperator(link.op, x);
  return kv('Chained', h('div.condition',
    h('code.mono', link.vars || x?.var || ''),
    h('code.op-name', `${link.op?.negated ? '!' : ''}@${link.op?.name || ''}`),
    link.op?.param ? h('code.mono.cond-param', truncate(link.op.param, 120)) : null,
    x ? h('span.muted', `value “${truncate(x.value, 60)}”`) : null,
    op.note ? h('span.op-note', op.note) : null), 'kv-cond');
}

/* ---------------------------------------------------------- recommendation */

/** "How to fix" box: assessment, explanation, app / WAF / Azure advice. */
export function renderRecommendationBody(rec, { azureFirst = false } = {}) {
  const list = (title, items, cls) =>
    items.length ? h(`div.rec-group.${cls}`, h('div.rec-group-title', title), h('ul.rec-list', items.map((t) => h('li', t)))) : null;
  const azure = list(azureFirst ? 'Fix in your Azure WAF policy' : 'Azure WAF (Front Door / Application Gateway)', rec.azure, 'rec-azure');
  const waf = list(azureFirst ? 'ModSecurity / Coraza / other CRS-based WAFs' : 'Fix in the WAF configuration', rec.waf, 'rec-waf');
  return h('div.rec-body',
    h('p.rec-why', h('strong', 'What the rule looks for: '), rec.why),
    list('Fix in the application', rec.app, 'rec-app'),
    ...(azureFirst ? [azure, waf] : [waf, azure]));
}

export function renderRecommendation(m, ctx, { open = true } = {}) {
  const rec = recommend(m, { varCtx: ctx.varCtx, azure: ctx.result?.azure || null });
  const details = renderRecommendationBody(rec, { azureFirst: !!ctx.result?.azure });
  const box = h(`details.rec.rec-${rec.tone}`, { open },
    h('summary.rec-head',
      icon('wrench'),
      h('span.rec-title', 'How to fix'),
      h(`span.rec-assess.rec-assess-${rec.tone}`, rec.assessmentLabel),
      h('span.rec-headline', rec.headline)),
    details);
  return box;
}

/* ------------------------------------------------------------ card actions */

function renderCardActions(m, ctx) {
  const primary = (m.links?.[0]?.matches || [])[0] || null;
  const panels = h('div.card-panels');
  let openPanel = null;
  const showPanel = (name, build, btn) => {
    panels.replaceChildren();
    actions.querySelectorAll('.btn[aria-expanded]').forEach((b) => b.setAttribute('aria-expanded', 'false'));
    if (openPanel === name) {
      openPanel = null;
      return;
    }
    openPanel = name;
    btn.setAttribute('aria-expanded', 'true');
    panels.appendChild(build());
  };
  const srcBtn = h('button.btn.btn-sm', { type: 'button', 'aria-expanded': 'false', on: { click: () => showPanel('src', () => renderSecLang(m.raw || '', { file: m.file, line: m.line }), srcBtn) } }, icon('code'), h('span', 'Rule source'));
  const exBtn = h('button.btn.btn-sm', { type: 'button', 'aria-expanded': 'false', on: { click: () => showPanel('ex', () => renderExclusions(m, ctx), exBtn) } }, icon('wrench'), h('span', 'Exclusion'));
  const url = ruleSourceUrl(m, ctx.version);
  const actions = h('div.card-actions',
    copyButton(String(m.id), 'Copy rule id'),
    primary ? copyButton(primary.value ?? '', 'Copy value', { title: 'Copy matched value' }) : null,
    m.raw ? srcBtn : null,
    primary || m.id ? exBtn : null,
    url ? h('a.btn.btn-sm', { href: url, target: '_blank', rel: 'noopener noreferrer', title: 'Open the rule on GitHub' }, icon('external'), h('span', `${m.file}:${m.line}`)) : h('span.muted.file-ref', m.file ? `${m.file}:${m.line}` : ''));
  return h('div.card-foot', actions, panels);
}

function renderExclusions(m, ctx) {
  const firstLink = m.links?.[0];
  const candidates = [];
  const seen = new Set();
  for (const x of firstLink?.matches || []) {
    if (seen.has(x.var)) continue;
    seen.add(x.var);
    candidates.push(x);
  }
  const wrap = h('div.exclusions');
  const content = h('div.ex-list');
  const draw = (match) => {
    const az = ctx.result?.azure;
    const azure = az ? { kind: az.kind, version: (/(\d\.\d)\s*$/.exec(az.ruleSet || '') || [])[1] || '2.1' } : null;
    const list = buildExclusions({ ruleId: m.id, match, path: ctx.path || ctx.entry.request?.url, file: m.file, ctx: ctx.varCtx, azure });
    // In the Azure profile, show the Azure snippet first.
    if (azure) list.sort((a, b) => (b.id === 'azure') - (a.id === 'azure'));
    content.replaceChildren(...list.map((x) => {
      let current = x.variants?.[0] || x;
      const codeBox = h('div.ex-code');
      const render = () => codeBox.replaceChildren(current.language === 'seclang' ? renderSecLang(current.code, { plain: true }) : h('pre.code', current.code));
      render();
      const tabs = x.variants?.length > 1
        ? h('div.ex-variants', { role: 'tablist', 'aria-label': 'Format' }, x.variants.map((v, i) => h('button.chip', {
            type: 'button', role: 'tab', 'aria-pressed': String(i === 0),
            on: { click: (e) => { current = v; render(); e.currentTarget.parentElement.querySelectorAll('.chip').forEach((c) => c.setAttribute('aria-pressed', String(c === e.currentTarget))); } },
          }, v.label)))
        : null;
      return h(`div.ex${x.available ? '' : '.ex-na'}`,
        h('div.ex-head', h('span.ex-title', x.title), copyButton(() => current.code, 'Copy', { title: `Copy ${x.title}` })),
        h('div.ex-desc', x.description),
        tabs,
        codeBox);
    }));
  };
  if (candidates.length > 1) {
    const sel = h('select.select', { 'aria-label': 'Variable to exclude', on: { change: (e) => draw(candidates[+e.target.value]) } },
      candidates.map((x, i) => h('option', { value: String(i) }, `${describeVar(x, ctx.varCtx).label.replace(/[“”]/g, '')} — ${x.var}`)));
    wrap.appendChild(h('div.ex-pick', h('span', 'Exclude variable'), sel));
  }
  wrap.appendChild(h('p.ex-intro', 'Tune the WAF for this false positive. Prefer the narrowest exclusion that works: one variable on one endpoint.'));
  wrap.appendChild(content);
  draw(candidates[0] || null);
  return wrap;
}

