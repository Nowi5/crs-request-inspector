// "Issues report": all findings across the captured requests, grouped by rule and request
// part, with recommendations for developers and the WAF owner. Exportable as Markdown.

import { h, icon, copyButton, toast } from '../dom.js';
import { isDetection, severityClass, ruleSourceUrl, attackCategory } from '../format.js';
import { buildIssues, issuesToMarkdown } from '../recommendations.js';
import { buildContext, renderRecommendationBody } from './findings.js';

/**
 * @param {{ getEntries(): Array, getSettings(): object, getVersion(): string, onSelect(id: string): void }} cb
 */
export function createReportDialog(cb) {
  const summary = h('div.report-summary');
  const listEl = h('div.report-list');
  const includeHigher = h('input', { type: 'checkbox', checked: true, on: { change: () => render() } });
  let issues = [];

  const markdown = () =>
    issuesToMarkdown(includeHigher.checked ? issues : issues.filter((i) => i.counted), {
      blockingPL: Number(cb.getSettings().blockingParanoiaLevel) || 1,
      version: cb.getVersion(),
      total: cb.getEntries().filter((e) => e.result).length,
    });
  const download = () => {
    const blob = new Blob([markdown()], { type: 'text/markdown' });
    const a = h('a', { href: URL.createObjectURL(blob), download: 'waf-findings-report.md' });
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(a.href);
      a.remove();
    }, 1000);
    toast('Report downloaded');
  };

  const closeBtn = h('button.icon-btn', { type: 'button', title: 'Close', 'aria-label': 'Close', on: { click: () => dialog.close() } }, icon('close'));
  const dialog = h('dialog.dialog.report-dialog', { 'aria-label': 'Issues report' },
    h('header.dialog-head', h('h2', icon('shield'), 'Issues report'), h('span.spacer'), closeBtn),
    h('div.report-toolbar',
      summary,
      h('label.toggle', includeHigher, h('span', 'Include higher paranoia levels')),
      copyButton(() => markdown(), 'Copy as Markdown', { title: 'Copy the report as Markdown (for tickets, PRs, e-mail)' }),
      h('button.btn.btn-sm', { type: 'button', on: { click: download } }, icon('download'), h('span', 'Download .md'))),
    listEl);

  function render() {
    const settings = cb.getSettings();
    const blockingPL = Number(settings.blockingParanoiaLevel) || 1;
    const entries = cb.getEntries().filter((e) => e.result);
    issues = buildIssues(entries, { blockingPL, isDetection, varCtxFor: (e) => buildContext(e).varCtx });
    const shown = includeHigher.checked ? issues : issues.filter((i) => i.counted);
    const counted = issues.filter((i) => i.counted).length;
    const blocked = entries.filter((e) => e.result.blocked).length;
    summary.replaceChildren(
      h('strong', `${issues.length} distinct finding${issues.length === 1 ? '' : 's'}`),
      h('span.muted', ` across ${entries.length} analysed request${entries.length === 1 ? '' : 's'} · ${counted} counted at PL${blockingPL} · ${blocked} request${blocked === 1 ? '' : 's'} would be blocked`));
    if (!shown.length) {
      listEl.replaceChildren(h('div.report-empty', icon('clean'), h('span', entries.length ? 'No findings – nothing to fix.' : 'No analysed requests yet.')));
      return;
    }
    const groups = [
      [`Counted at PL${blockingPL} – affects blocking`, shown.filter((i) => i.counted)],
      ['Only at higher paranoia levels', shown.filter((i) => !i.counted)],
    ];
    listEl.replaceChildren(
      ...groups.filter(([, l]) => l.length).flatMap(([title, l]) => [h('h3.report-group', title, h('span.muted', ` ${l.length}`)), ...l.map((it) => renderIssue(it, settings))]));
  }

  function renderIssue(it, settings) {
    const sev = severityClass(it.severity);
    const url = ruleSourceUrl(it.sample, cb.getVersion());
    const category = attackCategory(it.sample.tags, it.file);
    const body = h('div.issue-body',
      renderRecommendationBody(it.rec),
      h('div.issue-routes', h('div.rec-group-title', `Endpoints (${it.routes.length})`),
        h('ul.rec-list', it.routes.slice(0, 8).map((r) => h('li', h('code.mono', r.route), h('span.muted', ` · ${r.n} request${r.n === 1 ? '' : 's'}`))))),
      h('div.issue-actions',
        h('button.btn.btn-sm', { type: 'button', on: { click: () => { dialog.close(); cb.onSelect(it.sampleEntry.id); } } }, icon('search'), h('span', 'Show example request')),
        copyButton(String(it.varName), 'Copy variable'),
        url ? h('a.btn.btn-sm', { href: url, target: '_blank', rel: 'noopener noreferrer' }, icon('external'), h('span', `${it.file}:${it.line}`)) : null));
    return h(`details.issue.sev-${sev}${it.counted ? '' : '.issue-higher'}`,
      h('summary.issue-head',
        icon('chevronRight', 'chev'),
        h('span.rule-id', String(it.id)),
        it.severity ? h(`span.badge.sev.sev-${sev}`, it.severity) : null,
        it.pl != null ? h('span.badge.pl', `PL${it.pl}`) : null,
        category ? h('span.category', category) : null,
        h('span.issue-msg', it.msg || ''),
        h('code.rawvar', { title: it.rec.where }, it.varName),
        h('span.issue-count', { title: 'Requests with this finding' }, `${it.count}×`),
        h(`span.rec-assess.rec-assess-${it.rec.tone}`, it.rec.assessmentLabel)),
      h('p.issue-headline', it.rec.headline),
      body);
  }

  return {
    el: dialog,
    open() {
      render();
      if (!dialog.open) dialog.showModal();
    },
    refresh() {
      if (dialog.open) render();
    },
  };
}
