// "Request" and "Response" tabs: the request as the WAF sees it, with matched parts marked.

import { h, icon, copyButton } from '../dom.js';
import {
  splitUrl, parseQuery, parseCookies, getHeader, buildHitIndex, prettyBody, decodeBody, displayArgName,
  sourceInfo, formatBytes, truncate,
} from '../format.js';
import { toCurl, toRawHttp } from '../export.js';

function section(title, content, { count, open = true, actions } = {}) {
  return h('details.section', { open },
    h('summary.section-title', icon('chevronRight', 'chev'), h('span', title), count != null ? h('span.count', String(count)) : null, actions ? h('span.section-title-actions', actions) : null),
    h('div.section-body', content));
}

function hitPills(hits, onRule) {
  if (!hits || !hits.length) return null;
  return h('span.hits', hits.map((x) => h(`button.pill${x.active ? '.pill-active' : '.pill-higher'}`, {
    type: 'button',
    title: `${x.id} — ${x.msg || ''}${x.active ? '' : ` (only at PL${x.pl}+)`}. Show finding`,
    on: { click: (e) => { e.stopPropagation(); onRule?.(x.id); } },
  }, String(x.id))));
}

/** name/value table; rows: [{name, value, hits, label?}] */
function kvTable(rows, { nameHeader = 'Name', valueHeader = 'Value', onRule, mono = true } = {}) {
  if (!rows.length) return h('div.muted.empty-row', 'None');
  return h('table.kvtable',
    h('thead', h('tr', h('th', nameHeader), h('th', valueHeader), h('th.th-hits', 'Rules'))),
    h('tbody', rows.map((r) => h(`tr${r.hits && r.hits.length ? (r.hits.some((x) => x.active) ? '.row-hit' : '.row-hit-higher') : ''}`,
      h('td.kname', { title: r.title || r.name }, r.label || r.name),
      h(`td.kval${mono ? '.mono' : ''}`, r.value),
      h('td.khits', hitPills(r.hits, onRule))))));
}

export function renderRequest(ctx) {
  const { entry, result: r } = ctx;
  const req = entry.request || {};
  const v = r?.variables || {};
  const idx = buildHitIndex(r?.matches || [], ctx.blockingPL);
  const hits = (k) => idx.get(k) || null;
  const onRule = ctx.onRule;
  const u = splitUrl(req.url);
  const root = h('div.reqview');

  root.appendChild(h('div.view-toolbar',
    copyButton(() => toCurl(req), 'Copy as cURL', { title: 'Copy as cURL (bash)' }),
    copyButton(() => toRawHttp(req), 'Copy raw HTTP'),
    copyButton(req.url || '', 'Copy URL')));

  const src = sourceInfo(entry.source);
  const general = [
    { name: 'Request URL', value: req.url || '', hits: hits('s:REQUEST_URI_RAW') || hits('s:REQUEST_URI') },
    { name: 'Request line', value: v.REQUEST_LINE || `${req.method} ${u.pathAndQuery} ${req.httpVersion || ''}`, hits: hits('s:REQUEST_LINE') },
    { name: 'Method', value: req.method || '', hits: hits('s:REQUEST_METHOD') },
    { name: 'Path (REQUEST_FILENAME)', value: v.REQUEST_FILENAME || u.path, hits: [...(hits('s:REQUEST_FILENAME') || []), ...(hits('s:REQUEST_BASENAME') || [])] },
    { name: 'Protocol', value: v.REQUEST_PROTOCOL || req.httpVersion || '', hits: hits('s:REQUEST_PROTOCOL') },
  ];
  if (u.query) general.push({ name: 'Query string', value: v.QUERY_STRING ?? u.query.slice(1), hits: hits('s:QUERY_STRING') });
  general.push({ name: 'Body processor', value: r?.bodyProcessor || v.REQBODY_PROCESSOR || '—' });
  if (v.REQUEST_BODY_LENGTH) general.push({ name: 'Body length', value: formatBytes(v.REQUEST_BODY_LENGTH) });
  general.push({ name: 'Source', value: src.long });
  if (entry.startedAt) general.push({ name: 'Started', value: new Date(entry.startedAt).toLocaleString() });
  if (r?.elapsedMs != null) general.push({ name: 'Analysis', value: `${r.evaluatedRules ?? '?'} rules evaluated in ${r.elapsedMs} ms` });
  root.appendChild(section('General', kvTable(general, { onRule, mono: true })));

  // Headers
  const headers = (v.REQUEST_HEADERS && v.REQUEST_HEADERS.length ? v.REQUEST_HEADERS : req.headers || []).map((x) => ({
    name: x.name, value: x.value, hits: hits(`h:${String(x.name).toLowerCase()}`),
  }));
  root.appendChild(section('Request headers', kvTable(headers, { onRule }), { count: headers.length }));

  // Cookies
  const cookieList = v.REQUEST_COOKIES && v.REQUEST_COOKIES.length ? v.REQUEST_COOKIES : parseCookies(getHeader(req.headers, 'cookie'));
  if (cookieList.length) {
    root.appendChild(section('Cookies', kvTable(cookieList.map((x) => ({ name: x.name, value: x.value, hits: hits(`c:${x.name}`) })), { onRule }), { count: cookieList.length }));
  }

  // Query args
  const qargs = v.ARGS_GET ? v.ARGS_GET : parseQuery(u.query);
  if (qargs.length) {
    root.appendChild(section('Query arguments (ARGS_GET)', kvTable(qargs.map((x) => ({ name: x.name, value: x.value, hits: hits(`a:${x.name}`) })), { onRule }), { count: qargs.length }));
  }

  // Body args
  const pargs = v.ARGS_POST || [];
  if (pargs.length) {
    const json = String(r?.bodyProcessor || '').toUpperCase() === 'JSON';
    root.appendChild(section(`Body arguments (ARGS_POST${json ? ', JSON flattened' : ''})`,
      kvTable(pargs.map((x) => ({ name: x.name, label: json ? h('span', h('span.muted', 'json.'), displayArgName(x.name, 'json')) : x.name, value: x.value, hits: hits(`a:${x.name}`) })), { onRule }),
      { count: pargs.length }));
  }
  if (v.FILES && v.FILES.length) {
    root.appendChild(section('Uploaded files (FILES)', kvTable(v.FILES.map((x) => ({ name: x.name, value: x.value, hits: hits(`f:${x.name}`) })), { onRule }), { count: v.FILES.length }));
  }
  if (v.XML && v.XML.length) {
    root.appendChild(section('XML', kvTable(v.XML.map((x) => ({ name: x.name, value: x.value, hits: hits('s:XML') })), { onRule }), { count: v.XML.length }));
  }

  // Raw body
  if (req.body != null && req.body !== '') {
    const text = decodeBody(req.body, req.bodyEncoding);
    const pretty = prettyBody(text, getHeader(req.headers, 'content-type'));
    const bodyHits = hits('s:REQUEST_BODY');
    root.appendChild(section('Request body', [
      h('div.body-meta', h('span.muted', `${formatBytes(text.length)}${req.bodyEncoding === 'base64' ? ' · decoded from base64' : ''}${pretty.json ? ' · pretty-printed JSON' : ''}`), hitPills(bodyHits, onRule)),
      h('pre.code.body', truncate(pretty.text, 200000)),
    ], { actions: copyButton(text, 'Copy body', { iconOnly: true, title: 'Copy raw body' }) }));
  }
  return root;
}

export function renderResponse(ctx) {
  const { entry, result: r } = ctx;
  const res = entry.request?.response;
  const root = h('div.reqview');
  if (!res) return h('div.placeholder', 'No response captured for this request.');
  const idx = buildHitIndex(r?.matches || [], ctx.blockingPL);
  const hits = (k) => idx.get(k) || null;
  const onRule = ctx.onRule;
  const inspected = r?.responseInspected;
  const general = [
    { name: 'Status', value: `${res.status ?? ''} ${res.statusText || ''}`.trim(), hits: hits('s:RESPONSE_STATUS') },
    { name: 'Protocol', value: res.httpVersion || '', hits: hits('s:RESPONSE_PROTOCOL') },
    { name: 'MIME type', value: res.mimeType || getHeader(res.headers, 'content-type') || '—' },
    { name: 'Inspected by WAF', value: !inspected ? 'No (response evaluation disabled or not applicable)' : inspected.body ? 'Headers and body' : `Headers only${inspected.reason ? ` — ${inspected.reason}` : ''}` },
  ];
  if (r?.outbound) general.push({ name: 'Outbound score', value: `${r.outbound.score} / threshold ${r.outbound.threshold}` });
  root.appendChild(section('General', kvTable(general, { onRule })));
  const headers = (res.headers || []).map((x) => ({ name: x.name, value: x.value, hits: hits(`rh:${String(x.name).toLowerCase()}`) }));
  root.appendChild(section('Response headers', kvTable(headers, { onRule }), { count: headers.length }));
  if (res.body != null && res.body !== '') {
    const text = decodeBody(res.body, res.bodyEncoding);
    const pretty = prettyBody(text, res.mimeType || getHeader(res.headers, 'content-type'));
    root.appendChild(section('Response body', [
      h('div.body-meta', h('span.muted', `${formatBytes(text.length)}${pretty.json ? ' · pretty-printed JSON' : ''}`), hitPills(hits('s:RESPONSE_BODY'), onRule)),
      h('pre.code.body', truncate(pretty.text, 200000)),
    ], { actions: copyButton(text, 'Copy body', { iconOnly: true, title: 'Copy response body' }) }));
  } else {
    root.appendChild(section('Response body', h('div.muted.empty-row', 'Body not available.')));
  }
  return root;
}

