// Pure presentation helpers for the CRS Request Inspector UI.
// No DOM access here: everything in this module is unit-tested in Node (scripts/test-ui-logic.mjs).

/** Rule ids of the CRS anomaly-score evaluation rules (the actual "block"). */
export const EVALUATION_RULE_IDS = new Set([949110, 949111, 959100, 959101, 980130, 980140, 980170]);

export const FORMAT_LABELS = {
  powershell: 'PowerShell',
  curl: 'cURL',
  fetch: 'fetch',
  raw: 'Raw HTTP',
  har: 'HAR',
  devtools: 'DevTools',
  unknown: 'Unknown',
};

/* ------------------------------------------------------------------ URLs */

/**
 * Split a URL without normalising it (new URL() would percent-encode quotes and spaces,
 * but the WAF sees the request exactly as sent).
 */
export function splitUrl(url) {
  const s = String(url ?? '');
  const m = /^([a-z][a-z0-9+.-]*:)?\/\/([^/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/i.exec(s);
  if (!m) {
    const q = s.indexOf('?');
    const path = q >= 0 ? s.slice(0, q) : s;
    const query = q >= 0 ? s.slice(q) : '';
    return { scheme: '', host: '', path: path || '/', query, pathAndQuery: (path || '/') + query };
  }
  const path = m[3] || '/';
  const query = m[4] || '';
  return { scheme: (m[1] || '').replace(/:$/, ''), host: m[2] || '', path, query, pathAndQuery: path + query };
}

/** Parse a query string ("?a=1&b=2" or "a=1&b=2") into [{name, value}], decoding best effort. */
export function parseQuery(qs) {
  const s = String(qs ?? '').replace(/^\?/, '');
  if (!s) return [];
  return s.split('&').filter(Boolean).map((part) => {
    const i = part.indexOf('=');
    const name = i >= 0 ? part.slice(0, i) : part;
    const value = i >= 0 ? part.slice(i + 1) : '';
    return { name: safeDecode(name), value: safeDecode(value) };
  });
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch {
    return s;
  }
}

/** Parse a Cookie header value into [{name, value}]. */
export function parseCookies(header) {
  const s = String(header ?? '');
  if (!s.trim()) return [];
  return s.split(';').map((p) => p.trim()).filter(Boolean).map((p) => {
    const i = p.indexOf('=');
    return i >= 0 ? { name: p.slice(0, i).trim(), value: p.slice(i + 1).trim() } : { name: p, value: '' };
  });
}

export function getHeader(headers, name) {
  const n = String(name).toLowerCase();
  const h = (headers || []).find((x) => String(x.name).toLowerCase() === n);
  return h ? h.value : null;
}

/* ------------------------------------------------------------ resource types */

export const TYPE_GROUPS = [
  { id: 'fetch', label: 'Fetch/XHR' },
  { id: 'doc', label: 'Doc' },
  { id: 'js', label: 'JS' },
  { id: 'css', label: 'CSS' },
  { id: 'img', label: 'Img' },
  { id: 'other', label: 'Other' },
];

export function typeGroup(resourceType) {
  const t = String(resourceType || '').toLowerCase();
  if (t === 'fetch' || t === 'xhr' || t === 'xmlhttprequest' || t === 'eventsource' || t === 'preflight') return 'fetch';
  if (t === 'document' || t === 'main_frame' || t === 'sub_frame' || t === 'doc') return 'doc';
  if (t === 'script' || t === 'js') return 'js';
  if (t === 'stylesheet' || t === 'css') return 'css';
  if (t === 'image' || t === 'img' || t === 'imageset') return 'img';
  return 'other';
}

export function typeLabel(resourceType) {
  const t = String(resourceType || '').toLowerCase();
  const map = { fetch: 'fetch', xhr: 'xhr', xmlhttprequest: 'xhr', document: 'document', script: 'script', stylesheet: 'stylesheet', image: 'image', font: 'font', media: 'media', websocket: 'websocket', other: 'other', ping: 'ping', preflight: 'preflight', manifest: 'manifest' };
  return map[t] || t || '—';
}

/* ------------------------------------------------------------------ sources */

export function sourceInfo(source) {
  const s = String(source || '');
  if (s === 'devtools' || s === 'live') return { kind: 'live', short: 'live', long: 'Captured live from DevTools' };
  if (s.startsWith('paste:')) {
    const f = s.slice(6);
    if (f === 'har') return { kind: 'har', short: 'HAR', long: 'Imported from HAR' };
    return { kind: 'pasted', short: 'pasted', long: `Pasted · ${FORMAT_LABELS[f] || f}` };
  }
  if (s.startsWith('har')) return { kind: 'har', short: 'HAR', long: 'Imported from HAR' };
  if (s === 'mock') return { kind: 'live', short: 'sample', long: 'Sample data' };
  return { kind: 'other', short: s || '—', long: s || 'Unknown source' };
}

/* --------------------------------------------------------------- categories */

const TAG_CATEGORIES = {
  'attack-sqli': 'SQL injection',
  'attack-xss': 'XSS',
  'attack-rce': 'Remote command execution',
  'attack-lfi': 'Local file inclusion',
  'attack-rfi': 'Remote file inclusion',
  'attack-protocol': 'Protocol attack',
  'attack-generic': 'Generic attack',
  'attack-injection-php': 'PHP injection',
  'attack-injection-generic': 'Injection',
  'attack-injection-java': 'Java injection',
  'attack-java': 'Java attack',
  'attack-nodejs': 'Node.js injection',
  'attack-fixation': 'Session fixation',
  'attack-multipart-header': 'Multipart header attack',
  'attack-disclosure': 'Information disclosure',
  'attack-reputation-scanner': 'Scanner detection',
  'attack-reputation-ip': 'IP reputation',
  'attack-reputation-crawler': 'Crawler detection',
  'attack-dos': 'Denial of service',
  'attack-ssrf': 'Server-side request forgery',
  'attack-ai': 'AI prompt injection',
};

const FILE_CATEGORIES = {
  911: 'Method enforcement',
  913: 'Scanner detection',
  920: 'Protocol enforcement',
  921: 'Protocol attack',
  922: 'Multipart attack',
  930: 'Local file inclusion',
  931: 'Remote file inclusion',
  932: 'Remote command execution',
  933: 'PHP injection',
  934: 'Generic attack',
  941: 'XSS',
  942: 'SQL injection',
  943: 'Session fixation',
  944: 'Java attack',
  950: 'Data leakage',
  951: 'SQL data leakage',
  952: 'Java data leakage',
  953: 'PHP data leakage',
  954: 'IIS data leakage',
  955: 'Web shell',
  956: 'Ruby data leakage',
};

/** Human readable attack category for a rule match (derived from tags, then file name). */
export function attackCategory(tags, file) {
  const fileNum = fileNumber(file);
  const list = Array.isArray(tags) ? tags : [];
  for (const t of list) {
    const tag = String(t).toLowerCase();
    if (tag === 'attack-protocol' && fileNum === 920) return 'Protocol enforcement';
    if (TAG_CATEGORIES[tag]) return TAG_CATEGORIES[tag];
  }
  for (const t of list) {
    const tag = String(t).toLowerCase();
    if (tag.startsWith('attack-')) return humanize(tag.slice(7));
  }
  if (fileNum && FILE_CATEGORIES[fileNum]) return FILE_CATEGORIES[fileNum];
  return null;
}

function fileNumber(file) {
  const m = /(?:REQUEST|RESPONSE)-(\d{3})/i.exec(String(file || ''));
  return m ? +m[1] : null;
}

function humanize(s) {
  const t = s.replace(/[-_]+/g, ' ').trim();
  return t ? t[0].toUpperCase() + t.slice(1) : t;
}

/** CSS modifier for a severity badge. */
export function severityClass(sev) {
  switch (String(sev || '').toUpperCase()) {
    case 'EMERGENCY':
    case 'ALERT':
    case 'CRITICAL':
      return 'critical';
    case 'ERROR':
      return 'error';
    case 'WARNING':
      return 'warning';
    case 'NOTICE':
      return 'notice';
    default:
      return 'info';
  }
}

/* ------------------------------------------------------------------ matches */

/** True for a rule that is the anomaly-score evaluation (the block itself). */
export function isEvaluationRule(m) {
  return EVALUATION_RULE_IDS.has(Number(m.id)) || (m.isMeta && m.disruptive && m.disruptive !== 'pass' && m.disruptive !== 'allow');
}

/** Detection rules: visible findings (not internal plumbing, not the evaluation rule). */
export function isDetection(m) {
  return !m.isMeta && !isEvaluationRule(m);
}

/** Total anomaly score contributed by a match (all its score deltas). */
export function matchScore(m, dir) {
  let s = 0;
  for (const x of m.scores || []) if (!dir || x.dir === dir) s += Number(x.delta) || 0;
  return s;
}

/** Paranoia level at which a match counts (its score PL, else its rule PL). */
export function matchPL(m) {
  const s = (m.scores || []).find((x) => x.pl != null);
  if (s) return Number(s.pl);
  return m.pl != null ? Number(m.pl) : null;
}

/** The first "real" variable match of a rule match (first link's first match). */
export function primaryMatch(m) {
  const l = (m.links || [])[0];
  return l && l.matches && l.matches[0] ? l.matches[0] : null;
}

/**
 * Sort detection matches: blocking-relevant (PL <= blocking PL) first, then by score desc,
 * then PL asc, then id. Returns { active, higher } groups.
 */
export function groupFindings(matches, blockingPL) {
  const det = (matches || []).filter(isDetection);
  const cmp = (a, b) => matchScore(b) - matchScore(a) || (matchPL(a) ?? 9) - (matchPL(b) ?? 9) || a.id - b.id;
  const active = [];
  const higher = [];
  for (const m of det) {
    const pl = matchPL(m);
    if (pl != null && pl > blockingPL) higher.push(m);
    else active.push(m);
  }
  active.sort(cmp);
  higher.sort((a, b) => (matchPL(a) ?? 9) - (matchPL(b) ?? 9) || matchScore(b) - matchScore(a) || a.id - b.id);
  return { active, higher };
}

/* ---------------------------------------------------------------- verdicts */

/**
 * Per paranoia-level state for the PL matrix.
 * @returns {Array<{pl, inbound, outbound, blocked, evaluated, current}>}
 */
export function plMatrix(result) {
  const r = result || {};
  const bpl = r.paranoia?.blocking ?? 1;
  const dpl = r.paranoia?.detection ?? 4;
  const inT = r.inbound?.threshold ?? 5;
  const outT = r.outbound?.threshold ?? 4;
  const out = [];
  for (const pl of [1, 2, 3, 4]) {
    const inbound = Number(r.inbound?.cumulative?.[pl] ?? 0);
    const outbound = Number(r.outbound?.cumulative?.[pl] ?? 0);
    const evaluated = pl <= Math.max(dpl, bpl);
    out.push({
      pl,
      inbound,
      outbound,
      inboundBlocked: inbound >= inT,
      outboundBlocked: outbound >= outT,
      blocked: evaluated && (inbound >= inT || outbound >= outT),
      hits: inbound > 0 || outbound > 0,
      evaluated,
      current: pl === bpl,
    });
  }
  return out;
}

/** Lowest PL at which the request would be blocked by anomaly scoring (null if never). */
export function blockingPLFrom(result) {
  const cell = plMatrix(result).find((c) => c.blocked);
  return cell ? cell.pl : null;
}

/**
 * Status of an entry for the list icon / quick filters.
 * 'pending' | 'error' | 'blocked' | 'warn' (hits counted at the configured PL, below threshold)
 * | 'latent' (hits only at higher PLs) | 'clean' | 'none' (no result)
 */
export function entryStatus(entry) {
  if (!entry) return 'none';
  if (entry.status === 'pending') return 'pending';
  if (entry.status === 'error') return 'error';
  const r = entry.result;
  if (!r) return entry.status === 'done' ? 'none' : 'pending';
  if (r.blocked) return 'blocked';
  // Azure profile: follow the Azure decision (same logic as verdict()).
  if (r.azure) {
    const az = r.azure;
    if (!az.enabled) return 'clean';
    if (az.wouldBlock) return 'warn'; // would block, but only logged (Detection mode / Log action)
    if (az.decidedBy?.type === 'custom' && /^allow$/i.test(az.decidedBy.action)) return 'clean';
    if (az.managedSkipped) return 'clean';
  }
  const bpl = r.paranoia?.blocking ?? 1;
  let active = false;
  let higher = false;
  for (const m of r.matches || []) {
    if (!isDetection(m)) continue;
    const pl = matchPL(m);
    if (pl != null && pl > bpl) higher = true;
    else active = true;
  }
  if (active) return 'warn';
  if (higher) return 'latent';
  return 'clean';
}

export const STATUS_LABELS = {
  pending: 'Analyzing…',
  error: 'Analysis failed',
  blocked: 'Would be blocked',
  warn: 'Rules hit, below threshold',
  latent: 'Rules hit only at higher paranoia levels',
  clean: 'Clean',
  none: 'Not analyzed',
};

/** Compact summary used by the request list (computed once per result object). */
export function summarizeEntry(entry) {
  const r = entry.result;
  const status = entryStatus(entry);
  if (!r) return { status, score: null, threshold: null, outScore: 0, blockAt: null, matrix: null, rules: [], detections: 0, maxCumulative: 0 };
  const bpl = r.paranoia?.blocking ?? 1;
  const det = (r.matches || []).filter(isDetection);
  const { active, higher } = groupFindings(det, bpl);
  const seen = new Set();
  const rules = [];
  for (const m of [...active, ...higher]) {
    if (seen.has(m.id)) continue;
    seen.add(m.id);
    const pl = matchPL(m);
    rules.push({ id: m.id, active: !(pl != null && pl > bpl), pl, msg: m.msg, score: matchScore(m) });
  }
  const matrix = plMatrix(r);
  return {
    status,
    score: Number(r.inbound?.score ?? 0),
    threshold: Number(r.inbound?.threshold ?? 5),
    outScore: Number(r.outbound?.score ?? 0),
    outThreshold: Number(r.outbound?.threshold ?? 4),
    blockAt: blockingPLFrom(r),
    blockingPL: bpl,
    matrix,
    rules,
    detections: det.length,
    maxCumulative: Math.max(...matrix.map((c) => c.inbound + c.outbound)),
  };
}

/**
 * Verdict headline for the details pane.
 * @returns {{kind: 'blocked'|'warn'|'latent'|'clean'|'off', title: string, detail: string, hint: string|null}}
 */
export function verdict(result) {
  const r = result || {};
  const bpl = r.paranoia?.blocking ?? 1;
  const inScore = Number(r.inbound?.score ?? 0);
  const inT = Number(r.inbound?.threshold ?? 5);
  const outScore = Number(r.outbound?.score ?? 0);
  const outT = Number(r.outbound?.threshold ?? 4);
  const blockAt = blockingPLFrom(r);
  if (r.engineOff) return { kind: 'off', title: 'Rule engine turned off', detail: String(r.engineOff), hint: null };
  if (r.azure) {
    const az = r.azure;
    const d = az.decidedBy;
    if (r.blocked) {
      const detail = d?.type === 'custom'
        ? `Custom rule “${d.name}” (priority ${d.priority}) → ${d.action}`
        : `Managed rules: anomaly score ${az.managedScore} ≥ ${az.threshold} (${az.ruleSet || 'DRS'}) → ${az.action}`;
      return { kind: 'blocked', title: 'Would be BLOCKED by Azure WAF', detail, hint: null };
    }
    if (!az.enabled) return { kind: 'off', title: 'Azure WAF policy disabled', detail: 'The policy is disabled – nothing is inspected.', hint: null };
    if (d?.type === 'custom' && String(d.action).toLowerCase() === 'allow') {
      return { kind: 'clean', title: 'Allowed by Azure WAF', detail: `Custom rule “${d.name}” (priority ${d.priority}) → Allow – managed rules are not evaluated`, hint: null };
    }
    if (az.wouldBlock) {
      return { kind: 'warn', title: 'Logged only', detail: d?.type === 'custom' ? `Custom rule “${d.name}” → ${d.action}` : `Managed rules: score ${az.managedScore} ≥ ${az.threshold}`, hint: az.note || (az.action === 'log' ? 'Rule set action is Log' : null) };
    }
  }
  if (r.blocked) {
    const it = r.interruption || {};
    let detail;
    if (Number(it.ruleId) === 959100 || Number(it.ruleId) === 959101 || (outScore >= outT && inScore < inT)) {
      detail = `Outbound anomaly score ${outScore} ≥ threshold ${outT} (PL${bpl})`;
    } else if (EVALUATION_RULE_IDS.has(Number(it.ruleId)) || inScore >= inT) {
      detail = `Inbound anomaly score ${inScore} ≥ threshold ${inT} (PL${bpl})`;
    } else {
      detail = `Rule ${it.ruleId}${it.msg ? ` — ${it.msg}` : ''}`;
    }
    return { kind: 'blocked', title: 'Would be BLOCKED', detail, hint: null };
  }
  const hasDetections = (r.matches || []).some(isDetection);
  const hint = blockAt && blockAt > bpl ? `Would start blocking at PL${blockAt} (score ${plMatrix(r)[blockAt - 1].inbound} ≥ ${inT})` : null;
  if (inScore > 0 || outScore > 0) {
    const parts = [`Inbound score ${inScore} < ${inT}`];
    if (outScore > 0) parts.push(`outbound ${outScore} < ${outT}`);
    return { kind: 'warn', title: 'Passes', detail: `${parts.join(', ')} (PL${bpl})`, hint };
  }
  if (hasDetections) {
    return { kind: 'latent', title: 'Passes', detail: `No rule counts at PL${bpl} — score 0 < ${inT}`, hint: hint || 'Rules only hit at higher paranoia levels' };
  }
  return { kind: 'clean', title: 'Clean', detail: `No CRS rule matched up to PL${r.paranoia?.detection ?? 4}`, hint: null };
}

/* ------------------------------------------------------------ variable labels */

const SCALAR_LABELS = {
  REQUEST_FILENAME: 'URL path',
  REQUEST_BASENAME: 'URL file name',
  REQUEST_URI: 'Request URI',
  REQUEST_URI_RAW: 'Raw request URI',
  REQUEST_LINE: 'Request line',
  REQUEST_METHOD: 'HTTP method',
  REQUEST_PROTOCOL: 'HTTP version',
  QUERY_STRING: 'Query string',
  REQUEST_BODY: 'Request body',
  REQUEST_BODY_LENGTH: 'Body length',
  ARGS_COMBINED_SIZE: 'Combined argument size',
  FILES_COMBINED_SIZE: 'Combined upload size',
  REQBODY_PROCESSOR: 'Body processor',
  REQBODY_ERROR: 'Body parse error',
  REQBODY_ERROR_MSG: 'Body parse error',
  MULTIPART_STRICT_ERROR: 'Multipart error',
  MULTIPART_UNMATCHED_BOUNDARY: 'Multipart boundary',
  REMOTE_ADDR: 'Client IP',
  RESPONSE_BODY: 'Response body',
  RESPONSE_STATUS: 'Response status',
  RESPONSE_PROTOCOL: 'Response protocol',
  RESPONSE_CONTENT_TYPE: 'Response content type',
  RESPONSE_CONTENT_LENGTH: 'Response length',
  UNIQUE_ID: 'Unique id',
  FULL_REQUEST: 'Full request',
  FULL_REQUEST_LENGTH: 'Full request length',
  REQUEST_HEADERS_NAMES: 'Header names',
  REQUEST_COOKIES_NAMES: 'Cookie names',
  ARGS_NAMES: 'Argument names',
};

/**
 * Split a ModSecurity variable name like "ARGS:json.content" into collection + key.
 * Handles "MATCHED_VARS:ARGS:q" (key = "ARGS:q").
 */
export function splitVar(v) {
  const s = String(v || '');
  const i = s.indexOf(':');
  if (i < 0) return { collection: s, key: null };
  return { collection: s.slice(0, i), key: s.slice(i + 1) };
}

/**
 * Human label for where a match happened.
 * @param {{var: string, collection?: string, key?: string|null}|string} match
 * @param {{argsGet?: Set<string>|string[], argsPost?: Set<string>|string[], bodyProcessor?: string|null}} [ctx]
 * @returns {{kind: string, label: string, name: string|null, raw: string, area: string}}
 *   kind: json|query|form|multipart|xml|header|cookie|path|method|line|uri|body|file|response|internal|other
 *   area: request part ("headers", "cookies", "args", "body", "url", "response", "internal")
 */
export function describeVar(match, ctx = {}) {
  const raw = typeof match === 'string' ? match : match?.var || '';
  const sv = splitVar(raw);
  const collection = String((typeof match === 'object' && match?.collection) || sv.collection).toUpperCase();
  const key = typeof match === 'object' && match && match.key != null ? String(match.key) : sv.key;
  const has = (set, k) => (set ? (set instanceof Set ? set.has(k) : set.includes(k)) : false);
  const proc = String(ctx.bodyProcessor || '').toUpperCase();

  const argKind = (k, coll) => {
    if (coll === 'ARGS_GET' || coll === 'ARGS_GET_NAMES') return 'query';
    if (coll === 'ARGS_POST' || coll === 'ARGS_POST_NAMES') return postKind(k, proc);
    const inGet = has(ctx.argsGet, k);
    const inPost = has(ctx.argsPost, k);
    if (inPost && !inGet) return postKind(k, proc);
    if (inGet && !inPost) return 'query';
    if (/^json(\.|$)/.test(k) && (proc === 'JSON' || !proc)) return 'json';
    if (inGet) return 'query';
    return proc ? postKind(k, proc) : 'query';
  };

  switch (collection) {
    case 'ARGS':
    case 'ARGS_GET':
    case 'ARGS_POST': {
      if (key == null) return { kind: 'args', label: 'All arguments', name: null, raw, area: 'args' };
      const kind = argKind(key, collection);
      return { kind, label: `${ARG_LABELS[kind]} ${quoteName(displayArgName(key, kind))}`, name: displayArgName(key, kind), raw, area: kind === 'query' ? 'args' : 'body' };
    }
    case 'ARGS_NAMES':
    case 'ARGS_GET_NAMES':
    case 'ARGS_POST_NAMES': {
      if (key == null) return { kind: 'argnames', label: 'Argument names', name: null, raw, area: 'args' };
      const kind = argKind(key, collection);
      return { kind: 'argname', label: `${ARG_LABELS[kind]} name ${quoteName(displayArgName(key, kind))}`, name: displayArgName(key, kind), raw, area: kind === 'query' ? 'args' : 'body' };
    }
    case 'REQUEST_HEADERS':
      if (key == null) return { kind: 'header', label: 'Request headers', name: null, raw, area: 'headers' };
      if (key.toLowerCase() === 'cookie') return { kind: 'header', label: 'Cookie header', name: key, raw, area: 'headers' };
      return { kind: 'header', label: `Header ${quoteName(key)}`, name: key, raw, area: 'headers' };
    case 'REQUEST_HEADERS_NAMES':
      return { kind: 'headername', label: key ? `Header name ${quoteName(key)}` : 'Header names', name: key, raw, area: 'headers' };
    case 'REQUEST_COOKIES':
      return { kind: 'cookie', label: key ? `Cookie ${quoteName(key)}` : 'Cookies', name: key, raw, area: 'cookies' };
    case 'REQUEST_COOKIES_NAMES':
      return { kind: 'cookiename', label: key ? `Cookie name ${quoteName(key)}` : 'Cookie names', name: key, raw, area: 'cookies' };
    case 'FILES':
    case 'FILES_NAMES':
      return { kind: 'file', label: key ? `Uploaded file ${quoteName(key)}` : 'Uploaded files', name: key, raw, area: 'body' };
    case 'XML':
      return { kind: 'xml', label: key ? `XML body ${key}` : 'XML body', name: key, raw, area: 'body' };
    case 'RESPONSE_HEADERS':
      return { kind: 'response', label: key ? `Response header ${quoteName(key)}` : 'Response headers', name: key, raw, area: 'response' };
    case 'RESPONSE_HEADERS_NAMES':
      return { kind: 'response', label: 'Response header names', name: key, raw, area: 'response' };
    case 'TX':
    case 'MATCHED_VAR':
    case 'MATCHED_VARS':
    case 'MATCHED_VAR_NAME':
    case 'MATCHED_VARS_NAMES':
    case 'IP':
    case 'GLOBAL':
    case 'SESSION':
    case 'ENV':
    case 'RULE':
    case 'DURATION':
    case 'TIME':
      return { kind: 'internal', label: collection === 'TX' ? `Transaction variable ${key ?? ''}`.trim() : `${collection}${key ? ':' + key : ''}`, name: key, raw, area: 'internal' };
    default: {
      const base = SCALAR_LABELS[collection];
      const kind = collection === 'REQUEST_FILENAME' || collection === 'REQUEST_BASENAME' ? 'path'
        : collection === 'REQUEST_METHOD' ? 'method'
          : collection === 'REQUEST_LINE' || collection === 'REQUEST_PROTOCOL' ? 'line'
            : collection === 'REQUEST_URI' || collection === 'REQUEST_URI_RAW' || collection === 'QUERY_STRING' ? 'uri'
              : collection.startsWith('RESPONSE') ? 'response'
                : collection.startsWith('REQUEST_BODY') || collection.startsWith('REQBODY') || collection.startsWith('MULTIPART') ? 'body'
                  : 'other';
      const area = kind === 'response' ? 'response' : kind === 'body' ? 'body' : 'url';
      return { kind, label: base ? (key ? `${base} ${key}` : base) : (key ? `${collection} ${quoteName(key)}` : collection), name: key, raw, area };
    }
  }
}

const ARG_LABELS = { json: 'JSON body field', query: 'Query arg', form: 'Form field', multipart: 'Multipart field', xml: 'XML field', body: 'Body arg' };

function postKind(key, proc) {
  if (proc === 'JSON' || /^json(\.|$)/.test(key)) return 'json';
  if (proc === 'MULTIPART') return 'multipart';
  if (proc === 'XML') return 'xml';
  if (proc === 'URLENCODED') return 'form';
  return 'body';
}

/** "json.content" -> "content" for JSON args; other names unchanged. */
export function displayArgName(key, kind) {
  if (kind === 'json' && /^json\./.test(key)) return key.slice(5);
  if (kind === 'json' && key === 'json') return '(root)';
  return key;
}

function quoteName(n) {
  return `“${n}”`;
}

/* ---------------------------------------------------------------- operators */

const OP_DESCRIPTIONS = {
  rx: 'Regular expression',
  rxGlobal: 'Regular expression (global)',
  pm: 'Phrase match',
  pmf: 'Phrase match from file',
  pmFromFile: 'Phrase match from file',
  detectSQLi: 'libinjection SQL injection detection',
  detectXSS: 'libinjection XSS detection',
  validateByteRange: 'Allowed byte range',
  validateUrlEncoding: 'URL encoding validation',
  validateUtf8Encoding: 'UTF-8 encoding validation',
  within: 'Value within list',
  contains: 'Contains',
  containsWord: 'Contains word',
  beginsWith: 'Begins with',
  endsWith: 'Ends with',
  streq: 'String equals',
  strmatch: 'String match',
  eq: 'Equals',
  ge: 'Greater or equal',
  gt: 'Greater than',
  le: 'Less or equal',
  lt: 'Less than',
  ipMatch: 'IP match',
  ipMatchFromFile: 'IP match from file',
  unconditionalMatch: 'Unconditional match',
  noMatch: 'Never matches',
};

/**
 * Describe an operator for display.
 * @returns {{name: string, text: string, label: string, param: string, kind: 'regex'|'list'|'libinjection'|'bytes'|'compare'|'other', note: string|null}}
 */
export function describeOperator(op, match) {
  if (!op) return { name: '', text: '', label: 'No operator', param: '', kind: 'other', note: null };
  const name = String(op.name || '');
  const neg = op.negated ? '!' : '';
  const param = String(op.param ?? '');
  const text = `${neg}@${name}${param ? ' ' + param : ''}`;
  const label = (op.negated ? 'NOT ' : '') + (OP_DESCRIPTIONS[name] || name);
  let kind = 'other';
  let note = null;
  if (name === 'rx' || name === 'rxGlobal') kind = 'regex';
  else if (name === 'pm' || name === 'pmf' || name === 'pmFromFile' || name === 'within' || name === 'ipMatchFromFile') kind = 'list';
  else if (name === 'detectSQLi' || name === 'detectXSS') kind = 'libinjection';
  else if (name.startsWith('validate')) kind = 'bytes';
  else if (['eq', 'ge', 'gt', 'le', 'lt', 'streq'].includes(name)) kind = 'compare';
  if (match) {
    if (kind === 'libinjection') {
      const fp = /fingerprint:\s*(\S+)/i.exec(match.detail || '');
      note = fp ? `fingerprint ${fp[1]}` : match.detail || null;
    } else if (kind === 'list' && match.matched) {
      note = name === 'within' ? null : `matched phrase “${match.matched}”`;
    } else if (match.detail) {
      note = match.detail;
    }
    if (name === 'within' && op.negated) note = `“${truncate(match.value, 60)}” is not in the allowed list`;
  }
  return { name, text, label, param, kind, note };
}

/* --------------------------------------------------------------- rule links */

/** "OWASP_CRS/4.30.0" | "v4.30.0" | "4.30.0" -> "v4.30.0" */
export function normalizeVersion(v) {
  const m = /(\d+\.\d+\.\d+(?:[-.][\w.]+)?)/.exec(String(v || ''));
  return m ? `v${m[1]}` : null;
}

/** GitHub URL of a rule's source line (null for non-CRS rules). */
export function ruleSourceUrl(m, version) {
  if (!m || !m.file) return null;
  const origin = m.origin || 'crs';
  if (origin === 'modsecurity' || /modsecurity\.conf/i.test(m.file)) {
    return `https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/modsecurity.conf-recommended${m.line ? `#L${m.line}` : ''}`;
  }
  if (origin !== 'crs' || !/^(REQUEST|RESPONSE)-\d+/.test(m.file)) return null;
  const v = normalizeVersion(version) || normalizeVersion(m.ver);
  if (!v) return null;
  return `https://github.com/coreruleset/coreruleset/blob/${v}/rules/${m.file}${m.line ? `#L${m.line}` : ''}`;
}

/* ---------------------------------------------------------- paste detection */

/** Rough count of requests in pasted text of a given format (for the live hint). */
export function countRequests(text, format) {
  const s = String(text || '');
  switch (format) {
    case 'powershell': {
      const n = (s.match(/\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/gi) || []).length;
      return Math.max(1, n);
    }
    case 'curl':
      return Math.max(1, (s.match(/(?:^|[\n;&|]\s*)(?:\$\s+)?curl(?:\.exe)?(?=\s|\^)/gim) || []).length);
    case 'fetch':
      return Math.max(1, (s.match(/(?<![\w$.])fetch\s*\(/g) || []).length);
    case 'raw':
      return Math.max(1, (s.match(/^[A-Z][A-Z-]{2,15} \S+ HTTP\/\d(?:\.\d)?\s*$/gm) || []).length);
    case 'har': {
      try {
        const j = JSON.parse(s.trim());
        if (Array.isArray(j?.log?.entries)) return j.log.entries.length;
        if (Array.isArray(j)) return j.length;
        return 1;
      } catch {
        return 0;
      }
    }
    default:
      return 0;
  }
}

/* -------------------------------------------------------------------- misc */

export function truncate(s, n) {
  const t = String(s ?? '');
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
}

export function formatBytes(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} kB`;
  return `${(v / 1024 / 1024).toFixed(1)} MB`;
}

export function formatTime(ms) {
  if (!ms) return '';
  const d = new Date(ms);
  const p = (x, n = 2) => String(x).padStart(n, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

/** Pretty-print a body if it is JSON; returns { text, json: boolean }. */
export function prettyBody(body, contentType) {
  const s = String(body ?? '');
  const t = s.trim();
  if ((t.startsWith('{') || t.startsWith('[')) || /json/i.test(contentType || '')) {
    try {
      return { text: JSON.stringify(JSON.parse(t), null, 2), json: true };
    } catch {
      /* not JSON */
    }
  }
  if (/x-www-form-urlencoded/i.test(contentType || '') && s.includes('=')) {
    return { text: s, json: false, form: true };
  }
  return { text: s, json: false };
}

/** Decode a base64 body to a display string (latin1 bytes interpreted as UTF-8 when valid). */
export function decodeBody(body, encoding) {
  if (body == null) return '';
  if (encoding !== 'base64') return String(body);
  try {
    const bin = atob(String(body));
    try {
      const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      return bin;
    }
  } catch {
    return String(body);
  }
}

/** Sort comparator factory for list columns. */
export function compareBy(column, summaries) {
  const sum = (e) => summaries(e);
  const rank = { blocked: 0, warn: 1, latent: 2, clean: 3, none: 4, error: 5, pending: 6 };
  switch (column) {
    case 'status':
      return (a, b) => rank[sum(a).status] - rank[sum(b).status] || (sum(b).maxCumulative - sum(a).maxCumulative);
    case 'method':
      return (a, b) => String(a.request?.method).localeCompare(String(b.request?.method));
    case 'name':
      return (a, b) => splitUrl(a.request?.url).pathAndQuery.localeCompare(splitUrl(b.request?.url).pathAndQuery);
    case 'type':
      return (a, b) => typeLabel(a.resourceType).localeCompare(typeLabel(b.resourceType));
    case 'score':
      return (a, b) => (sum(a).score ?? -1) - (sum(b).score ?? -1) || (sum(a).blockAt ? 5 - sum(a).blockAt : 0) - (sum(b).blockAt ? 5 - sum(b).blockAt : 0) || sum(a).maxCumulative - sum(b).maxCumulative;
    case 'rules':
      return (a, b) => sum(a).detections - sum(b).detections;
    case 'source':
      return (a, b) => String(a.source).localeCompare(String(b.source));
    case 'time':
    default:
      return (a, b) => (a.startedAt || 0) - (b.startedAt || 0);
  }
}

/* ------------------------------------------------------------- hit index */

/**
 * Key of the request part a variable refers to, used to mark rows in the Request /
 * Response tabs: "h:user-agent", "c:app_session", "a:json.content", "s:REQUEST_FILENAME", ...
 */
export function hitKey(v) {
  const { collection, key } = splitVar(v);
  const c = collection.toUpperCase();
  const k = key == null ? null : String(key);
  if (c === 'REQUEST_HEADERS' || c === 'REQUEST_HEADERS_NAMES') return k ? `h:${k.toLowerCase()}` : 's:REQUEST_HEADERS';
  if (c === 'REQUEST_COOKIES' || c === 'REQUEST_COOKIES_NAMES') return k ? `c:${k}` : 's:REQUEST_COOKIES';
  if (/^ARGS(_GET|_POST)?(_NAMES)?$/.test(c)) return k ? `a:${k}` : 's:ARGS';
  if (c === 'FILES' || c === 'FILES_NAMES') return k ? `f:${k}` : 's:FILES';
  if (c === 'XML') return 's:XML';
  if (c === 'RESPONSE_HEADERS' || c === 'RESPONSE_HEADERS_NAMES') return k ? `rh:${k.toLowerCase()}` : 's:RESPONSE_HEADERS';
  if (c === 'TX' || c.startsWith('MATCHED_')) return null;
  return `s:${c}`;
}

/**
 * Map of hitKey -> [{ id, active, pl }] for all detection matches.
 * @param {object[]} matches  result.matches
 * @param {number} blockingPL
 */
export function buildHitIndex(matches, blockingPL) {
  const map = new Map();
  for (const m of matches || []) {
    if (!isDetection(m)) continue;
    const pl = matchPL(m);
    const active = !(pl != null && pl > blockingPL);
    for (const l of m.links || []) {
      for (const x of l.matches || []) {
        const key = hitKey(x.var);
        if (!key) continue;
        const list = map.get(key) || [];
        if (!list.some((y) => y.id === m.id)) list.push({ id: m.id, active, pl, msg: m.msg });
        map.set(key, list);
      }
    }
  }
  for (const list of map.values()) list.sort((a, b) => Number(b.active) - Number(a.active) || a.id - b.id);
  return map;
}
