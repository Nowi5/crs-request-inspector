// SecLang rule engine: compiles parsed directives and evaluates transactions with
// ModSecurity v2 semantics (phases, chains, skipAfter, ctl, setvar, anomaly scoring).

import { parseConfig, parseActions, parseVariables, parseOperator } from './seclang.js';
import { createOperator } from './operators.js';
import { getTransform, TRANSFORM_NAMES } from './transforms.js';
import { compilePcre } from './pcre.js';
import { Transaction } from './transaction.js';
import { asciiLower, atoi, displayBinary } from './bytes.js';

export const SEVERITIES = ['EMERGENCY', 'ALERT', 'CRITICAL', 'ERROR', 'WARNING', 'NOTICE', 'INFO', 'DEBUG'];

const KNOWN_COLLECTIONS = new Set([
  'ARGS', 'ARGS_COMBINED_SIZE', 'ARGS_GET', 'ARGS_GET_NAMES', 'ARGS_NAMES', 'ARGS_POST', 'ARGS_POST_NAMES', 'AUTH_TYPE', 'DURATION',
  'ENV', 'FILES', 'FILES_COMBINED_SIZE', 'FILES_NAMES', 'FILES_SIZES', 'FILES_TMPNAMES', 'FILES_TMP_CONTENT', 'FULL_REQUEST',
  'FULL_REQUEST_LENGTH', 'GEO', 'GLOBAL', 'HIGHEST_SEVERITY', 'INBOUND_DATA_ERROR', 'IP', 'MATCHED_VAR', 'MATCHED_VARS',
  'MATCHED_VAR_NAME', 'MATCHED_VARS_NAMES', 'MULTIPART_BOUNDARY_QUOTED', 'MULTIPART_BOUNDARY_WHITESPACE', 'MULTIPART_CRLF_LF_LINES',
  'MULTIPART_DATA_AFTER', 'MULTIPART_DATA_BEFORE', 'MULTIPART_DUPLICATE_PART_HEADER', 'MULTIPART_FILENAME', 'MULTIPART_FILE_LIMIT_EXCEEDED',
  'MULTIPART_HEADER_FOLDING', 'MULTIPART_INVALID_HEADER_FOLDING', 'MULTIPART_INVALID_PART', 'MULTIPART_INVALID_QUOTING',
  'MULTIPART_LF_LINE', 'MULTIPART_MISSING_SEMICOLON', 'MULTIPART_NAME', 'MULTIPART_PART_HEADERS', 'MULTIPART_STRICT_ERROR',
  'MULTIPART_UNMATCHED_BOUNDARY', 'OUTBOUND_DATA_ERROR', 'PATH_INFO', 'QUERY_STRING', 'REMOTE_ADDR', 'REMOTE_HOST', 'REMOTE_PORT',
  'REMOTE_USER', 'REQBODY_ERROR', 'REQBODY_ERROR_MSG', 'REQBODY_PROCESSOR', 'REQBODY_PROCESSOR_ERROR', 'REQBODY_PROCESSOR_ERROR_MSG',
  'REQUEST_BASENAME', 'REQUEST_BODY', 'REQUEST_BODY_LENGTH', 'REQUEST_COOKIES', 'REQUEST_COOKIES_NAMES', 'REQUEST_FILENAME',
  'REQUEST_HEADERS', 'REQUEST_HEADERS_NAMES', 'REQUEST_LINE', 'REQUEST_METHOD', 'REQUEST_PROTOCOL', 'REQUEST_URI', 'REQUEST_URI_RAW',
  'RESOURCE', 'RESPONSE_BODY', 'RESPONSE_CONTENT_LENGTH', 'RESPONSE_CONTENT_TYPE', 'RESPONSE_HEADERS', 'RESPONSE_HEADERS_NAMES',
  'RESPONSE_PROTOCOL', 'RESPONSE_STATUS', 'RULE', 'SERVER_ADDR', 'SERVER_NAME', 'SERVER_PORT', 'SESSION', 'SESSIONID', 'STATUS_LINE',
  'TIME', 'TIME_DAY', 'TIME_EPOCH', 'TIME_HOUR', 'TIME_MIN', 'TIME_MON', 'TIME_SEC', 'TIME_WDAY', 'TIME_YEAR', 'TX', 'UNIQUE_ID',
  'URLENCODED_ERROR', 'USER', 'USERID', 'WEBAPPID', 'XML',
]);

const NON_DISRUPTIVE_EXEC = new Set(['setvar', 'ctl', 'initcol', 'expirevar', 'setenv', 'setuid', 'setsid', 'setrsc', 'deprecatevar', 'exec', 'sanitisearg', 'sanitisematched', 'sanitisematchedbytes', 'sanitiserequestheader', 'sanitiseresponseheader', 'append', 'prepend']);
const METADATA = new Set(['id', 'phase', 'msg', 'logdata', 'severity', 'tag', 'ver', 'rev', 'maturity', 'accuracy']);
const DISRUPTIVE = new Set(['deny', 'drop', 'block', 'pass', 'allow', 'redirect', 'proxy', 'pause']);
const FLOW = new Set(['chain', 'skip', 'skipafter']);
const IGNORED = new Set(['log', 'nolog', 'auditlog', 'noauditlog', 'capture', 'multimatch', 'status', 't', 'xmlns']);

function parsePhase(v) {
  const s = String(v).trim().toLowerCase().replace(/^'|'$/g, '');
  if (s === 'request') return 2;
  if (s === 'response') return 4;
  if (s === 'logging') return 5;
  const n = parseInt(s, 10);
  return n >= 1 && n <= 5 ? n : 2;
}

function parseSeverity(v) {
  if (v == null) return null;
  const s = String(v).trim().replace(/^'|'$/g, '');
  if (/^\d$/.test(s)) return +s;
  const idx = SEVERITIES.indexOf(s.toUpperCase());
  return idx >= 0 ? idx : null;
}

/** Parse "920100 920200-920299,930000" into predicate ranges. */
function parseIdRanges(spec) {
  const ranges = [];
  for (const part of String(spec).split(/[\s,]+/)) {
    if (!part) continue;
    const m = /^(\d+)(?:-(\d+))?$/.exec(part.replace(/^'|'$/g, ''));
    if (m) ranges.push([+m[1], m[2] ? +m[2] : +m[1]]);
  }
  return ranges;
}
const inRanges = (id, ranges) => id != null && ranges.some(([a, b]) => id >= a && id <= b);

/**
 * Tag / msg selector with ModSecurity v2 semantics.
 *  - 'regex' (SecRuleRemoveByTag/ByMsg, SecRuleUpdateTargetByTag/ByMsg, ctl:ruleRemoveByTag):
 *    msc_pregcomp(pattern, 0) + msc_regexec -> unanchored, case-sensitive regex, no DOTALL.
 *  - 'exact' (ctl:ruleRemoveTargetByTag / ctl:ruleRemoveTargetByMsg): re.c compares the
 *    exception parameter with strcmp() -> exact, case-sensitive string equality.
 */
function tagMatcher(spec, mode = 'regex') {
  const s = String(spec);
  if (mode === 'exact') return (v) => String(v) === s;
  const r = compilePcre(s, { baseFlags: '' });
  if (r.re) return (v) => r.re.test(v);
  return (v) => String(v).includes(s);
}

// Azure profile exclusions (origin 'azure'): Azure distinguishes query-string and body arguments,
// ModSecurity's !ARGS:x cannot. A negated ARGS_GET/ARGS_POST(_NAMES) target in an Azure profile
// update directive therefore also removes the entries of that source from ARGS / ARGS_NAMES.
// This is NOT ModSecurity semantics and is only enabled for directives with origin 'azure'.
const ARG_SOURCE_EXCLUSION = {
  ARGS_GET: { collection: 'ARGS', src: 'get' },
  ARGS_POST: { collection: 'ARGS', src: 'post' },
  ARGS_GET_NAMES: { collection: 'ARGS_NAMES', src: 'get' },
  ARGS_POST_NAMES: { collection: 'ARGS_NAMES', src: 'post' },
};

/** Compile a parsed variable spec: adds lowercase key / compiled key regex. */
function compileTarget(v, warn) {
  const t = { ...v, keyLower: v.key !== null ? asciiLower(v.key) : null, re: null };
  if (v.keyRegex !== null) {
    const r = compilePcre(v.keyRegex, { baseFlags: 'is' });
    if (r.re) t.re = r.re;
    else warn(`variable key regex /${v.keyRegex}/ not supported: ${r.error}`);
  }
  if (!KNOWN_COLLECTIONS.has(v.collection)) warn(`unknown variable ${v.collection}`);
  return t;
}

function targetMatchesEntry(t, collection, name, entry) {
  if (t.collection !== collection) {
    const a = t.argSource;
    if (!a || a.collection !== collection || !entry || entry.src !== a.src) return false;
  }
  if (t.keyLower === null && !t.re && t.keyRegex === null) return true;
  if (t.keyLower !== null) return asciiLower(name) === t.keyLower;
  return !!t.re && t.re.test(name);
}

const DEFAULT_CONFIG = {
  requestBodyAccess: true,
  requestBodyLimit: 0,
  requestBodyNoFilesLimit: 0,
  requestBodyLimitAction: 'Reject',
  responseBodyAccess: true,
  responseBodyMimeTypes: ['text/plain', 'text/html', 'text/xml'],
  responseBodyLimit: 524288,
  argumentSeparator: '&',
  jsonDepthLimit: 512,
  argumentsLimit: 0,
};

export class RuleSet {
  constructor({ dataFiles = new Map(), meta = {} } = {}) {
    this.items = [];
    this.byId = new Map();
    this.defaultActions = {};
    this.config = { ...DEFAULT_CONFIG };
    this.dataFiles = dataFiles;
    this.meta = meta;
    this.warnings = [];
    this.errors = [];
    this.pendingChain = null;
    this.ruleCount = 0;
    this.files = [];
  }

  warn(where, message) {
    this.warnings.push({ file: where.file, line: where.line, id: where.id ?? null, message });
  }

  /**
   * Add a configuration file.
   * @param {string} name   file name (for reporting)
   * @param {string} text   file content as byte string
   * @param {{origin?: string, ignoreDirectives?: string[]}} opts
   */
  addFile(name, text, opts = {}) {
    const { directives, errors } = parseConfig(text, name);
    this.files.push({ name, origin: opts.origin || 'crs' });
    for (const e of errors) this.errors.push(e);
    const ignore = new Set((opts.ignoreDirectives || []).map((d) => d.toLowerCase()));
    for (const d of directives) {
      d.origin = opts.origin || 'crs';
      const dn = d.name.toLowerCase();
      if (ignore.has(dn)) continue;
      try {
        this.addDirective(d, dn);
      } catch (e) {
        this.errors.push({ file: d.file, line: d.line, message: e.message });
      }
    }
    if (this.pendingChain) {
      this.errors.push({ file: name, line: this.pendingChain.line, message: 'chain without a following rule' });
      this.pendingChain = null;
    }
  }

  addDirective(d, dn) {
    switch (dn) {
      case 'secrule':
      case 'secaction': {
        const rule = this.compileRule(d, dn === 'secaction');
        if (this.pendingChain) {
          if (dn === 'secaction') throw new Error('SecAction cannot be part of a chain');
          const parent = this.pendingChain;
          parent.next = rule;
          rule.starter = parent.starter;
          rule.phase = rule.starter.phase;
          rule.id = rule.starter.id;
          rule.isChild = true;
          rule.starter.links.push(rule);
          this.pendingChain = rule.chain ? rule : null;
          return;
        }
        rule.starter = rule;
        rule.links = [rule];
        this.items.push(rule);
        this.ruleCount++;
        if (rule.id != null) {
          if (this.byId.has(rule.id)) this.warn(rule, `duplicate rule id ${rule.id}`);
          this.byId.set(rule.id, rule);
        }
        this.pendingChain = rule.chain ? rule : null;
        return;
      }
      case 'secmarker':
        this.items.push({ kind: 'marker', name: (d.args[0] || '').replace(/^'|'$/g, ''), file: d.file, line: d.line });
        return;
      case 'secdefaultaction': {
        const acts = parseActions(d.args[0] || '');
        let phase = 2;
        let disruptive = 'pass';
        for (const a of acts) {
          const n = a.name.toLowerCase();
          if (n === 'phase') phase = parsePhase(a.value);
          if (DISRUPTIVE.has(n)) disruptive = n;
        }
        this.defaultActions[phase] = { disruptive, actions: acts };
        return;
      }
      case 'secruleremovebyid': {
        const ranges = parseIdRanges(d.args.join(' '));
        for (const r of this.items) if (r.kind === 'rule' && inRanges(r.id, ranges)) r.removedBy = `${d.name} at ${d.file}:${d.line}`;
        return;
      }
      case 'secruleremovebytag': {
        const m = tagMatcher(d.args[0] || '');
        for (const r of this.items) if (r.kind === 'rule' && r.tags.some(m)) r.removedBy = `${d.name} at ${d.file}:${d.line}`;
        return;
      }
      case 'secruleremovebymsg': {
        const m = tagMatcher(d.args[0] || '');
        for (const r of this.items) if (r.kind === 'rule' && r.msg && m(r.msg)) r.removedBy = `${d.name} at ${d.file}:${d.line}`;
        return;
      }
      case 'secruleupdatetargetbyid':
      case 'secruleupdatetargetbytag':
      case 'secruleupdatetargetbymsg': {
        let select;
        if (dn === 'secruleupdatetargetbyid') {
          const ranges = parseIdRanges(d.args[0]);
          select = (r) => inRanges(r.id, ranges);
        } else if (dn === 'secruleupdatetargetbytag') {
          const m = tagMatcher(d.args[0]);
          select = (r) => r.tags.some(m);
        } else {
          const m = tagMatcher(d.args[0]);
          select = (r) => r.msg && m(r.msg);
        }
        const newTargets = parseVariables(d.args[1] || '').map((v) => {
          const t = compileTarget(v, (msg) => this.warn(d, msg));
          if (d.origin === 'azure' && t.exclude && ARG_SOURCE_EXCLUSION[t.collection]) t.argSource = ARG_SOURCE_EXCLUSION[t.collection];
          return t;
        });
        const replace = d.args[2] ? parseVariables(d.args[2])[0] : null;
        let n = 0;
        for (const r of this.items) {
          if (r.kind !== 'rule' || !select(r) || !r.targets) continue;
          n++;
          if (replace) {
            const idx = r.targets.findIndex((t) => t.collection === replace.collection && (t.key || '') === (replace.key || ''));
            if (idx >= 0) r.targets.splice(idx, 1, ...newTargets);
            else r.targets.push(...newTargets);
          } else r.targets.push(...newTargets);
          (r.updates ||= []).push(`${d.name} ${d.args.join(' ')} (${d.file}:${d.line})`);
        }
        if (!n) this.warn(d, `${d.name} ${d.args[0]}: no matching rule`);
        return;
      }
      case 'secruleupdateactionbyid': {
        const [idSpec] = String(d.args[0]).split(':');
        const ranges = parseIdRanges(idSpec);
        const acts = parseActions(d.args[1] || '');
        for (const r of this.items) {
          if (r.kind !== 'rule' || !inRanges(r.id, ranges)) continue;
          for (const a of acts) this.applyAction(r, a, true);
          (r.updates ||= []).push(`${d.name} ${d.args.join(' ')} (${d.file}:${d.line})`);
        }
        return;
      }
      case 'secrequestbodyaccess':
        this.config.requestBodyAccess = /^on$/i.test(d.args[0]);
        return;
      case 'secrequestbodylimit':
        this.config.requestBodyLimit = atoi(d.args[0]);
        return;
      case 'secrequestbodynofileslimit':
        this.config.requestBodyNoFilesLimit = atoi(d.args[0]);
        return;
      case 'secrequestbodylimitaction':
        this.config.requestBodyLimitAction = d.args[0];
        return;
      case 'secrequestbodyjsondepthlimit':
        this.config.jsonDepthLimit = atoi(d.args[0]);
        return;
      case 'secargumentslimit':
        this.config.argumentsLimit = atoi(d.args[0]);
        return;
      case 'secresponsebodyaccess':
        this.config.responseBodyAccess = /^on$/i.test(d.args[0]);
        return;
      case 'secresponsebodymimetype':
        this.config.responseBodyMimeTypes = d.args.map((s) => s.toLowerCase());
        return;
      case 'secresponsebodymimetypesclear':
        this.config.responseBodyMimeTypes = [];
        return;
      case 'secresponsebodylimit':
        this.config.responseBodyLimit = atoi(d.args[0]);
        return;
      case 'secargumentseparator':
        this.config.argumentSeparator = d.args[0] || '&';
        return;
      case 'secruleengine':
        this.config.ruleEngine = d.args[0];
        return;
      case 'seccomponentsignature':
        this.meta.signature = d.args[0];
        return;
      default:
        // Logging, storage, PCRE limits etc. have no effect on the evaluation here.
        return;
    }
  }

  compileRule(d, isAction) {
    const rule = {
      kind: 'rule',
      directive: isAction ? 'SecAction' : 'SecRule',
      file: d.file,
      line: d.line,
      endLine: d.endLine,
      raw: d.raw,
      origin: d.origin,
      id: null,
      phase: 2,
      tfns: [],
      tfnNames: [],
      tags: [],
      msg: null,
      logdata: null,
      severity: null,
      ver: null,
      rev: null,
      capture: false,
      multiMatch: false,
      chain: false,
      disruptive: null,
      disruptiveValue: null,
      status: null,
      skipAfter: null,
      skip: 0,
      log: true,
      exec: [],
      next: null,
    };
    let actionText;
    if (isAction) {
      actionText = d.args[0] || '';
      rule.targets = null;
      rule.op = { name: 'unconditionalMatch', negated: false, param: '' };
    } else {
      if (d.args.length < 2) throw new Error('SecRule needs at least variables and operator');
      actionText = d.args[2] || '';
      rule.varsText = d.args[0];
      rule.targets = parseVariables(d.args[0]).map((v) => compileTarget(v, (msg) => this.warn(rule, msg)));
      rule.op = parseOperator(d.args[1]);
    }
    rule.actions = parseActions(actionText);
    for (const a of rule.actions) this.applyAction(rule, a, false);
    try {
      rule.opImpl = createOperator(rule.op.name, rule.op.param, { dataFiles: this.dataFiles, warn: (m) => this.warn(rule, m) });
      if (rule.opImpl.unsupported) this.warn(rule, rule.opImpl.unsupported);
    } catch (e) {
      rule.opImpl = { exec: () => null, unsupported: e.message };
      this.warn(rule, `operator @${rule.op.name}: ${e.message}`);
    }
    rule.pl = null;
    for (const t of rule.tags) {
      const m = /^paranoia-level\/(\d)$/.exec(t);
      if (m) rule.pl = +m[1];
    }
    return rule;
  }

  applyAction(rule, a, isUpdate) {
    const name = a.name.toLowerCase();
    const v = a.value;
    switch (name) {
      case 'id':
        rule.id = parseInt(String(v).replace(/'/g, ''), 10);
        return;
      case 'phase':
        rule.phase = parsePhase(v);
        return;
      case 't': {
        const tn = String(v).trim();
        if (tn.toLowerCase() === 'none') {
          rule.tfns = [];
          rule.tfnNames = [];
          return;
        }
        const fn = getTransform(tn);
        if (!fn) {
          this.warn(rule, `unknown transformation t:${tn} (ignored)`);
          return;
        }
        rule.tfns.push(fn);
        rule.tfnNames.push(TRANSFORM_NAMES[tn.toLowerCase()] || tn);
        return;
      }
      case 'msg':
        rule.msg = v;
        return;
      case 'logdata':
        rule.logdata = v;
        return;
      case 'severity':
        rule.severity = parseSeverity(v);
        return;
      case 'tag':
        rule.tags.push(v);
        return;
      case 'ver':
        rule.ver = v;
        return;
      case 'rev':
        rule.rev = v;
        return;
      case 'capture':
        rule.capture = true;
        return;
      case 'multimatch':
        rule.multiMatch = true;
        return;
      case 'chain':
        rule.chain = true;
        return;
      case 'status':
        rule.status = atoi(v);
        return;
      case 'skipafter':
        rule.skipAfter = String(v).replace(/^'|'$/g, '');
        return;
      case 'skip':
        rule.skip = atoi(v);
        return;
      case 'log':
        rule.log = true;
        return;
      case 'nolog':
        rule.log = false;
        return;
      default:
        break;
    }
    if (DISRUPTIVE.has(name)) {
      rule.disruptive = name;
      rule.disruptiveValue = v;
      return;
    }
    if (NON_DISRUPTIVE_EXEC.has(name)) {
      if (isUpdate && name === 'setvar') rule.exec = rule.exec.filter((x) => x.name !== 'setvar');
      rule.exec.push({ name, value: v });
      return;
    }
    if (METADATA.has(name) || FLOW.has(name) || IGNORED.has(name)) return;
    this.warn(rule, `unknown action ${a.name} (ignored)`);
  }

  /** Build per-phase execution lists. Call after all files were added. */
  /** Remove rules matching a predicate (e.g. rules not present in a managed WAF profile). */
  disableRules(predicate, reason) {
    let n = 0;
    for (const it of this.items) {
      if (it.kind === 'rule' && !it.removedBy && predicate(it)) {
        it.removedBy = reason;
        n++;
      }
    }
    this.finalize();
    return n;
  }

  finalize() {
    this.phases = { 1: [], 2: [], 3: [], 4: [], 5: [] };
    for (const it of this.items) {
      if (it.kind === 'marker') {
        for (const p of [1, 2, 3, 4, 5]) this.phases[p].push(it);
      } else if (!it.removedBy) {
        this.phases[it.phase].push(it);
      }
    }
    for (const it of this.items) {
      if (it.kind !== 'rule') continue;
      it.rawFull = it.links.map((l) => l.raw).join('\n');
      it.isMeta = !it.log || it.pl == null && it.severity == null;
    }
    return this;
  }

  /** Evaluate one request. */
  evaluate(request, opts = {}) {
    const t0 = (globalThis.performance || Date).now();
    const tx = new Transaction(request, { ...this.config, ...opts.txConfig });
    const st = {
      tx,
      matches: [],
      interruptions: [],
      removedRanges: [],
      removedTags: [],
      removedTargets: [],
      engineOff: null,
      detectionOnly: /detectiononly/i.test(this.config.ruleEngine || '') && opts.honorDetectionOnly,
      tfnCache: new Map(),
      warnings: new Set(),
      ruleActions: opts.ruleActions || null,
      ruleScores: opts.ruleScores || null,
      continueAfterInterruption: opts.continueAfterInterruption !== false,
      phasesRun: [],
      skipRequestPhases: false,
      allowed: null,
      evaluatedRules: 0,
    };
    const stopped = () => st.engineOff || (st.interruptions.length && !st.continueAfterInterruption);

    for (const phase of [1, 2, 3, 4, 5]) {
      if (phase === 5) {
        // Logging phase always runs (reporting rules); it cannot block.
        if (opts.runLoggingPhase === false) break;
        st.phasesRun.push(5);
        const saved = st.interruptions.length;
        this.runPhase(5, st, true);
        st.interruptions.length = saved;
        break;
      }
      if (stopped()) continue;
      if (phase === 2) {
        this.checkBodyLimits(st);
        tx.processRequestBody();
        this.checkBodyLimitsAfter(st);
        if (stopped()) break;
      }
      if (phase === 3) {
        // A blocked request never reaches the application: there is no response to inspect.
        // (opts.responseAfterBlock emulates SecRuleEngine DetectionOnly, where response rules still run.)
        if (st.interruptions.length && !opts.responseAfterBlock) {
          st.skipResponsePhases = true;
          st.warnings.add('Response rules were not evaluated: the request is already blocked, so the WAF answers instead of the application.');
          continue;
        }
        if (opts.evaluateResponse === false || !tx.setResponse()) {
          st.skipResponsePhases = true;
          continue;
        }
        if (!this.config.responseBodyAccess) tx.set('RESPONSE_BODY', []);
      }
      if ((phase === 1 || phase === 2) && st.skipRequestPhases) continue;
      if ((phase === 3 || phase === 4) && st.skipResponsePhases) continue;
      st.phasesRun.push(phase);
      this.runPhase(phase, st);
    }

    const elapsed = (globalThis.performance || Date).now() - t0;
    return this.buildResult(st, elapsed, request);
  }

  checkBodyLimits(st) {
    const { tx } = st;
    const len = tx.body.length;
    if (!len || !tx.requestBodyAccess) return;
    if (this.config.requestBodyLimit && len > this.config.requestBodyLimit && /reject/i.test(this.config.requestBodyLimitAction)) {
      this.engineInterrupt(st, 2, 413, `Request body (${len} bytes) is larger than SecRequestBodyLimit (${this.config.requestBodyLimit} bytes)`);
    }
  }

  checkBodyLimitsAfter(st) {
    const { tx } = st;
    const len = tx.body.length;
    if (!len || !tx.requestBodyAccess) return;
    const noFiles = len - (tx.multipartFilesSize || 0);
    if (this.config.requestBodyNoFilesLimit && noFiles > this.config.requestBodyNoFilesLimit && /reject/i.test(this.config.requestBodyLimitAction)) {
      this.engineInterrupt(st, 2, 413, `Request body without files (${noFiles} bytes) is larger than SecRequestBodyNoFilesLimit (${this.config.requestBodyNoFilesLimit} bytes)`);
    }
    if (this.config.argumentsLimit && tx.collection('ARGS').length > this.config.argumentsLimit) {
      st.warnings.add(`More than SecArgumentsLimit (${this.config.argumentsLimit}) arguments; ModSecurity stops parsing further arguments.`);
    }
  }

  engineInterrupt(st, phase, status, msg) {
    const record = {
      rule: { id: 'ENGINE', phase, file: 'ModSecurity engine', line: 0, msg, tags: ['engine-limit'], severity: 2, pl: null, links: [], rawFull: '' },
      links: [],
      scores: [],
      msg,
      logdata: '',
      disruptive: 'deny',
      status,
      phase,
    };
    st.matches.push(record);
    st.interruptions.push(record);
  }

  runPhase(phase, st, force = false) {
    const list = this.phases[phase];
    for (let i = 0; i < list.length; i++) {
      if (st.engineOff && !force) return;
      if (!force && st.interruptions.length && !st.continueAfterInterruption) return;
      const rule = list[i];
      if (rule.kind === 'marker') continue;
      if (this.isRemoved(rule, st)) continue;
      st.evaluatedRules++;
      const res = this.execRule(rule, st, phase);
      if (!res) continue;
      if (res.allow) {
        if (res.allow === 'phase') return;
        if (res.allow === 'request') {
          if (phase <= 2) st.skipRequestPhases = true;
          return;
        }
        // full allow
        st.skipRequestPhases = true;
        st.engineOff = st.engineOff || { reason: `allow by rule ${rule.id}` };
        return;
      }
      if (rule.skipAfter) {
        let j = i + 1;
        while (j < list.length && !(list[j].kind === 'marker' && list[j].name === rule.skipAfter)) j++;
        i = j; // continue after the marker (or end of list)
      } else if (rule.skip > 0) {
        let n = rule.skip;
        while (n > 0 && i + 1 < list.length) {
          i++;
          if (list[i].kind === 'rule') n--;
        }
      }
    }
  }

  isRemoved(rule, st) {
    if (st.removedRanges.length && inRanges(rule.id, st.removedRanges)) return true;
    if (st.removedTags.length && rule.tags.some((t) => st.removedTags.some((m) => m(t)))) return true;
    return false;
  }

  /** Evaluate a rule (with its chain). Returns null when it did not match. */
  execRule(rule, st, phase) {
    const { tx } = st;
    tx.currentRule = rule;
    tx.matchedVars = [];
    const record = { rule, links: [], scores: [], phase, matchCount: 0 };
    const override = st.ruleActions?.get(rule.id);
    if (override) record.override = override;
    for (const link of rule.links) {
      const lres = this.evalLink(link, st, record);
      record.links.push(lres);
      if (!lres.matched) return null;
    }
    // Whole chain matched.
    record.msg = rule.msg != null ? tx.expand(rule.msg) : null;
    record.logdata = rule.logdata != null ? tx.expand(rule.logdata) : null;
    let disruptive = rule.disruptive;
    if (disruptive === 'block' || !disruptive) {
      const def = this.defaultActions[phase]?.disruptive || 'pass';
      record.blockResolvedTo = disruptive === 'block' ? def : null;
      disruptive = disruptive === 'block' ? def : 'pass';
    }
    record.disruptive = disruptive;
    record.status = rule.status || (disruptive === 'deny' ? 403 : null);
    if (rule.log && rule.severity != null) {
      const hs = atoi(tx.collection('HIGHEST_SEVERITY')[0].value);
      if (rule.severity < hs) tx.scalar('HIGHEST_SEVERITY', String(rule.severity));
    }
    st.matches.push(record);
    if (record.override === 'block' || record.override === 'redirect') {
      record.disruptive = 'deny';
      record.status = 403;
      record.msg = `${record.msg || rule.msg || ''} [rule action override: ${record.override}]`.trim();
      st.interruptions.push(record);
      return { matched: true };
    }
    if (record.override === 'allow') {
      st.engineOff = { reason: `Allowed by rule ${rule.id} (rule action override: allow)` };
      st.skipRequestPhases = true;
      return { allow: 'all' };
    }
    if (record.override === 'log') {
      // Log only: the rule is reported, but neither interrupts (even a hard deny/allow) nor scores.
      if (disruptive !== 'pass') record.overriddenDisruptive = disruptive;
      record.disruptive = 'pass';
      record.status = null;
      return { matched: true };
    }
    if (['deny', 'drop', 'redirect', 'proxy'].includes(disruptive)) {
      if (!st.detectionOnly) st.interruptions.push(record);
      else record.detectionOnly = true;
    }
    if (disruptive === 'allow') {
      const v = (rule.disruptiveValue || '').toLowerCase();
      return { allow: v === 'phase' ? 'phase' : v === 'request' ? 'request' : 'all' };
    }
    return { matched: true };
  }

  applyTfns(value, link, st) {
    if (!link.tfns.length) return value;
    const key = link.tfnNames.join(',');
    let cache = st.tfnCache.get(key);
    if (!cache) st.tfnCache.set(key, (cache = new Map()));
    let v = cache.get(value);
    if (v === undefined) {
      v = value;
      for (const fn of link.tfns) v = fn(v);
      cache.set(value, v);
    }
    return v;
  }

  resolveTargets(link, st) {
    const { tx } = st;
    const out = [];
    const excludes = link.targets.filter((t) => t.exclude);
    const runtimeEx = st.removedTargets.filter((r) => r.matches(link.starter));
    for (const t of link.targets) {
      if (t.exclude) continue;
      const entries = tx.collection(t.collection);
      if (!entries) continue;
      let sel = entries;
      if (t.keyLower !== null) sel = entries.filter((e) => asciiLower(e.name) === t.keyLower);
      else if (t.keyRegex !== null) sel = t.re ? entries.filter((e) => t.re.test(e.name)) : [];
      if (excludes.length || runtimeEx.length) {
        sel = sel.filter((e) => {
          for (const x of excludes) if (targetMatchesEntry(x, t.collection, e.name, e)) return false;
          for (const r of runtimeEx) if (targetMatchesEntry(r.target, t.collection, e.name, e)) return false;
          return true;
        });
      }
      if (t.count) {
        out.push({ name: '&' + t.raw.replace(/^[!&]+/, ''), value: String(sel.length), collection: t.collection, isCount: true });
        continue;
      }
      for (const e of sel) out.push({ name: e.name !== '' ? `${t.collection}:${e.name}` : t.collection, value: e.value, collection: t.collection, key: e.name });
    }
    return out;
  }

  evalLink(link, st, record) {
    const { tx } = st;
    const lres = { link, matched: false, matches: [], checked: 0 };
    if (link.opImpl.unsupported) {
      // Reported once in the rule set info (Settings), not on every request.
      lres.unsupported = link.opImpl.unsupported;
      return lres;
    }
    const targets = link.targets === null ? [{ name: '', value: '', collection: null }] : this.resolveTargets(link, st);
    lres.checked = targets.length;
    for (const t of targets) {
      let r = null;
      let v;
      let hit = false;
      try {
        if (link.multiMatch && link.tfns.length) {
          v = t.value;
          const stages = [v];
          for (const fn of link.tfns) stages.push((v = fn(v)));
          for (const s of stages) {
            r = link.opImpl.exec(s, tx);
            hit = link.op.negated ? !r : !!r;
            if (hit) {
              v = s;
              break;
            }
          }
        } else {
          v = this.applyTfns(t.value, link, st);
          r = link.opImpl.exec(v, tx);
          hit = link.op.negated ? !r : !!r;
        }
      } catch (e) {
        st.warnings.add(`Rule ${link.starter.id}: ${e.message}`);
        continue;
      }
      if (!hit) continue;
      const m = {
        var: t.name,
        collection: t.collection,
        key: t.key,
        value: t.value,
        transformed: v,
        matched: r ? r.matched : null,
        index: r ? r.index : -1,
        detail: r?.detail || null,
        captures: link.capture && r?.captures ? r.captures : null,
      };
      tx.matchedVar = { name: t.name, value: v };
      tx.matchedVars.push({ name: t.name, value: v });
      if (link.capture && r?.captures) {
        for (let k = 0; k < 10; k++) {
          if (k < r.captures.length) tx.setTx(String(k), r.captures[k]);
          else tx.delTx(String(k));
        }
      }
      // Non-disruptive actions run for every match (ModSecurity v2 semantics).
      for (const a of link.exec) this.execAction(a, st, record, link);
      if (!link.chain) {
        if (link.starter.logdata != null) m.logdata = tx.expand(link.starter.logdata);
      }
      lres.matches.push(m);
      record.matchCount++;
    }
    lres.matched = lres.matches.length > 0;
    return lres;
  }

  execAction(a, st, record, link) {
    const { tx } = st;
    switch (a.name) {
      case 'setvar':
        this.execSetvar(a.value, st, record);
        return;
      case 'ctl':
        this.execCtl(a.value, st, record, link);
        return;
      default:
        return; // initcol, setenv, expirevar... have no observable effect here
    }
  }

  execSetvar(spec, st, record) {
    const { tx } = st;
    let s = String(spec).trim();
    let del = false;
    if (s.startsWith('!')) {
      del = true;
      s = s.slice(1);
    }
    const eq = s.indexOf('=');
    const lhs = eq >= 0 ? s.slice(0, eq) : s;
    let rhs = eq >= 0 ? s.slice(eq + 1) : '1';
    const dot = lhs.indexOf('.');
    const coll = (dot >= 0 ? lhs.slice(0, dot) : 'tx').toUpperCase();
    const name = tx.expand(dot >= 0 ? lhs.slice(dot + 1) : lhs);
    rhs = tx.expand(rhs);
    if (coll !== 'TX') {
      const map = tx.otherCollections[coll];
      if (!map) return;
      if (del) map.delete(asciiLower(name));
      else map.set(asciiLower(name), { name, value: rhs });
      return;
    }
    if (del) {
      tx.delTx(name);
      return;
    }
    if (rhs.startsWith('+') || rhs.startsWith('-')) {
      let delta = atoi(rhs);
      const ln = asciiLower(name);
      const m = /^(?:inbound_)?anomaly_score_pl([1-4])$/.exec(ln) || /^outbound_anomaly_score_pl([1-4])$/.exec(ln);
      if (m && delta > 0) {
        const id = record.rule?.id;
        // Profile overrides (e.g. Azure DRS): own severity scores; non-scoring rule actions.
        if (st.ruleScores?.has(id)) delta = st.ruleScores.get(id);
        if (record.override && record.override !== 'anomalyscoring') {
          record.scores.push({ dir: ln.startsWith('outbound') ? 'outbound' : 'inbound', pl: +m[1], delta, var: name, suppressed: true });
          return;
        }
      }
      const old = atoi(tx.getTx(name) ?? '0');
      tx.setTx(name, String(old + delta));
      if (m) record.scores.push({ dir: ln.startsWith('outbound') ? 'outbound' : 'inbound', pl: +m[1], delta, var: name });
      return;
    }
    tx.setTx(name, rhs);
  }

  execCtl(spec, st, record, link) {
    const { tx } = st;
    const s = tx.expand(String(spec));
    const eq = s.indexOf('=');
    const name = (eq >= 0 ? s.slice(0, eq) : s).trim().toLowerCase();
    const value = eq >= 0 ? s.slice(eq + 1).trim() : '';
    (record.ctl ||= []).push(s);
    switch (name) {
      case 'ruleremovebyid':
        st.removedRanges.push(...parseIdRanges(value));
        return;
      case 'ruleremovebytag':
        st.removedTags.push(tagMatcher(value));
        return;
      case 'ruleremovetargetbyid':
      case 'ruleremovetargetbytag':
      case 'ruleremovetargetbymsg': {
        const semi = value.indexOf(';');
        if (semi < 0) return;
        const sel = value.slice(0, semi);
        const target = compileTarget(parseVariables(value.slice(semi + 1))[0] || { collection: '', key: null, keyRegex: null }, () => {});
        let matches;
        if (name === 'ruleremovetargetbyid') {
          const ranges = parseIdRanges(sel);
          matches = (r) => inRanges(r.id, ranges);
        } else if (name === 'ruleremovetargetbytag') {
          const m = tagMatcher(sel, 'exact');
          matches = (r) => r.tags.some(m);
        } else {
          const m = tagMatcher(sel, 'exact');
          matches = (r) => !!r.msg && m(r.msg);
        }
        st.removedTargets.push({ matches, target, spec: value });
        return;
      }
      case 'ruleengine':
        if (/^off$/i.test(value)) st.engineOff = { reason: `ctl:ruleEngine=Off by rule ${link.starter.id}` };
        else if (/^detectiononly$/i.test(value)) st.detectionOnly = true;
        return;
      case 'requestbodyprocessor':
        tx.reqbodyProcessor = value.toUpperCase();
        return;
      case 'forcerequestbodyvariable':
        tx.forceRequestBodyVariable = /^on$/i.test(value);
        return;
      case 'requestbodyaccess':
        tx.requestBodyAccess = /^on$/i.test(value);
        return;
      case 'requestbodylimit':
        return;
      default:
        return; // auditEngine, auditLogParts, debugLogLevel, ...
    }
  }

  buildResult(st, elapsed, request) {
    const { tx } = st;
    const inbound = { 1: 0, 2: 0, 3: 0, 4: 0 };
    const outbound = { 1: 0, 2: 0, 3: 0, 4: 0 };
    for (const m of st.matches) for (const s of m.scores) if (!s.suppressed) (s.dir === 'inbound' ? inbound : outbound)[s.pl] += s.delta;
    const num = (n) => atoi(tx.getTx(n) ?? '0');
    const crs4 = tx.getTx('blocking_paranoia_level') !== undefined;
    const blockingPL = crs4 ? num('blocking_paranoia_level') : num('paranoia_level') || 1;
    const detectionPL = crs4 ? num('detection_paranoia_level') : num('executing_paranoia_level') || blockingPL;
    const inThreshold = num('inbound_anomaly_score_threshold') || 5;
    const outThreshold = num('outbound_anomaly_score_threshold') || 4;
    const cumulative = (scores) => {
      const res = {};
      let sum = 0;
      for (const pl of [1, 2, 3, 4]) {
        sum += scores[pl];
        res[pl] = sum;
      }
      return res;
    };
    const first = st.interruptions[0] || null;
    return {
      blocked: !!first,
      interruption: first ? summarizeInterruption(first) : null,
      interruptions: st.interruptions.map(summarizeInterruption),
      engineOff: st.engineOff ? st.engineOff.reason : null,
      paranoia: { blocking: blockingPL, detection: detectionPL },
      inbound: { byPL: inbound, cumulative: cumulative(inbound), threshold: inThreshold, score: cumulative(inbound)[blockingPL] },
      outbound: { byPL: outbound, cumulative: cumulative(outbound), threshold: outThreshold, score: cumulative(outbound)[blockingPL] },
      matches: st.matches.map((m) => summarizeMatch(m)),
      phasesRun: st.phasesRun,
      responseInspected: tx.response ? { body: !!tx.responseBodyInspected, reason: tx.responseBodySkipReason || null } : null,
      bodyProcessor: tx.reqbodyProcessor || null,
      bodyNotes: tx.bodyNotes,
      warnings: [...st.warnings],
      variables: snapshotVariables(tx),
      evaluatedRules: st.evaluatedRules,
      elapsedMs: Math.round(elapsed * 10) / 10,
    };
  }
}

function summarizeInterruption(m) {
  return { ruleId: m.rule.id, action: m.disruptive, status: m.status, phase: m.phase, msg: m.msg };
}

const MAX_VALUE = 4000;

function snippet(bin, index, matchLen) {
  // Returns { before, match, after, truncated } around the match (display strings).
  if (index == null || index < 0) {
    return { before: displayBinary(bin, MAX_VALUE), match: '', after: '', truncated: bin.length > MAX_VALUE };
  }
  const start = Math.max(0, index - 300);
  const end = Math.min(bin.length, index + matchLen + 300);
  return {
    before: (start > 0 ? '…' : '') + displayBinary(bin.slice(start, index)),
    match: displayBinary(bin.slice(index, index + matchLen), 2000),
    after: displayBinary(bin.slice(index + matchLen, end)) + (end < bin.length ? '…' : ''),
    truncated: start > 0 || end < bin.length,
  };
}

function summarizeMatch(m) {
  const r = m.rule;
  return {
    id: r.id,
    file: r.file,
    line: r.line,
    phase: m.phase,
    msg: m.msg ?? r.msg ?? null,
    logdata: m.logdata ? displayBinary(m.logdata, 1000) : null,
    severity: r.severity != null ? SEVERITIES[r.severity] : null,
    pl: r.pl ?? (m.scores[0]?.pl ?? null),
    tags: r.tags,
    ver: r.ver,
    log: r.log !== false,
    isMeta: !!r.isMeta,
    disruptive: m.disruptive,
    blockResolvedTo: m.blockResolvedTo ?? null,
    status: m.status ?? null,
    detectionOnly: !!m.detectionOnly,
    scores: m.scores.filter((x) => !x.suppressed),
    suppressedScores: m.scores.filter((x) => x.suppressed),
    override: m.override || null,
    overriddenDisruptive: m.overriddenDisruptive || null,
    ctl: m.ctl || null,
    raw: r.rawFull,
    origin: r.origin,
    links: m.links.map((l) => ({
      vars: l.link.varsText ?? null,
      op: l.link.op ? { name: l.link.op.name, negated: l.link.op.negated, param: displayBinary(l.link.op.param, 600), paramLength: l.link.op.param.length } : null,
      tfns: l.link.tfnNames,
      checked: l.checked,
      unsupported: l.unsupported || null,
      matches: l.matches.slice(0, 50).map((x) => ({
        var: displayBinary(x.var, 300),
        collection: x.collection,
        key: x.key != null ? displayBinary(x.key, 300) : null,
        value: displayBinary(x.value, MAX_VALUE),
        valueLength: x.value.length,
        transformedDiffers: x.transformed !== x.value,
        transformed: snippet(x.transformed, x.matched != null ? x.index : -1, x.matched != null ? x.matched.length : 0),
        matched: x.matched != null ? displayBinary(x.matched, 500) : null,
        detail: x.detail,
        captures: x.captures ? x.captures.map((c) => displayBinary(c, 300)) : null,
        logdata: x.logdata ? displayBinary(x.logdata, 1000) : null,
      })),
      moreMatches: Math.max(0, l.matches.length - 50),
    })),
  };
}

function snapshotVariables(tx) {
  const pick = (name) => (tx.collection(name) || []).map((e) => ({ name: displayBinary(e.name, 300), value: displayBinary(e.value, 2000), length: e.value.length }));
  const scalar = (name) => displayBinary(tx.collection(name)?.[0]?.value ?? '', 2000);
  return {
    REQUEST_LINE: scalar('REQUEST_LINE'),
    REQUEST_METHOD: scalar('REQUEST_METHOD'),
    REQUEST_PROTOCOL: scalar('REQUEST_PROTOCOL'),
    REQUEST_FILENAME: scalar('REQUEST_FILENAME'),
    REQUEST_BASENAME: scalar('REQUEST_BASENAME'),
    QUERY_STRING: scalar('QUERY_STRING'),
    REQBODY_PROCESSOR: scalar('REQBODY_PROCESSOR'),
    REQBODY_ERROR_MSG: scalar('REQBODY_ERROR_MSG'),
    ARGS_GET: pick('ARGS_GET'),
    ARGS_POST: pick('ARGS_POST'),
    REQUEST_HEADERS: pick('REQUEST_HEADERS'),
    REQUEST_COOKIES: pick('REQUEST_COOKIES'),
    FILES: pick('FILES'),
    XML: pick('XML'),
    REQUEST_BODY_LENGTH: scalar('REQUEST_BODY_LENGTH'),
    RESPONSE_STATUS: tx.response ? scalar('RESPONSE_STATUS') : null,
  };
}
