// Azure WAF simulation: turns a parsed Azure WAF policy into an engine profile (rules that exist
// in the policy's Default Rule Set, overrides, exclusions, scores) and combines custom-rule and
// managed-rule results into an Azure verdict.

import { DRS } from './drs-data.js';
import { parseAzurePolicy, summarizePolicy } from './policy.js';
import { evaluateCustomRules } from './custom-rules.js';
import { loadRuleSet } from '../engine/loader.js';
import { utf8ToBinary } from '../engine/bytes.js';

export const AZURE_BASE_CRS = 'v3.3.10'; // DRS 2.x is baselined on OWASP CRS 3.3.x
// 200000/200001 only select the body processor (not detections): never exclude targets from them.
const ALL_MANAGED = '200002-200999,911000-944999';

const escRe = (s) => String(s).replace(/[\\^$.|?*+()[\]{}/]/g, '\\$&').replace(/"/g, '\\x22');

// Collections excluded per Azure match variable family and side (value / key).
// Query-string and body variants use ARGS_GET / ARGS_POST(_NAMES); in the Azure profile file
// (origin 'azure') the engine also applies them to the matching-source entries of ARGS / ARGS_NAMES.
const EXCLUSION_COLLECTIONS = {
  requestheader: { values: ['REQUEST_HEADERS'], keys: ['REQUEST_HEADERS_NAMES'] },
  requestcookie: { values: ['REQUEST_COOKIES'], keys: ['REQUEST_COOKIES_NAMES'] },
  requestarg: { values: ['ARGS', 'ARGS_GET', 'ARGS_POST'], keys: ['ARGS_NAMES', 'ARGS_GET_NAMES', 'ARGS_POST_NAMES'] },
  querystringarg: { values: ['ARGS_GET'], keys: ['ARGS_GET_NAMES'] },
  requestbodypostarg: { values: ['ARGS_POST'], keys: ['ARGS_POST_NAMES'] },
  requestbodyjsonarg: { values: ['ARGS_POST'], keys: ['ARGS_POST_NAMES'] },
};

/**
 * Map an Azure exclusion to ModSecurity negative targets.
 *
 * Semantics (Microsoft Learn, "WAF exclusion lists" for Front Door and Application Gateway):
 *  - Front Door *Names (RequestHeaderNames, RequestCookieNames, QueryStringArgNames,
 *    RequestBodyPostArgNames, RequestBodyJsonArgNames): the *values* of the named fields are not
 *    evaluated, "however, the field names are still evaluated".
 *  - Application Gateway *Keys: the names (keys) only; *Values and the legacy *Names: values only.
 *  - Front Door: header/cookie names are case-insensitive, query/POST/JSON names case-sensitive.
 *    Application Gateway CRS 3.2+ / DRS: only header names are case-insensitive (CRS <= 3.1: all).
 * @param {{variable: string, operator?: string, selector?: string}} ex
 * @param {{caseSensitive?: boolean}} [opts]
 */
export function exclusionTargets(ex, opts = {}) {
  const v = String(ex.variable).toLowerCase();
  const m = /^(requestheader|requestcookie|requestarg|querystringarg|requestbodypostarg|requestbodyjsonarg)(names|keys|values)$/.exec(v);
  if (!m) return null;
  const family = m[1];
  const side = m[2] === 'keys' ? 'keys' : 'values';
  const op = String(ex.operator || 'Equals').toLowerCase();
  const sel = String(ex.selector ?? '');
  let key;
  if (op === 'equalsany' || (!sel && op !== 'equals')) key = null;
  else if (family === 'requestbodyjsonarg') {
    // JSON args are named json.a.b, array elements json.a.0.b: allow indices between segments.
    const p = sel.split('.').map(escRe).join('(?:\\.\\d+)*\\.');
    key = op === 'equals' ? `^json\\.(?:\\d+\\.)*${p}(?:\\.\\d+)*$` : op === 'startswith' ? `^json\\.(?:\\d+\\.)*${p}` : op === 'endswith' ? `${p}(?:\\.\\d+)*$` : `^json\\..*${escRe(sel)}`;
  } else {
    const s = escRe(sel);
    // Application Gateway RequestArg* also covers JSON body fields (named json.<field> here).
    const pre = family === 'requestarg' ? '(?:json\\.)?' : '';
    key = op === 'equals' ? `^${pre}${s}$` : op === 'startswith' ? `^${pre}${s}` : op === 'endswith' ? `${s}$` : s;
  }
  if (key !== null && opts.caseSensitive) key = '(?-i)' + key;
  return EXCLUSION_COLLECTIONS[family][side].map((c) => (key === null ? `!${c}` : `!${c}:/${key}/`)).join('|');
}

// Rule groups -> rule id ranges (DRS names and CRS file-style names, e.g. REQUEST-941-APPLICATION-ATTACK-XSS).
const DRS_GROUP_RANGES = {
  GENERAL: '200002-200999',
  'METHOD-ENFORCEMENT': '911000-911999',
  'PROTOCOL-ENFORCEMENT': '920000-920999',
  'PROTOCOL-ATTACK': '921000-921999',
  LFI: '930000-930999',
  RFI: '931000-931999',
  RCE: '932000-932999',
  PHP: '933000-933999',
  NODEJS: '934000-934999',
  XSS: '941000-941999',
  SQLI: '942000-942999',
  FIX: '943000-943999',
  JAVA: '944000-944999',
};
export function groupIdRange(name) {
  const n = String(name || '').trim().toUpperCase();
  const m = /^(?:REQUEST|RESPONSE)-(\d{3})-/.exec(n);
  if (m) return `${m[1]}000-${m[1]}999`;
  return DRS_GROUP_RANGES[n] || null;
}

function drsVersionFor(set) {
  if (!set) return null;
  if (/owasp/i.test(set.type)) return 'owasp';
  const v = String(set.version);
  return DRS[v] ? v : '2.1';
}

/**
 * Build the engine profile for a policy.
 * @returns {object} profile
 */
export function azureProfile(policy) {
  const notes = [];
  const set = policy?.managedRuleSets.find((s) => /defaultruleset|owasp/i.test(s.type)) || null;
  const ver = drsVersionFor(set);
  const drs = ver && ver !== 'owasp' ? DRS[ver] : null;
  const anomaly = !drs || Number(ver) >= 2; // DRS < 2.0 blocks on the first matching rule
  const enabled = new Set();
  const groupIds = new Map();
  if (drs) {
    for (const [id, r] of Object.entries(drs.rules)) {
      if (!groupIds.has(r.group)) groupIds.set(r.group, []);
      groupIds.get(r.group).push(Number(id));
      enabled.add(Number(id));
    }
    for (const id of drs.defaultDisabled) enabled.delete(id);
  }
  const ruleActions = new Map();
  const ruleScores = new Map();
  if (drs && anomaly) for (const [id, r] of Object.entries(drs.rules)) if (r.score) ruleScores.set(Number(id), r.score);
  const forced = { enabled: new Set(), disabled: new Set() };
  const exclusionLines = [];
  let exclusionCount = 0;
  // Case sensitivity of exclusion selectors (see exclusionTargets).
  const legacyAppGw = policy?.kind === 'appgw' && ver === 'owasp' && /^(?:[0-2]\.|3\.[01]$)/.test(String(set?.version || ''));
  const caseSensitiveFor = (variable) => !legacyAppGw && !/^requestheader/i.test(variable);
  const addExclusion = (ids, ex, scope) => {
    const t = exclusionTargets(ex, { caseSensitive: caseSensitiveFor(ex.variable) });
    if (!t) {
      notes.push(`Exclusion on ${ex.variable} (${scope}) is not supported by the simulator.`);
      return;
    }
    exclusionLines.push(`# ${scope}: ${ex.variable} ${ex.operator} "${String(ex.selector).replace(/\n/g, ' ')}"`);
    exclusionLines.push(`SecRuleUpdateTargetById ${ids} "${t}"`);
    exclusionCount++;
  };
  // Rule ids of a rule group: the DRS group's rules when known, else the id range of the group.
  const groupSpec = (name) => {
    if (drs) {
      const key = [...groupIds.keys()].find((k) => k.toLowerCase() === String(name).toLowerCase());
      if (key && groupIds.get(key).length) return groupIds.get(key).join(',');
    }
    return groupIdRange(name);
  };
  const skipScoped = (ex, what) => notes.push(`Exclusion on ${ex.variable} ${ex.operator} "${ex.selector}" is scoped to ${what}, which the simulator cannot map to CRS rules – it is not applied.`);
  if (set) {
    for (const g of set.overrides) {
      for (const r of g.rules) {
        if (r.enabled) {
          enabled.add(r.id);
          forced.enabled.add(r.id);
        } else {
          enabled.delete(r.id);
          forced.disabled.add(r.id);
        }
        const a = String(r.action || '').toLowerCase();
        if (a && a !== 'anomalyscoring') ruleActions.set(r.id, a);
        for (const ex of r.exclusions) addExclusion(String(r.id), ex, `rule ${r.id}`);
      }
      if (!g.exclusions.length) continue;
      const spec = groupSpec(g.group);
      for (const ex of g.exclusions) {
        if (spec) addExclusion(spec, ex, `group ${g.group}`);
        else skipScoped(ex, `rule group “${g.group}”`);
      }
    }
    for (const ex of set.exclusions) addExclusion(ALL_MANAGED, ex, `rule set ${set.type} ${set.version}`);
  }
  for (const ex of policy?.exclusions || []) {
    if (ex.scope && ex.scope.length) {
      const specs = [];
      for (const s of ex.scope) {
        if (s.type && !/defaultruleset|owasp/i.test(s.type)) {
          skipScoped(ex, `rule set ${s.type} ${s.version || ''}`.trim());
          continue;
        }
        if (!s.groups.length) {
          specs.push(ALL_MANAGED);
          continue;
        }
        for (const g of s.groups) {
          if (g.rules.length) specs.push(...g.rules);
          else {
            const spec = groupSpec(g.group);
            if (spec) specs.push(spec);
            else skipScoped(ex, `rule group “${g.group}”`);
          }
        }
      }
      if (specs.length) addExclusion([...new Set(specs)].join(','), ex, 'policy (scoped)');
    } else addExclusion(ALL_MANAGED, ex, 'policy');
  }
  if (!anomaly && drs) for (const id of enabled) if (!ruleActions.has(id)) ruleActions.set(id, 'block');
  // Request body errors (200002 / 200003) are hard denies in modsecurity.conf-recommended, but
  // anomaly-scoring "Critical" (5) rules in DRS 2.x / App Gateway CRS 3.x.
  const updateLines = [];
  if (set && anomaly) {
    for (const id of [200002, 200003]) updateLines.push(`SecRuleUpdateActionById ${id} "pass,setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"`);
  }

  const before = ['# Azure WAF profile (generated from the imported policy)'];
  // Azure does not reject large bodies like ModSecurity's SecRequestBodyNoFilesLimit.
  before.push('SecRequestBodyNoFilesLimit 0', 'SecRequestBodyLimit 0');
  if (policy && !policy.requestBodyCheck) before.push('SecRequestBodyAccess Off');
  // Azure has no allowed-methods setting; 911100 uses the CRS 3.3 default list.

  const msticRules = drs ? Object.keys(drs.rules).map(Number).filter((id) => id >= 99000000 && enabled.has(id)) : [];
  if (msticRules.length) notes.push(`${msticRules.length} Microsoft Threat Intelligence rules (99xxxxxx) are enabled in Azure but not public – they cannot be simulated.`);
  if (ver === 'owasp') notes.push(`Application Gateway ${set.type} ${set.version} is approximated with OWASP CRS 3.3 (PL1 + PL2 rules).`);
  if (policy && !set) notes.push('The policy has no Default Rule Set: managed rules are disabled, only custom rules apply.');

  return {
    drsVersion: ver,
    managedRules: !!set,
    ruleSet: set ? `${set.type} ${set.version}` : null,
    ruleSetAction: set ? set.action || (anomaly ? 'Block' : null) : null,
    anomaly,
    enabled,
    forced,
    ruleActions,
    ruleScores,
    seclangBefore: before.join('\n') + '\n',
    seclangAfter: [...updateLines, ...exclusionLines].join('\n') + '\n',
    exclusionCount,
    notes,
    msticRules,
  };
}

/**
 * Load the CRS rule set configured as the policy's managed rules.
 * @returns {Promise<{rs, policy, profile, info}>}
 */
export async function loadAzureRuleSet({ readText, index, settings }) {
  const { policy, errors, warnings } = parseAzurePolicy(settings.azurePolicy || '');
  const profile = azureProfile(policy);
  const hasBase = index.rulesets.some((r) => r.version === AZURE_BASE_CRS);
  const version = hasBase ? AZURE_BASE_CRS : index.rulesets.find((r) => /^v3\./.test(r.version))?.version || index.default;
  const drs = profile.drsVersion && profile.drsVersion !== 'owasp' ? DRS[profile.drsVersion] : null;
  // With a DRS every managed rule that is not enabled in the policy is removed below, so run at
  // PL4: DRS rules that are PL3/PL4 in CRS 3.3 (e.g. 942460 in DRS 2.0) are evaluated too.
  // Application Gateway OWASP rule sets are approximated with CRS PL1 + PL2.
  const pl = drs ? 4 : 2;
  const rs = await loadRuleSet({
    readText,
    index,
    settings: {
      ...settings,
      version,
      blockingParanoiaLevel: pl,
      detectionParanoiaLevel: pl,
      inboundThreshold: 5,
      evaluateResponses: false,
      includeModsecRecommended: true,
      customRulesBefore: profile.seclangBefore + (settings.customRulesBefore || ''),
      customRulesAfter: settings.customRulesAfter || '',
    },
  });
  // Profile overrides / exclusions get their own origin: the engine scopes ARGS_GET / ARGS_POST
  // exclusions to query-string / body arguments only for this origin.
  if (profile.seclangAfter.trim()) rs.addFile('azure-waf-profile.conf', utf8ToBinary(profile.seclangAfter), { origin: 'azure' });
  // Keep only managed rules that exist (and are enabled) in the policy's rule set.
  const removed = [];
  const noManaged = !!policy && !profile.managedRules;
  rs.disableRules((r) => {
    const id = Number(r.id);
    if (!Number.isFinite(id)) return false;
    let off;
    if (noManaged) {
      // No Default Rule Set in the policy: Azure evaluates custom rules only.
      off = r.origin === 'crs' || (r.origin === 'modsecurity' && id >= 200002);
    } else {
      const managed = (id >= 911000 && id <= 944999 && r.severity != null) || [200004, 200005, 200007].includes(id);
      if (!managed && !(id >= 200002 && id <= 200003)) return false;
      if (drs) off = !profile.enabled.has(id);
      else off = profile.forced.disabled.has(id) || (r.pl != null && r.pl > 2);
    }
    if (off) removed.push(id);
    return off;
  }, noManaged ? 'The Azure WAF policy has no managed rule set (Default Rule Set)' : drs ? `Not active in Azure DRS ${profile.drsVersion} for this policy` : 'Disabled in the Azure WAF policy');
  const crsIds = new Set(rs.items.filter((r) => r.kind === 'rule').map((r) => Number(r.id)));
  const notInCrs = drs ? [...profile.enabled].filter((id) => id < 99000000 && !crsIds.has(id)) : [];
  if (notInCrs.length) profile.notes.push(`${notInCrs.length} DRS rules have no CRS ${version} equivalent and are not simulated: ${notInCrs.slice(0, 12).join(', ')}${notInCrs.length > 12 ? ', …' : ''}.`);
  const info = {
    summary: summarizePolicy(policy),
    errors,
    warnings: [...warnings, ...profile.notes],
    baseCrs: version,
    activeManagedRules: drs ? [...profile.enabled].filter((id) => crsIds.has(id)).length : null,
    removedRules: removed.length,
    exclusions: profile.exclusionCount,
    overrides: profile.ruleActions.size + profile.forced.disabled.size + profile.forced.enabled.size,
  };
  return { rs, policy, profile, info };
}

/**
 * Evaluate a request like Azure WAF would.
 */
export function evaluateAzure(ctx, req, settings) {
  const { rs, policy, profile } = ctx;
  const custom = policy ? evaluateCustomRules(policy, req, { clientIp: settings.clientIp || '', country: settings.clientCountry }) : { rules: [], decision: null, logged: [] };
  const res = rs.evaluate(req, {
    continueAfterInterruption: true,
    evaluateResponse: false,
    ruleActions: profile.ruleActions,
    ruleScores: profile.ruleScores,
    txConfig: { remoteAddr: settings.remoteAddr },
  });
  const prevention = !!policy && policy.mode === 'Prevention';
  const active = !!policy && policy.enabled;
  const az = {
    policyName: policy?.name || null,
    kind: policy?.kind || null,
    mode: policy?.mode || null,
    enabled: active,
    ruleSet: profile.ruleSet,
    ruleSetAction: profile.ruleSetAction,
    customRules: custom.rules,
    customLogged: custom.logged,
    decidedBy: null,
    action: 'allow',
    wouldBlock: false,
    managedSkipped: false,
    managedScore: res.inbound.score,
    threshold: 5,
    status: policy?.customBlockResponseStatusCode || 403,
  };
  const managedInterruption = res.interruption;
  if (!active) {
    az.decidedBy = { type: 'policy', reason: 'Policy is disabled' };
  } else if (custom.decision) {
    const a = custom.decision.action.toLowerCase();
    az.decidedBy = { type: 'custom', name: custom.decision.name, priority: custom.decision.priority, action: custom.decision.action };
    az.managedSkipped = true;
    az.action = a;
    az.wouldBlock = a !== 'allow';
  } else if (managedInterruption) {
    const setAction = String(profile.ruleSetAction || 'Block').toLowerCase();
    az.decidedBy = { type: 'managed', ruleId: managedInterruption.ruleId, msg: managedInterruption.msg, ruleSetAction: profile.ruleSetAction };
    az.action = setAction === 'log' ? 'log' : setAction;
    az.wouldBlock = setAction !== 'log';
  }
  const blocks = az.wouldBlock && prevention;
  if (!az.wouldBlock || !prevention) {
    if (az.wouldBlock && !prevention) az.note = 'Detection mode: Azure only logs this request – it would be blocked in Prevention mode.';
    res.blocked = false;
    res.interruption = null;
  }
  if (blocks && az.decidedBy?.type === 'custom') {
    res.blocked = true;
    res.interruption = { ruleId: `Custom rule “${az.decidedBy.name}”`, action: az.action, status: az.action === 'redirect' ? 302 : az.status, phase: 1, msg: `Azure custom rule “${az.decidedBy.name}” (priority ${az.decidedBy.priority}) → ${az.decidedBy.action}` };
  } else if (blocks && az.decidedBy?.type === 'managed') {
    res.blocked = true;
    res.interruption = { ...managedInterruption, status: az.action === 'redirect' ? 302 : az.status };
  }
  if (az.decidedBy?.type === 'custom' && az.action === 'allow') {
    res.blocked = false;
    res.interruption = null;
  }
  res.azure = az;
  return res;
}
