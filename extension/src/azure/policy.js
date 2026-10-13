// Azure WAF policy import: parses the JSON of an Azure Front Door (or Application Gateway)
// WAF policy into a normalised structure used by the simulator.
//
// Accepted inputs (paste or file):
//  - Azure portal "JSON View" of the policy resource ({ id, name, sku, properties: {...} })
//  - `az network front-door waf-policy show` / `list` output (flat object or array)
//  - ARM template / resource export ({ resources: [{ type: ".../frontdoorwebapplicationfirewallpolicies", properties }] })
//  - Application Gateway WAF policy (ApplicationGatewayWebApplicationFirewallPolicies)

/**
 * @typedef {Object} AzCondition
 * @property {string} variable   RemoteAddr|SocketAddr|RequestMethod|QueryString|PostArgs|RequestUri|RequestHeader|RequestBody|Cookies|...
 * @property {string|null} selector
 * @property {string} operator   Any|IPMatch|GeoMatch|Equal|Contains|LessThan|GreaterThan|LessThanOrEqual|GreaterThanOrEqual|BeginsWith|EndsWith|RegEx|...
 * @property {boolean} negate
 * @property {string[]} values
 * @property {string[]} transforms
 */
/**
 * @typedef {Object} AzCustomRule
 * @property {string} name
 * @property {number} priority
 * @property {boolean} enabled
 * @property {string} ruleType   MatchRule|RateLimitRule
 * @property {string} action     Allow|Block|Log|Redirect|JSChallenge|CAPTCHA
 * @property {AzCondition[]} conditions
 * @property {number} [rateLimitThreshold]
 * @property {number} [rateLimitDurationInMinutes]
 */
/**
 * @typedef {Object} AzExclusion
 * @property {string} variable   RequestHeaderNames|RequestCookieNames|QueryStringArgNames|RequestBodyPostArgNames|RequestBodyJsonArgNames|RequestArgNames|...
 * @property {string} operator   Equals|Contains|StartsWith|EndsWith|EqualsAny
 * @property {string} selector
 */

import { detectWafConfigFormat, terraformToArm, bicepToArm, FORMAT_LABELS } from './iac.js';

const lc = (s) => String(s ?? '').toLowerCase();

function findPolicyObject(input, warnings) {
  if (Array.isArray(input)) {
    const list = input.filter((x) => x && typeof x === 'object');
    if (list.length > 1) warnings.push(`The input contains ${list.length} policies; using the first one (“${list[0].name || 'unnamed'}”).`);
    return list.length ? findPolicyObject(list[0], warnings) : null;
  }
  if (!input || typeof input !== 'object') return null;
  if (Array.isArray(input.resources)) {
    const res = input.resources.filter((r) => /webapplicationfirewallpolicies/i.test(r.type || ''));
    if (res.length > 1) warnings.push(`The template contains ${res.length} WAF policies; using the first one.`);
    if (res.length) return { ...res[0], fromTemplate: true };
  }
  if (Array.isArray(input.value)) return findPolicyObject(input.value, warnings);
  return input;
}

function pick(obj, ...keys) {
  for (const k of keys) if (obj && obj[k] !== undefined && obj[k] !== null) return obj[k];
  return undefined;
}

function normExclusion(x) {
  return {
    variable: String(pick(x, 'matchVariable', 'match_variable') || ''),
    operator: String(pick(x, 'selectorMatchOperator', 'operator') || 'Equals'),
    selector: String(pick(x, 'selector') ?? ''),
  };
}

function normCondition(c, isAppGw) {
  if (isAppGw) {
    const vars = c.matchVariables || [];
    // App Gateway allows several variables per condition (OR). We expand to the first and keep the rest.
    const v = vars[0] || {};
    return {
      variable: String(v.variableName || ''),
      selector: v.selector ?? null,
      operator: String(c.operator || ''),
      negate: !!(c.negationConditon ?? c.negationCondition ?? c.negateCondition),
      values: (c.matchValues || []).map(String),
      transforms: (c.transforms || []).map(String),
      extraVariables: vars.slice(1).map((x) => ({ variable: x.variableName, selector: x.selector ?? null })),
    };
  }
  return {
    variable: String(pick(c, 'matchVariable', 'match_variable') || ''),
    selector: pick(c, 'selector') ?? null,
    operator: String(pick(c, 'operator') || ''),
    negate: !!pick(c, 'negateCondition', 'negate_condition', 'negationCondition'),
    values: (pick(c, 'matchValue', 'matchValues', 'match_values') || []).map(String),
    transforms: (pick(c, 'transforms') || []).map(String),
  };
}

/**
 * Parse an Azure WAF policy.
 * @param {string|object} text
 * @returns {{ policy: object|null, errors: string[], warnings: string[] }}
 */
export function parseAzurePolicy(text) {
  const errors = [];
  const warnings = [];
  let input = text;
  let format = 'azure-json';
  if (typeof text === 'string') {
    const t = text.trim();
    if (!t) return { policy: null, errors: [], warnings: [], format: 'empty' };
    format = detectWafConfigFormat(t);
    if (format === 'terraform' || format === 'bicep') {
      const conv = format === 'terraform' ? terraformToArm(t) : bicepToArm(t);
      warnings.push(...conv.warnings);
      if (!conv.policies.length) return { policy: null, errors: [`No Azure WAF policy resource found in the ${FORMAT_LABELS[format]} input.`], warnings, format };
      input = conv.policies;
    } else if (format === 'aws' || format === 'cloudflare') {
      return { policy: null, errors: [`${FORMAT_LABELS[format]} configurations use their own rule engines (not OWASP CRS / Azure DRS) and cannot be simulated. Use the OWASP CRS profile with matching paranoia level and threshold instead.`], warnings, format };
    } else if (format === 'modsecurity') {
      return { policy: null, errors: ['This is a ModSecurity / Coraza / CRS configuration – choose the “OWASP CRS” profile and import it there.'], warnings, format };
    } else {
      try {
        input = JSON.parse(t);
      } catch (e) {
        const what = format === 'invalid-json' ? 'Not valid JSON' : 'Not a recognised format';
        return { policy: null, errors: [`${what}: ${e.message}. Supported: Azure WAF policy JSON (portal JSON View, az CLI, ARM export), Terraform (azurerm_*_firewall_policy) and Bicep.`], warnings, format };
      }
    }
  }
  const raw = findPolicyObject(input, warnings);
  if (!raw) return { policy: null, errors: ['No WAF policy object found in the JSON.'], warnings, format };
  const props = raw.properties && typeof raw.properties === 'object' ? raw.properties : raw;
  const type = String(raw.type || '');
  const isAppGw = /applicationgateway/i.test(type) || Array.isArray(props.customRules) || !!props.managedRules?.exclusions && !props.customRules?.rules;
  const settings = props.policySettings || {};
  const skuName = raw.sku?.name || props.sku?.name || null;

  if (!props.policySettings && !props.customRules && !props.managedRules) {
    errors.push('The JSON does not look like a WAF policy (no policySettings, customRules or managedRules).');
    return { policy: null, errors, warnings };
  }

  const rawCustom = isAppGw ? props.customRules || [] : props.customRules?.rules || props.customRules || [];
  const customRules = (Array.isArray(rawCustom) ? rawCustom : []).map((r, i) => ({
    name: String(r.name || `rule${i + 1}`),
    priority: Number(r.priority ?? i + 1),
    enabled: lc(r.enabledState ?? r.state ?? 'Enabled') !== 'disabled',
    ruleType: String(r.ruleType || 'MatchRule'),
    action: String(r.action || 'Block'),
    rateLimitThreshold: r.rateLimitThreshold ?? null,
    rateLimitDurationInMinutes: r.rateLimitDurationInMinutes ?? null,
    conditions: (r.matchConditions || []).map((c) => normCondition(c, isAppGw)),
  }));
  customRules.sort((a, b) => a.priority - b.priority);
  const prios = new Set();
  for (const r of customRules) {
    if (prios.has(r.priority)) warnings.push(`Custom rules share priority ${r.priority} – Azure requires unique priorities.`);
    prios.add(r.priority);
  }

  const mr = props.managedRules || {};
  const managedRuleSets = (mr.managedRuleSets || []).map((s) => ({
    type: String(s.ruleSetType || ''),
    version: String(s.ruleSetVersion || ''),
    action: s.ruleSetAction ?? null,
    exclusions: (s.exclusions || []).map(normExclusion),
    overrides: (s.ruleGroupOverrides || []).map((g) => ({
      group: String(g.ruleGroupName || ''),
      exclusions: (g.exclusions || []).map(normExclusion),
      rules: (g.rules || []).map((r) => ({
        id: Number(String(r.ruleId).replace(/\D/g, '')),
        enabled: lc(r.enabledState ?? r.state ?? 'Enabled') !== 'disabled',
        action: r.action ?? null,
        exclusions: (r.exclusions || []).map(normExclusion),
      })),
    })),
  }));
  // Application Gateway: policy-level exclusions may be scoped to rule sets/groups/rules.
  const exclusions = [];
  for (const x of mr.exclusions || []) {
    const ex = normExclusion(x);
    if (Array.isArray(x.exclusionManagedRuleSets) && x.exclusionManagedRuleSets.length) {
      ex.scope = x.exclusionManagedRuleSets.map((s) => ({
        type: String(s.ruleSetType || ''),
        version: String(s.ruleSetVersion || ''),
        groups: (s.ruleGroups || []).map((g) => ({ group: g.ruleGroupName, rules: (g.rules || []).map((r) => Number(String(r.ruleId).replace(/\D/g, ''))) })),
      }));
    }
    exclusions.push(ex);
  }

  const policy = {
    name: String(raw.name || props.name || 'WAF policy'),
    kind: isAppGw ? 'appgw' : 'frontdoor',
    sku: skuName,
    enabled: lc(settings.enabledState ?? settings.state ?? 'Enabled') !== 'disabled',
    mode: /prevention/i.test(settings.mode || '') ? 'Prevention' : 'Detection',
    modeExplicit: !!settings.mode,
    requestBodyCheck: lc(settings.requestBodyCheck ?? 'Enabled') !== 'disabled' && settings.requestBodyCheck !== false,
    customBlockResponseStatusCode: settings.customBlockResponseStatusCode ?? 403,
    redirectUrl: settings.redirectUrl ?? null,
    customRules,
    managedRuleSets,
    exclusions,
  };

  // Validation / hints
  if (!settings.mode) warnings.push('policySettings.mode is missing – assuming Detection (Azure default).');
  if (policy.kind === 'frontdoor' && skuName && !/premium|classic/i.test(skuName) && managedRuleSets.length) warnings.push(`SKU ${skuName}: managed rule sets require Front Door Premium (or classic).`);
  const drs = managedRuleSets.find((s) => /defaultruleset|owasp/i.test(s.type));
  if (!drs) warnings.push('No Default Rule Set (DRS) in managedRules – only custom rules are simulated.');
  else if (/^Microsoft_DefaultRuleSet$|^DefaultRuleSet$/i.test(drs.type) && !/^2\.[0-2]$|^1\.[01]$/.test(drs.version)) warnings.push(`DRS version ${drs.version} is not known to the simulator; treating it like DRS 2.1.`);
  else if (/owasp/i.test(drs.type)) warnings.push(`Rule set ${drs.type} ${drs.version} (Application Gateway CRS) is approximated with OWASP CRS 3.3.`);
  for (const s of managedRuleSets) if (/botmanager/i.test(s.type)) warnings.push(`${s.type} ${s.version} uses Microsoft threat intelligence (IP reputation) and is not simulated.`);
  for (const r of customRules) {
    if (/ratelimit/i.test(r.ruleType)) warnings.push(`Custom rule “${r.name}” is a rate-limit rule: the simulator shows whether its conditions match, but cannot count requests.`);
    for (const c of r.conditions) {
      if (/^(GeoMatch)$/i.test(c.operator)) warnings.push(`Custom rule “${r.name}” uses GeoMatch – set “Client country” in the settings to simulate it.`);
      if (/asn|fingerprint|servicetag/i.test(c.operator + c.variable)) warnings.push(`Custom rule “${r.name}” uses ${c.operator} on ${c.variable}, which cannot be simulated from a browser request.`);
    }
  }
  policy.sourceFormat = format;
  return { policy, errors, warnings: [...new Set(warnings)], format };
}

/** One-line summary for the UI. */
export function summarizePolicy(p) {
  if (!p) return null;
  const drs = p.managedRuleSets.find((s) => /defaultruleset|owasp/i.test(s.type));
  const overrides = p.managedRuleSets.reduce((n, s) => n + s.overrides.reduce((m, g) => m + g.rules.length, 0), 0);
  const exclusions = p.exclusions.length + p.managedRuleSets.reduce((n, s) => n + s.exclusions.length + s.overrides.reduce((m, g) => m + g.exclusions.length + g.rules.reduce((k, r) => k + r.exclusions.length, 0), 0), 0);
  return {
    name: p.name,
    kind: p.kind === 'appgw' ? 'Application Gateway' : 'Front Door',
    sku: p.sku,
    mode: p.mode,
    enabled: p.enabled,
    ruleSet: drs ? `${drs.type} ${drs.version}` : 'none',
    ruleSetAction: drs?.action || null,
    customRules: p.customRules.length,
    customRulesEnabled: p.customRules.filter((r) => r.enabled).length,
    overrides,
    exclusions,
    requestBodyCheck: p.requestBodyCheck,
  };
}
