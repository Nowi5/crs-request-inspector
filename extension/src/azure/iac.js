// Infrastructure-as-code importers for Azure WAF policies: Terraform (azurerm provider) and Bicep.
// Both are converted into the ARM resource shape ({ type, name, sku, properties }) understood by
// parseAzurePolicy(). Expressions (var.x, param refs, functions) cannot be evaluated and are kept
// as text with a warning.

/* ================================================================ Terraform */

/** Tokenise a subset of HCL: identifiers, strings, numbers, punctuation; comments skipped. */
function hclTokens(src) {
  const toks = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === '#' || (c === '/' && src[i + 1] === '/')) {
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      const e = src.indexOf('*/', i + 2);
      i = e < 0 ? n : e + 2;
      continue;
    }
    if (c === '\n') {
      toks.push({ t: 'nl' });
      i++;
      continue;
    }
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === '"') {
      let s = '';
      i++;
      while (i < n && src[i] !== '"') {
        if (src[i] === '\\' && i + 1 < n) {
          const e = src[i + 1];
          s += e === 'n' ? '\n' : e === 't' ? '\t' : e;
          i += 2;
        } else s += src[i++];
      }
      i++;
      toks.push({ t: 'str', v: s });
      continue;
    }
    if (c === '<' && src[i + 1] === '<') {
      // heredoc <<EOF / <<-EOF
      const m = /^<<-?([A-Za-z_]\w*)\r?\n/.exec(src.slice(i));
      if (m) {
        const end = src.indexOf(`\n${m[1]}`, i + m[0].length - 1);
        const body = src.slice(i + m[0].length, end < 0 ? n : end);
        toks.push({ t: 'str', v: body });
        i = end < 0 ? n : end + m[1].length + 1;
        continue;
      }
    }
    if (/[0-9]/.test(c) || (c === '-' && /[0-9]/.test(src[i + 1] || ''))) {
      const m = /^-?\d+(\.\d+)?/.exec(src.slice(i));
      toks.push({ t: 'num', v: Number(m[0]) });
      i += m[0].length;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      const m = /^[A-Za-z_][\w.\-[\]*]*/.exec(src.slice(i));
      toks.push({ t: 'id', v: m[0] });
      i += m[0].length;
      continue;
    }
    toks.push({ t: 'p', v: c });
    i++;
  }
  return toks;
}

/**
 * Parse HCL into { blocks: [{type, labels, body}], attrs: {} } recursively.
 * Bodies: { attrs: { key: value }, blocks: [ { type, labels, body } ] }
 */
export function parseHcl(src) {
  const toks = hclTokens(src);
  let p = 0;
  const peek = () => toks[p];
  const skipNl = () => {
    while (toks[p] && (toks[p].t === 'nl' || (toks[p].t === 'p' && toks[p].v === ','))) p++;
  };
  const parseValue = () => {
    skipNl();
    const t = toks[p];
    if (!t) return null;
    if (t.t === 'str' || t.t === 'num') {
      p++;
      // string concatenation / interpolation is kept as-is
      return t.v;
    }
    if (t.t === 'id') {
      p++;
      if (t.v === 'true') return true;
      if (t.v === 'false') return false;
      if (t.v === 'null') return null;
      // expression: function call or reference
      let expr = t.v;
      if (peek()?.t === 'p' && peek().v === '(') {
        let depth = 0;
        do {
          const x = toks[p++];
          if (x.t === 'p' && x.v === '(') depth++;
          if (x.t === 'p' && x.v === ')') depth--;
          expr += x.t === 'str' ? JSON.stringify(x.v) : x.v ?? '';
        } while (depth > 0 && p < toks.length);
      }
      return { expr };
    }
    if (t.t === 'p' && t.v === '[') {
      p++;
      const arr = [];
      skipNl();
      while (p < toks.length && !(toks[p].t === 'p' && toks[p].v === ']')) {
        arr.push(parseValue());
        skipNl();
      }
      p++;
      return arr;
    }
    if (t.t === 'p' && t.v === '{') {
      p++;
      const body = parseBody('}');
      return body.attrs;
    }
    p++;
    return null;
  };
  const parseBody = (close) => {
    const body = { attrs: {}, blocks: [] };
    for (;;) {
      skipNl();
      const t = toks[p];
      if (!t) break;
      if (close && t.t === 'p' && t.v === close) {
        p++;
        break;
      }
      if (t.t !== 'id' && t.t !== 'str') {
        p++;
        continue;
      }
      const name = t.v;
      p++;
      const nx = peek();
      if (nx && nx.t === 'p' && (nx.v === '=' || nx.v === ':')) {
        p++;
        body.attrs[name] = parseValue();
        continue;
      }
      // block: name "label" "label" {
      const labels = [];
      while (peek() && (peek().t === 'str' || peek().t === 'id')) labels.push(toks[p++].v);
      if (peek() && peek().t === 'p' && peek().v === '{') {
        p++;
        body.blocks.push({ type: name, labels, body: parseBody('}') });
      }
    }
    return body;
  };
  return parseBody(null);
}

const blocks = (body, type) => (body?.blocks || []).filter((b) => b.type === type).map((b) => b.body);
const attr = (body, k, warnings) => {
  const v = body?.attrs?.[k];
  if (v && typeof v === 'object' && !Array.isArray(v) && v.expr) {
    warnings.push(`Terraform expression \`${v.expr}\` for ${k} cannot be evaluated – using it as text.`);
    return v.expr;
  }
  return v;
};
const list = (v) => (Array.isArray(v) ? v.map((x) => (x && typeof x === 'object' && x.expr ? x.expr : x)) : v == null ? [] : [v]);
const enabledState = (v) => (v === false || v === 'false' ? 'Disabled' : 'Enabled');

function tfExclusion(e, w) {
  return { matchVariable: attr(e, 'match_variable', w), selectorMatchOperator: attr(e, 'operator', w) || attr(e, 'selector_match_operator', w), selector: attr(e, 'selector', w) };
}

function tfFrontDoor(res, type, w) {
  const b = res.body;
  const isCdn = type === 'azurerm_cdn_frontdoor_firewall_policy';
  const ps = isCdn ? b : blocks(b, 'policy_settings')[0] || b;
  const props = {
    policySettings: {
      enabledState: enabledState(attr(ps, 'enabled', w)),
      mode: attr(ps, 'mode', w) || 'Detection',
      requestBodyCheck: attr(ps, 'request_body_check_enabled', w) === false ? 'Disabled' : 'Enabled',
      customBlockResponseStatusCode: attr(ps, 'custom_block_response_status_code', w),
      redirectUrl: attr(ps, 'redirect_url', w),
    },
    customRules: {
      rules: blocks(b, 'custom_rule').map((r) => ({
        name: attr(r, 'name', w),
        enabledState: enabledState(attr(r, 'enabled', w)),
        priority: attr(r, 'priority', w),
        ruleType: attr(r, 'type', w) || 'MatchRule',
        rateLimitDurationInMinutes: attr(r, 'rate_limit_duration_in_minutes', w),
        rateLimitThreshold: attr(r, 'rate_limit_threshold', w),
        action: attr(r, 'action', w),
        matchConditions: blocks(r, 'match_condition').map((c) => ({
          matchVariable: attr(c, 'match_variable', w),
          selector: attr(c, 'selector', w) ?? null,
          operator: attr(c, 'operator', w),
          negateCondition: !!attr(c, 'negation_condition', w),
          matchValue: list(attr(c, 'match_values', w)),
          transforms: list(attr(c, 'transforms', w)),
        })),
      })),
    },
    managedRules: {
      managedRuleSets: blocks(b, 'managed_rule').map((m) => ({
        ruleSetType: attr(m, 'type', w),
        ruleSetVersion: String(attr(m, 'version', w) ?? ''),
        ruleSetAction: attr(m, 'action', w),
        exclusions: blocks(m, 'exclusion').map((e) => tfExclusion(e, w)),
        ruleGroupOverrides: blocks(m, 'override').map((o) => ({
          ruleGroupName: attr(o, 'rule_group_name', w),
          exclusions: blocks(o, 'exclusion').map((e) => tfExclusion(e, w)),
          rules: blocks(o, 'rule').map((r) => ({
            ruleId: String(attr(r, 'rule_id', w)),
            enabledState: enabledState(attr(r, 'enabled', w)),
            action: attr(r, 'action', w),
            exclusions: blocks(r, 'exclusion').map((e) => tfExclusion(e, w)),
          })),
        })),
      })),
    },
  };
  return { type: 'Microsoft.Network/frontdoorWebApplicationFirewallPolicies', name: attr(b, 'name', w) || res.labels[1], sku: { name: attr(b, 'sku_name', w) || null }, properties: props };
}

function tfAppGateway(res, w) {
  const b = res.body;
  const ps = blocks(b, 'policy_settings')[0] || {};
  const mr = blocks(b, 'managed_rules')[0] || {};
  const props = {
    policySettings: {
      state: enabledState(attr(ps, 'enabled', w)),
      mode: attr(ps, 'mode', w) || 'Prevention',
      requestBodyCheck: attr(ps, 'request_body_check', w) !== false,
    },
    customRules: blocks(b, 'custom_rules').map((r) => ({
      name: attr(r, 'name', w),
      priority: attr(r, 'priority', w),
      ruleType: attr(r, 'rule_type', w) || 'MatchRule',
      state: enabledState(attr(r, 'enabled', w)),
      action: attr(r, 'action', w),
      matchConditions: blocks(r, 'match_conditions').map((c) => ({
        matchVariables: blocks(c, 'match_variables').map((v) => ({ variableName: attr(v, 'variable_name', w), selector: attr(v, 'selector', w) ?? null })),
        operator: attr(c, 'operator', w),
        negationConditon: !!attr(c, 'negation_condition', w),
        matchValues: list(attr(c, 'match_values', w)),
        transforms: list(attr(c, 'transforms', w)),
      })),
    })),
    managedRules: {
      managedRuleSets: blocks(mr, 'managed_rule_set').map((s) => ({
        ruleSetType: attr(s, 'type', w) || 'OWASP',
        ruleSetVersion: String(attr(s, 'version', w) ?? ''),
        ruleGroupOverrides: blocks(s, 'rule_group_override').map((o) => ({
          ruleGroupName: attr(o, 'rule_group_name', w),
          rules: [
            ...blocks(o, 'rule').map((r) => ({ ruleId: String(attr(r, 'id', w)), state: enabledState(attr(r, 'enabled', w)), action: attr(r, 'action', w) })),
            ...list(attr(o, 'disabled_rules', w)).map((id) => ({ ruleId: String(id), state: 'Disabled' })),
          ],
        })),
      })),
      exclusions: blocks(mr, 'exclusion').map((e) => ({
        matchVariable: attr(e, 'match_variable', w),
        selectorMatchOperator: attr(e, 'selector_match_operator', w),
        selector: attr(e, 'selector', w),
        exclusionManagedRuleSets: blocks(e, 'excluded_rule_set').map((s) => ({
          ruleSetType: attr(s, 'type', w),
          ruleSetVersion: attr(s, 'version', w),
          ruleGroups: blocks(s, 'rule_group').map((g) => ({ ruleGroupName: attr(g, 'rule_group_name', w), rules: list(attr(g, 'excluded_rules', w)).map((id) => ({ ruleId: String(id) })) })),
        })),
      })),
    },
  };
  return { type: 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies', name: attr(b, 'name', w) || res.labels[1], properties: props };
}

const TF_TYPES = ['azurerm_cdn_frontdoor_firewall_policy', 'azurerm_frontdoor_firewall_policy', 'azurerm_web_application_firewall_policy'];

/** Terraform → ARM-shaped policy object(s). */
export function terraformToArm(src) {
  const warnings = [];
  const root = parseHcl(src);
  const resources = root.blocks.filter((b) => b.type === 'resource' && TF_TYPES.includes(b.labels[0]));
  const policies = resources.map((r) => (r.labels[0] === 'azurerm_web_application_firewall_policy' ? tfAppGateway(r, warnings) : tfFrontDoor(r, r.labels[0], warnings)));
  return { policies, warnings: [...new Set(warnings)] };
}

/* ==================================================================== Bicep */

/** Parse a Bicep object/array literal starting at src[i] === '{' or '['. */
function bicepValue(src, start, warnings) {
  let i = start;
  const n = src.length;
  const ws = () => {
    for (;;) {
      while (i < n && /\s/.test(src[i])) i++;
      if (src.startsWith('//', i)) {
        while (i < n && src[i] !== '\n') i++;
        continue;
      }
      if (src.startsWith('/*', i)) {
        const e = src.indexOf('*/', i + 2);
        i = e < 0 ? n : e + 2;
        continue;
      }
      break;
    }
  };
  const str = () => {
    if (src.startsWith("'''", i)) {
      const e = src.indexOf("'''", i + 3);
      const v = src.slice(i + 3, e < 0 ? n : e);
      i = e < 0 ? n : e + 3;
      return v;
    }
    i++;
    let s = '';
    while (i < n && src[i] !== "'") {
      if (src[i] === '\\' && i + 1 < n) {
        const e = src[i + 1];
        s += e === 'n' ? '\n' : e === 't' ? '\t' : e === '$' ? '$' : e;
        i += 2;
      } else s += src[i++];
    }
    i++;
    if (/\$\{/.test(s)) warnings.push(`Bicep interpolation in '${s}' cannot be evaluated – using it as text.`);
    return s;
  };
  const value = () => {
    ws();
    const c = src[i];
    if (c === '{') {
      i++;
      const obj = {};
      for (;;) {
        ws();
        if (src[i] === '}') {
          i++;
          return obj;
        }
        if (i >= n) return obj;
        let key;
        if (src[i] === "'") key = str();
        else {
          const m = /^[A-Za-z_$][\w$]*/.exec(src.slice(i));
          if (!m) {
            i++;
            continue;
          }
          key = m[0];
          i += key.length;
        }
        ws();
        if (src[i] === ':') i++;
        obj[key] = value();
        ws();
        if (src[i] === ',') i++;
      }
    }
    if (c === '[') {
      i++;
      const arr = [];
      for (;;) {
        ws();
        if (src[i] === ']') {
          i++;
          return arr;
        }
        if (i >= n) return arr;
        arr.push(value());
        ws();
        if (src[i] === ',') i++;
      }
    }
    if (c === "'") return str();
    const m = /^(-?\d+(\.\d+)?)(?![\w.])/.exec(src.slice(i));
    if (m) {
      i += m[0].length;
      return Number(m[1]);
    }
    // identifier / expression up to end of line (or closing bracket)
    const e = /^[^\n\]}]+/.exec(src.slice(i));
    const expr = (e ? e[0] : '').trim();
    i += e ? e[0].length : 1;
    if (expr === 'true') return true;
    if (expr === 'false') return false;
    if (expr === 'null') return null;
    warnings.push(`Bicep expression \`${expr}\` cannot be evaluated – using it as text.`);
    return expr;
  };
  const v = value();
  return { value: v, end: i };
}

/** Bicep → ARM-shaped policy object(s). */
export function bicepToArm(src) {
  const warnings = [];
  const policies = [];
  const re = /resource\s+(\w+)\s+'(Microsoft\.Network\/(?:FrontDoorWebApplicationFirewallPolicies|ApplicationGatewayWebApplicationFirewallPolicies))@[^']*'\s*(?:existing\s*)?=\s*/gi;
  let m;
  while ((m = re.exec(src))) {
    const start = src.indexOf('{', m.index + m[0].length - 1);
    if (start < 0) continue;
    const { value } = bicepValue(src, start, warnings);
    policies.push({ type: m[2], name: typeof value.name === 'string' ? value.name : m[1], sku: value.sku || null, properties: value.properties || {} });
  }
  return { policies, warnings: [...new Set(warnings)] };
}

/* ================================================================ detection */

/** Detect the format of a WAF configuration text. */
export function detectWafConfigFormat(text) {
  const t = String(text || '').trim();
  if (!t) return 'empty';
  if (/^[[{]/.test(t)) {
    try {
      const j = JSON.parse(t);
      const s = JSON.stringify(j).slice(0, 20000);
      if (/"ManagedRuleGroupStatement"|"VisibilityConfig"|"DefaultAction":\{"(Allow|Block)"/.test(s)) return 'aws';
      if (/"phase":"http_request_firewall_(managed|custom)"|"kind":"(zone|managed|root)"/.test(s)) return 'cloudflare';
      return 'azure-json';
    } catch {
      return 'invalid-json';
    }
  }
  if (/resource\s+"azurerm_(cdn_frontdoor|frontdoor|web_application)_firewall_policy"/.test(t)) return 'terraform';
  if (/resource\s+\w+\s+'Microsoft\.Network\/(FrontDoor|ApplicationGateway)WebApplicationFirewallPolicies@/i.test(t)) return 'bicep';
  if (/resource\s+"aws_wafv2_web_acl"/.test(t)) return 'aws';
  if (/resource\s+"cloudflare_(ruleset|waf)/.test(t)) return 'cloudflare';
  if (/^\s*(SecRule|SecAction|SecRuleRemove\w*|SecRuleUpdate\w*|SecDefaultAction|SecMarker|SecRequestBody\w*|Include)\b/m.test(t)) return 'modsecurity';
  return 'unknown';
}

export const FORMAT_LABELS = {
  'azure-json': 'Azure WAF policy (JSON)',
  terraform: 'Terraform (azurerm)',
  bicep: 'Bicep',
  modsecurity: 'ModSecurity / Coraza / CRS configuration',
  aws: 'AWS WAF',
  cloudflare: 'Cloudflare',
  'invalid-json': 'Invalid JSON',
  unknown: 'Unknown format',
  empty: 'Empty',
};
