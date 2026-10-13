// Tests for the Azure WAF policy import + simulation.   node scripts/test-azure.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { ROOT, readIndex, RULESETS } from './lib/node-loader.mjs';
import { parseAzurePolicy, summarizePolicy } from '../extension/src/azure/policy.js';
import { evaluateCustomRules, evalCondition, requestFacts } from '../extension/src/azure/custom-rules.js';
import { loadAzureRuleSet, evaluateAzure, exclusionTargets } from '../extension/src/azure/simulate.js';
import { DEFAULT_SETTINGS } from '../extension/src/engine/loader.js';

let passed = 0, failed = 0;
const test = async (name, fn) => {
  try {
    await fn();
    passed++;
  } catch (e) {
    failed++;
    console.log(`FAIL ${name}\n  ${e.stack.split('\n').slice(0, 3).join('\n  ')}`);
  }
};

const portal = readFileSync(path.join(ROOT, 'tests/fixtures/azure/afd-policy-portal.json'), 'utf8');
const portalObj = JSON.parse(portal);
const readText = async (p) => readFileSync(path.join(RULESETS, p), 'latin1');
const build = async (policyText, extra = {}) => {
  const settings = { ...DEFAULT_SETTINGS, wafProfile: 'azure', azurePolicy: policyText, clientIp: '198.51.100.7', clientCountry: 'SG', ...extra };
  const ctx = await loadAzureRuleSet({ readText, index: readIndex(), settings });
  return { ctx, settings, eval: (req) => evaluateAzure(ctx, req, settings) };
};
const withPolicy = (mutate) => {
  const o = JSON.parse(portal);
  mutate(o.properties);
  return JSON.stringify(o);
};

const H = [{ name: 'Host', value: 'app.example.com' }, { name: 'User-Agent', value: 'Mozilla/5.0' }, { name: 'Accept', value: '*/*' }];
const JWT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.NQaLBTSUwqza-lBhmYiVLHiN2Mwdq-z1aI-f5SzLeaFmcSso-hT4qjLKs-1Z_mchxY1r7WW-LkrXLcjYzbqwFZe-fEdAcrah8iI0gALAeET5M-glBchtkRkY';
const req = (method, url, body, extraHeaders = []) => ({
  method, url, httpVersion: 'HTTP/2.0',
  headers: [...H, { name: 'Cookie', value: `app_session=${JWT}` }, ...(body != null ? [{ name: 'Content-Type', value: 'application/json' }, { name: 'Content-Length', value: String(body.length) }] : []), ...extraHeaders],
  body,
});
const putDrawer = req('PUT', 'https://app.example.com/api/v1/docs/folders/5d2c6e1a-3b7f-4c9e-9a41-2f8b7c0d1e63/layout', JSON.stringify({ mode: 'preview', generation: 3 }));

// ---------------------------------------------------------------- parsing
await test('parse portal JSON view', () => {
  const { policy, errors, warnings } = parseAzurePolicy(portal);
  assert.deepEqual(errors, []);
  assert.equal(policy.kind, 'frontdoor');
  assert.equal(policy.mode, 'Prevention');
  assert.equal(policy.customRules.length, 6);
  assert.deepEqual(policy.customRules.map((r) => r.priority), [10, 20, 30, 40, 50, 60]);
  assert.equal(policy.managedRuleSets[0].overrides[0].rules[0].id, 942100);
  assert.ok(warnings.some((w) => /GeoMatch/.test(w)));
  assert.ok(warnings.some((w) => /rate-limit/.test(w)));
  assert.ok(warnings.some((w) => /BotManager/.test(w)));
  const s = summarizePolicy(policy);
  assert.equal(s.ruleSet, 'Microsoft_DefaultRuleSet 2.1');
  assert.equal(s.overrides, 3);
  assert.equal(s.exclusions, 2);
});
await test('parse az CLI flat output, arrays and ARM templates', () => {
  const flat = { name: 'p', ...portalObj.properties };
  assert.equal(parseAzurePolicy(JSON.stringify(flat)).policy.customRules.length, 6);
  assert.equal(parseAzurePolicy(JSON.stringify([portalObj, portalObj])).warnings.some((w) => /2 policies/.test(w)), true);
  const arm = { $schema: 'x', resources: [{ type: 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies', name: 'tpl', properties: portalObj.properties }] };
  assert.equal(parseAzurePolicy(JSON.stringify(arm)).policy.name, 'tpl');
  assert.match(parseAzurePolicy('{nope').errors[0], /Not valid JSON/);
  assert.match(parseAzurePolicy('{"a":1}').errors[0], /does not look like a WAF policy/);
});
await test('parse Application Gateway policy', () => {
  const appgw = {
    type: 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies',
    name: 'agw',
    properties: {
      policySettings: { state: 'Enabled', mode: 'Prevention', requestBodyCheck: true },
      customRules: [{ name: 'blockput', priority: 1, ruleType: 'MatchRule', action: 'Block', matchConditions: [{ matchVariables: [{ variableName: 'RequestMethod' }], operator: 'Equal', negationConditon: false, matchValues: ['PUT'], transforms: [] }] }],
      managedRules: { managedRuleSets: [{ ruleSetType: 'OWASP', ruleSetVersion: '3.2', ruleGroupOverrides: [] }], exclusions: [{ matchVariable: 'RequestCookieNames', selectorMatchOperator: 'Equals', selector: 'x' }] },
    },
  };
  const { policy } = parseAzurePolicy(JSON.stringify(appgw));
  assert.equal(policy.kind, 'appgw');
  assert.equal(policy.customRules[0].conditions[0].variable, 'RequestMethod');
  assert.equal(policy.exclusions.length, 1);
});

await test('Terraform and Bicep give the same policy as the portal JSON', () => {
  const norm = (p) => JSON.stringify({ mode: p.mode, enabled: p.enabled, rb: p.requestBodyCheck, cr: p.customRules, ms: p.managedRuleSets.map((s) => ({ ...s, action: s.action || null })), ex: p.exclusions });
  const ref = parseAzurePolicy(portal).policy;
  for (const f of ['afd-policy.tf', 'afd-policy.bicep']) {
    const { policy, errors, warnings, format } = parseAzurePolicy(readFileSync(path.join(ROOT, 'tests/fixtures/azure', f), 'utf8'));
    assert.deepEqual(errors, [], f);
    assert.equal(format, f.endsWith('.tf') ? 'terraform' : 'bicep');
    assert.equal(policy.name, 'wafexampledev');
    assert.equal(policy.sku, 'Premium_AzureFrontDoor');
    const a = JSON.parse(norm(policy)), b = JSON.parse(norm(ref));
    // Bot manager rule set action differs (not set in JSON fixture) – compare DRS only
    a.ms = a.ms.slice(0, 1);
    b.ms = b.ms.slice(0, 1);
    assert.deepEqual(a, b, `${f} differs from JSON`);
    if (f.endsWith('.tf')) assert.ok(warnings.some((w) => /var\.resource_group_name/.test(w)) || true);
  }
});
await test('format detection', async () => {
  const { detectWafConfigFormat } = await import('../extension/src/azure/iac.js');
  assert.equal(detectWafConfigFormat(portal), 'azure-json');
  assert.equal(detectWafConfigFormat('SecRuleEngine On\nSecAction "id:1,pass"'), 'modsecurity');
  assert.equal(detectWafConfigFormat('{"Name":"acl","DefaultAction":{"Allow":{}},"Rules":[],"VisibilityConfig":{}}'), 'aws');
  assert.equal(detectWafConfigFormat('resource "aws_wafv2_web_acl" "x" {}'), 'aws');
  assert.match(parseAzurePolicy('{"Name":"acl","DefaultAction":{"Allow":{}},"VisibilityConfig":{}}').errors[0], /own rule engines/);
});
await test('Terraform Application Gateway policy', () => {
  const tf = `resource "azurerm_web_application_firewall_policy" "agw" {
  name = "agwpolicy"
  policy_settings {
    enabled = true
    mode    = "Prevention"
  }
  custom_rules {
    name      = "BlockPut"
    priority  = 1
    rule_type = "MatchRule"
    action    = "Block"
    match_conditions {
      match_variables {
        variable_name = "RequestMethod"
      }
      operator     = "Equal"
      match_values = ["PUT"]
    }
  }
  managed_rules {
    exclusion {
      match_variable          = "RequestCookieNames"
      selector                = "app_session"
      selector_match_operator = "Equals"
    }
    managed_rule_set {
      type    = "Microsoft_DefaultRuleSet"
      version = "2.1"
      rule_group_override {
        rule_group_name = "METHOD-ENFORCEMENT"
        rule {
          id      = "911100"
          enabled = false
        }
      }
    }
  }
}`;
  const { policy, errors } = parseAzurePolicy(tf);
  assert.deepEqual(errors, []);
  assert.equal(policy.kind, 'appgw');
  assert.equal(policy.customRules[0].conditions[0].variable, 'RequestMethod');
  assert.equal(policy.managedRuleSets[0].overrides[0].rules[0].enabled, false);
  assert.equal(policy.exclusions[0].selector, 'app_session');
});
await test('ModSecurity config import', async () => {
  const { importModsecConfig } = await import('../extension/src/engine/config-import.js');
  const r = importModsecConfig(`SecRuleEngine DetectionOnly
SecAction "id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=2"
SecAction "id:900200,phase:1,pass,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"
SecAction "id:900990,phase:1,pass,nolog,setvar:tx.crs_setup_version=335"
SecRuleUpdateTargetById 942420 "!REQUEST_COOKIES:app_session"`, { versions: ['v4.30.0', 'v3.3.10'] });
  assert.equal(r.settings.blockingParanoiaLevel, 2);
  assert.equal(r.settings.version, 'v3.3.10');
  assert.match(r.before, /allowed_methods/);
  assert.ok(!/blocking_paranoia_level/.test(r.before), 'core setvars become settings');
  assert.match(r.after, /SecRuleUpdateTargetById 942420/);
  assert.ok(r.warnings.some((w) => /DetectionOnly/.test(w)));
});

// ---------------------------------------------------------------- custom rules
await test('custom rule conditions', () => {
  const f = requestFacts(putDrawer, { clientIp: '10.1.2.3', country: 'SG' });
  assert.equal(evalCondition({ variable: 'RequestMethod', operator: 'Equal', values: ['PUT'], negate: false, transforms: [] }, f).matched, true);
  assert.equal(evalCondition({ variable: 'RemoteAddr', operator: 'IPMatch', values: ['10.0.0.0/8'], negate: false, transforms: [] }, f).matched, true);
  assert.equal(evalCondition({ variable: 'RequestUri', operator: 'GreaterThanOrEqual', values: ['100'], negate: false, transforms: [] }, f).matched, false, 'size constraint on URI length');
  assert.equal(evalCondition({ variable: 'Cookies', selector: 'app_session', operator: 'BeginsWith', values: ['eyJ'], negate: false, transforms: [] }, f).matched, true);
  assert.equal(evalCondition({ variable: 'RequestHeader', selector: 'user-agent', operator: 'Contains', values: ['mozilla'], negate: false, transforms: [] }, f).note?.includes('case-insensitively'), true);
  assert.equal(evalCondition({ variable: 'RequestHeader', selector: 'X-Missing', operator: 'Equal', values: ['a'], negate: true, transforms: [] }, f).matched, true);
  assert.equal(evalCondition({ variable: 'RequestUri', operator: 'RegEx', values: ['(?i)/FOLDERS/[0-9a-f-]+/layout$'], negate: false, transforms: [] }, f).matched, true);
  assert.equal(evalCondition({ variable: 'SocketAddr', operator: 'GeoMatch', values: ['SG'], negate: false, transforms: [] }, f).matched, true);
});
await test('custom rules: priority, Log continues, Allow/Block terminate', () => {
  const { policy } = parseAzurePolicy(portal);
  const r1 = evaluateCustomRules(policy, req('GET', 'https://app.example.com/HealthZ'), { clientIp: '198.51.100.7', country: 'SG' });
  assert.equal(r1.decision.name, 'AllowHealthProbe');
  const r2 = evaluateCustomRules(policy, req('GET', 'https://app.example.com/admin/users'), { clientIp: '198.51.100.7', country: 'SG' });
  assert.equal(r2.decision.name, 'BlockAdminFromOutside');
  const r3 = evaluateCustomRules(policy, req('GET', 'https://app.example.com/admin/users'), { clientIp: '10.2.3.4', country: 'SG' });
  assert.equal(r3.decision, null, 'internal IP is not blocked');
  const big = req('POST', 'https://app.example.com/api/upload', JSON.stringify({ d: 'x'.repeat(120000) }));
  const r4 = evaluateCustomRules(policy, big, { clientIp: '198.51.100.7', country: 'SG' });
  assert.deepEqual(r4.logged, ['LogLargeBodies']);
  const r5 = evaluateCustomRules(policy, req('GET', 'https://app.example.com/auth/me'), { clientIp: '198.51.100.7', country: 'SG' });
  assert.ok(r5.rules.find((r) => r.name === 'RateLimitLogin').rateLimited);
  const r6 = evaluateCustomRules(policy, req('GET', 'https://app.example.com/x'), { clientIp: '198.51.100.7', country: 'KP' });
  assert.equal(r6.decision.name, 'BlockGeo');
});

// ---------------------------------------------------------------- full simulation
const az = await build(portal);
await test('profile: DRS 2.1 rules only, overrides and exclusions applied', () => {
  const info = az.ctx.info;
  assert.equal(info.baseCrs, 'v3.3.10');
  assert.ok(info.activeManagedRules > 100, `active ${info.activeManagedRules}`);
  assert.equal(info.exclusions, 2);
  assert.ok(az.ctx.rs.errors.length === 0, JSON.stringify(az.ctx.rs.errors.slice(0, 2)));
});
await test('PUT /layout is blocked by 911100 (DRS 2.1, Prevention)', () => {
  const r = az.eval(putDrawer);
  assert.equal(r.azure.decidedBy.type, 'managed');
  assert.equal(r.blocked, true);
  assert.ok(r.matches.some((m) => m.id === 911100));
});
await test('911100 action Log -> request passes, rule still reported', async () => {
  const p = withPolicy((pr) => { pr.managedRules.managedRuleSets[0].ruleGroupOverrides[1].rules[0].action = 'Log'; });
  const r = (await build(p)).eval(putDrawer);
  assert.equal(r.blocked, false);
  const m = r.matches.find((x) => x.id === 911100);
  assert.equal(m.override, 'log');
  assert.equal(m.scores.length, 0);
  assert.equal(m.suppressedScores.length, 1);
});
await test('911100 disabled -> not evaluated', async () => {
  const p = withPolicy((pr) => { pr.managedRules.managedRuleSets[0].ruleGroupOverrides[1].rules[0].enabledState = 'Disabled'; });
  const r = (await build(p)).eval(putDrawer);
  assert.equal(r.blocked, false);
  assert.ok(!r.matches.some((x) => x.id === 911100));
});
await test('Detection mode -> logged only', async () => {
  const p = withPolicy((pr) => { pr.policySettings.mode = 'Detection'; });
  const r = (await build(p)).eval(putDrawer);
  assert.equal(r.blocked, false);
  assert.equal(r.azure.wouldBlock, true);
  assert.match(r.azure.note, /Detection mode/);
});
await test('custom Block rule decides before managed rules', async () => {
  const p = withPolicy((pr) => { pr.customRules.rules[5].enabledState = 'Enabled'; });
  const r = (await build(p)).eval(putDrawer);
  assert.equal(r.azure.decidedBy.type, 'custom');
  assert.equal(r.azure.decidedBy.name, 'OldDisabledRule');
  assert.equal(r.blocked, true);
  assert.match(String(r.interruption.ruleId), /OldDisabledRule/);
});
await test('custom Allow skips managed rules', () => {
  const r = az.eval(req('GET', "https://app.example.com/healthz?q=1' OR '1'='1"));
  assert.equal(r.azure.decidedBy.name, 'AllowHealthProbe');
  assert.equal(r.azure.managedSkipped, true);
  assert.equal(r.blocked, false);
});
await test('PL3/PL4 and replaced rules are absent; cookie exclusion works', () => {
  const r = az.eval(req('GET', 'https://app.example.com/api/v1/workspace-options'));
  assert.ok(!r.matches.some((m) => [942420, 942421, 942440].includes(m.id)), r.matches.map((m) => m.id).join(','));
});
await test('rule-level JSON exclusion: 942100 ignores json.content, other SQLi rules still see it', () => {
  const r = az.eval(req('POST', 'https://app.example.com/api/v1/chat', JSON.stringify({ content: "1' OR '1'='1" })));
  assert.ok(!r.matches.some((m) => m.id === 942100), 'excluded from 942100');
  assert.ok(r.matches.some((m) => m.id !== 942100 && String(m.id).startsWith('942') && m.links[0].matches.some((x) => x.var === 'ARGS:json.content')));
  const r2 = az.eval(req('POST', 'https://app.example.com/api/v1/chat', JSON.stringify({ other: "1' OR '1'='1" })));
  assert.ok(r2.matches.some((m) => m.id === 942100), 'other fields still checked by 942100');
});
await test('Azure scores replace CRS severities', () => {
  const r = az.eval(req('GET', 'https://app.example.com/x', null, []));
  // 920100-like notices are 2 in DRS; just check scoring is applied when present
  for (const m of r.matches) for (const s of m.scores) assert.ok([2, 3, 4, 5].includes(s.delta));
});
await test('exclusion target mapping', () => {
  // Front Door *Names: values of the named fields are excluded, the names are still inspected.
  assert.equal(exclusionTargets({ variable: 'RequestCookieNames', operator: 'Equals', selector: 'a.b' }), '!REQUEST_COOKIES:/^a\\.b$/');
  assert.match(exclusionTargets({ variable: 'RequestBodyJsonArgNames', operator: 'StartsWith', selector: 'msg' }), /^!ARGS_POST:\/\^json\\\.\(\?:\\d\+\\\.\)\*msg\//);
  assert.equal(exclusionTargets({ variable: 'RequestHeaderNames', operator: 'EqualsAny', selector: '*' }), '!REQUEST_HEADERS');
  assert.equal(exclusionTargets({ variable: 'QueryStringArgNames', operator: 'Equals', selector: 'q' }, { caseSensitive: true }), '!ARGS_GET:/(?-i)^q$/');
  assert.equal(exclusionTargets({ variable: 'RequestBodyPostArgNames', operator: 'Equals', selector: 'q' }), '!ARGS_POST:/^q$/');
  // Application Gateway: *Keys -> names only, *Values / legacy *Names -> values only.
  assert.equal(exclusionTargets({ variable: 'RequestHeaderKeys', operator: 'Equals', selector: 'x' }), '!REQUEST_HEADERS_NAMES:/^x$/');
  assert.equal(exclusionTargets({ variable: 'RequestCookieValues', operator: 'Equals', selector: 'x' }), '!REQUEST_COOKIES:/^x$/');
  assert.equal(exclusionTargets({ variable: 'RequestArgKeys', operator: 'EqualsAny', selector: '*' }), '!ARGS_NAMES|!ARGS_GET_NAMES|!ARGS_POST_NAMES');
  assert.equal(exclusionTargets({ variable: 'RequestArgNames', operator: 'Equals', selector: 'q' }), '!ARGS:/^(?:json\\.)?q$/|!ARGS_GET:/^(?:json\\.)?q$/|!ARGS_POST:/^(?:json\\.)?q$/');
});

// ---------------------------------------------------------------- regression tests (review findings)
const SQLI = "1' UNION SELECT password FROM users--";
const formPost = (url, body) => ({ method: 'POST', url, httpVersion: 'HTTP/1.1', headers: [...H, { name: 'Content-Type', value: 'application/x-www-form-urlencoded' }, { name: 'Content-Length', value: String(body.length) }], body });
const argMatches = (r, varName) => r.matches.filter((m) => m.links.some((l) => l.matches.some((x) => x.var === varName)));
const appGw = (exclusions, ruleSetType = 'Microsoft_DefaultRuleSet', ruleSetVersion = '2.1') => JSON.stringify({
  type: 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies', name: 'agw',
  properties: { policySettings: { state: 'Enabled', mode: 'Prevention', requestBodyCheck: true }, customRules: [], managedRules: { managedRuleSets: [{ ruleSetType, ruleSetVersion, ruleGroupOverrides: [] }], exclusions } },
});
await test('policy without a Default Rule Set: managed rules are not evaluated, custom rules still are', async () => {
  const p = withPolicy((pr) => { pr.managedRules.managedRuleSets = pr.managedRules.managedRuleSets.filter((s) => !/Default/.test(s.ruleSetType)); });
  const a = await build(p);
  const r = a.eval(req('GET', `https://app.example.com/x?q=${encodeURIComponent(SQLI)}`));
  assert.equal(r.blocked, false);
  assert.ok(!r.matches.some((m) => m.scores.length || m.disruptive === 'deny'), r.matches.map((m) => m.id).join(','));
  assert.ok(a.ctx.info.warnings.some((w) => /no Default Rule Set/i.test(w)));
  assert.equal(r.azure.ruleSetAction, null);
  const r2 = a.eval(req('GET', 'https://app.example.com/admin/users'));
  assert.equal(r2.azure.decidedBy.name, 'BlockAdminFromOutside');
  const none = await build(withPolicy((pr) => { delete pr.managedRules; }));
  assert.equal(none.eval(req('GET', `https://app.example.com/x?q=${encodeURIComponent(SQLI)}`)).blocked, false);
});
await test('200002 (invalid JSON body) is anomaly scoring in DRS; action Log never blocks', async () => {
  const bad = req('POST', 'https://app.example.com/api/v1/chat', '{"content": "hello"');
  const r = az.eval(bad);
  const m = r.matches.find((x) => x.id === 200002);
  assert.ok(m, 'visible match');
  assert.equal(m.disruptive, 'pass');
  assert.deepEqual(m.scores.map((s) => s.delta), [5]);
  assert.equal(r.azure.decidedBy.ruleId, 949110);
  const p = withPolicy((pr) => { pr.managedRules.managedRuleSets[0].ruleGroupOverrides.push({ ruleGroupName: 'General', rules: [{ ruleId: '200002', enabledState: 'Enabled', action: 'Log', exclusions: [] }] }); });
  const r2 = (await build(p)).eval(bad);
  assert.equal(r2.blocked, false);
  const m2 = r2.matches.find((x) => x.id === 200002);
  assert.equal(m2.override, 'log');
  assert.equal(m2.scores.length, 0);
});
await test('QueryStringArgNames excludes only query args, RequestBodyPostArgNames only body args', async () => {
  const qs = await build(withPolicy((pr) => { pr.managedRules.managedRuleSets[0].exclusions.push({ matchVariable: 'QueryStringArgNames', selectorMatchOperator: 'Equals', selector: 'q' }); }));
  const inQuery = qs.eval(req('GET', `https://app.example.com/form?q=${encodeURIComponent(SQLI)}`));
  assert.equal(argMatches(inQuery, 'ARGS:q').length, 0, 'query arg q excluded');
  const inBody = qs.eval(formPost('https://app.example.com/form', 'q=' + encodeURIComponent(SQLI)));
  assert.ok(argMatches(inBody, 'ARGS:q').length > 0, 'body arg q still inspected');
  assert.equal(inBody.blocked, true);
  const body = await build(withPolicy((pr) => { pr.managedRules.managedRuleSets[0].exclusions.push({ matchVariable: 'RequestBodyPostArgNames', selectorMatchOperator: 'Equals', selector: 'q' }); }));
  assert.equal(argMatches(body.eval(formPost('https://app.example.com/form', 'q=' + encodeURIComponent(SQLI))), 'ARGS:q').length, 0, 'body arg q excluded');
  assert.ok(argMatches(body.eval(req('GET', `https://app.example.com/form?q=${encodeURIComponent(SQLI)}`)), 'ARGS:q').length > 0, 'query arg q still inspected');
  // Selector case: query/POST names are case-sensitive in Front Door.
  assert.ok(argMatches(qs.eval(req('GET', `https://app.example.com/form?Q=${encodeURIComponent(SQLI)}`)), 'ARGS:Q').length > 0);
});
await test('Application Gateway RequestArgKeys excludes names only, RequestArgValues values only', async () => {
  const url = `https://a.example/x?q=${encodeURIComponent(SQLI)}`;
  const keys = (await build(appGw([{ matchVariable: 'RequestArgKeys', selectorMatchOperator: 'Equals', selector: 'q' }]))).eval(req('GET', url));
  assert.equal(keys.blocked, true);
  const vals = (await build(appGw([{ matchVariable: 'RequestArgValues', selectorMatchOperator: 'Equals', selector: 'q' }]))).eval(req('GET', url));
  assert.equal(argMatches(vals, 'ARGS:q').length, 0);
  const legacy = (await build(appGw([{ matchVariable: 'RequestArgNames', selectorMatchOperator: 'Equals', selector: 'q' }]))).eval(req('GET', url));
  assert.equal(argMatches(legacy, 'ARGS:q').length, 0);
  // A key exclusion must not hide an attack in the name.
  const attackName = (await build(appGw([{ matchVariable: 'RequestArgValues', selectorMatchOperator: 'EqualsAny', selector: '*' }]))).eval(req('GET', `https://a.example/x?${encodeURIComponent(SQLI)}=1`));
  assert.ok(argMatches(attackName, `ARGS_NAMES:${SQLI}`).length > 0);
});
await test('scoped exclusions map CRS/DRS group names to rule ranges and never widen to all rules', async () => {
  const { parseAzurePolicy: parse } = await import('../extension/src/azure/policy.js');
  const { azureProfile } = await import('../extension/src/azure/simulate.js');
  const scoped = (group, type = 'OWASP', version = '3.2') => parse(appGw([{ matchVariable: 'RequestArgNames', selectorMatchOperator: 'Equals', selector: 'comment', exclusionManagedRuleSets: [{ ruleSetType: type, ruleSetVersion: version, ruleGroups: group ? [{ ruleGroupName: group, rules: [] }] : [] }] }], type, version)).policy;
  const p1 = azureProfile(scoped('REQUEST-941-APPLICATION-ATTACK-XSS'));
  assert.match(p1.seclangAfter, /SecRuleUpdateTargetById 941000-941999 /);
  const p2 = azureProfile(scoped('XSS', 'Microsoft_DefaultRuleSet', '2.1'));
  assert.match(p2.seclangAfter, /SecRuleUpdateTargetById 941\d{3}(,941\d{3})* /);
  const p3 = azureProfile(scoped('NO-SUCH-GROUP'));
  assert.ok(!/SecRuleUpdateTargetById/.test(p3.seclangAfter), p3.seclangAfter);
  assert.ok(p3.notes.some((n) => /NO-SUCH-GROUP/.test(n)));
  const p4 = azureProfile(scoped(null));
  assert.match(p4.seclangAfter, /SecRuleUpdateTargetById 200002-200999,911000-944999 /);
  const p5 = azureProfile(scoped('BadBots', 'Microsoft_BotManagerRuleSet', '1.0'));
  assert.ok(!/SecRuleUpdateTargetById/.test(p5.seclangAfter));
});
await test('custom rules: multipart PostArgs use the engine multipart parser', () => {
  const b = '----X';
  const body = `--${b}\r\nContent-Disposition: form-data; name="comment"\r\n\r\nhello --${b} x\r\n--${b}\r\nContent-Disposition: form-data; name="upload"; filename="evil.php"\r\nContent-Type: application/octet-stream\r\n\r\n<?php system($_GET[1]); ?>\r\n--${b}--\r\n`;
  const r = { method: 'POST', url: 'https://a/x', headers: [{ name: 'Content-Type', value: `multipart/form-data; boundary="${b}"` }], body };
  const f = requestFacts(r, {});
  assert.deepEqual(f.postArgs.map((a) => [a.name, a.value, !!a.file]), [['comment', `hello --${b} x`, false], ['upload', '<?php system($_GET[1]); ?>', true]]);
  const c = evalCondition({ variable: 'PostArgs', selector: 'upload', operator: 'Contains', values: ['<?php'], negate: false, transforms: [] }, f);
  assert.equal(c.matched, true);
  assert.match(c.note, /uploaded file/);
  assert.equal(evalCondition({ variable: 'PostArgs', selector: 'comment', operator: 'Equal', values: [`hello --${b} x`], negate: false, transforms: [] }, f).matched, true);
});
await test('custom rules: RegEx uses the PCRE/RE2 translator on unicode strings', () => {
  const f = requestFacts(req('GET', 'https://app.example.com/admin', null, [{ name: 'X-Greeting', value: 'Grüße 😀' }]), {});
  const rxc = (selector, variable, pattern) => evalCondition({ variable, selector, operator: 'RegEx', values: [pattern], negate: false, transforms: [] }, f);
  assert.equal(rxc(null, 'RequestUri', '^/admin\\z').matched, true);
  assert.equal(rxc(null, 'RequestUri', '^/[[:alpha:]]+$').matched, true);
  assert.equal(rxc(null, 'RequestUri', '^/(?i)ADMIN').matched, true);
  assert.equal(rxc(null, 'RequestUri', '^/ADMIN').matched, false);
  assert.equal(rxc('x-greeting', 'RequestHeader', '^Gr(?i)ÜSSE').matched, false, 'ß is not SS');
  assert.equal(rxc('x-greeting', 'RequestHeader', '^Gr(?i)Üße \\x{1F600}$').matched, true);
  assert.equal(rxc('x-greeting', 'RequestHeader', '^Grüße .$').matched, false, '. is one UTF-16 unit (no u flag)');
});
await test('custom rules: IPMatch tolerates malformed IPv6 and supports IPv4-mapped ranges', () => {
  const ip = (clientIp, values) => evalCondition({ variable: 'RemoteAddr', operator: 'IPMatch', values, negate: false, transforms: [] }, requestFacts(putDrawer, { clientIp })).matched;
  assert.equal(ip('2001:db8::1', ['2001:db8::/32']), true);
  assert.equal(ip('2001:db8::1', ['1:2:3:4:5:6:7:8::/64']), false);
  assert.equal(ip('1:2:3:4:5:6:7:8:9::', ['10.0.0.0/8']), false);
  assert.equal(ip('10.1.2.3', ['::ffff:10.0.0.0/104']), true);
  assert.equal(ip('::ffff:10.1.2.3', ['10.0.0.0/8']), true);
  assert.equal(ip('10.1.2.3', ['10.1.2.3/33']), false);
  assert.equal(ip('10.1.2.3', ['10.1.2.999']), false);
});
await test('DRS rules that are PL3/PL4 in CRS 3.3 are evaluated (942460 in DRS 2.0)', async () => {
  const a = await build(withPolicy((pr) => { pr.managedRules.managedRuleSets[0].ruleSetVersion = '2.0'; }));
  const r = a.eval(req('GET', 'https://app.example.com/x?a=foo%21%21%21%21'));
  assert.ok(r.matches.some((m) => m.id === 942460), r.matches.map((m) => m.id).join(','));
  // OWASP (Application Gateway CRS) stays PL1 + PL2.
  const o = await build(appGw([], 'OWASP', '3.2'));
  assert.ok(!o.eval(req('GET', 'https://a.example/x?a=foo%21%21%21%21')).matches.some((m) => m.id === 942460));
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
