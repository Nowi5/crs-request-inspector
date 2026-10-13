// Generates WAF tuning snippets (rule exclusions) for a false positive.
// Pure functions, unit-tested in scripts/test-ui-logic.mjs.

import { describeVar, splitUrl } from './format.js';
import { shellQuote } from './export.js';

/** Terraform string literal: escapes backslash, quote and template sequences. */
export function tfString(v) {
  return '"' + String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\$\{/g, '$$${').replace(/%\{/g, '%%{') + '"';
}

/** Bicep string literal: escapes backslash, quote and interpolation. */
export function bicepString(v) {
  return "'" + String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\$\{/g, '\\${') + "'";
}
import { DRS } from '../azure/drs-data.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUMBER = /^\d+$/;
const HEX_ID = /^[0-9a-f]{16,}$/i; // Mongo ObjectIds, hashes
const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;

/** True when a path segment looks like an identifier (UUID, number, hash, opaque token). */
export function isIdSegment(seg) {
  const s = String(seg);
  if (!s) return false;
  if (UUID.test(s) || NUMBER.test(s) || HEX_ID.test(s) || ULID.test(s)) return true;
  // Opaque tokens: long, mixes letters and digits, no dots (file names keep their literal form).
  if (s.length >= 20 && /^[A-Za-z0-9_~-]+$/.test(s) && /\d/.test(s) && /[A-Za-z]/.test(s)) return true;
  // Prefixed numeric ids like "INV-2024-000123" are kept literal; plain email-ish/encoded segments too.
  return false;
}

/** Escape a string for use inside a PCRE regex. */
export function escapeRegex(s) {
  return String(s).replace(/[\\^$.|?*+()[\]{}]/g, '\\$&');
}

/**
 * Literal text as a PCRE fragment that is safe inside any SecLang context (operator argument,
 * action list, target list): "." and "/" become \. and \/, every other byte outside
 * [A-Za-z0-9_-] becomes \xHH (UTF-8), so quotes, commas, semicolons, pipes and backslashes
 * from request data can never change the rule.
 */
export function pcreLiteral(s) {
  let out = '';
  for (const b of new TextEncoder().encode(String(s))) {
    const c = String.fromCharCode(b);
    if (/[A-Za-z0-9_-]/.test(c)) out += c;
    else if (c === '.' || c === '/') out += '\\' + c;
    else out += '\\x' + b.toString(16).padStart(2, '0');
  }
  return out;
}

/** Escape a value for a double-quoted SecLang argument. */
export function escapeSecLangString(s) {
  return String(s).replace(/"/g, '\\"');
}

/**
 * Generalise a URL path into an anchored regex: identifier-like segments become `[^/]+`.
 * "/api/v1/docs/folders/5d2c6e1a-…/comments" -> "^/api/v1/docs/folders/[^/]+/comments$"
 */
export function generalizePath(path) {
  let p = String(path || '/');
  const cut = p.search(/[?#]/);
  if (cut >= 0) p = p.slice(0, cut);
  if (!p.startsWith('/')) p = '/' + p;
  const parts = p.split('/').map((seg) => {
    if (isIdSegment(seg)) return '[^/]+';
    // Ids embedded in a segment ("normal_489275.jpg", "invoice-2024.pdf"): digit runs of 3+ become [0-9]+.
    return pcreLiteral(seg).replace(/(?<!\\x[0-9a-f]?)\d{3,}/g, '[0-9]+');
  });
  return `^${parts.join('/')}$`;
}

/** Whether a variable name can be written literally as a SecLang target (else use a regex key). */
function safeKey(key) {
  return /^[A-Za-z0-9_.\-[\]]+$/.test(key);
}

/**
 * The SecLang target for a matched variable, e.g. "ARGS:json.content" or "REQUEST_URI_RAW".
 * Returns null for variables that cannot be excluded (TX, MATCHED_VARS, ...).
 */
export function exclusionTarget(match) {
  if (!match) return null;
  const raw = String(match.var || '');
  const i = raw.indexOf(':');
  const collection = String(match.collection || (i >= 0 ? raw.slice(0, i) : raw)).toUpperCase();
  const key = match.key != null ? String(match.key) : i >= 0 ? raw.slice(i + 1) : null;
  if (['TX', 'MATCHED_VAR', 'MATCHED_VARS', 'MATCHED_VAR_NAME', 'MATCHED_VARS_NAMES', 'IP', 'GLOBAL', 'SESSION', 'RULE', 'ENV', 'TIME', 'DURATION'].includes(collection)) return null;
  if (key == null || key === '') return collection;
  if (safeKey(key)) return `${collection}:${key}`;
  return `${collection}:/^${pcreLiteral(key)}$/`;
}

const AZURE_VARS = {
  json: { appgw: 'RequestBodyJsonArgNames', afd: 'RequestBodyJsonArgNames', label: 'Request body JSON arg names' },
  query: { appgw: 'RequestArgNames', afd: 'QueryStringArgNames', label: 'Request arg names (query string)' },
  form: { appgw: 'RequestBodyPostArgNames', afd: 'RequestBodyPostArgNames', label: 'Request body post arg names' },
  multipart: { appgw: 'RequestBodyPostArgNames', afd: 'RequestBodyPostArgNames', label: 'Request body post arg names' },
  body: { appgw: 'RequestBodyPostArgNames', afd: 'RequestBodyPostArgNames', label: 'Request body post arg names' },
  argname: null,
  header: { appgw: 'RequestHeaderNames', afd: 'RequestHeaderNames', label: 'Request header names' },
  headername: { appgw: 'RequestHeaderNames', afd: 'RequestHeaderNames', label: 'Request header names' },
  cookie: { appgw: 'RequestCookieNames', afd: 'RequestCookieNames', label: 'Request cookie names' },
  cookiename: { appgw: 'RequestCookieNames', afd: 'RequestCookieNames', label: 'Request cookie names' },
};

/**
 * Build exclusion snippets for one rule match.
 *
 * @param {object} p
 * @param {number} p.ruleId
 * @param {object|null} p.match       primary variable match ({var, collection, key})
 * @param {string} p.path             REQUEST_FILENAME (or URL)
 * @param {string} [p.file]           rule file (for the Azure rule group)
 * @param {object} [p.ctx]            describeVar context (argsGet/argsPost/bodyProcessor)
 * @param {number} [p.exclusionId]    id for the generated runtime rule
 * @param {{kind: 'frontdoor'|'appgw', version: string}|null} [p.azure]  simulated Azure policy, if any
 * @returns {Array<{id: string, title: string, description: string, code: string, language: 'seclang'|'json'|'text', available: boolean}>}
 */
export function buildExclusions({ ruleId, match, path, file, ctx, exclusionId = 1000001, azure = null }) {
  const target = exclusionTarget(match);
  const info = match ? describeVar(match, ctx) : null;
  const pathRx = generalizePath(path && /^[a-z]+:\/\//i.test(path) ? splitUrl(path).path : path);
  const pathArg = escapeSecLangString(pathRx);
  const out = [];
  const where = info ? info.label.replace(/[“”]/g, '') : 'this variable';

  if (target) {
    out.push({
      id: 'runtime-target',
      title: 'Runtime exclusion — this endpoint, this variable',
      description: `Stops rule ${ruleId} from inspecting ${where} on matching URLs only. Put it in the rules loaded before CRS (REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf).`,
      code: `SecRule REQUEST_FILENAME "@rx ${pathArg}" \\\n    "id:${exclusionId},\\\n    phase:1,\\\n    pass,\\\n    t:none,\\\n    nolog,\\\n    ctl:ruleRemoveTargetById=${ruleId};${target}"`,
      language: 'seclang',
      available: true,
    });
  }
  out.push({
    id: 'runtime-rule',
    title: 'Runtime exclusion — this endpoint, whole rule',
    description: `Disables rule ${ruleId} completely for matching URLs. Broader than a target exclusion; use when the rule hits several variables.`,
    code: `SecRule REQUEST_FILENAME "@rx ${pathArg}" \\\n    "id:${exclusionId + (target ? 1 : 0)},\\\n    phase:1,\\\n    pass,\\\n    t:none,\\\n    nolog,\\\n    ctl:ruleRemoveById=${ruleId}"`,
    language: 'seclang',
    available: true,
  });
  if (target) {
    out.push({
      id: 'configure-target',
      title: 'Configure-time exclusion — everywhere, this variable',
      description: `Removes ${where} from rule ${ruleId} for all URLs. Must be placed after CRS is loaded (RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf).`,
      code: `SecRuleUpdateTargetById ${ruleId} "!${escapeSecLangString(target)}"`,
      language: 'seclang',
      available: true,
    });
  }
  out.push(...azureExclusion({ ruleId, info, file, azure }));
  return out;
}

/** "REQUEST-942-APPLICATION-ATTACK-SQLI.conf" -> "REQUEST-942-APPLICATION-ATTACK-SQLI" */
export function ruleGroupName(file) {
  return String(file || '').replace(/\.conf$/i, '') || 'General';
}

const CRS_FILE_GROUPS = { 200: 'General', 911: 'METHOD-ENFORCEMENT', 920: 'PROTOCOL-ENFORCEMENT', 921: 'PROTOCOL-ATTACK', 930: 'LFI', 931: 'RFI', 932: 'RCE', 933: 'PHP', 934: 'NODEJS', 941: 'XSS', 942: 'SQLI', 943: 'FIX', 944: 'JAVA' };

/** DRS rule group of a rule id (from the DRS tables, else derived from the CRS file number). */
export function drsGroup(ruleId, version = '2.1') {
  const r = DRS[version]?.rules?.[ruleId] || DRS['2.1']?.rules?.[ruleId];
  if (r) return r.group;
  return CRS_FILE_GROUPS[Math.floor(Number(ruleId) / 1000)] || null;
}

/** Is the rule part of the given DRS version at all? */
export function inDrs(ruleId, version = '2.1') {
  return !!(DRS[version] || DRS['2.1']).rules[ruleId];
}

function azureExclusion({ ruleId, info, azure }) {
  const version = azure?.version && DRS[azure.version] ? azure.version : '2.1';
  const kind = azure?.kind || 'frontdoor';
  const az = info ? AZURE_VARS[info.kind] : null;
  const group = drsGroup(ruleId, version) || 'SQLI';
  if (Number.isFinite(Number(ruleId)) && Number(ruleId) >= 911000 && !inDrs(ruleId, version)) {
    return [{
      id: 'azure',
      title: `Azure WAF (DRS ${version})`,
      description: `Rule ${ruleId} does not exist in Azure's Default Rule Set ${version} (Azure only runs paranoia levels 1–2 and replaces some OWASP rules) – no Azure exclusion is needed.`,
      code: `# Not applicable to Azure WAF DRS ${version}`,
      language: 'text',
      available: false,
    }];
  }
  if (!az || !info.name) {
    const disable = { ruleSetType: 'Microsoft_DefaultRuleSet', ruleSetVersion: version, ruleGroupOverrides: [{ ruleGroupName: group, rules: [{ ruleId: String(ruleId), enabledState: 'Disabled', action: 'AnomalyScoring', exclusions: [] }] }] };
    return [{
      id: 'azure',
      title: 'Azure WAF (Front Door / Application Gateway)',
      description: `Azure WAF exclusions cannot target ${info ? info.label.replace(/[“”]/g, '') : 'this variable'}. Disable rule ${ruleId} (or set its action to Log) in the managed rules, or add a narrowly scoped custom rule.`,
      code: JSON.stringify(disable, null, 2),
      language: 'json',
      available: false,
      variants: [
        { id: 'json', label: 'Front Door JSON', language: 'json', code: JSON.stringify(disable, null, 2) },
        { id: 'cli', label: 'Azure CLI', language: 'text', code: `az network front-door waf-policy managed-rules override add \\\n  --resource-group <resource-group> --policy-name <policy> \\\n  --type Microsoft_DefaultRuleSet --rule-group-id ${group} --rule-id ${ruleId} \\\n  --disabled true --action Log` },
        { id: 'terraform', label: 'Terraform', language: 'text', code: tfManaged(version, group, ruleId, null, false) },
      ],
    }];
  }
  const selector = info.name;
  const ex = { matchVariable: az.afd, selectorMatchOperator: 'Equals', selector };
  const fd = {
    ruleSetType: 'Microsoft_DefaultRuleSet',
    ruleSetVersion: version,
    ruleGroupOverrides: [{ ruleGroupName: group, rules: [{ ruleId: String(ruleId), enabledState: 'Enabled', action: 'AnomalyScoring', exclusions: [ex] }] }],
  };
  const q = (v) => (/^[A-Za-z0-9_.\-[\]]+$/.test(String(v)) ? String(v) : shellQuote(v));
  const appgw = {
    matchVariable: az.appgw,
    selectorMatchOperator: 'Equals',
    selector,
    exclusionManagedRuleSets: [{ ruleSetType: 'Microsoft_DefaultRuleSet', ruleSetVersion: version, ruleGroups: [{ ruleGroupName: group, rules: [{ ruleId: String(ruleId) }] }] }],
  };
  const variants = [
    { id: 'json', label: 'Front Door JSON', language: 'json', code: JSON.stringify(fd, null, 2) },
    { id: 'cli', label: 'Azure CLI', language: 'text', code: `az network front-door waf-policy managed-rules exclusion add \\\n  --resource-group <resource-group> --policy-name <policy> \\\n  --type Microsoft_DefaultRuleSet --rule-group-id ${group} --rule-id ${ruleId} \\\n  --match-variable ${az.afd} --operator Equals --value ${q(selector)}` },
    { id: 'terraform', label: 'Terraform', language: 'text', code: tfManaged(version, group, ruleId, { variable: az.afd, selector }, true) },
    { id: 'bicep', label: 'Bicep', language: 'text', code: bicepManaged(version, group, ruleId, { variable: az.afd, selector }) },
    { id: 'appgw', label: 'App Gateway JSON', language: 'json', code: JSON.stringify(appgw, null, 2) },
  ];
  if (kind === 'appgw') variants.unshift(variants.pop());
  return [{
    id: 'azure',
    title: `Azure WAF – rule exclusion (DRS ${version}, group ${group})`,
    description: `Excludes ${az.label} equals “${selector}” from rule ${ruleId} only. Pick your format: merge the JSON into managedRules.managedRuleSets, run the CLI command, or add the block to your Terraform / Bicep policy.`,
    code: variants[0].code,
    language: variants[0].language,
    available: true,
    variants,
  }];
}

function tfManaged(version, group, ruleId, exclusion, enabled) {
  const ex = exclusion
    ? `\n      exclusion {\n        match_variable = "${exclusion.variable}"\n        operator       = "Equals"\n        selector       = ${tfString(exclusion.selector)}\n      }`
    : '';
  return `# azurerm_cdn_frontdoor_firewall_policy (Front Door Standard/Premium)
managed_rule {
  type    = "Microsoft_DefaultRuleSet"
  version = "${version}"
  action  = "Block"

  override {
    rule_group_name = "${group}"
    rule {
      rule_id = "${ruleId}"
      enabled = ${enabled ? 'true' : 'false'}
      action  = "${enabled ? 'AnomalyScoring' : 'Log'}"${ex}
    }
  }
}`;
}

function bicepManaged(version, group, ruleId, exclusion) {
  return `// Microsoft.Network/FrontDoorWebApplicationFirewallPolicies – properties.managedRules.managedRuleSets
{
  ruleSetType: 'Microsoft_DefaultRuleSet'
  ruleSetVersion: '${version}'
  ruleGroupOverrides: [
    {
      ruleGroupName: '${group}'
      rules: [
        {
          ruleId: '${ruleId}'
          enabledState: 'Enabled'
          action: 'AnomalyScoring'
          exclusions: [
            {
              matchVariable: '${exclusion.variable}'
              selectorMatchOperator: 'Equals'
              selector: ${bicepString(exclusion.selector)}
            }
          ]
        }
      ]
    }
  ]
}`;
}
