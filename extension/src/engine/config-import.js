// Import a ModSecurity / Coraza / CRS configuration (crs-setup.conf, REQUEST-900/RESPONSE-999
// exclusion files, custom rule files) into the extension settings.
//  - tx.* setup variables (paranoia levels, thresholds, CRS version) become settings
//  - SecRuleUpdate* / SecRuleRemove* directives go into "custom rules after CRS"
//  - everything else (SecAction/SecRule exclusions, crs-setup variables) goes "before CRS"

import { parseConfig, parseActions } from './seclang.js';

const AFTER = /^secrule(update|remove)/i;
const CORE_VARS = new Set(['blocking_paranoia_level', 'paranoia_level', 'detection_paranoia_level', 'executing_paranoia_level', 'inbound_anomaly_score_threshold', 'outbound_anomaly_score_threshold', 'crs_setup_version', 'early_blocking']);
const IGNORED = /^(include|includeoptional|loadmodule|<\/?ifmodule|<\/?location|<\/?virtualhost|secauditlog\w*|secauditengine|secdebuglog\w*|sectmpdir|secdatadir|secunicodemapfile|secstatusengine|secresponsebodymimetype|seccomponentsignature)$/i;

/**
 * @param {string} text
 * @param {{ versions?: string[] }} opts  available CRS versions (e.g. ['v4.30.0','v4.25.2','v3.3.10'])
 * @returns {{ settings: object, before: string, after: string, detected: string[], warnings: string[], directives: number }}
 */
export function importModsecConfig(text, { versions = [] } = {}) {
  const { directives, errors } = parseConfig(String(text || ''), 'import');
  const warnings = errors.map((e) => `Line ${e.line}: ${e.message}`);
  const settings = {};
  const detected = [];
  const before = [];
  const after = [];
  const tx = {};
  for (const d of directives) {
    const name = d.name;
    if (IGNORED.test(name)) {
      if (/^include/i.test(name)) warnings.push(`Line ${d.line}: ${name} ${d.args[0] || ''} – included files are not loaded; paste their content as well.`);
      continue;
    }
    if (/^secruleengine$/i.test(name)) {
      if (/detectiononly/i.test(d.args[0] || '')) warnings.push('SecRuleEngine DetectionOnly: your WAF only logs – nothing is blocked in production. The extension still shows what would be blocked with the engine On.');
      if (/^off$/i.test(d.args[0] || '')) warnings.push('SecRuleEngine Off: the WAF is disabled.');
      detected.push(`SecRuleEngine ${d.args[0]}`);
      continue;
    }
    if (/^sec(rule|action)$/i.test(name)) {
      const actions = parseActions(name.toLowerCase() === 'secaction' ? d.args[0] || '' : d.args[2] || '');
      const setvars = [];
      for (const a of actions) {
        if (a.name.toLowerCase() !== 'setvar' || !a.value) continue;
        const m = /^tx\.([\w-]+)=(.*)$/i.exec(a.value.trim());
        if (m) {
          tx[m[1].toLowerCase()] = m[2].trim();
          setvars.push(m[1].toLowerCase());
        }
      }
      // SecActions that only set levels/thresholds/version become settings (so the toolbar PL buttons keep working).
      if (name.toLowerCase() === 'secaction' && setvars.length && setvars.every((v) => CORE_VARS.has(v))) continue;
    }
    (AFTER.test(name) ? after : before).push(d.raw);
  }
  const num = (k) => (tx[k] != null && /^\d+$/.test(tx[k]) ? Number(tx[k]) : null);
  const bpl = num('blocking_paranoia_level') ?? num('paranoia_level');
  const dpl = num('detection_paranoia_level') ?? num('executing_paranoia_level');
  if (bpl) {
    settings.blockingParanoiaLevel = Math.min(4, Math.max(1, bpl));
    detected.push(`Blocking paranoia level ${settings.blockingParanoiaLevel}`);
  }
  if (dpl) {
    settings.detectionParanoiaLevel = Math.min(4, Math.max(settings.blockingParanoiaLevel || 1, dpl));
    detected.push(`Detection paranoia level ${settings.detectionParanoiaLevel}`);
  }
  if (num('inbound_anomaly_score_threshold')) {
    settings.inboundThreshold = num('inbound_anomaly_score_threshold');
    detected.push(`Inbound threshold ${settings.inboundThreshold}`);
  }
  if (num('outbound_anomaly_score_threshold')) {
    settings.outboundThreshold = num('outbound_anomaly_score_threshold');
    detected.push(`Outbound threshold ${settings.outboundThreshold}`);
  }
  if (tx.early_blocking === '1') {
    settings.earlyBlocking = true;
    detected.push('Early blocking on');
  }
  const setup = num('crs_setup_version');
  if (setup && versions.length) {
    const major = setup >= 400 ? '4' : '3';
    const pick = versions.find((v) => v.replace(/^v/, '').startsWith(major + '.'));
    if (pick) {
      settings.version = pick;
      detected.push(`CRS ${major}.x (crs_setup_version ${setup}) → using ${pick}`);
    }
  }
  if (tx.allowed_methods) detected.push(`Allowed methods: ${tx.allowed_methods.replace(/^'|'$/g, '')}`);
  if (tx.allowed_request_content_type) detected.push('Custom allowed content types');
  const exclusions = [...before, ...after].filter((r) => /ctl:ruleRemove|SecRuleRemove|SecRuleUpdateTarget/i.test(r)).length;
  if (exclusions) detected.push(`${exclusions} exclusion directive${exclusions === 1 ? '' : 's'}`);
  return { settings, before: before.join('\n'), after: after.join('\n'), detected, warnings, directives: directives.length };
}
