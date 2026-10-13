// Settings drawer: WAF configuration used for the analysis.

import { h, icon } from '../dom.js';
import { parseAzurePolicy, summarizePolicy } from '../../azure/policy.js';
import { FORMAT_LABELS, detectWafConfigFormat } from '../../azure/iac.js';
import { importModsecConfig } from '../../engine/config-import.js';

const FIELD_DEFAULTS = {
  version: null,
  blockingParanoiaLevel: 1,
  detectionParanoiaLevel: 4,
  inboundThreshold: 5,
  outboundThreshold: 4,
  earlyBlocking: false,
  includeModsecRecommended: true,
  evaluateResponses: true,
  continueAfterBlock: true,
  remoteAddr: '203.0.113.10',
  protocolOverride: '',
  customRulesBefore: '',
  customRulesAfter: '',
  wafProfile: 'crs',
  azurePolicy: '',
  clientCountry: '',
  clientIp: '',
};

/**
 * @param {{ host: object, onApply(partial): Promise<void>, onClose(): void }} cb
 */
export function createSettingsDrawer(cb) {
  const body = h('div.drawer-body');
  const applyBtn = h('button.btn.btn-primary', { type: 'submit', disabled: true }, 'Apply');
  const resetBtn = h('button.btn', { type: 'button', title: 'Restore the default settings (not applied until you click Apply)', on: { click: () => { fill({ ...FIELD_DEFAULTS, version: draft.version }); markDirty(); } } }, 'Defaults');
  const status = h('span.drawer-status.muted', { 'aria-live': 'polite' });
  const form = h('form.drawer-form', { on: { submit: (e) => { e.preventDefault(); apply(); } } },
    h('header.drawer-head', h('h2', icon('gear'), 'WAF settings'), h('button.icon-btn', { type: 'button', title: 'Close (Esc)', 'aria-label': 'Close settings', on: { click: () => cb.onClose() } }, icon('close'))),
    body,
    h('footer.drawer-foot', status, h('span.spacer'), resetBtn, applyBtn));
  const el = h('aside.drawer', { 'aria-label': 'Settings', hidden: true }, form);

  let draft = {};
  let original = {};
  let lastInfoSig = '';

  function markDirty() {
    const dirty = JSON.stringify(normalize(draft)) !== JSON.stringify(normalize(original));
    applyBtn.disabled = !dirty;
    status.textContent = dirty ? 'Unsaved changes — Apply re-analyzes all requests' : '';
  }
  function normalize(s) {
    const o = { ...s };
    for (const k of ['blockingParanoiaLevel', 'detectionParanoiaLevel', 'inboundThreshold', 'outboundThreshold']) o[k] = Number(o[k]);
    return o;
  }

  const set = (k) => (e) => {
    const t = e.target;
    draft[k] = t.type === 'checkbox' ? t.checked : t.type === 'number' ? Number(t.value) : t.value;
    if (k === 'blockingParanoiaLevel' && Number(draft.detectionParanoiaLevel) < Number(draft.blockingParanoiaLevel)) {
      draft.detectionParanoiaLevel = draft.blockingParanoiaLevel;
      fill(draft);
    }
    markDirty();
  };

  function segmented(name, key, value, min = 1) {
    return h('div.segmented', { role: 'radiogroup', 'aria-label': name },
      [1, 2, 3, 4].map((n) => h('label.seg-opt', { title: `${name}: PL${n}` },
        h('input', { type: 'radio', name: key, value: String(n), checked: Number(value) === n, disabled: n < min, on: { change: () => { draft[key] = n; if (key === 'blockingParanoiaLevel') { if (Number(draft.detectionParanoiaLevel) < n) draft.detectionParanoiaLevel = n; } fill(draft); markDirty(); body.querySelector(`input[name="${key}"][value="${n}"]`)?.focus(); } } }),
        h('span', `PL${n}`))));
  }

  function field(label, control, hint) {
    return h('div.field', h('label.field-label', label), control, hint ? h('div.field-hint', hint) : null);
  }

  function toggle(label, key, hint) {
    return h('label.switch-row',
      h('input', { type: 'checkbox', checked: !!draft[key], on: { change: set(key) } }),
      h('span.switch', { 'aria-hidden': 'true' }),
      h('span.switch-text', h('span', label), hint ? h('span.field-hint', hint) : null));
  }

  function profileSection(info) {
    const azure = draft.wafProfile === 'azure';
    const choice = h('div.segmented.profile-choice', { role: 'radiogroup', 'aria-label': 'WAF profile' },
      [['crs', 'OWASP CRS – ModSecurity, Coraza, other CRS-based WAFs'], ['azure', 'Azure WAF policy – Front Door / Application Gateway']].map(([v, l]) =>
        h('label.seg-opt', h('input', { type: 'radio', name: 'wafProfile', value: v, checked: draft.wafProfile === v, on: { change: () => { draft.wafProfile = v; fill(draft); markDirty(); body.querySelector(`input[name="wafProfile"][value="${v}"]`)?.focus(); } } }), h('span', l))));
    const children = [h('h3', 'WAF profile'), choice];
    if (!azure) children.push(modsecImport(info));
    if (azure) {
      const fileInput = h('input', { type: 'file', accept: '.json,.tf,.bicep,.txt,application/json', hidden: true, on: { change: async (e) => { const f = e.target.files[0]; e.target.value = ''; if (!f) return; draft.azurePolicy = await f.text(); fill(draft); markDirty(); } } });
      const preview = h('div.policy-preview');
      const ta = h('textarea.input.code-input', {
        rows: '8', spellcheck: false, value: draft.azurePolicy || '',
        placeholder: 'Paste your WAF policy here – detected automatically:\n• JSON: Azure portal → WAF policy → Overview → JSON View, az network front-door waf-policy show, ARM export\n• Terraform: resource "azurerm_cdn_frontdoor_firewall_policy" / "azurerm_web_application_firewall_policy"\n• Bicep: resource … \'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies@…\'',
        on: { input: (e) => { draft.azurePolicy = e.target.value; renderPreview(preview, draft.azurePolicy, info); markDirty(); } },
      });
      children.push(
        field('Azure WAF policy (JSON, Terraform or Bicep)', h('div', ta, h('div.policy-actions', h('button.btn.btn-sm', { type: 'button', on: { click: () => fileInput.click() } }, icon('upload'), h('span', 'Load file…')), fileInput)),
          'Stored only in this browser. Custom rules, managed rule overrides, exclusions, mode and rule-set version are simulated.'),
        preview,
        h('div.field-row',
          field('Client IP', h('input.input', { type: 'text', value: draft.clientIp || '', placeholder: 'e.g. 198.51.100.7', spellcheck: false, on: { input: set('clientIp') } }), 'Used by IPMatch custom rules (empty = unknown)'),
          field('Client country', h('input.input', { type: 'text', value: draft.clientCountry || '', maxlength: '2', placeholder: 'e.g. SG', spellcheck: false, on: { input: (e) => { draft.clientCountry = e.target.value.toUpperCase(); markDirty(); } } }), 'ISO code for GeoMatch rules')));
      renderPreview(preview, draft.azurePolicy, info);
    }
    return h('section.drawer-section', children);
  }

  let lastImport = null;
  const importResult = (r) => [
    h('div.pv-grid', h('div', h('strong', `Imported ${r.directives} directive${r.directives === 1 ? '' : 's'}`)), ...r.detected.map((d) => h('div', '✓ ' + d))),
    r.warnings.length ? h('ul.import-warnings', r.warnings.map((w) => h('li', w))) : null,
    h('div.field-hint', 'Review the fields below, then click Apply.'),
  ];

  function modsecImport(info) {
    const ta = h('textarea.input.code-input', {
      rows: '5', spellcheck: false,
      placeholder: 'Paste crs-setup.conf, REQUEST-900 / RESPONSE-999 exclusion files or your own SecRule files.\nParanoia level, thresholds and CRS version are read from tx.* setvars; exclusions are added to the custom rules below.',
    });
    const out = h('div.import-result');
    const fileInput = h('input', { type: 'file', accept: '.conf,.txt,.example', hidden: true, on: { change: async (e) => { const f = e.target.files[0]; e.target.value = ''; if (f) ta.value = await f.text(); } } });
    const run = () => {
      const text = ta.value;
      const fmt = detectWafConfigFormat(text);
      if (fmt !== 'modsecurity') {
        out.replaceChildren(h('div.policy-errors', h('div', icon('error'), h('span', fmt === 'empty' ? 'Paste a configuration first.' : `Detected ${FORMAT_LABELS[fmt] || fmt}. ${['azure-json', 'terraform', 'bicep'].includes(fmt) ? 'Switch the WAF profile to “Azure WAF policy” to import it.' : 'Only SecLang (ModSecurity / Coraza / CRS) configuration can be imported here.'}`))));
        return;
      }
      const r = importModsecConfig(text, { versions: info.versions || [] });
      Object.assign(draft, r.settings);
      if (r.before) draft.customRulesBefore = [draft.customRulesBefore, `# Imported ${new Date().toISOString().slice(0, 10)}\n${r.before}`].filter(Boolean).join('\n');
      if (r.after) draft.customRulesAfter = [draft.customRulesAfter, `# Imported ${new Date().toISOString().slice(0, 10)}\n${r.after}`].filter(Boolean).join('\n');
      lastImport = r;
      fill(draft);
      markDirty();
    };
    if (lastImport) out.replaceChildren(...importResult(lastImport).filter(Boolean));
    return h('details.import-box', { open: !!lastImport },
      h('summary', icon('upload'), ' Import ModSecurity / Coraza / CRS configuration'),
      ta,
      h('div.policy-actions', h('button.btn.btn-sm', { type: 'button', on: { click: () => fileInput.click() } }, icon('upload'), h('span', 'Load file…')), fileInput, h('button.btn.btn-sm.btn-primary', { type: 'button', on: { click: run } }, 'Import into settings')),
      out);
  }

  function renderPreview(el, text, info) {
    const { policy, errors, warnings, format } = parseAzurePolicy(text || '');
    if (!policy && !errors.length) {
      el.replaceChildren(h('div.field-hint', 'No policy loaded yet – managed rules will use Azure defaults for DRS 2.1 once a policy is provided.'));
      return;
    }
    if (!policy) {
      el.replaceChildren(h('div.policy-errors', errors.map((e) => h('div', icon('error'), h('span', e)))));
      return;
    }
    const sm = summarizePolicy(policy);
    const az = info?.azure;
    const row = (k, v, cls = '') => h('div.pv-row', h('span.pv-k', k), h(`span.pv-v${cls}`, v));
    el.replaceChildren(
      h('div.pv-grid',
        row('Format', FORMAT_LABELS[format] || format),
        row('Policy', `${sm.name} · ${sm.kind}${sm.sku ? ' · ' + sm.sku : ''}`),
        row('Mode', `${sm.enabled ? sm.mode : 'Disabled'}`, sm.enabled && sm.mode === 'Prevention' ? '.pv-ok' : '.pv-warn'),
        row('Managed rules', `${sm.ruleSet}${sm.ruleSetAction ? ' · action ' + sm.ruleSetAction : ''}`),
        row('Custom rules', `${sm.customRulesEnabled} enabled / ${sm.customRules}`),
        row('Overrides / exclusions', `${sm.overrides} rule overrides · ${sm.exclusions} exclusions`),
        row('Request body check', sm.requestBodyCheck ? 'Enabled' : 'Disabled'),
        az && az.summary?.name === sm.name ? row('Simulated', `${az.activeManagedRules ?? '—'} managed rules active (CRS ${az.baseCrs} base) · ${az.removedRules} not in policy`) : null),
      warnings.length || (az?.warnings?.length) ? h('details.ri-list', h('summary', `${new Set([...warnings, ...(az?.warnings || [])]).size} notes`), h('ul', [...new Set([...warnings, ...(az?.warnings || [])])].map((w) => h('li', w)))) : null);
  }

  function fill(s) {
    draft = { ...FIELD_DEFAULTS, ...s };
    const info = safeInfo();
    const versions = info.versions?.length ? info.versions : [info.version].filter(Boolean);
    const versionValue = draft.version || info.defaultVersion || info.version || versions[0] || '';
    const azure = draft.wafProfile === 'azure';
    body.replaceChildren(...[
      profileSection(info),
      azure ? h('section.drawer-section', h('h3', 'Rule set'), h('div.field-hint', 'Determined by the policy: Azure DRS 2.x is simulated with OWASP CRS 3.3 rules filtered to the rules that exist and are enabled in your policy (paranoia levels 1–2, Azure severities, threshold 5).'), rulesetInfo(info)) : null,
      azure ? null : h('section.drawer-section',
        h('h3', 'Rule set'),
        field('CRS version', h('select.select', { on: { change: set('version') } },
          versions.map((v) => h('option', { value: v, selected: v === versionValue }, v)))),
        rulesetInfo(info)),
      azure ? null : h('section.drawer-section',
        h('h3', 'Paranoia level & thresholds'),
        field('Blocking paranoia level', segmented('Blocking paranoia level', 'blockingParanoiaLevel', draft.blockingParanoiaLevel), 'Rules up to this level count towards the anomaly score that blocks requests.'),
        field('Detection paranoia level', segmented('Detection paranoia level', 'detectionParanoiaLevel', draft.detectionParanoiaLevel, Number(draft.blockingParanoiaLevel)), 'Evaluate higher PLs to show what would hit if you raised the level (does not affect blocking).'),
        h('div.field-row',
          field('Inbound threshold', h('input.input.input-num', { type: 'number', min: '1', max: '1000', value: String(draft.inboundThreshold), on: { input: set('inboundThreshold') } })),
          field('Outbound threshold', h('input.input.input-num', { type: 'number', min: '1', max: '1000', value: String(draft.outboundThreshold), on: { input: set('outboundThreshold') } })))),
      azure ? null : h('section.drawer-section',
        h('h3', 'Engine'),
        toggle('Include ModSecurity recommended base config', 'includeModsecRecommended', 'modsecurity.conf-recommended (body processors, limits, rules 200000–200005)'),
        toggle('Evaluate responses', 'evaluateResponses', 'Run outbound rules (phases 3/4) when a response is available'),
        toggle('Early blocking', 'earlyBlocking', 'CRS 4: block at the end of phase 1 when the score is already reached'),
        toggle('Continue after block', 'continueAfterBlock', 'Keep evaluating after the blocking decision so all hits are shown'),
        h('div.field-row',
          field('Remote address', h('input.input', { type: 'text', value: draft.remoteAddr || '', spellcheck: false, on: { input: set('remoteAddr') } }), 'REMOTE_ADDR seen by the WAF'),
          field('HTTP version', h('select.select', { on: { change: set('protocolOverride') } },
            [['', 'As captured'], ['HTTP/1.1', 'Force HTTP/1.1'], ['HTTP/2.0', 'Force HTTP/2.0']].map(([v, l]) => h('option', { value: v, selected: (draft.protocolOverride || '') === v }, l)))))),
      h('section.drawer-section',
        h('h3', 'Custom rules'),
        field('Custom rules before CRS (crs-setup / exclusions)', h('textarea.input.code-input', { rows: '6', spellcheck: false, placeholder: '# e.g. runtime exclusions\nSecRule REQUEST_FILENAME "@rx ^/api/v1/docs/" "id:1000001,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:json.content"', value: draft.customRulesBefore || '', on: { input: set('customRulesBefore') } })),
        field('Custom rules after CRS', h('textarea.input.code-input', { rows: '4', spellcheck: false, placeholder: '# e.g. SecRuleUpdateTargetById 942100 "!ARGS:json.content"', value: draft.customRulesAfter || '', on: { input: set('customRulesAfter') } }))),
    ].filter(Boolean));
  }

  function safeInfo() {
    try {
      return cb.host.getRulesetInfo() || {};
    } catch {
      return {};
    }
  }

  function rulesetInfo(info) {
    const warnings = info.warnings || [];
    const errors = info.errors || [];
    const fmt = (w) => `${w.file || ''}${w.line ? ':' + w.line : ''}${w.id ? ` [${w.id}]` : ''} ${w.message || String(w)}`.trim();
    return h('div.ruleset-info',
      h('div.ri-line',
        h('span.ri-k', 'Loaded'),
        h('span', info.loading ? 'loading…' : `${info.version || '—'} · ${info.rules ?? '?'} rules`)),
      errors.length ? h('details.ri-list.ri-errors', h('summary', `${errors.length} error${errors.length === 1 ? '' : 's'}`), h('ul', errors.slice(0, 200).map((w) => h('li.mono', fmt(w))))) : null,
      warnings.length ? h('details.ri-list', h('summary', `${warnings.length} warning${warnings.length === 1 ? '' : 's'}`), h('ul', warnings.slice(0, 200).map((w) => h('li.mono', fmt(w))))) : null);
  }

  async function apply() {
    const partial = normalize(draft);
    applyBtn.disabled = true;
    status.textContent = 'Applying…';
    try {
      await cb.onApply(partial);
      original = { ...partial };
      status.textContent = 'Applied';
      fill(partial);
      setTimeout(() => { if (status.textContent === 'Applied') status.textContent = ''; }, 1500);
    } catch (e) {
      status.textContent = `Failed: ${e && e.message ? e.message : e}`;
      applyBtn.disabled = false;
    }
  }

  return {
    el,
    open() {
      if (!el.hidden) {
        // Already open: keep unsaved edits, just bring focus back.
        el.querySelector('select, input, textarea')?.focus();
        return;
      }
      original = { ...FIELD_DEFAULTS, ...cb.host.getSettings() };
      fill(original);
      markDirty();
      el.hidden = false;
      requestAnimationFrame(() => el.classList.add('open'));
      el.querySelector('select, input')?.focus();
    },
    close() {
      el.classList.remove('open');
      el.hidden = true;
    },
    /** Settings changed elsewhere (toolbar): adopt them for every field the user has not edited. */
    rebase(settings) {
      if (el.hidden) return;
      const next = { ...FIELD_DEFAULTS, ...settings };
      let changed = false;
      for (const k of Object.keys(next)) {
        if (JSON.stringify(draft[k]) === JSON.stringify(original[k]) && JSON.stringify(draft[k]) !== JSON.stringify(next[k])) {
          draft[k] = next[k];
          changed = true;
        }
      }
      original = next;
      if (changed) {
        const active = document.activeElement;
        const key = active && el.contains(active) ? active.name || null : null;
        fill(draft);
        if (key) el.querySelector(`[name="${key}"]`)?.focus();
      }
      markDirty();
    },
    refreshInfo() {
      if (el.hidden) return;
      const info = safeInfo();
      const sig = JSON.stringify([info.loading, info.version, info.rules, (info.warnings || []).length, (info.errors || []).length, info.error || null, info.azure?.summary?.name, info.azure?.activeManagedRules]);
      if (sig === lastInfoSig) return;
      lastInfoSig = sig;
      const old = el.querySelector('.ruleset-info');
      if (old) {
        const openState = [...old.querySelectorAll('details')].map((d) => d.open);
        const fresh = rulesetInfo(info);
        [...fresh.querySelectorAll('details')].forEach((d, i) => { if (openState[i]) d.open = true; });
        old.replaceWith(fresh);
      }
      // The version list may arrive after the drawer was opened.
      const sel = el.querySelector('select');
      const versions = info.versions || [];
      if (sel && versions.length > sel.options.length) {
        const value = draft.version || info.defaultVersion || info.version || versions[0];
        sel.replaceChildren(...versions.map((v) => h('option', { value: v, selected: v === value }, v)));
      }
    },
    get isOpen() {
      return !el.hidden;
    },
  };
}
