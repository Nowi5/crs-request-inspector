// Paste dialog: analyze PowerShell / cURL / fetch / raw HTTP / HAR text.

import { h, icon } from '../dom.js';
import { FORMAT_LABELS, countRequests } from '../format.js';

const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '');
export const MOD_KEY = isMac ? '⌘' : 'Ctrl';

/**
 * @param {{ host: object, onAdded(result: {added: number, ids?: string[], errors: string[], format?: string}): void }} cb
 */
export function createPasteDialog(cb) {
  const textarea = h('textarea.paste-input', {
    spellcheck: false,
    autocomplete: 'off',
    'aria-label': 'Request to analyze',
    placeholder: 'Paste a request here…\n\ncurl \'https://example.com/api/search?q=1%27%20OR%201=1\' -H \'accept: application/json\'\n\nor: Invoke-WebRequest -UseBasicParsing -Uri "https://…" …\nor: fetch("https://…", { … })\nor: POST /api HTTP/1.1 ⏎ Host: … ⏎ ⏎ {"a":1}',
  });
  const detect = h('span.detect-chip', { 'aria-live': 'polite' });
  const errors = h('div.paste-errors', { role: 'alert', hidden: true });
  const analyzeBtn = h('button.btn.btn-primary', { type: 'submit', disabled: true }, h('span', 'Analyze'), h('kbd', `${MOD_KEY}+Enter`));
  const cancelBtn = h('button.btn', { type: 'button', on: { click: () => close() } }, 'Cancel');
  const closeBtn = h('button.icon-btn', { type: 'button', title: 'Close', 'aria-label': 'Close', on: { click: () => close() } }, icon('close'));

  const help = h('aside.paste-help',
    h('h4', 'Supported formats'),
    h('ul',
      h('li', h('strong', 'Chrome DevTools'), ' → Network → right-click a request → ', h('em', 'Copy'), ' →',
        h('ul.formats',
          h('li', 'Copy as PowerShell'),
          h('li', 'Copy as cURL (bash) / (cmd)'),
          h('li', 'Copy as fetch / fetch (Node.js)'),
          h('li', 'Copy all as … (several requests at once)'))),
      h('li', h('strong', 'Raw HTTP'), ' request text (request line, headers, blank line, body)'),
      h('li', h('strong', 'HAR'), ' — paste the JSON, drop a .har file on the panel, or use Import HAR')),
    h('p.muted', 'Everything is analyzed locally in your browser. Nothing is sent anywhere.'));

  const form = h('form.paste-form', { method: 'dialog', on: { submit: (e) => { e.preventDefault(); submit(); } } },
    h('header.dialog-head', h('h2', icon('paste'), 'Analyze a request'), detect, closeBtn),
    h('div.paste-body', h('div.paste-main', textarea, errors), help),
    h('footer.dialog-foot', h('span.muted.foot-hint', 'The request is checked against the configured CRS rule set and paranoia level.'), cancelBtn, analyzeBtn));
  const dialog = h('dialog.dialog.paste-dialog', { 'aria-label': 'Analyze a request' }, form);

  let detectTimer = 0;
  const updateDetect = () => {
    clearTimeout(detectTimer);
    detectTimer = setTimeout(() => {
      const text = textarea.value;
      analyzeBtn.disabled = !text.trim();
      if (!text.trim()) {
        detect.className = 'detect-chip';
        detect.textContent = 'Waiting for input';
        return;
      }
      let format = 'unknown';
      let count = null;
      try {
        const d = cb.host.detectFormat(text);
        if (d && typeof d === 'object') {
          format = d.format;
          count = d.count ?? null;
        } else format = d || 'unknown';
      } catch {
        format = 'unknown';
      }
      if (count == null) count = countRequests(text, format);
      detect.className = `detect-chip ${format === 'unknown' ? 'detect-unknown' : 'detect-ok'}`;
      detect.textContent = format === 'unknown'
        ? 'Format not recognised'
        : `${FORMAT_LABELS[format] || format} · ${count} request${count === 1 ? '' : 's'}`;
    }, 120);
  };
  textarea.addEventListener('input', () => {
    errors.hidden = true;
    updateDetect();
  });
  textarea.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      submit();
    }
  });
  dialog.addEventListener('close', () => document.body.classList.remove('modal-open'));
  dialog.addEventListener('click', (e) => {
    if (e.target === dialog) close(); // backdrop click
  });

  let busy = false;
  async function submit() {
    const text = textarea.value;
    if (!text.trim() || busy) return;
    busy = true;
    analyzeBtn.disabled = true;
    analyzeBtn.classList.add('busy');
    try {
      const res = await cb.host.analyzeText(text);
      const errs = res?.errors || [];
      if (!res || !res.added) {
        showErrors(errs.length ? errs : ['No request found in the pasted text.']);
        return;
      }
      close();
      textarea.value = '';
      cb.onAdded(res);
    } catch (e) {
      showErrors([String(e && e.message ? e.message : e)]);
    } finally {
      busy = false;
      analyzeBtn.classList.remove('busy');
      analyzeBtn.disabled = !textarea.value.trim();
    }
  }

  function showErrors(list) {
    errors.replaceChildren(h('strong', list.length === 1 ? 'Could not analyze:' : `${list.length} problems:`), h('ul', list.map((x) => h('li', String(x)))));
    errors.hidden = false;
  }

  function open(text) {
    if (typeof text === 'string') textarea.value = text;
    errors.hidden = true;
    if (!dialog.open) dialog.showModal();
    document.body.classList.add('modal-open');
    updateDetect();
    textarea.focus();
    if (typeof text === 'string') textarea.setSelectionRange(0, 0);
  }
  function close() {
    if (dialog.open) dialog.close();
  }

  return { el: dialog, open, close, get isOpen() { return dialog.open; } };
}
