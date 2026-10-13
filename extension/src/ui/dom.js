// Tiny DOM helpers. All text goes through textContent / createTextNode — request data is
// attacker-controlled, so nothing in the UI ever assigns untrusted strings to innerHTML.

const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * h('div.cls1.cls2', { attrs, on: {click}, dataset, style }, ...children)
 * Children: Node | string | number | null | false | arrays thereof.
 */
export function h(tag, props, ...children) {
  const [name, ...classes] = String(tag).split('.');
  const el = document.createElement(name || 'div');
  if (classes.length) el.className = classes.join(' ');
  if (props && (typeof props !== 'object' || props instanceof Node || Array.isArray(props))) {
    children.unshift(props);
    props = null;
  }
  if (props) applyProps(el, props);
  append(el, children);
  return el;
}

function applyProps(el, props) {
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class' || k === 'className') el.className = [el.className, v].filter(Boolean).join(' ');
    else if (k === 'on') for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k === 'text') el.textContent = String(v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked' || k === 'disabled' || k === 'selected' || k === 'hidden' || k === 'open' || k === 'readOnly' || k === 'spellcheck') el[k] = !!v;
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, String(v));
  }
}

export function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false || c === true) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

/* ------------------------------------------------------------------ icons */

// 16×16 icon paths (trusted constants). Stroke icons use currentColor.
const ICONS = {
  record: { fill: '<circle cx="8" cy="8" r="5"/>' },
  clear: { stroke: '<circle cx="8" cy="8" r="5.5"/><path d="M4.2 11.8 11.8 4.2"/>' },
  paste: { stroke: '<rect x="3.5" y="3" width="9" height="11" rx="1.5"/><path d="M6 3V2.2c0-.4.3-.7.7-.7h2.6c.4 0 .7.3.7.7V3"/><path d="M6 7.5h4M6 10h4"/>' },
  upload: { stroke: '<path d="M8 10.5V2.5M5 5.5l3-3 3 3"/><path d="M2.5 10v2.5c0 .6.4 1 1 1h9c.6 0 1-.4 1-1V10"/>' },
  download: { stroke: '<path d="M8 2.5v8M5 7.5l3 3 3-3"/><path d="M2.5 10v2.5c0 .6.4 1 1 1h9c.6 0 1-.4 1-1V10"/>' },
  gear: { stroke: '<circle cx="8" cy="8" r="2.2"/><path d="M8 1.5v1.6M8 12.9v1.6M14.5 8h-1.6M3.1 8H1.5M12.6 3.4l-1.1 1.1M4.5 11.5l-1.1 1.1M12.6 12.6l-1.1-1.1M4.5 4.5 3.4 3.4"/><circle cx="8" cy="8" r="4.6"/>' },
  filter: { stroke: '<path d="M2 3h12l-4.6 5.4v4.3L6.6 14V8.4z"/>' },
  search: { stroke: '<circle cx="7" cy="7" r="4.2"/><path d="m10.2 10.2 3.3 3.3"/>' },
  close: { stroke: '<path d="m4 4 8 8M12 4l-8 8"/>' },
  copy: { stroke: '<rect x="5.5" y="5.5" width="8" height="8.5" rx="1.2"/><path d="M3.5 10.5H3a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1h6.5a1 1 0 0 1 1 1v.5"/>' },
  external: { stroke: '<path d="M9.5 2.5h4v4M13.5 2.5 7.5 8.5"/><path d="M11.5 9.5v3a1 1 0 0 1-1 1h-7a1 1 0 0 1-1-1v-7a1 1 0 0 1 1-1h3"/>' },
  chevronRight: { stroke: '<path d="m6 3.5 4.5 4.5L6 12.5"/>' },
  chevronDown: { stroke: '<path d="M3.5 6 8 10.5 12.5 6"/>' },
  blocked: { fill: '<path d="M5.2 1.5h5.6l3.7 3.7v5.6l-3.7 3.7H5.2l-3.7-3.7V5.2z"/><path d="m5.6 5.6 4.8 4.8M10.4 5.6l-4.8 4.8" stroke="var(--icon-on-fill, #fff)" stroke-width="1.6" stroke-linecap="round" fill="none"/>' },
  warn: { fill: '<path d="M8 1.6c.4 0 .7.2.9.5l6 10.6c.4.7-.1 1.6-.9 1.6H2c-.8 0-1.3-.9-.9-1.6l6-10.6c.2-.3.5-.5.9-.5z"/><path d="M8 5.8v3.6" stroke="var(--icon-on-fill-dark, #202124)" stroke-width="1.6" stroke-linecap="round"/><circle cx="8" cy="11.6" r=".95" fill="var(--icon-on-fill-dark, #202124)"/>' },
  latent: { stroke: '<circle cx="8" cy="8" r="5.6"/><path d="M8 10.8V5.6M5.6 7.8 8 5.4l2.4 2.4"/>' },
  clean: { fill: '<circle cx="8" cy="8" r="6.5"/><path d="m5.2 8.2 1.9 1.9 3.8-4" stroke="var(--icon-on-fill, #fff)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" fill="none"/>' },
  error: { stroke: '<circle cx="8" cy="8" r="5.6"/><path d="M8 4.8v3.8"/><circle cx="8" cy="11" r=".5" fill="currentColor"/>' },
  info: { stroke: '<circle cx="8" cy="8" r="5.8"/><path d="M8 7.2v4"/><circle cx="8" cy="4.9" r=".55" fill="currentColor"/>' },
  shield: { stroke: '<path d="M8 1.6 13.2 3.5v4.1c0 3.1-2.2 5.8-5.2 6.8-3-1-5.2-3.7-5.2-6.8V3.5z"/><path d="m5.7 8 1.6 1.6 3-3.2"/>' },
  code: { stroke: '<path d="M5.5 4.5 2 8l3.5 3.5M10.5 4.5 14 8l-3.5 3.5"/>' },
  wrench: { stroke: '<path d="M10.2 2.2a3.3 3.3 0 0 0-3.9 4.3L2.4 10.4a1.4 1.4 0 0 0 2 2l3.9-3.9a3.3 3.3 0 0 0 4.3-3.9L10.8 6.4 9.2 6.2 9 4.6z"/>' },
  terminal: { stroke: '<rect x="1.8" y="2.8" width="12.4" height="10.4" rx="1.3"/><path d="m4.5 6 2 2-2 2M8 10.5h3.5"/>' },
  arrowUp: { stroke: '<path d="M8 13V3M4 7l4-4 4 4"/>' },
  dot: { fill: '<circle cx="8" cy="8" r="3"/>' },
  preserve: { stroke: '<rect x="2.5" y="2.5" width="11" height="11" rx="2"/><path d="m5.2 8.2 1.9 1.9 3.8-4"/>' },
  expand: { stroke: '<path d="M2.5 6V2.5H6M13.5 6V2.5H10M2.5 10v3.5H6M13.5 10v3.5H10"/>' },
};

/** Create an SVG icon element. */
export function icon(name, cls = '') {
  const def = ICONS[name] || ICONS.dot;
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 16 16');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  svg.setAttribute('class', `icon icon-${name}${cls ? ' ' + cls : ''}`);
  if (def.fill) {
    svg.setAttribute('fill', 'currentColor');
    svg.innerHTML = def.fill; // trusted constant markup
  } else {
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.4');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.innerHTML = def.stroke; // trusted constant markup
  }
  return svg;
}

/** Icon-only toolbar button with tooltip + aria-label. */
export function iconButton(name, label, onClick, extra = {}) {
  const b = h('button.icon-btn', { type: 'button', title: label, 'aria-label': label, ...extra, on: { click: onClick, ...(extra.on || {}) } }, icon(name));
  return b;
}

/** Status icon (blocked / warn / latent / clean / pending / error). */
export function statusIcon(status, title) {
  if (status === 'pending') {
    return h('span.status-icon.status-pending', { title: title || 'Analyzing…', role: 'img', 'aria-label': title || 'Analyzing' }, h('span.spinner'));
  }
  const map = { blocked: 'blocked', warn: 'warn', latent: 'latent', clean: 'clean', error: 'error', none: 'dot' };
  const el = h(`span.status-icon.status-${status}`, { title: title || status, role: 'img', 'aria-label': title || status });
  el.appendChild(icon(map[status] || 'dot'));
  return el;
}

/* -------------------------------------------------------------- clipboard */

export async function copyText(text) {
  const s = String(text ?? '');
  try {
    if (navigator.clipboard && window.isSecureContext !== false) {
      await navigator.clipboard.writeText(s);
      return true;
    }
  } catch {
    /* fall through to execCommand (DevTools panels may lack clipboard-write) */
  }
  const ta = h('textarea', { style: { position: 'fixed', top: '-1000px', left: '-1000px', opacity: '0' }, readonly: true });
  ta.value = s;
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  }
  ta.remove();
  return ok;
}

/* ------------------------------------------------------------------ toast */

let toastEl = null;
let toastTimer = 0;
export function toast(message, kind = 'info', ms = 2200) {
  if (!toastEl) {
    toastEl = h('div.toast', { role: 'status', 'aria-live': 'polite' });
    document.body.appendChild(toastEl);
  }
  toastEl.className = `toast toast-${kind} toast-show`;
  toastEl.textContent = String(message);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.remove('toast-show'), ms);
}

/** Button that copies text and confirms with a toast. */
export function copyButton(getText, label = 'Copy', { iconOnly = false, title, cls = '' } = {}) {
  const onClick = async (e) => {
    e.stopPropagation();
    const ok = await copyText(typeof getText === 'function' ? getText() : getText);
    toast(ok ? `${title || label} — copied` : 'Copy failed', ok ? 'info' : 'error', 1600);
  };
  if (iconOnly) return h(`button.icon-btn.icon-btn-sm${cls ? '.' + cls : ''}`, { type: 'button', title: title || label, 'aria-label': title || label, on: { click: onClick } }, icon('copy'));
  return h(`button.btn.btn-sm${cls ? '.' + cls : ''}`, { type: 'button', title: title || label, on: { click: onClick } }, icon('copy'), h('span', label));
}

/* ----------------------------------------------------------- local storage */

export function loadPref(key, fallback) {
  try {
    const v = localStorage.getItem(`crs-inspector.${key}`);
    return v == null ? fallback : JSON.parse(v);
  } catch {
    return fallback;
  }
}

export function savePref(key, value) {
  try {
    localStorage.setItem(`crs-inspector.${key}`, JSON.stringify(value));
  } catch {
    /* storage unavailable */
  }
}

/** Highlight before/match/after into a <pre>-like element. */
export function highlighted(before, match, after, cls = 'value') {
  return h(`div.${cls}`, before || '', match ? h('mark.hit', match) : '', after || '');
}

/** requestAnimationFrame that still fires while the page is hidden (DevTools panel not shown). */
export function nextFrame(fn) {
  if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return setTimeout(fn, 50);
  return requestAnimationFrame(fn);
}
