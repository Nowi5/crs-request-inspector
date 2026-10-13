// Renders SecLang source with simple syntax highlighting (token spans, no innerHTML).

import { h, copyButton } from '../dom.js';
import { tokenizeSecLang } from '../seclang.js';

export function renderSecLang(code, { file, line, plain = false } = {}) {
  const pre = h('pre.code.seclang');
  for (const t of tokenizeSecLang(code)) {
    if (t.type === 'txt') pre.appendChild(document.createTextNode(t.text));
    else pre.appendChild(h(`span.tk-${t.type}`, t.text));
  }
  if (plain) return pre;
  return h('div.source-block',
    h('div.source-head', h('span.mono.muted', file ? `${file}${line ? ':' + line : ''}` : 'Rule source'), copyButton(code, 'Copy', { title: 'Copy rule source' })),
    pre);
}
