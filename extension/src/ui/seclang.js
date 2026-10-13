// Minimal SecLang tokenizer for syntax highlighting of rule sources. Pure, unit-tested.
// Token types: com (comment), dir (directive), var (variables), op (operator name),
// param (operator argument), act (action name), str (quoted action value), id (rule id),
// punct (quotes, commas, line continuations), txt (everything else).

const ACTION_HINT = /(?:^|[,\s\\])(?:id|phase|msg|tag|ver|severity|setvar|chain|t|block|pass|deny|nolog|log|capture|ctl|skipAfter|logdata|rev|accuracy|maturity|auditlog|noauditlog|drop|allow|status|multiMatch|expirevar|initcol|setenv|redirect|exec|skip)(?::|,|\s*$|\s*\\)/;

export function tokenizeSecLang(src) {
  const s = String(src ?? '');
  const out = [];
  const push = (type, text) => {
    if (!text) return;
    const last = out[out.length - 1];
    if (last && last.type === type) last.text += text;
    else out.push({ type, text });
  };
  let i = 0;
  let lineStart = true;
  let argIndex = -1; // argument index after a directive on the current logical line
  while (i < s.length) {
    const c = s[i];
    if (c === '\n') {
      push('txt', c);
      i++;
      // a line not ending in "\" ends the logical directive
      const prev = s.slice(0, i - 1).replace(/[ \t]+$/, '');
      if (!prev.endsWith('\\')) argIndex = -1;
      lineStart = true;
      continue;
    }
    if (c === ' ' || c === '\t' || c === '\r') {
      push('txt', c);
      i++;
      continue;
    }
    if (lineStart && c === '#') {
      const end = s.indexOf('\n', i);
      push('com', s.slice(i, end < 0 ? s.length : end));
      i = end < 0 ? s.length : end;
      continue;
    }
    lineStart = false;
    if (c === '\\' && /^\\[ \t]*(\r?\n|$)/.test(s.slice(i))) {
      push('punct', '\\');
      i++;
      continue;
    }
    if (c === '"' || c === "'") {
      const q = c;
      let j = i + 1;
      while (j < s.length && s[j] !== q) j += s[j] === '\\' ? 2 : 1;
      const inner = s.slice(i + 1, Math.min(j, s.length));
      push('punct', q);
      emitQuoted(inner, argIndex, push);
      if (j < s.length) push('punct', q);
      i = j + 1;
      argIndex++;
      continue;
    }
    // bare word
    let j = i;
    while (j < s.length && !/[\s"']/.test(s[j])) j++;
    const word = s.slice(i, j);
    if (argIndex < 0 && /^Sec[A-Za-z]+$/.test(word)) {
      push('dir', word);
      argIndex = 0;
    } else if (argIndex === 0) {
      push('var', word);
      argIndex++;
    } else {
      push('txt', word);
    }
    i = j;
  }
  return out;
}

function emitQuoted(inner, argIndex, push) {
  if (/^!?@/.test(inner)) {
    const m = /^(!?@[A-Za-z]+)([\s\S]*)$/.exec(inner);
    push('op', m[1]);
    push('param', m[2]);
    return;
  }
  if (argIndex === 0 && !ACTION_HINT.test(inner)) {
    push('var', inner);
    return;
  }
  if (ACTION_HINT.test(inner) || argIndex >= 1) {
    emitActions(inner, push);
    return;
  }
  push('param', inner);
}

function emitActions(s, push) {
  let i = 0;
  let expectName = true;
  while (i < s.length) {
    const c = s[i];
    if (c === ',') {
      push('punct', c);
      expectName = true;
      i++;
      continue;
    }
    if (c === '\\' && /^\\[ \t]*\r?\n/.test(s.slice(i))) {
      push('punct', '\\');
      i++;
      continue;
    }
    if (/\s/.test(c)) {
      push('txt', c);
      i++;
      continue;
    }
    if (c === "'") {
      let j = i + 1;
      while (j < s.length && s[j] !== "'") j += s[j] === '\\' ? 2 : 1;
      push('str', s.slice(i, Math.min(j + 1, s.length)));
      i = j + 1;
      continue;
    }
    if (expectName) {
      let j = i;
      while (j < s.length && /[A-Za-z_]/.test(s[j])) j++;
      if (j === i) j = i + 1;
      const name = s.slice(i, j);
      push('act', name);
      i = j;
      expectName = false;
      if (s[i] === ':') {
        push('punct', ':');
        i++;
        if (name === 'id') {
          let k = i;
          while (k < s.length && /[0-9]/.test(s[k])) k++;
          push('id', s.slice(i, k));
          i = k;
        }
      }
      continue;
    }
    let j = i;
    while (j < s.length && !/[,'\s\\]/.test(s[j])) j++;
    if (j === i) j = i + 1;
    push('txt', s.slice(i, j));
    i = j;
  }
}
