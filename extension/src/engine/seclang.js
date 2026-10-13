// SecLang (ModSecurity configuration language) parser.
//
// Produces a flat list of directives with source positions. Only the directives that
// matter for rule evaluation are interpreted by the engine (SecRule, SecAction,
// SecMarker, SecDefaultAction, SecRuleRemove*, SecRuleUpdate*); everything else is
// kept as an "other" directive so it can be reported.

/**
 * @typedef {Object} Directive
 * @property {string} name      directive name as written, e.g. "SecRule"
 * @property {string[]} args    unquoted arguments
 * @property {string} file
 * @property {number} line      1-based line of the first physical line
 * @property {number} endLine
 * @property {string} raw       raw text (physical lines joined with "\n")
 */

/**
 * Split config text into logical lines (handling backslash continuations and comments).
 * @returns {{text: string, line: number, endLine: number, raw: string}[]}
 */
export function logicalLines(text) {
  const lines = text.split(/\r?\n/);
  const out = [];
  let buf = null;
  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];
    if (buf === null) {
      const trimmed = line.trim();
      if (trimmed === '' || trimmed.startsWith('#')) continue;
      buf = { text: '', line: idx + 1, endLine: idx + 1, raw: [] };
    }
    buf.raw.push(line);
    buf.endLine = idx + 1;
    const rstripped = line.replace(/[ \t]+$/, '');
    if (rstripped.endsWith('\\')) {
      buf.text += rstripped.slice(0, -1);
      continue;
    }
    buf.text += line;
    out.push({ text: buf.text, line: buf.line, endLine: buf.endLine, raw: buf.raw.join('\n') });
    buf = null;
  }
  if (buf) out.push({ text: buf.text, line: buf.line, endLine: buf.endLine, raw: buf.raw.join('\n') });
  return out;
}

/**
 * Tokenize directive arguments like Apache's ap_getword_conf: whitespace separated,
 * single or double quoted; inside quotes, `\\` and `\<quote>` are unescaped.
 */
export function tokenizeArgs(text) {
  const args = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    while (i < n && /\s/.test(text[i])) i++;
    if (i >= n) break;
    const q = text[i];
    if (q === '"' || q === "'") {
      i++;
      let s = '';
      while (i < n && text[i] !== q) {
        if (text[i] === '\\' && i + 1 < n && (text[i + 1] === q || text[i + 1] === '\\')) {
          s += text[i + 1];
          i += 2;
        } else {
          s += text[i++];
        }
      }
      i++; // closing quote
      args.push(s);
    } else {
      let s = '';
      while (i < n && !/\s/.test(text[i])) s += text[i++];
      args.push(s);
    }
  }
  return args;
}

/** Parse a config file into directives. */
export function parseConfig(text, file = 'inline') {
  const directives = [];
  const errors = [];
  for (const ll of logicalLines(text)) {
    const m = /^\s*(\S+)\s*([\s\S]*)$/.exec(ll.text);
    if (!m) continue;
    const name = m[1];
    let args;
    try {
      args = tokenizeArgs(m[2]);
    } catch (e) {
      errors.push({ file, line: ll.line, message: e.message });
      continue;
    }
    directives.push({ name, args, file, line: ll.line, endLine: ll.endLine, raw: ll.raw });
  }
  return { directives, errors };
}

/**
 * Parse a ModSecurity action list: `id:1,phase:2,t:none,msg:'a, b',setvar:'tx.x=+1'`.
 * @returns {{name: string, value: string|null}[]}
 */
export function parseActions(text) {
  const actions = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    while (i < n && (text[i] === ',' || /\s/.test(text[i]))) i++;
    if (i >= n) break;
    let name = '';
    while (i < n && text[i] !== ':' && text[i] !== ',') name += text[i++];
    name = name.trim();
    let value = null;
    if (text[i] === ':') {
      i++;
      while (i < n && /[ \t]/.test(text[i])) i++;
      if (text[i] === "'") {
        i++;
        value = '';
        while (i < n && text[i] !== "'") {
          if (text[i] === '\\' && i + 1 < n && (text[i + 1] === "'" || text[i + 1] === '\\')) {
            value += text[i + 1];
            i += 2;
          } else {
            value += text[i++];
          }
        }
        i++; // closing quote
        // skip to next comma
        while (i < n && text[i] !== ',') i++;
      } else {
        value = '';
        while (i < n && text[i] !== ',') value += text[i++];
        value = value.trim();
      }
    }
    if (name) actions.push({ name, value });
  }
  return actions;
}

/**
 * Parse a variable list: `ARGS|!ARGS:foo|&REQUEST_HEADERS:Content-Type|REQUEST_COOKIES:/^_ga/|XML:/*`.
 * @returns {{collection: string, key: string|null, keyRegex: string|null, count: boolean, exclude: boolean, raw: string}[]}
 */
export function parseVariables(text) {
  const vars = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    while (i < n && (text[i] === '|' || /\s/.test(text[i]))) i++;
    if (i >= n) break;
    const start = i;
    let exclude = false;
    let count = false;
    while (text[i] === '!' || text[i] === '&') {
      if (text[i] === '!') exclude = true;
      else count = true;
      i++;
    }
    let collection = '';
    while (i < n && /[A-Za-z0-9_]/.test(text[i])) collection += text[i++];
    collection = collection.toUpperCase();
    let key = null;
    let keyRegex = null;
    if (text[i] === ':' || text[i] === '.') {
      i++;
      if (text[i] === '/' && collection !== 'XML') {
        // regex key /.../ (escaped slashes allowed)
        i++;
        let re = '';
        while (i < n && text[i] !== '/') {
          if (text[i] === '\\' && i + 1 < n) {
            re += text[i] + text[i + 1];
            i += 2;
          } else re += text[i++];
        }
        i++; // closing slash
        keyRegex = re;
      } else if (text[i] === "'") {
        i++;
        key = '';
        while (i < n && text[i] !== "'") key += text[i++];
        i++;
      } else {
        key = '';
        while (i < n && text[i] !== '|') key += text[i++];
        key = key.trim();
      }
    }
    vars.push({ collection, key, keyRegex, count, exclude, raw: text.slice(start, i).trim() });
  }
  return vars;
}

/**
 * Parse the operator argument of SecRule: `@rx foo`, `!@pm a b`, or an implicit regex.
 * @returns {{name: string, negated: boolean, param: string}}
 */
export function parseOperator(text) {
  let s = text;
  let negated = false;
  let i = 0;
  while (s[i] === ' ' || s[i] === '\t') i++;
  if (s[i] === '!') {
    negated = true;
    i++;
  }
  if (s[i] === '@') {
    const m = /^@([A-Za-z0-9_]+)\s*/.exec(s.slice(i));
    if (m) {
      return { name: m[1], negated, param: s.slice(i + m[0].length) };
    }
  }
  return { name: 'rx', negated, param: s.slice(i) };
}
