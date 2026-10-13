// Recommendations: for a detected rule hit, explain what it means and what to change –
// in the application (developer) and in the WAF configuration – plus Azure WAF notes.
// Pure functions (no DOM), unit-tested in scripts/test-ui-logic.mjs.

import { describeVar, matchPL } from './format.js';

/* ------------------------------------------------------------- value classes */

/** Classify a matched value to judge whether a hit is likely a false positive. */
export function classifyValue(value) {
  const s = String(value ?? '').trim();
  if (!s) return 'empty';
  if (/^eyJ[\w-]+\.[\w-]+\.[\w-]*$/.test(s)) return 'jwt';
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) return 'uuid';
  if (/^[0-9a-f]{16,}$/i.test(s)) return 'hex';
  if (/^https?:\/\//i.test(s) && !/\s/.test(s)) return 'url';
  if (s.length >= 20 && !/\s/.test(s) && /^[A-Za-z0-9+/=_~.%-]+$/.test(s) && /\d/.test(s) && /[A-Z]/.test(s) && /[a-z]/.test(s)) return 'token';
  if (/<\/?[a-z][\w-]*[\s>/]/i.test(s)) return 'markup';
  if (/\s/.test(s) && s.split(/\s+/).filter(Boolean).length >= 3) return 'text';
  return 'other';
}

const VALUE_LABELS = {
  jwt: 'a JWT (signed token)',
  uuid: 'a UUID',
  hex: 'a hex string (hash / id)',
  token: 'a random token / encoded value (base64, signature, session id)',
  url: 'a URL',
  markup: 'HTML / markup',
  text: 'free text',
};

/** Cookies set by platforms/frameworks – the application cannot change their format. */
const PLATFORM_COOKIES = [
  [/^AppServiceAuthSession$|^AppServiceAuthSession\d*$/i, 'Azure App Service Authentication (Easy Auth)'],
  [/^ARRAffinity(SameSite)?$/i, 'Azure App Service load balancer (ARR affinity)'],
  [/^\.AspNetCore\.|^\.ASPXAUTH$|^ASP\.NET_SessionId$|^__RequestVerificationToken/i, 'ASP.NET'],
  [/^ai_(user|session)$/i, 'Azure Application Insights'],
  [/^_ga|^_gid$|^_gat|^__utm|^_gcl_/i, 'Google Analytics'],
  [/^_fbp$|^_fbc$/i, 'Meta Pixel'],
  [/^__cf|^cf_clearance$/i, 'Cloudflare'],
  [/^MSAL|^msal\./i, 'MSAL (Microsoft identity)'],
  [/^AWSALB|^AWSELB/i, 'AWS load balancer'],
  [/^next-auth\.|^__Secure-next-auth\./i, 'NextAuth.js'],
];

export function platformCookie(name) {
  for (const [re, label] of PLATFORM_COOKIES) if (re.test(String(name || ''))) return label;
  return null;
}

/* ------------------------------------------------------------ knowledge base */

// Short, actionable text per rule (or rule family). `why` explains the rule; `app` are changes
// to the website/API; `waf` are WAF configuration changes. Use {var} and {name} placeholders.
const RULES = {
  911100: {
    why: 'The HTTP method is not in the WAF\'s list of allowed methods. CRS only allows GET, HEAD, POST and OPTIONS by default (tx.allowed_methods).',
    app: [
      'Nothing is wrong with the request – PUT, PATCH and DELETE are normal REST methods. Prefer fixing the WAF configuration.',
      'Only if the WAF cannot be changed: expose the operation as POST (e.g. POST …/{id}/update). Do not use X-HTTP-Method-Override headers – CRS blocks those too (rule 920450).',
    ],
    waf: [
      "ModSecurity/Coraza: add the methods your API uses in crs-setup: setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'.",
    ],
    risk: 'policy',
  },
  913100: { why: 'The User-Agent matches a known security scanner.', app: ['Do not use scanner-like User-Agent strings in your own clients, tests or monitoring.'], waf: ['Allow-list trusted monitoring by IP instead of disabling the rule.'], risk: 'policy' },
  920100: { why: 'The request line is not valid HTTP (raw spaces, control characters or an unusual URL form).', app: ['Build URLs with standard libraries (URL / encodeURIComponent); never put raw spaces or control characters in the path or query.'], risk: 'policy' },
  920120: { why: 'An uploaded file name or field name contains characters used for evasion (quotes, semicolons, …).', app: ['Sanitise file names on the client before upload (letters, digits, dot, dash, underscore).', 'Store files under a generated id server-side; keep the original name only as metadata.'], risk: 'policy' },
  920170: { why: 'A GET or HEAD request carries a body. Many servers and proxies treat this as smuggling-prone.', app: ['Do not send a body with GET/HEAD: move the data into query parameters or switch the endpoint to POST.'], risk: 'policy' },
  920180: { why: 'An HTTP/1.x POST has neither Content-Length nor Transfer-Encoding.', app: ['Send Content-Length (browsers do this automatically; check custom clients/proxies).'], risk: 'policy' },
  920220: { why: 'Invalid URL encoding (a "%" that is not followed by two hex digits).', app: ['Percent-encode values with encodeURIComponent; encode a literal "%" as %25.'], risk: 'policy' },
  920230: { why: 'The value looks URL-encoded more than once (e.g. %2527).', app: ['Encode values exactly once. Check for double encoding in routers, redirect helpers and HTTP clients.'], risk: 'policy' },
  920240: { why: 'Invalid URL encoding in a form-encoded body.', app: ['Serialise form bodies with URLSearchParams / FormData instead of building them by hand.'], risk: 'policy' },
  920250: { why: 'The request contains invalid UTF-8.', app: ['Send all text as UTF-8; do not mix Latin-1 encoded bytes into URLs or bodies.'], risk: 'policy' },
  920260: { why: 'Full-width / half-width Unicode encoding (%uFFxx) that is commonly used to evade filters.', app: ['Use standard UTF-8 percent-encoding, not the legacy %uXXXX form.'], risk: 'policy' },
  920270: { why: 'Invalid character (e.g. NUL byte) in the request.', app: ['Strip or encode control characters before sending; never send NUL bytes in parameters.'], risk: 'policy' },
  920271: { why: 'Non-printable characters in the request.', app: ['Strip control characters (tabs, line breaks) from values or send them in a JSON body.'], risk: 'policy' },
  920272: { why: 'Characters outside the printable ASCII range (PL3) – typically non-English text or emoji in a parameter.', app: ['Expected for international text. If the field is free text, keep it in the request body and exclude the field rather than changing the content.'], risk: 'policy' },
  920273: { why: 'Very strict character check (PL4): anything other than letters, digits and a few symbols counts – spaces, quotes, colons, slashes.', app: ['PL4 is impractical for most applications; nearly any free text or token triggers it. Usually no application change is appropriate.'], risk: 'policy' },
  920274: { why: 'Characters outside a very strict set in request headers (PL4).', app: ['Usually not actionable – most browser headers trigger this at PL4.'], risk: 'policy' },
  920280: { why: 'The Host header is missing.', app: ['Always send a Host header (all browsers do; check raw HTTP clients).'], risk: 'policy' },
  920290: { why: 'The Host header is empty.', app: ['Send the real host name in the Host header.'], risk: 'policy' },
  920300: { why: 'The Accept header is missing (PL2).', app: ["Send an Accept header from non-browser clients (e.g. 'Accept: application/json')."], risk: 'policy' },
  920310: { why: 'The Accept header is empty.', app: ['Send a non-empty Accept header.'], risk: 'policy' },
  920311: { why: 'The Accept header is empty.', app: ['Send a non-empty Accept header.'], risk: 'policy' },
  920320: { why: 'The User-Agent header is missing (PL2).', app: ['Set a User-Agent in server-to-server calls, scripts and mobile clients (e.g. "MyApp/1.4").', 'Note: "Copy as fetch" pastes contain no User-Agent – use "Copy as PowerShell/cURL" for accurate results.'], risk: 'policy' },
  920330: { why: 'The User-Agent header is empty.', app: ['Send a descriptive User-Agent.'], risk: 'policy' },
  920340: { why: 'Request body announced but Content-Type missing.', app: ['Always send Content-Type with a body (application/json, …).'], risk: 'policy' },
  920341: { why: 'Request body announced but Content-Type missing.', app: ['Always send Content-Type with a body (application/json, …).'], risk: 'policy' },
  920350: { why: 'The Host header is a numeric IP address – typical for scanners and bots.', app: ['Call the service by its DNS name, not by IP (also for health checks).'], risk: 'policy' },
  920360: { why: 'An argument name is longer than the configured limit (tx.arg_name_length).', app: ['Use shorter field names; do not encode data into parameter names.'], waf: ['Raise tx.arg_name_length if long names are legitimate.'], risk: 'policy' },
  920370: { why: 'An argument value is longer than the configured limit (tx.arg_length).', app: ['Send large content (documents, base64 files) as a file upload or in the body, and split very large payloads.'], waf: ['Raise tx.arg_length for this endpoint if long values are legitimate.'], risk: 'policy' },
  920380: { why: 'Too many arguments (tx.max_num_args).', app: ['Reduce the number of parameters, e.g. send arrays as JSON instead of hundreds of form fields.'], waf: ['Raise tx.max_num_args if needed.'], risk: 'policy' },
  920390: { why: 'Total size of all arguments exceeds tx.total_arg_length.', app: ['Move large data into file uploads; paginate bulk operations.'], waf: ['Raise tx.total_arg_length for this endpoint.'], risk: 'policy' },
  920400: { why: 'Uploaded file larger than tx.max_file_size.', app: ['Use chunked/resumable uploads or direct-to-storage uploads (e.g. SAS URLs to Blob Storage).'], waf: ['Raise tx.max_file_size if needed.'], risk: 'policy' },
  920410: { why: 'Combined upload size larger than tx.combined_file_sizes.', app: ['Upload files one at a time or directly to storage.'], waf: ['Raise tx.combined_file_sizes if needed.'], risk: 'policy' },
  920420: { why: 'The Content-Type is not in tx.allowed_request_content_type (allowed by default: form-urlencoded, multipart/form-data, XML, application/json and +json types).', app: ['Use application/json for API bodies. For binary uploads prefer multipart/form-data.'], waf: ["Add the type to tx.allowed_request_content_type (e.g. '|application/octet-stream|')."], risk: 'policy' },
  920430: { why: 'The HTTP version is not allowed by policy.', app: ['Use HTTP/1.1, HTTP/2 or HTTP/3.'], risk: 'policy' },
  920440: { why: 'The URL ends with a restricted file extension (.bak, .config, .log, .sql, .ini, …) that usually indicates sensitive files.', app: ['Do not expose routes or downloads with these extensions; serve such content through an id-based endpoint with the correct Content-Type.'], risk: 'policy' },
  920450: { why: 'A restricted header is present (e.g. Proxy, Lock-Token, Content-Range, If, X-HTTP-Method-Override, Expect, x-middleware-subrequest).', app: ['Do not send these headers from the client. Replace method-override headers with the real HTTP method.'], risk: 'policy' },
  920451: { why: 'A restricted header is present (extended list, e.g. Accept-Charset).', app: ['Remove the header from the client request.'], risk: 'policy' },
  920480: { why: 'The charset in Content-Type is not allowed (only utf-8 and a few Latin charsets).', app: ["Send 'charset=utf-8' or no charset parameter."], risk: 'policy' },
  920500: { why: 'Access to a backup or editor working file (~, .swp, .bak) was requested.', app: ['Make sure no such files are deployed or linked.'], risk: 'likely-attack' },
  920520: { why: 'Accept-Encoding header is unusually long.', app: ['Use the client default Accept-Encoding.'], risk: 'policy' },
  920540: { why: 'A Unicode escape (\\uXXXX) was found where it can be used to bypass filters.', app: ['Send real UTF-8 characters instead of \\u escapes outside JSON strings.'], risk: 'policy' },
  920600: { why: 'The Accept header contains invalid characters or syntax.', app: ['Send a standard Accept header.'], risk: 'policy' },
  920610: { why: 'The raw URI contains a fragment (#) – browsers never send fragments.', app: ['Remove "#…" from server-side generated request URLs.'], risk: 'policy' },
  920620: { why: 'Multiple Content-Type headers.', app: ['Send exactly one Content-Type header.'], risk: 'policy' },
  942420: { why: 'Counts special characters in cookies (PL3): 8 or more of ~ ! @ # $ % ^ & * ( ) - + = { } [ ] | : ; " \' ` < > in one cookie.', risk: 'auto' },
  942421: { why: 'Counts special characters in cookies (PL4): 3 or more in one cookie.', risk: 'auto' },
  942430: { why: 'Counts special characters in a parameter (PL2): 12 or more.', risk: 'auto' },
  942431: { why: 'Counts special characters in a parameter (PL3): 6 or more.', risk: 'auto' },
  942432: { why: 'Counts special characters in a parameter (PL4): 2 or more.', risk: 'auto' },
  942440: { why: 'Detects SQL comment sequences such as "--", "/*" or "#" – also present in many random tokens (url-safe base64 uses "-").', risk: 'auto' },
  942460: { why: 'Four or more repeated non-word characters (e.g. "....", "----", "!!!!").', risk: 'auto' },
  942100: { why: 'libinjection recognised SQL syntax (tokens such as quotes, operators, keywords) in the value.', risk: 'auto' },
  941100: { why: 'libinjection recognised an HTML/JavaScript injection (tags, event handlers, javascript: URLs).', risk: 'auto' },
  200002: { why: 'The body could not be parsed (e.g. invalid JSON while Content-Type says application/json). ModSecurity rejects such requests before CRS runs.', app: ['Send a body that matches its Content-Type (valid JSON for application/json). Check empty bodies and trailing characters.'], risk: 'policy' },
  200003: { why: 'The multipart body failed strict validation.', app: ['Let the browser/HTTP library build multipart bodies (FormData); do not hand-craft boundaries.'], risk: 'policy' },
  200004: { why: 'Possible unmatched multipart boundary.', app: ['Use a standard multipart encoder; make sure the boundary does not appear in file content.'], risk: 'policy' },
  200007: { why: 'More arguments than SecArgumentsLimit.', app: ['Reduce the number of parameters (send arrays as JSON).'], risk: 'policy' },
  ENGINE: { why: 'The request body is larger than the WAF inspects or accepts (ModSecurity default: 128 KB without files, 13 MB in total).', app: ['Upload large files directly to storage (e.g. Blob SAS URL) or in chunks; avoid large base64 payloads in JSON.'], waf: ['Raise SecRequestBodyNoFilesLimit / SecRequestBodyLimit if larger bodies are needed.'], risk: 'policy' },
};

// Families: first matching entry wins.
const FAMILIES = [
  { test: (id) => id >= 920000 && id < 921000, why: 'HTTP protocol compliance check.', app: ['Make the client send standard-conformant HTTP (headers, encodings, methods).'], risk: 'policy' },
  { test: (id) => id >= 921000 && id < 922000, why: 'HTTP protocol attack: request smuggling, response splitting or header injection (CR/LF characters, HTTP syntax inside values).', app: ['Never put CR/LF characters into headers, cookies or query values; remove line breaks from values that end up in headers.', 'If a free-text field legitimately contains text like "GET /path HTTP/1.1" (e.g. documentation, chat), keep it in the JSON body and exclude that field.'], risk: 'auto' },
  { test: (id) => id >= 922000 && id < 923000, why: 'Multipart attack (unusual charset or Content-Transfer-Encoding in parts).', app: ['Build multipart bodies with FormData / standard libraries; do not set per-part charsets or transfer encodings.'], risk: 'policy' },
  { test: (id) => id >= 930000 && id < 931000, why: 'Local file inclusion / path traversal: "../", OS file names (/etc/passwd, web.config) or restricted files (.git, .env).', app: ['Do not accept file system paths from the client – reference files by id or by a key from an allow-list.', 'Resolve and validate paths server-side (canonicalise, ensure they stay inside the base directory).'], risk: 'auto' },
  { test: (id) => id >= 931000 && id < 932000, why: 'Remote file inclusion: a full URL (often with an IP address or ending with "?") in a parameter.', app: ['Avoid passing absolute URLs as parameters (redirect targets, image URLs, webhooks). Pass ids or relative paths instead.', 'If URLs must be accepted, validate them against an allow-list of hosts server-side (also protects against SSRF/open redirects).'], risk: 'auto' },
  { test: (id) => id >= 932000 && id < 933000, why: 'Remote command execution: shell syntax or command names (Unix shell, Windows cmd, PowerShell).', app: ['Never pass request data to a shell or exec; use library APIs with argument arrays.', 'Natural-language or code text (chat, comments, scripts) often contains command words – keep such fields in the body and exclude them narrowly.'], risk: 'auto' },
  { test: (id) => id >= 933000 && id < 934000, why: 'PHP injection: PHP tags, function names or variables.', app: ['Never evaluate request data as code. Free text mentioning PHP functions is a false positive – exclude the field.'], risk: 'auto' },
  { test: (id) => id >= 934000 && id < 935000, why: 'Generic application attack: Node.js / Ruby / Python injection, SSRF to cloud metadata, prototype pollution (__proto__, constructor.prototype), ORM lookup operators.', app: ['Never use request keys like __proto__ / constructor; reject them when merging JSON into objects.', 'Do not fetch URLs supplied by the client without an allow-list (SSRF).'], risk: 'auto' },
  { test: (id) => id >= 941000 && id < 942000, why: 'Cross-site scripting: HTML tags, event handlers (onerror=…), javascript: URLs or script-like syntax.', app: ['Encode all output for its context (HTML, attribute, JS, URL); in React avoid dangerouslySetInnerHTML or sanitise with DOMPurify.', 'Set a Content-Security-Policy.', 'If the field is meant to contain HTML/Markdown (rich-text editor), sanitise it server-side with an allow-list and exclude that field for this endpoint.'], risk: 'auto' },
  { test: (id) => id >= 942000 && id < 943000, why: 'SQL injection: SQL keywords, quotes, comments, operators or special-character density.', app: ['Use parameterised queries / an ORM everywhere – then the input is harmless to the database.', 'Free text (chat, notes, search) naturally contains words like "select … from … where" and quotes: exclude the field narrowly rather than changing what users can type.'], risk: 'auto' },
  { test: (id) => id >= 943000 && id < 944000, why: 'Session fixation: a session id passed as a URL parameter, or Set-Cookie inside a value.', app: ['Never transport session ids in URLs or parameters – use cookies with HttpOnly/Secure/SameSite.'], risk: 'auto' },
  { test: (id) => id >= 944000 && id < 945000, why: 'Java attack: class names (java.lang.Runtime), deserialization gadgets, Log4Shell (${jndi:…}) or Spring expressions.', app: ['Never deserialize untrusted data; patch Log4j and similar libraries.'], risk: 'auto' },
  { test: (id) => id >= 950000 && id < 960000, why: 'Data leakage in the response: error messages, stack traces, SQL errors, directory listings or source code.', app: ['Disable detailed error pages in production; return generic errors and log details server-side.', 'Remove directory listings and debug endpoints.'], risk: 'leak' },
  { test: (id) => id >= 200000 && id < 201000, why: 'ModSecurity engine check from the recommended base configuration.', app: ['Send well-formed bodies matching their Content-Type.'], risk: 'policy' },
];

/* ------------------------------------------------------------ main function */

const ASSESSMENTS = {
  'false-positive': { label: 'Likely false positive', tone: 'ok' },
  review: { label: 'Review – probably legitimate input', tone: 'warn' },
  'likely-attack': { label: 'Looks like an attack payload', tone: 'bad' },
  policy: { label: 'Protocol / policy issue', tone: 'info' },
  leak: { label: 'Information leak in the response', tone: 'bad' },
};

function resolveRule(id) {
  if (RULES[id]) return { ...RULES[id] };
  const n = Number(id);
  for (const f of FAMILIES) if (Number.isFinite(n) && f.test(n)) return { why: f.why, app: f.app, waf: f.waf, risk: f.risk };
  return { why: 'Generic CRS detection.', app: [], risk: 'auto' };
}

function locationAdvice(info, x, valueKind, ruleId) {
  const app = [];
  const waf = [];
  const name = info.name || x?.key || '';
  const pc = info.kind === 'cookie' || info.kind === 'cookiename' ? platformCookie(name) : null;
  if (info.kind === 'cookie' || info.kind === 'cookiename') {
    if (pc) {
      app.push(`“${name}” is set by ${pc}, not by your code – its format cannot be changed. Tune the WAF instead.`);
    } else if (valueKind === 'jwt') {
      app.push(`“${name}” is set by your application and contains a full JWT. Consider storing an opaque random session id (hex) in the cookie and keeping the token server-side: smaller cookies on every request, no special characters, and the token is never exposed to the browser. Otherwise keep the JWT and exclude the cookie from this rule.`);
    } else {
      app.push(`Cookies are sent with every request, so a noisy cookie affects the whole site. Store cookie values URL-safe: base64url or hex without + / = ; , quotes or spaces (e.g. Base64UrlEncoder in .NET, Buffer.toString('base64url') in Node).`);
    }
    waf.push(`Exclude the cookie from this rule: ModSecurity “!REQUEST_COOKIES:${name}”; Azure WAF exclusion “Request cookie name Equals ${name}” for rule ${ruleId}.`);
  } else if (info.kind === 'header' || info.kind === 'headername') {
    app.push(`Check whether the client must send header “${name}” and whether its value can be simplified (no free text, no special characters).`);
    waf.push(`Exclude the header from this rule (ModSecurity “!REQUEST_HEADERS:${name}”; Azure “Request header name Equals ${name}”).`);
  } else if (['json', 'query', 'form', 'multipart', 'xml', 'argname'].includes(info.kind)) {
    if (valueKind === 'text' || valueKind === 'markup') {
      app.push(`“${name}” carries user-entered ${valueKind === 'markup' ? 'HTML' : 'text'}. Keep it as is, but make sure the server treats it as data: parameterised queries, output encoding, no shell/eval.`);
      app.push('Avoid hiding such fields from the WAF by encoding them on the client (base64/hex): it has the same effect as an exclusion but is invisible to the WAF team. Prefer an explicit, documented exclusion for this field and endpoint.');
    }
    waf.push(`Exclude only this ${info.kind === 'json' ? 'JSON field' : 'parameter'} for this endpoint – see the Exclusion button for ready-made snippets (Azure: ${info.kind === 'json' ? 'Request body JSON arg name' : info.kind === 'query' ? 'Query string arg name' : 'Request body post arg name'} Equals “${name}”).`);
  } else if (info.kind === 'path' || info.kind === 'uri' || info.kind === 'line') {
    app.push('The URL itself matched. Avoid putting user content or encoded data into path segments; use ids in the path and send content in the body.');
    waf.push('URL-based matches can only be excluded by disabling the rule for that path (ctl:ruleRemoveById) – Azure WAF cannot exclude the URL path; use a custom rule or disable the rule.');
  } else if (info.kind === 'method') {
    // handled by the rule entry
  } else if (info.kind === 'file') {
    app.push('Sanitise upload file names on the client; store files under generated names.');
  }
  return { app, waf };
}

function valueAdvice(valueKind, ruleId) {
  switch (valueKind) {
    case 'jwt':
      return ['The value is a JWT: base64url segments contain "-" and "_" and random character sequences that resemble SQL comments/operators. This is not an attack – exclude the variable.'];
    case 'token':
    case 'hex':
    case 'uuid':
      return [`The value is ${VALUE_LABELS[valueKind]} – random data that only coincidentally resembles attack syntax. If you generate it yourself, prefer hex or base64url without "--" sequences; otherwise exclude the variable.`];
    case 'url':
      return ['The value is a URL. If it is a link the app generates (redirect target, return URL), pass a relative path or an id instead of a full URL.'];
    default:
      return [];
  }
}

function assess(rule, m, x, valueKind) {
  if (rule.risk === 'policy' || rule.risk === 'leak') return rule.risk;
  if (['jwt', 'token', 'hex', 'uuid'].includes(valueKind)) return 'false-positive';
  const id = Number(m.id);
  const pl = matchPL(m) ?? 1;
  if (valueKind === 'text' || valueKind === 'markup') {
    // libinjection / strong PL1 signatures on free text deserve a closer look
    if (pl === 1 && (id === 942100 || id === 941100 || (id >= 941110 && id <= 941190) || (id >= 930100 && id <= 930130))) return 'likely-attack';
    return 'review';
  }
  if (pl >= 3) return 'false-positive';
  if (pl === 1) return 'likely-attack';
  return 'review';
}

/** Notes that depend on the simulated Azure policy (when one is loaded). */
function policyNotes(m, az) {
  if (!az) return [];
  const out = [];
  if (m.override === 'log') out.push(`Your policy sets rule ${m.id} to Log: it is reported but does not add to the anomaly score.`);
  if (m.override === 'block' || m.override === 'redirect') out.push(`Your policy sets rule ${m.id} to ${m.override}: a single match blocks the request.`);
  if (az.managedSkipped) out.push(`Custom rule “${az.decidedBy?.name}” decided this request (${az.decidedBy?.action}) – Azure did not evaluate managed rules.`);
  if (az.mode === 'Detection') out.push('Your policy is in Detection mode: Azure only logs this finding.');
  if (!out.length && m.id !== 'ENGINE') out.push(`Active in your policy (${az.ruleSet || 'managed rules'}). To allow legitimate traffic, add a rule exclusion (Exclusion button → Front Door JSON / CLI / Terraform / Bicep), or set the rule to Log.`);
  return out;
}

function azureNotes(m) {
  const id = Number(m.id);
  const pl = matchPL(m);
  const notes = [];
  if (id >= 950000 && id < 960000) notes.push('Azure WAF (Front Door / Application Gateway) does not inspect response bodies – this finding is not enforced there.');
  else if (pl >= 3) notes.push(`Not relevant on Azure WAF: Azure supports only paranoia levels 1 and 2 – PL${pl} rules are absent (DRS) or permanently inactive (CRS 3.2).`);
  else if (pl === 2) notes.push('Azure DRS 2.2: PL2 rules are disabled by default (DRS 2.1 / CRS 3.2 enable many of them).');
  if (id === 942440) notes.push('Azure DRS 2.x replaces 942440 with Microsoft rule 99031002 (same detection).');
  if (id === 942430) notes.push('Azure DRS 2.x replaces 942430 with Microsoft rule 99031005.');
  if (id === 911100) notes.push('Azure DRS: 911100 is a PL1 Critical rule (group METHOD-ENFORCEMENT, "lock-down methods PUT, PATCH"). Azure has no setting for the allowed-method list – if your API needs PUT/PATCH/DELETE, disable rule 911100 or set its action to Log in the WAF policy. Avoid a broad custom Allow rule: it skips all managed rules for matching requests.');
  if (id === 920320 || id === 920300) notes.push('Azure DRS: this is a PL2 Notice rule (+2).');
  if (id === 'ENGINE' || m.id === 'ENGINE') notes.push('Azure WAF has its own body inspection and size limits configured in the policy (request body inspection, max request body size).');
  if (notes.length && !(id >= 950000 && id < 960000)) notes.push('Azure blocks only when the policy is in Prevention mode; in Detection mode (the default) it just logs.');
  return notes;
}

/**
 * Build a recommendation for one finding.
 * @param {object} m   summarised match (engine result)
 * @param {object} ctx { varCtx } – see buildContext()
 * @returns {{assessment: string, assessmentLabel: string, tone: string, headline: string, why: string, app: string[], waf: string[], azure: string[], valueKind: string, where: string}}
 */
export function recommend(m, ctx = {}) {
  const x = (m.links?.[0]?.matches || [])[0] || null;
  const info = x ? describeVar(x, ctx.varCtx || {}) : { kind: m.id === 'ENGINE' ? 'body' : 'other', label: 'Request', name: null };
  const rule = resolveRule(m.id);
  const valueKind = x ? classifyValue(x.value) : 'empty';
  const loc = x ? locationAdvice(info, x, valueKind, m.id) : { app: [], waf: [] };
  const assessment = assess(rule, m, x, valueKind);
  const a = ASSESSMENTS[assessment];

  let headline;
  const where = info.label.replace(/[“”]/g, '"');
  if (assessment === 'false-positive') headline = `${where} contains ${VALUE_LABELS[valueKind] || 'data'} that resembles attack syntax – tune the WAF rather than the application.`;
  else if (assessment === 'review') headline = `${where} contains ${VALUE_LABELS[valueKind] || 'input'} that matches an attack pattern. Usually legitimate – make sure the server treats it safely, then exclude narrowly.`;
  else if (assessment === 'likely-attack') headline = `${where} contains a typical attack payload. If this request is normal application traffic, find out why the app produces this value.`;
  else if (assessment === 'leak') headline = 'The response reveals internal details (errors, stack traces, files).';
  else headline = 'The request does not meet the WAF policy – fix the client or adjust the policy.';

  const app = [...(rule.app || []), ...valueAdvice(valueKind, m.id), ...loc.app];
  const waf = [...(rule.waf || []), ...loc.waf];
  if (!waf.length && m.id !== 'ENGINE') waf.push(`If the request is legitimate, disable rule ${m.id} for this endpoint only (ctl:ruleRemoveById=${m.id}) – see the Exclusion button.`);
  return {
    assessment,
    assessmentLabel: a.label,
    tone: a.tone,
    headline,
    why: rule.why,
    app: dedupe(app),
    waf: dedupe(waf),
    azure: [...policyNotes(m, ctx.azure), ...azureNotes(m)],
    valueKind,
    where,
  };
}

function dedupe(list) {
  return [...new Set(list.filter(Boolean))];
}

/* ------------------------------------------------------------ issues report */

/** Generalise a path for grouping (ids -> :id). */
export function routeKey(path) {
  return String(path || '/')
    .split('?')[0]
    .split('/')
    .map((s) => (/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(s) || /^\d+$/.test(s) || /^[0-9a-f]{16,}$/i.test(s) || (s.length >= 20 && /\d/.test(s) && /^[\w~-]+$/.test(s)) ? ':id' : s.replace(/\d{3,}/g, 'N')))
    .join('/');
}

/**
 * Group findings across entries: one issue per (rule, variable).
 * @param {Array} entries  host entries with results
 * @param {{blockingPL:number, varCtxFor:(entry)=>object}} opts
 */
export function buildIssues(entries, { blockingPL = 1, varCtxFor = () => ({}), isDetection = () => true } = {}) {
  const map = new Map();
  for (const e of entries) {
    const r = e.result;
    if (!r || !Array.isArray(r.matches)) continue;
    const path = r.variables?.REQUEST_FILENAME || '/';
    const route = `${e.request?.method || ''} ${routeKey(path)}`;
    for (const m of r.matches) {
      if (!isDetection(m)) continue;
      const x = (m.links?.[0]?.matches || [])[0];
      const varName = x ? x.var.replace(/^(ARGS|ARGS_GET|ARGS_POST):json\.(.+?)\.\d+(\..*)?$/, '$1:json.$2[]$3') : String(m.id);
      const key = `${m.id}|${varName}`;
      let it = map.get(key);
      if (!it) {
        it = { key, id: m.id, file: m.file, line: m.line, msg: m.msg, severity: m.severity, pl: matchPL(m), varName, sample: m, sampleEntry: e, requests: new Set(), routes: new Map(), blocked: 0, scoreSum: 0 };
        map.set(key, it);
      }
      it.requests.add(e.id);
      it.routes.set(route, (it.routes.get(route) || 0) + 1);
      if (r.blocked) it.blocked++;
    }
  }
  const out = [];
  for (const it of map.values()) {
    const rec = recommend(it.sample, { varCtx: varCtxFor(it.sampleEntry), azure: it.sampleEntry.result?.azure || null });
    out.push({
      ...it,
      count: it.requests.size,
      routes: [...it.routes.entries()].sort((a, b) => b[1] - a[1]).map(([route, n]) => ({ route, n })),
      counted: (it.pl ?? 1) <= blockingPL,
      rec,
    });
  }
  out.sort((a, b) => Number(b.counted) - Number(a.counted) || (a.pl ?? 9) - (b.pl ?? 9) || b.count - a.count || String(a.id).localeCompare(String(b.id)));
  return out;
}

/** Escape text for Markdown (request-derived names must not inject links, images or HTML). */
export function mdText(v) {
  return String(v ?? '').replace(/[\\`*_{}[\]()<>#+!|~]/g, (c) => '\\' + c).replace(/\r?\n/g, ' ');
}

/** Inline code span that is safe for any content (uses a fence longer than any backtick run). */
export function mdCode(v) {
  const t = String(v ?? '').replace(/\r?\n/g, ' ');
  const longest = Math.max(0, ...(t.match(/`+/g) || []).map((x) => x.length));
  const fence = '`'.repeat(longest + 1);
  const pad = t.startsWith('`') || t.endsWith('`') ? ' ' : '';
  return fence + pad + t + pad + fence;
}

/** Markdown export of the issues report for developers / WAF owners. */
export function issuesToMarkdown(issues, { blockingPL = 1, version = '', total = 0 } = {}) {
  const lines = [];
  lines.push(`# WAF findings report`, '');
  lines.push(`CRS ${version || ''} · simulated paranoia level PL${blockingPL} · ${total} requests analysed · ${issues.length} distinct findings`, '');
  const section = (title, list) => {
    if (!list.length) return;
    lines.push(`## ${title}`, '');
    for (const it of list) {
      lines.push(`### ${mdText(it.id)} – ${mdText(it.msg || '')}`);
      lines.push('');
      lines.push(`- **Where:** ${mdText(it.rec.where)} (${mdCode(it.varName)})`);
      lines.push(`- **Paranoia level:** PL${it.pl ?? '?'} · severity ${it.severity || '-'} · ${it.count} request(s)`);
      lines.push(`- **Endpoints:** ${it.routes.slice(0, 5).map((r) => `${mdCode(r.route)} (${r.n})`).join(', ')}${it.routes.length > 5 ? ', …' : ''}`);
      lines.push(`- **Assessment:** ${it.rec.assessmentLabel} – ${mdText(it.rec.headline)}`);
      lines.push(`- **Why:** ${mdText(it.rec.why)}`);
      if (it.rec.app.length) {
        lines.push(`- **Application:**`);
        for (const a of it.rec.app) lines.push(`  - ${mdText(a)}`);
      }
      if (it.rec.waf.length) {
        lines.push(`- **WAF:**`);
        for (const a of it.rec.waf) lines.push(`  - ${mdText(a)}`);
      }
      if (it.rec.azure.length) {
        lines.push(`- **Azure WAF:**`);
        for (const a of it.rec.azure) lines.push(`  - ${mdText(a)}`);
      }
      lines.push('');
    }
  };
  section(`Counted at PL${blockingPL} (affects blocking)`, issues.filter((i) => i.counted));
  section('Only at higher paranoia levels', issues.filter((i) => !i.counted));
  return lines.join('\n');
}
