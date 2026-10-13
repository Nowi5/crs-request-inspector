#!/usr/bin/env node
// Tests for extension/src/parsers (input parsing -> normalized request model).
// Usage: node scripts/test-parsers.mjs [name-filter]
// Plain node:assert, no dependencies. Exits non-zero when a test fails.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseInput, detectFormat, parseHar, fromHarEntry, normalizeRequest,
} from '../extension/src/parsers/index.js';
import { computeReferer } from '../extension/src/parsers/fetch.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIX = path.join(ROOT, 'tests', 'fixtures', 'paste');
const fixture = (name) => readFileSync(path.join(FIX, name), 'utf8');

// ---------------------------------------------------------------------------------------
// Tiny test harness
// ---------------------------------------------------------------------------------------
const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const filter = process.argv[2];

/** Parse and assert there were no errors. */
function parseOk(text, options, expectedFormat) {
  const res = parseInput(text, options);
  assert.deepEqual(res.errors, [], `unexpected errors: ${res.errors.join(' | ')}`);
  if (expectedFormat) assert.equal(res.format, expectedFormat);
  return res;
}
const H = (name, value) => ({ name, value });
const header = (req, name) => req.headers.filter((h) => h.name.toLowerCase() === name.toLowerCase()).map((h) => h.value);
const hasNote = (req, re) => req.notes.some((n) => (typeof re === 'string' ? n === re : re.test(n)));
const utf8Len = (s) => new TextEncoder().encode(s).length;

// ---------------------------------------------------------------------------------------
// Shared expected values (redacted test cookies)
// ---------------------------------------------------------------------------------------
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36';
const SEC_CH_UA = '"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"';
const AUTH = 'cjky+ZV4b2KyZjwmsRIuCPOLNEPOCPOLNEPO/aE7+eMJvWmwtgiaES/J0Cn+r+4RPDcsTwXRjkwSs2maLamcYuuEShOKB8BpEm==';
const CSRF = 'rvqs8QY0fdXWv8qPmqIdwB.4e0823d35aa61ac819ee1bfb708d03335efe856b1bad53806489fb06af5fd6a7';
const SESSION_JWT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJyb2xlIjoiYWRtaW4ifQ.c2lnbmF0dXJlLXJlZGFjdGVkLWZvci10ZXN0cw';
const ALANG = 'en-SG,en;q=0.9,de-DE;q=0.8,de;q=0.7,en-US;q=0.6,zh-CN;q=0.5,zh;q=0.4';
const THREAD = '5d2c6e1a-3b7f-4c9e-9a41-2f8b7c0d1e63';
const POST_URL = `https://dev.example.com/api/v1/docs/folders/${THREAD}/comments`;
const GET_URL = 'https://dev.example.com/api/v1/workspace-options';
const REFERER = `https://dev.example.com/docs/${THREAD}`;
const BODY = '{"content":"enc:hex1:48656c6c6f","resourceItems":[],"linkedResourceItemIds":[],"sourceLinks":[]}';
const PSEUDO_NOTE = 'Detected HTTP/2 pseudo-headers (authority, method, path, scheme); treated as an HTTP/2 request and removed from the header list.';
const FETCH_COOKIE_NOTE = "Cookies are not included in 'Copy as fetch' output; use 'Copy as cURL' or PowerShell to include them.";

const PS_GET_HEADERS = [
  H('Host', 'dev.example.com'),
  H('accept', '*/*'),
  H('accept-encoding', 'gzip, deflate, br, zstd'),
  H('accept-language', ALANG),
  H('cache-control', 'no-cache'),
  H('dnt', '1'),
  H('pragma', 'no-cache'),
  H('priority', 'u=1, i'),
  H('referer', REFERER),
  H('sec-ch-ua', SEC_CH_UA),
  H('sec-ch-ua-mobile', '?0'),
  H('sec-ch-ua-platform', '"Windows"'),
  H('sec-fetch-dest', 'empty'),
  H('sec-fetch-mode', 'cors'),
  H('sec-fetch-site', 'same-origin'),
  H('User-Agent', UA),
  H('Cookie', `AppServiceAuthSession=${AUTH}; app_session=${SESSION_JWT}; app_csrf=${CSRF}`),
];

const PS_POST_HEADERS = [
  H('Host', 'dev.example.com'),
  H('accept', '*/*'),
  H('accept-encoding', 'gzip, deflate, br, zstd'),
  H('accept-language', ALANG),
  H('dnt', '1'),
  H('origin', 'https://dev.example.com'),
  H('priority', 'u=1, i'),
  H('referer', REFERER),
  H('sec-ch-ua', SEC_CH_UA),
  H('sec-ch-ua-mobile', '?0'),
  H('sec-ch-ua-platform', '"Windows"'),
  H('sec-fetch-dest', 'empty'),
  H('sec-fetch-mode', 'cors'),
  H('sec-fetch-site', 'same-origin'),
  H('x-csrf-token', CSRF),
  H('User-Agent', UA),
  H('Cookie', `AppServiceAuthSession=${AUTH}; app_csrf=${CSRF}; app_session=${SESSION_JWT}`),
  H('Content-Type', 'application/json'),
  H('Content-Length', String(utf8Len(BODY))),
];

// What Chrome's "Copy as cURL" of example 2 turns into (cookie at the -b position).
const CURL_POST_HEADERS = [
  H('Host', 'dev.example.com'),
  H('accept', '*/*'),
  H('accept-language', ALANG),
  H('content-type', 'application/json'),
  H('Cookie', `AppServiceAuthSession=${AUTH}; app_csrf=${CSRF}; app_session=${SESSION_JWT}`),
  H('dnt', '1'),
  H('origin', 'https://dev.example.com'),
  H('priority', 'u=1, i'),
  H('referer', REFERER),
  H('sec-ch-ua', SEC_CH_UA),
  H('sec-ch-ua-mobile', '?0'),
  H('sec-ch-ua-platform', '"Windows"'),
  H('sec-fetch-dest', 'empty'),
  H('sec-fetch-mode', 'cors'),
  H('sec-fetch-site', 'same-origin'),
  H('user-agent', UA),
  H('x-csrf-token', CSRF),
  H('Accept-Encoding', 'deflate, gzip, br, zstd'),
  H('Content-Length', '96'),
];

// ---------------------------------------------------------------------------------------
// PowerShell
// ---------------------------------------------------------------------------------------
test('powershell: example 1 (HTTP/2 GET with WebSession)', () => {
  const { requests } = parseOk(fixture('powershell-get-h2.txt'), {}, 'powershell');
  assert.equal(requests.length, 1);
  const r = requests[0];
  assert.equal(r.method, 'GET');
  assert.equal(r.url, GET_URL);
  assert.equal(r.httpVersion, 'HTTP/2.0');
  assert.equal(r.source, 'powershell');
  assert.deepEqual(r.headers, PS_GET_HEADERS);
  assert.equal(r.body, null);
  assert.equal(r.bodyEncoding, 'text');
  assert.ok(hasNote(r, PSEUDO_NOTE), r.notes.join('\n'));
  assert.equal(header(r, 'content-length').length, 0, 'no Content-Length for GET without body');
});

test('powershell: example 2 (HTTP/2 JSON POST)', () => {
  const { requests } = parseOk(fixture('powershell-post-h2.txt'), {}, 'powershell');
  assert.equal(requests.length, 1);
  const r = requests[0];
  assert.equal(r.method, 'POST');
  assert.equal(r.url, POST_URL);
  assert.equal(r.httpVersion, 'HTTP/2.0');
  assert.deepEqual(r.headers, PS_POST_HEADERS);
  assert.equal(r.body, BODY);
  assert.equal(header(r, 'content-length')[0], '96');
  assert.ok(hasNote(r, PSEUDO_NOTE));
  assert.ok(hasNote(r, /Added headers: Host .*Content-Length/));
});

test('powershell: "Copy all as PowerShell" (two invocations, ;\\r\\n separated)', () => {
  const { requests } = parseOk(fixture('powershell-copy-all.txt'), {}, 'powershell');
  assert.equal(requests.length, 2);
  const single1 = parseOk(fixture('powershell-get-h2.txt')).requests[0];
  const single2 = parseOk(fixture('powershell-post-h2.txt')).requests[0];
  assert.deepEqual(requests[0], single1);
  assert.deepEqual(requests[1], single2);
});

test('powershell: session state is per $session assignment', () => {
  const text = [
    '$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession',
    '$session.Cookies.Add((New-Object System.Net.Cookie("a", "1", "/", "x.example.com")))',
    'Invoke-WebRequest -Uri "https://x.example.com/one" -WebSession $session; Invoke-WebRequest -Uri "https://x.example.com/two" -WebSession $session',
    '$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession',
    'Invoke-WebRequest -Uri "https://x.example.com/three" -WebSession $session',
  ].join('\n');
  const { requests } = parseOk(text);
  assert.equal(requests.length, 3);
  assert.deepEqual(header(requests[0], 'cookie'), ['a=1']);
  assert.deepEqual(header(requests[1], 'cookie'), ['a=1']);
  assert.deepEqual(header(requests[2], 'cookie'), []);
});

test('powershell: cookie domain matching and skipped-cookie note', () => {
  const text = `$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.Cookies.Add((New-Object System.Net.Cookie("host_only", "1", "/", "app.example.com")))
$session.Cookies.Add((New-Object System.Net.Cookie("parent", "2", "/", ".example.com")))
$session.Cookies.Add((New-Object System.Net.Cookie("other", "3", "/", "other.test")))
$session.Cookies.Add((New-Object System.Net.Cookie("pathed", "4", "/admin", "app.example.com")))
$session.Cookies.Add((New-Object System.Net.Cookie("suffix", "5", "/", "ample.com")))
Invoke-WebRequest -UseBasicParsing -Uri "https://app.example.com/api/x" -WebSession $session`;
  const r = parseOk(text).requests[0];
  assert.deepEqual(header(r, 'cookie'), ['host_only=1; parent=2']);
  const note = r.notes.find((n) => n.startsWith('Skipped session cookies'));
  assert.ok(note, r.notes.join('\n'));
  assert.match(note, /other \(domain other\.test/);
  assert.match(note, /pathed \(domain app\.example\.com, path \/admin\)/);
  assert.match(note, /suffix/);
});

test('powershell: non-ASCII body via [Text.Encoding]::UTF8.GetBytes and $([char]N)', () => {
  // Chrome emits non-ASCII characters as $([char]N) subexpressions (UTF-16 code units).
  const text = 'Invoke-WebRequest -UseBasicParsing -Uri "https://dev.example.com/api/m" `\n'
    + '-Method "POST" `\n'
    + '-ContentType "application/json" `\n'
    + '-Body ([System.Text.Encoding]::UTF8.GetBytes("{`"t`":`"Gr$([char]252)$([char]223)e $([char]55357)$([char]56832)`"}"))';
  const r = parseOk(text).requests[0];
  const expected = '{"t":"Gr' + String.fromCharCode(252, 223) + 'e ' + String.fromCodePoint(0x1f600) + '"}';
  assert.equal(r.body, expected);
  assert.equal(r.bodyEncoding, 'text');
  assert.deepEqual(header(r, 'content-length'), [String(utf8Len(expected))]);
  assert.equal(r.httpVersion, 'HTTP/1.1');
});

test('powershell: quoting, escapes, here-strings and variables', () => {
  const text = `
# hand-written
$body = @"
{"name": "O'Brien", "tab": "a\`tb"}
"@
$h = @{ 'X-Single' = 'it''s'; "X-Double" = "say ""hi"" \`$HOME \`u{263A}"
  X-Bare = 42 }
Invoke-RestMethod -Uri 'https://api.example.com/v1/items?q=a b&x=%41' -Meth Put -Head $h -ContentType "application/json; charset=utf-8" -Body $body -SkipCertificateCheck -MaximumRedirection 0 -TimeoutSec 5
`;
  const r = parseOk(text, {}, 'powershell').requests[0];
  assert.equal(r.method, 'PUT');
  assert.equal(r.url, 'https://api.example.com/v1/items?q=a b&x=%41');
  assert.deepEqual(header(r, 'x-single'), ["it's"]);
  assert.deepEqual(header(r, 'x-double'), ['say "hi" $HOME ' + String.fromCodePoint(0x263a)]);
  assert.deepEqual(header(r, 'x-bare'), ['42']);
  assert.equal(r.body, '{"name": "O\'Brien", "tab": "a\tb"}');
  assert.deepEqual(header(r, 'content-type'), ['application/json; charset=utf-8']);
});

test('powershell: hashtable bodies, ConvertTo-Json, default content type, user agent parameter', () => {
  const text = `$payload = @{ user = "a b"; role = "admin&x" }
Invoke-WebRequest -Uri https://api.example.com/form -Method Post -Body $payload -UserAgent "ua-test/1"
Invoke-WebRequest https://api.example.com/search -Body @{ q = "x y"; n = 1 }
$json = @{ a = 1; b = @("x", "y") } | ConvertTo-Json -Compress
iwr -Uri "https://api.example.com/json" -Method PATCH -ContentType 'application/json' -Body $json
iwr -Uri "https://api.example.com/raw" -Method POST -Body "plain=1"`;
  const { requests } = parseOk(text);
  assert.equal(requests.length, 4);
  const [form, query, json, raw] = requests;
  assert.equal(form.body, 'user=a+b&role=admin%26x');
  assert.deepEqual(header(form, 'content-type'), ['application/x-www-form-urlencoded']);
  assert.deepEqual(header(form, 'user-agent'), ['ua-test/1']);
  assert.equal(query.method, 'GET');
  assert.equal(query.url, 'https://api.example.com/search?q=x+y&n=1');
  assert.equal(query.body, null);
  assert.equal(json.body, '{"a":1,"b":["x","y"]}');
  assert.equal(json.method, 'PATCH');
  assert.equal(raw.body, 'plain=1');
  assert.deepEqual(header(raw, 'content-type'), ['application/x-www-form-urlencoded']);
  assert.ok(hasNote(raw, /PowerShell sends application\/x-www-form-urlencoded/));
});

test('powershell: POST without body gets Content-Length: 0', () => {
  const r = parseOk('Invoke-WebRequest -Uri "https://a.example.com/x" -Method POST').requests[0];
  assert.deepEqual(header(r, 'content-length'), ['0']);
  assert.equal(r.body, null);
});

test('powershell: errors are reported without losing other requests', () => {
  const text = 'Invoke-WebRequest -Uri "https://a.example.com/ok"\nInvoke-WebRequest -Method POST\nInvoke-WebRequest -Uri "https://a.example.com/unterminated';
  const res = parseInput(text);
  assert.equal(res.format, 'powershell');
  assert.equal(res.requests.length, 1);
  assert.equal(res.requests[0].url, 'https://a.example.com/ok');
  assert.equal(res.errors.length, 2, res.errors.join('\n'));
});

// ---------------------------------------------------------------------------------------
// curl
// ---------------------------------------------------------------------------------------
test('curl bash: example 2 as Chrome "Copy as cURL (bash)"', () => {
  const { requests } = parseOk(fixture('curl-bash-post.txt'), {}, 'curl');
  assert.equal(requests.length, 1);
  const r = requests[0];
  assert.equal(r.method, 'POST');
  assert.equal(r.url, POST_URL);
  assert.equal(r.httpVersion, 'HTTP/1.1');
  assert.equal(r.source, 'curl');
  assert.deepEqual(r.headers, CURL_POST_HEADERS);
  assert.equal(r.body, BODY);
  assert.ok(hasNote(r, /--compressed/));
});

test('curl cmd: example 2 as Chrome "Copy as cURL (cmd)" equals the bash result', () => {
  const bash = parseOk(fixture('curl-bash-post.txt')).requests[0];
  const cmd = parseOk(fixture('curl-cmd-post.txt'), {}, 'curl').requests[0];
  assert.deepEqual(cmd, bash);
});

test('curl: "Copy all as cURL" bash ( ;\\n ) and cmd ( &\\r\\n )', () => {
  const bash = parseOk(fixture('curl-bash-copy-all.txt'), {}, 'curl').requests;
  const cmd = parseOk(fixture('curl-cmd-copy-all.txt'), {}, 'curl').requests;
  assert.equal(bash.length, 2);
  assert.deepEqual(cmd, bash);
  assert.equal(bash[0].method, 'GET');
  assert.equal(bash[0].url, GET_URL);
  assert.equal(bash[0].body, null);
  assert.deepEqual(header(bash[0], 'cookie'), [`AppServiceAuthSession=${AUTH}; app_session=${SESSION_JWT}; app_csrf=${CSRF}`]);
  assert.deepEqual(header(bash[0], 'content-length'), []);
  assert.deepEqual(bash[1], parseOk(fixture('curl-bash-post.txt')).requests[0]);
  // Variant separator " ^&" + newline (escaped ampersand) must also split the commands.
  const caret = parseOk(fixture('curl-cmd-copy-all.txt').replace(/ &\r\n/g, ' ^&\n'), {}, 'curl').requests;
  assert.deepEqual(caret, bash);
});

test("curl bash: $'...' ANSI-C quoting, URL glob escapes, empty header, -X", () => {
  const r = parseOk(fixture('curl-bash-ansi-c.txt'), {}, 'curl').requests[0];
  assert.equal(r.method, 'PUT');
  assert.equal(r.url, 'https://shop.example.com/api/reviews?filter[status]=open&sort={date}');
  const body = '{"comment":"It\'s great!\nThanks\tCaf' + String.fromCharCode(233) + ' \\o/"}';
  assert.equal(r.body, body);
  assert.deepEqual(header(r, 'x-empty'), ['']);
  assert.deepEqual(header(r, 'content-length'), [String(utf8Len(body))]);
  assert.deepEqual(header(r, 'accept-encoding'), ['deflate, gzip, br, zstd']);
});

test('curl cmd: caret escapes for % & " \\ ^ < > | and multi-line bodies', () => {
  const r = parseOk(fixture('curl-cmd-special-chars.txt'), {}, 'curl').requests[0];
  assert.equal(r.url, 'https://shop.example.com/search?q=100%25&path=%PATH%&x={a}');
  // Chrome's cmd escaping turns CRLF into a cmd newline, so the CR is lost.
  assert.equal(r.body, 'line1 "quoted" \\back\\slash\nline2 & 50% ^caret^ <tag> |pipe|');
  assert.equal(r.method, 'POST');
});

test('curl: -F multipart body, -u basic auth, -A user agent, --form-string', () => {
  const r = parseOk(fixture('curl-bash-multipart-form.txt'), { multipartBoundary: '------------------------0123456789abcdef' }, 'curl').requests[0];
  const b = '------------------------0123456789abcdef';
  assert.equal(r.method, 'POST');
  assert.equal(r.url, 'https://upload.example.com/api/v2/files');
  const body = `--${b}\r\nContent-Disposition: form-data; name="title"\r\n\r\nQuarterly report\r\n`
    + `--${b}\r\nContent-Disposition: form-data; name="summary"\r\nContent-Type: text/markdown\r\n\r\nRevenue up\r\n`
    + `--${b}\r\nContent-Disposition: form-data; name="file"; filename="q3 summary.pdf"\r\nContent-Type: application/pdf\r\n\r\n\r\n`
    + `--${b}\r\nContent-Disposition: form-data; name="comment"\r\n\r\n<script>alert(1)</script>\r\n`
    + `--${b}--\r\n`;
  assert.equal(r.body, body);
  assert.deepEqual(r.headers, [
    H('Host', 'upload.example.com'),
    H('Authorization', 'Basic ' + Buffer.from('tester:s3cret-test').toString('base64')),
    H('User-Agent', 'curl-fixture/1.0'),
    H('Content-Type', `multipart/form-data; boundary=${b}`),
    H('Content-Length', String(utf8Len(body))),
  ]);
  assert.ok(hasNote(r, /q3 summary\.pdf .*not available/));
});

test('curl: random multipart boundary looks like curl\'s', () => {
  const r = parseOk("curl -F a=1 https://x.example.com/").requests[0];
  assert.match(header(r, 'content-type')[0], /^multipart\/form-data; boundary=-{24}[0-9a-f]{16}$/);
});

test('curl: -d defaults, multiple -d, --data-urlencode, -G, -I, --json, -H Host, short clusters', () => {
  const text = [
    "curl -sSL -d 'a=1' -d b=2 --data-urlencode 'q=x y&z' --data-urlencode '=ä' https://api.example.com/p",
    "curl -G -d 'x=1' --data-urlencode 'y=a/b' 'https://api.example.com/g?keep=1#frag'",
    'curl -I https://api.example.com/head',
    'curl --json \'{"k":1}\' https://api.example.com/j',
    "curl -XDELETE -H 'Host: virtual.example' -H 'X-Dup: 1' -H 'X-Dup: 2' -e https://ref.example/ https://10.0.0.5:8443/x",
    "curl -X POST https://api.example.com/empty",
  ].join('\n');
  const { requests } = parseOk(text);
  assert.equal(requests.length, 6);
  const [p, g, head, j, del, empty] = requests;
  assert.equal(p.method, 'POST');
  assert.equal(p.body, 'a=1&b=2&q=x%20y%26z&%C3%A4');
  assert.deepEqual(header(p, 'content-type'), ['application/x-www-form-urlencoded']);
  assert.ok(hasNote(p, /curl sends application\/x-www-form-urlencoded/));
  assert.equal(g.method, 'GET');
  assert.equal(g.url, 'https://api.example.com/g?keep=1&x=1&y=a%2Fb#frag');
  assert.equal(g.body, null);
  assert.equal(head.method, 'HEAD');
  assert.equal(j.body, '{"k":1}');
  assert.deepEqual(header(j, 'content-type'), ['application/json']);
  assert.deepEqual(header(j, 'accept'), ['application/json']);
  assert.equal(del.method, 'DELETE');
  assert.deepEqual(del.headers, [
    H('Host', 'virtual.example'), H('X-Dup', '1'), H('X-Dup', '2'), H('Referer', 'https://ref.example/'),
  ]);
  assert.deepEqual(header(empty, 'content-length'), ['0']);
});

test('curl: problems are reported per command, good commands are kept', () => {
  const res = parseInput("curl https://ok.example.com/a ;\ncurl -H 'x: y'\ncurl --data-binary @payload.bin --bogus-flag https://ok.example.com/b");
  assert.equal(res.format, 'curl');
  assert.equal(res.requests.length, 2);
  assert.equal(res.errors.length, 1);
  assert.match(res.errors[0], /No URL/);
  assert.ok(hasNote(res.requests[1], /payload\.bin.*not available/));
  assert.ok(hasNote(res.requests[1], /--bogus-flag/));
});

// ---------------------------------------------------------------------------------------
// fetch
// ---------------------------------------------------------------------------------------
const FETCH_HEADERS = [
  H('Host', 'dev.example.com'),
  H('accept', '*/*'),
  H('accept-language', ALANG),
  H('content-type', 'application/json'),
  H('priority', 'u=1, i'),
  H('sec-ch-ua', SEC_CH_UA),
  H('sec-ch-ua-mobile', '?0'),
  H('sec-ch-ua-platform', '"Windows"'),
  H('sec-fetch-dest', 'empty'),
  H('sec-fetch-mode', 'cors'),
  H('sec-fetch-site', 'same-origin'),
  H('x-csrf-token', CSRF),
];

test('fetch: example 2 as Chrome "Copy as fetch"', () => {
  const r = parseOk(fixture('fetch-post.txt'), {}, 'fetch').requests[0];
  assert.equal(r.method, 'POST');
  assert.equal(r.url, POST_URL);
  assert.equal(r.httpVersion, 'HTTP/1.1');
  assert.equal(r.source, 'fetch');
  assert.deepEqual(r.headers, [...FETCH_HEADERS, H('Referer', REFERER), H('Content-Length', '96')]);
  assert.equal(r.body, BODY);
  assert.ok(hasNote(r, FETCH_COOKIE_NOTE));
});

test('fetch: example 2 as Chrome "Copy as fetch (Node.js)"', () => {
  const r = parseOk(fixture('fetch-nodejs-post.txt'), {}, 'fetch').requests[0];
  assert.equal(r.method, 'POST');
  assert.deepEqual(r.headers, [
    ...FETCH_HEADERS,
    H('cookie', `AppServiceAuthSession=${AUTH}; app_csrf=${CSRF}; app_session=${SESSION_JWT}`),
    H('Referer', REFERER),
    H('Content-Length', '96'),
  ]);
  assert.equal(r.body, BODY);
  assert.ok(!hasNote(r, FETCH_COOKIE_NOTE));
  assert.ok(hasNote(r, /Referrer-Policy/));
});

test('fetch: "Copy all as fetch" and body: null', () => {
  const { requests } = parseOk(fixture('fetch-copy-all.txt'), {}, 'fetch');
  assert.equal(requests.length, 2);
  assert.equal(requests[0].method, 'GET');
  assert.equal(requests[0].body, null);
  assert.deepEqual(header(requests[0], 'content-length'), []);
  assert.deepEqual(requests[1], parseOk(fixture('fetch-post.txt')).requests[0]);
});

test('fetch: referrer policy handling and hand-written literals', () => {
  assert.equal(computeReferer('https://a.example/p?q#f', 'https://b.example/x'), 'https://a.example/');
  assert.equal(computeReferer('https://a.example/p?q#f', 'https://a.example/x'), 'https://a.example/p?q');
  assert.equal(computeReferer('https://a.example/p', 'http://a.example/x'), null);
  assert.equal(computeReferer('https://a.example/p', 'https://b.example/x', 'unsafe-url'), 'https://a.example/p');
  assert.equal(computeReferer('https://a.example/p', 'https://a.example/x', 'no-referrer'), null);
  const text = `// hand-written
const res = await fetch('https://api.example.com/v1/x?y=1', {
  method: 'put',
  headers: { 'X-A': "1", /* comment */ Accept: \`text/plain\`, },
  body: JSON.stringify({ a: [1, 2], b: 'c' }),
  referrer: 'https://www.example.com/page',
  referrerPolicy: 'no-referrer',
  mode: 'cors',
});`;
  const r = parseOk(text, {}, 'fetch').requests[0];
  assert.equal(r.method, 'PUT');
  assert.equal(r.url, 'https://api.example.com/v1/x?y=1');
  assert.equal(r.body, '{"a":[1,2],"b":"c"}');
  assert.deepEqual(header(r, 'referer'), []);
  assert.deepEqual(header(r, 'content-type'), ['text/plain;charset=UTF-8']);
  assert.deepEqual(header(r, 'accept'), ['text/plain']);
});

// ---------------------------------------------------------------------------------------
// Raw HTTP
// ---------------------------------------------------------------------------------------
test('raw: origin-form POST with Host header', () => {
  const r = parseOk(fixture('raw-post.txt'), {}, 'raw').requests[0];
  const body = 'username=admin&password=%27+OR+%271%27%3D%271&remember=on';
  assert.equal(r.method, 'POST');
  assert.equal(r.url, 'https://shop.example.com/account/login?next=%2Fdashboard&lang=en');
  assert.equal(r.httpVersion, 'HTTP/1.1');
  assert.equal(r.source, 'raw');
  assert.deepEqual(r.headers, [
    H('Host', 'shop.example.com'),
    H('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0'),
    H('Accept', 'text/html,application/xhtml+xml'),
    H('Accept-Language', 'en-US,en;q=0.5'),
    H('Content-Type', 'application/x-www-form-urlencoded'),
    H('Cookie', 'sid=test-session-123; theme=dark'),
    H('X-Forwarded-For', '203.0.113.7'),
    H('Content-Length', String(body.length)),
  ]);
  assert.equal(r.body, body);
  assert.ok(hasNote(r, 'Scheme not specified; assumed https.'));
});

test('raw: CRLF input keeps the body byte-exact and honours Content-Length', () => {
  const text = 'PUT /x HTTP/1.1\r\nHost: a.example.com\r\nContent-Length: 7\r\n\r\nab\r\ncd\r\n\r\n';
  const r = parseOk(text, {}, 'raw').requests[0];
  assert.equal(r.body, 'ab\r\ncd\r');
  assert.deepEqual(header(r, 'content-length'), ['7']);
});

test('raw: multiple requests (### / ---), absolute-form, HTTP/2 pseudo-header dump, folding', () => {
  const { requests } = parseOk(fixture('raw-multi.txt'), {}, 'raw');
  assert.equal(requests.length, 3);
  const [legacy, gql, del] = requests;
  assert.equal(legacy.url, 'http://legacy.example.com:8080/cgi-bin/status.cgi?verbose=1');
  assert.equal(legacy.httpVersion, 'HTTP/1.0');
  assert.deepEqual(legacy.headers[0], H('Host', 'legacy.example.com:8080'));
  assert.equal(legacy.body, null);

  assert.equal(gql.method, 'POST');
  assert.equal(gql.url, 'https://api.example.com/graphql?op=search');
  assert.equal(gql.httpVersion, 'HTTP/2.0');
  const gqlBody = '{"query":"{ search(q: \\"<img src=x onerror=alert(1)>\\") { id } }"}';
  assert.equal(gql.body, gqlBody);
  assert.deepEqual(gql.headers, [
    H('Host', 'api.example.com'),
    H('content-type', 'application/json'),
    H('x-long-header', 'first part continued part'),
    H('accept', 'application/json'),
    H('Content-Length', String(gqlBody.length)),
  ]);
  assert.ok(hasNote(gql, /Detected HTTP\/2 pseudo-headers \(:method, :authority, :scheme, :path\)/));

  assert.equal(del.method, 'DELETE');
  assert.equal(del.url, 'https://api.example.com:443/api/items/42');
  assert.equal(del.httpVersion, 'HTTP/2.0');
  assert.deepEqual(header(del, 'content-length'), []);
});

// ---------------------------------------------------------------------------------------
// HAR / DevTools
// ---------------------------------------------------------------------------------------
test('har: two requests (HTTP/2 POST with pseudo-headers, HTTP/1.1 GET with request.cookies)', () => {
  const text = fixture('chrome-two-requests.har');
  const res = parseInput(text);
  assert.equal(res.format, 'har');
  assert.deepEqual(res.errors, ['1 HAR entry with non-HTTP(S) URLs skipped.']);
  assert.equal(res.requests.length, 2);
  assert.deepEqual(parseHar(text), res.requests);
  assert.deepEqual(parseHar(JSON.parse(text)), res.requests);

  const [post, get] = res.requests;
  assert.equal(post.method, 'POST');
  assert.equal(post.url, POST_URL);
  assert.equal(post.httpVersion, 'HTTP/2.0');
  assert.equal(post.source, 'har');
  assert.equal(post.resourceType, 'fetch');
  assert.equal(post.startedAt, Date.parse('2026-10-13T06:12:01.123Z'));
  assert.deepEqual(post.headers, [
    H('Host', 'dev.example.com'),
    H('accept', '*/*'),
    H('accept-encoding', 'gzip, deflate, br, zstd'),
    H('content-length', '96'),
    H('content-type', 'application/json'),
    H('cookie', `app_csrf=${CSRF}`),
    H('origin', 'https://dev.example.com'),
    H('user-agent', UA),
    H('x-csrf-token', CSRF),
  ]);
  assert.equal(post.body, BODY);
  assert.ok(hasNote(post, 'Detected HTTP/2 pseudo-headers (:authority, :method, :path, :scheme); treated as an HTTP/2 request and removed from the header list.'));
  assert.deepEqual(post.response, {
    status: 201,
    statusText: '',
    httpVersion: 'HTTP/2.0',
    headers: [
      H('content-type', 'application/json; charset=utf-8'),
      H('date', 'Tue, 13 Oct 2026 06:12:01 GMT'),
      H('server', 'nginx'),
    ],
    mimeType: 'application/json',
    body: '{"id":"m-1","status":"ok"}',
    bodyEncoding: 'text',
  });

  assert.equal(get.method, 'GET');
  assert.equal(get.url, 'http://legacy.example.com:8080/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&page=2');
  assert.equal(get.httpVersion, 'HTTP/1.1');
  assert.equal(get.resourceType, 'document');
  assert.deepEqual(get.headers.at(-1), H('Cookie', 'JSESSIONID=test-0123456789; lang=en'));
  assert.deepEqual(get.headers[0], H('Host', 'legacy.example.com:8080'));
  assert.equal(get.body, null);
  assert.ok(hasNote(get, /request\.cookies/));
  assert.equal(get.response.status, 403);
  assert.equal(get.response.body, 'Rm9yYmlkZGVu');
  assert.equal(get.response.bodyEncoding, 'base64');
});

test('har: fromHarEntry for DevTools entries, version mapping, skipped URLs, postData.params', () => {
  const base = (over) => ({
    startedDateTime: '2026-10-13T00:00:00.000Z',
    _resourceType: 'xhr',
    getContent() {},
    request: { method: 'POST', url: 'https://a.example.com/f', httpVersion: 'h3', headers: [], cookies: [], ...over },
    response: { status: 200, statusText: 'OK', httpVersion: 'h3', headers: [], content: { mimeType: 'text/plain' } },
  });
  const r = fromHarEntry(base({ postData: { mimeType: 'application/x-www-form-urlencoded', params: [{ name: 'a b', value: 'c&d' }, { name: 'e', value: '%41' }] } }), { source: 'devtools' });
  assert.equal(r.source, 'devtools');
  assert.equal(r.httpVersion, 'HTTP/3.0');
  assert.equal(r.body, 'a+b=c%26d&e=%41');
  assert.deepEqual(header(r, 'content-type'), ['application/x-www-form-urlencoded']);
  assert.equal(r.response.body, null);
  assert.equal(r.response.httpVersion, 'HTTP/3.0');
  assert.equal(fromHarEntry(base({ url: 'data:text/plain,hi' })), null);
  assert.equal(fromHarEntry(base({ url: 'blob:https://a.example.com/123' })), null);
  assert.equal(fromHarEntry(base({ url: 'chrome-extension://abc/x.js' })), null);
  const b64 = fromHarEntry(base({ postData: { mimeType: 'application/octet-stream', text: 'AAEC/w==', encoding: 'base64' } }));
  assert.equal(b64.bodyEncoding, 'base64');
  assert.deepEqual(header(b64, 'content-length'), ['4']);
  for (const [v, want] of [['http/2.0', 'HTTP/2.0'], ['h2', 'HTTP/2.0'], ['HTTP/2', 'HTTP/2.0'], ['http/3', 'HTTP/3.0'],
    ['HTTP/3', 'HTTP/3.0'], ['http/1.1', 'HTTP/1.1'], ['http/1.0', 'HTTP/1.0'], ['', 'HTTP/1.1'], ['unknown', 'HTTP/1.1']]) {
    const e = base({ method: 'GET', httpVersion: v });
    assert.equal(fromHarEntry(e).httpVersion, want, `version ${v}`);
  }
});

// ---------------------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------------------
test('normalize: keepPseudoHeaders disables HTTP/2 detection', () => {
  const r = parseOk(fixture('powershell-get-h2.txt'), { keepPseudoHeaders: true }).requests[0];
  assert.equal(r.httpVersion, 'HTTP/1.1');
  assert.deepEqual(r.headers.slice(0, 5).map((h) => h.name), ['Host', 'authority', 'method', 'path', 'scheme']);
  assert.ok(!hasNote(r, PSEUDO_NOTE));
});

test('normalize: colon-less pseudo-header names that do not match the URL stay regular headers', () => {
  const r = normalizeRequest({
    method: 'GET', url: 'https://a.example.com/x', source: 'raw',
    headers: [H('path', '/other'), H('scheme', 'https'), H('method', 'GET')],
  });
  assert.equal(r.httpVersion, 'HTTP/1.1');
  assert.deepEqual(r.headers.map((h) => h.name), ['Host', 'path', 'scheme', 'method']);
  assert.ok(hasNote(r, /kept as regular headers/));
  // A single colon-less candidate is never treated as a pseudo-header.
  const single = normalizeRequest({ url: 'https://a.example.com/x', source: 'raw', headers: [H('path', '/x')] });
  assert.deepEqual(single.headers.map((h) => h.name), ['Host', 'path']);
});

test('normalize: Host, Content-Length, Transfer-Encoding, duplicates, trimming, idempotence', () => {
  const r = normalizeRequest({
    method: 'put', url: 'http://Example.com:8080/a?b=%20c', source: 'raw',
    headers: [H(' X-Dup ', '  1 '), H('X-Dup', '2')], body: 'h' + String.fromCharCode(233), cookies: ['a=1', 'b=2'], userAgent: 'ua',
  });
  assert.equal(r.method, 'PUT');
  assert.equal(r.url, 'http://Example.com:8080/a?b=%20c');
  assert.deepEqual(r.headers, [
    H('Host', 'example.com:8080'), H('X-Dup', '1'), H('X-Dup', '2'), H('User-Agent', 'ua'), H('Cookie', 'a=1; b=2'),
    H('Content-Length', '3'),
  ]);
  assert.deepEqual(normalizeRequest(r), r);
  const d = normalizeRequest({ method: 'DELETE', url: 'https://a.example.com:443/', source: 'raw' });
  assert.deepEqual(d.headers, [H('Host', 'a.example.com')]);
  const te = normalizeRequest({ method: 'POST', url: 'https://a.example.com/', source: 'raw', headers: [H('Transfer-Encoding', 'chunked')], body: '5\r\nhello\r\n0\r\n\r\n' });
  assert.deepEqual(header(te, 'content-length'), []);
  const existing = normalizeRequest({ method: 'GET', url: 'https://a.example.com/', source: 'curl', headers: [H('Cookie', 'x=1')], cookies: ['y=2'] });
  assert.deepEqual(header(existing, 'cookie'), ['x=1; y=2']);
  assert.throws(() => normalizeRequest({ url: '/relative', source: 'raw' }), /absolute URL/);
});

// ---------------------------------------------------------------------------------------
// Detection / top-level API
// ---------------------------------------------------------------------------------------
test('detectFormat on every fixture and on garbage', () => {
  const expected = {
    'powershell-get-h2.txt': 'powershell', 'powershell-post-h2.txt': 'powershell', 'powershell-copy-all.txt': 'powershell',
    'curl-bash-post.txt': 'curl', 'curl-cmd-post.txt': 'curl', 'curl-bash-copy-all.txt': 'curl', 'curl-cmd-copy-all.txt': 'curl',
    'curl-bash-ansi-c.txt': 'curl', 'curl-cmd-special-chars.txt': 'curl', 'curl-bash-multipart-form.txt': 'curl',
    'fetch-post.txt': 'fetch', 'fetch-nodejs-post.txt': 'fetch', 'fetch-copy-all.txt': 'fetch',
    'raw-post.txt': 'raw', 'raw-multi.txt': 'raw', 'chrome-two-requests.har': 'har',
  };
  for (const [file, fmt] of Object.entries(expected)) assert.equal(detectFormat(fixture(file)), fmt, file);
  assert.equal(detectFormat('hello world'), 'unknown');
  assert.equal(detectFormat('{"not":"har"}'), 'unknown');
  assert.equal(detectFormat(''), 'unknown');
});

test('parseInput never throws', () => {
  for (const input of [undefined, null, 42, '', '   ', 'garbage', '{"log":{}}', 'curl', "curl 'unterminated", 'fetch(', 'fetch(x, {})',
    'GET', 'GET /x HTTP/1.1\n\n', '$x = "', 'Invoke-WebRequest', '{"log":{"entries":[{"request":{}}]}}', '\uFEFF']) {
    const res = parseInput(/** @type {any} */ (input));
    assert.ok(Array.isArray(res.requests) && Array.isArray(res.errors) && typeof res.format === 'string', String(input));
    assert.ok(res.requests.length === 0 && res.errors.length > 0, `expected an error for ${JSON.stringify(input)}`);
  }
});

// ---------------------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------------------
let passed = 0;
let failed = 0;
for (const t of tests) {
  if (filter && !t.name.includes(filter)) continue;
  try {
    await t.fn();
    passed++;
    console.log(`  ok   ${t.name}`);
  } catch (e) {
    failed++;
    console.log(`  FAIL ${t.name}`);
    console.log(String(e && e.stack ? e.stack : e).split('\n').map((l) => '       ' + l).join('\n'));
  }
}
console.log(`\n${passed} passed, ${failed} failed, ${passed + failed} total`);
process.exit(failed ? 1 : 0);
