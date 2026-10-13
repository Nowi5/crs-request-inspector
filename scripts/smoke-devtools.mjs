// Smoke test of the DevTools capture path (real host + worker) in headless Chrome, with a fake
// chrome.devtools environment and the bridge object that src/devtools.js normally provides.
// Needs the preview server: node scripts/serve.mjs 5178
//   node scripts/smoke-devtools.mjs
import assert from 'node:assert/strict';
import { launch, sleep } from './docs/cdp.mjs';

const FAKE = `
(() => {
  const har = (url, method = 'GET', extra = {}) => ({
    startedDateTime: new Date().toISOString(),
    _resourceType: extra.type || 'fetch',
    request: { method, url, httpVersion: 'http/2.0', headers: [
      { name: ':authority', value: 'app.example.com' }, { name: ':method', value: method }, { name: ':path', value: new URL(url).pathname + new URL(url).search }, { name: ':scheme', value: 'https' },
      { name: 'user-agent', value: 'Mozilla/5.0' }, { name: 'accept', value: '*/*' }, ...(extra.headers || []) ],
      cookies: [], queryString: [], postData: extra.postData, headersSize: -1, bodySize: 0 },
    response: { status: extra.status || 200, statusText: 'OK', httpVersion: 'http/2.0', headers: [{ name: 'content-type', value: extra.mime || 'application/json' }], cookies: [], content: { size: (extra.body || '').length, mimeType: extra.mime || 'application/json' }, redirectURL: '', headersSize: -1, bodySize: -1 },
    getContent(cb) { window.__getContentCalls = (window.__getContentCalls || 0) + 1; setTimeout(() => cb(extra.body || '', null), 5); },
  });
  window.__har = har;
  const buffered = [har('https://app.example.com/api/v1/workspace-options'), har("https://app.example.com/api/search?q=1' OR '1'='1")];
  window.chrome = { devtools: { panels: { themeName: 'default', setThemeChangeHandler() {} }, inspectedWindow: { tabId: 1 }, network: {} } };
  window.__crsDevtoolsBridge = {
    drain: () => buffered.splice(0),
    setSink: (fn) => { window.__sink = fn; },
    setNavigationSink: (fn) => { window.__nav = fn; },
  };
  window.__errors = [];
  window.addEventListener('error', (e) => window.__errors.push(String(e.message)));
  window.addEventListener('unhandledrejection', (e) => window.__errors.push(String(e.reason)));
})();
`;

const b = await launch({ width: 1440, height: 900, scale: 1 });
let failed = 0;
const check = async (name, fn) => {
  try {
    await fn();
    console.log('ok  ', name);
  } catch (e) {
    failed++;
    console.log('FAIL', name, '-', e.message);
  }
};
try {
  await b.sendPage('Page.addScriptToEvaluateOnNewDocument', { source: FAKE });
  await b.navigate('http://localhost:5178/panel.html', 4000);
  const rows = () => b.evaluate(`[...document.querySelectorAll('.list-rows [role=row]')].map((r) => r.textContent.replace(/\\s+/g, ' ').trim())`);

  await check('buffered requests are analysed', async () => {
    const r = await rows();
    assert.equal(r.length, 2, JSON.stringify(r));
    assert.ok(r.some((x) => /workspace-options/.test(x)));
  });
  await check('live requests stream in (incl. response body via getContent)', async () => {
    await b.evaluate(`window.__sink(window.__har('https://app.example.com/page', 'GET', { type: 'document', mime: 'text/html', status: 500, body: '<b>Warning</b>: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/x.php on line 3' }))`);
    await b.evaluate(`window.__sink(window.__har('https://app.example.com/api/v1/items/1', 'DELETE'))`);
    await sleep(2500);
    const r = await rows();
    assert.equal(r.length, 4, JSON.stringify(r));
    assert.equal(await b.evaluate('window.__getContentCalls'), 1, 'only text/html bodies are fetched');
  });
  await check('verdicts: SQLi and DELETE blocked, response leak detected', async () => {
    const blocked = await b.evaluate(`document.querySelectorAll('.list-rows [role=row] .st-blocked, .list-rows [role=row] [data-status="blocked"]').length`);
    const text = (await rows()).join('\n');
    assert.ok(/911100/.test(text), 'DELETE → 911100');
    assert.ok(/942100|942/.test(text), 'SQLi');
    assert.ok(/95\d{4}/.test(text), 'response rule 95xxxx: ' + text);
    console.log('      blocked icons:', blocked);
  });
  await check('navigation clears the list (preserve log off)', async () => {
    await b.evaluate(`window.__nav('https://app.example.com/other')`);
    await sleep(500);
    assert.equal((await rows()).length, 0);
  });
  await check('no JS errors', async () => {
    const errs = await b.evaluate('window.__errors');
    assert.deepEqual(errs, []);
  });
} finally {
  await b.close();
}
process.exit(failed ? 1 : 0);
