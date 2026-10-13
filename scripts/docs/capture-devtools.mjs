// Captures the extension running inside real Chrome DevTools on the Example Shop demo
// (docs/images/devtools.png). Starts a headed Chrome with a temporary profile, undocked DevTools,
// and composes page + DevTools into one "browser window" image.
//   node demo/server.mjs 5180 &   (Example Shop)
//   node scripts/docs/capture-devtools.mjs
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { launch, sleep } from './cdp.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUT = path.join(ROOT, 'docs', 'images');
mkdirSync(OUT, { recursive: true });
const W = 1600;
const PAGE_H = 430;
const DT_H = 640;
const SELECT = process.argv[2] || 'auth/login';

const b = await launch({
  headless: false,
  emulate: false,
  width: W,
  height: PAGE_H + DT_H + 100,
  scale: 1,
  extraArgs: ['--auto-open-devtools-for-tabs', '--host-resolver-rules=MAP shop.example.test 127.0.0.1', '--disable-backgrounding-occluded-windows', '--disable-renderer-backgrounding', '--hide-crash-restore-bubble'],
  profileSetup: (dir) => {
    mkdirSync(path.join(dir, 'Default'), { recursive: true });
    writeFileSync(path.join(dir, 'Default', 'Preferences'), JSON.stringify({ devtools: { preferences: { currentDockState: '"bottom"', 'InspectorView.splitViewState': '{"horizontal":{"size":${DT_H}}}', uiTheme: '"default"' } } }));
  },
});
try {
  const { id } = await b.send('Extensions.loadUnpacked', { path: path.join(ROOT, 'extension') });
  const { targetId } = await b.send('Target.createTarget', { url: 'about:blank' });
  await sleep(3000);
  const { targetInfos } = await b.send('Target.getTargets');
  const dt = targetInfos.filter((t) => t.url.startsWith('devtools://')).pop();
  if (!dt) throw new Error('DevTools target not found');
  const { sessionId: ds } = await b.send('Target.attachToTarget', { targetId: dt.targetId, flatten: true });
  await b.send('Page.enable', {}, ds);
  // Size both windows.
  const pageWin = await b.send('Browser.getWindowForTarget', { targetId });
  await b.send('Browser.setWindowBounds', { windowId: pageWin.windowId, bounds: { left: 0, top: 0, width: W, height: PAGE_H + DT_H + 100, windowState: 'normal' } });
  const r = await b.send('Runtime.evaluate', {
    expression: `(async () => { const UI = await import('./ui/legacy/legacy.js'); const iv = UI.InspectorView.InspectorView.instance(); const pid = iv.tabbedPane.tabIds().find((i) => i.startsWith('chrome-extension://')); await iv.showPanel(pid); return pid; })()`,
    awaitPromise: true,
    returnByValue: true,
  }, ds);
  console.log('panel', r.result?.value);
  await sleep(1500);
  const { sessionId: ps } = await b.send('Target.attachToTarget', { targetId, flatten: true });
  await b.send('Page.enable', {}, ps);
  await b.send('Page.navigate', { url: 'http://shop.example.test:5180/?attacks' }, ps);
  await sleep(3000);
  const { targetInfos: t2 } = await b.send('Target.getTargets');
  const panel = t2.find((t) => t.url.includes(`chrome-extension://${id}/panel.html`));
  if (panel) {
    const { sessionId: pn } = await b.send('Target.attachToTarget', { targetId: panel.targetId, flatten: true });
    // Wait until all demo requests are captured and analysed (getHAR() fallback runs every 2 s).
    for (let i = 0; i < 40; i++) {
      const st = (await b.send('Runtime.evaluate', { expression: `({ n: (window.__crsInspector?.host.getEntries() || []).length, pending: (window.__crsInspector?.host.getEntries() || []).filter((e) => e.status === 'pending').length })`, returnByValue: true }, pn)).result.value;
      if (st.n >= 13 && !st.pending) break;
      await sleep(500);
    }
    await sleep(800);
    const n = await b.send('Runtime.evaluate', { expression: `(() => { const rows = [...document.querySelectorAll('.list-rows [role=row]')]; const r = rows.find((x) => x.textContent.includes(${JSON.stringify(SELECT)})) || rows[0]; r?.click(); return rows.length; })()`, returnByValue: true }, pn);
    console.log('rows', n.result?.value);
    await sleep(1500);
  }
  // Docked DevTools is laid out over the whole content area; the page occupies the top part.
  const ev = async (sid, e) => (await b.send('Runtime.evaluate', { expression: e, returnByValue: true }, sid)).result.value;
  const pv = await ev(ps, '({w: innerWidth, h: innerHeight})');
  const dv = await ev(ds, '({w: innerWidth, h: innerHeight})');
  console.log('page viewport', pv, 'devtools viewport', dv);
  const shotPage = await b.send('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: 0, width: pv.w, height: Math.min(pv.h, PAGE_H), scale: 1 } }, ps);
  const top = dv.h > pv.h ? dv.h - (dv.h - pv.h) : 0;
  const shotDt = await b.send('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: pv.h, width: dv.w, height: dv.h - pv.h, scale: 1 } }, ds);
  const html = `<!doctype html><html><body style="margin:0;background:#dfe3ea;padding:28px;font:13px system-ui,'Segoe UI',sans-serif">
  <div style="display:inline-block;border-radius:12px;overflow:hidden;box-shadow:0 18px 50px rgba(15,23,42,.28);background:#fff">
    <div style="height:44px;background:#e8eaed;display:flex;align-items:center;gap:8px;padding:0 14px">
      <span style="width:12px;height:12px;border-radius:50%;background:#ff5f57"></span><span style="width:12px;height:12px;border-radius:50%;background:#febc2e"></span><span style="width:12px;height:12px;border-radius:50%;background:#28c840"></span>
      <div style="margin-left:18px;flex:1;max-width:620px;height:28px;border-radius:14px;background:#fff;display:flex;align-items:center;padding:0 14px;color:#444">shop.example.test/?attacks</div>
    </div>
    <img src="data:image/png;base64,${shotPage.data}" style="display:block">
    <div style="height:1px;background:#c7cbd1"></div>
    <img src="data:image/png;base64,${shotDt.data}" style="display:block">
  </div></body></html>`;
  const composeFile = path.join(OUT, '_compose.html');
  writeFileSync(composeFile, html);
  // Compose in a separate headless browser (no DevTools attached → no size overlay).
  const hb = await launch({ width: W + 80, height: 1200, scale: 1 });
  await hb.navigate(pathToFileURL(composeFile).href, 1500);
  const size = await hb.evaluate('(() => { const r = document.body.firstElementChild.getBoundingClientRect(); return { w: Math.ceil(r.right + 28), h: Math.ceil(r.bottom + 28) }; })()');
  await hb.sendPage('Emulation.setDeviceMetricsOverride', { width: size.w, height: size.h, deviceScaleFactor: 1, mobile: false });
  await sleep(400);
  const shot = await hb.sendPage('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: 0, width: size.w, height: size.h, scale: 1 } });
  await hb.close();
  writeFileSync(path.join(OUT, process.argv[3] || 'devtools.png'), Buffer.from(shot.data, 'base64'));
  rmSync(composeFile);
  console.log('saved', process.argv[3] || 'devtools.png', size);
} catch (e) {
  console.error(e);
  process.exitCode = 1;
} finally {
  await b.close();
}
