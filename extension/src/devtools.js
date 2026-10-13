// DevTools page: creates the "OWASP CRS" panel and captures network requests of the
// inspected tab from the moment DevTools opens. Requests are buffered until the panel
// is shown for the first time (Chrome only loads panel pages lazily), then streamed.
'use strict';

const buffer = [];
const MAX_BUFFER = 3000;
let sink = null;
let navigationSink = null;

chrome.devtools.network.onRequestFinished.addListener((request) => {
  if (sink) {
    sink(request);
    return;
  }
  buffer.push(request);
  if (buffer.length > MAX_BUFFER) buffer.shift();
});

chrome.devtools.network.onNavigated.addListener((url) => {
  if (navigationSink) navigationSink(url);
  else buffer.length = 0;
});

const bridge = {
  drain: () => buffer.splice(0),
  setSink: (fn) => {
    sink = fn;
  },
  setNavigationSink: (fn) => {
    navigationSink = fn;
  },
};

chrome.devtools.panels.create('OWASP CRS', 'icons/icon-32.png', 'panel.html', (panel) => {
  panel.onShown.addListener((panelWindow) => {
    // The panel's host (src/host/real-host.js) picks this up.
    // Always (re)attach: the panel document may have been reloaded.
    if (panelWindow.__crsDevtoolsBridge !== bridge) panelWindow.__crsDevtoolsBridge = bridge;
  });
});
