// Toolbar button: open the standalone analyser (paste / HAR import) in a new tab.
chrome.action.onClicked.addListener(() => {
  chrome.tabs.create({ url: chrome.runtime.getURL('panel.html?standalone=1') });
});
