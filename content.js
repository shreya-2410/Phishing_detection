// Inject a large red semi-transparent overlay warning about possible phishing
// Send hovered link URLs to the background script for analysis
document.addEventListener(
  "mouseover",
  (event) => {
    const target = event.target;
    const anchor = target instanceof Element ? target.closest("a[href]") : null;
    if (anchor && anchor.href) {
      try {
        chrome.runtime.sendMessage({ type: "HOVER_URL", url: anchor.href }, (response) => {
          // Optionally handle response: response?.isSuspicious
          // For now, we don't take UI action in the content script.
        });
      } catch (_) {
        // Ignore messaging errors
      }
    }
  },
  true
);
