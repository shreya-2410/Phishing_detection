// Inject a large red semi-transparent overlay warning about possible phishing
// Send hovered link URLs to the background script for analysis
(() => {
  let overlayEl = null;
  let overlayTimeoutId = null;
  let lastAnchor = null;

  function removeOverlay() {
    if (overlayTimeoutId) {
      clearTimeout(overlayTimeoutId);
      overlayTimeoutId = null;
    }
    if (overlayEl && overlayEl.parentNode) {
      overlayEl.parentNode.removeChild(overlayEl);
    }
    overlayEl = null;
  }

  function showTemporaryOverlayNear(element, mouseEvent) {
    removeOverlay();
    const rect = element.getBoundingClientRect();
    const overlay = document.createElement("div");
    overlay.textContent = "Suspicious Link";
    overlay.style.position = "fixed";
    const posX = mouseEvent ? mouseEvent.clientX + 10 : rect.left + rect.width + 10;
    const posY = mouseEvent ? mouseEvent.clientY + 10 : rect.top;
    overlay.style.left = `${Math.min(posX, window.innerWidth - 160)}px`;
    overlay.style.top = `${Math.min(posY, window.innerHeight - 40)}px`;
    overlay.style.background = "#dc2626";
    overlay.style.color = "#fff";
    overlay.style.padding = "6px 10px";
    overlay.style.borderRadius = "6px";
    overlay.style.fontSize = "12px";
    overlay.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif";
    overlay.style.zIndex = "2147483646";
    overlay.style.boxShadow = "0 2px 8px rgba(0,0,0,0.25)";
    overlay.style.pointerEvents = "none";
    document.documentElement.appendChild(overlay);
    overlayEl = overlay;
    overlayTimeoutId = window.setTimeout(removeOverlay, 2500);
  }

  document.addEventListener(
    "mouseover",
    (event) => {
      const target = event.target;
      const anchor = target instanceof Element ? target.closest("a[href]") : null;
      if (!anchor || !anchor.href) return;
      lastAnchor = anchor;
      try {
        chrome.runtime.sendMessage({ type: "HOVER_URL", url: anchor.href }, (response) => {
          if (response && response.isSuspicious) {
            showTemporaryOverlayNear(anchor, event);
          }
        });
      } catch (_) {
        // Ignore messaging errors
      }
    },
    true
  );

  document.addEventListener(
    "mouseout",
    (event) => {
      const related = event.relatedTarget;
      const from = event.target;
      const fromAnchor = from instanceof Element ? from.closest("a[href]") : null;
      if (fromAnchor && fromAnchor === lastAnchor) {
        // If moving away from the last hovered link, remove overlay
        const stillInsideSameAnchor =
          related instanceof Element && !!related.closest("a[href]") && related.closest("a[href]") === lastAnchor;
        if (!stillInsideSameAnchor) {
          removeOverlay();
          lastAnchor = null;
        }
      }
    },
    true
  );
})();
