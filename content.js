// Inject a large red semi-transparent overlay warning about possible phishing
(function injectPhishingWarningOverlay() {
  const OVERLAY_ID = "phishing-warning-overlay";
  if (document.getElementById(OVERLAY_ID)) {
    return; // already injected
  }

  const overlay = document.createElement("div");
  overlay.id = OVERLAY_ID;
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-live", "assertive");
  overlay.style.position = "fixed";
  overlay.style.top = "0";
  overlay.style.left = "0";
  overlay.style.width = "100%";
  overlay.style.height = "100%";
  overlay.style.background = "rgba(200, 0, 0, 0.7)";
  overlay.style.zIndex = "2147483647"; // above most elements
  overlay.style.display = "flex";
  overlay.style.alignItems = "center";
  overlay.style.justifyContent = "center";
  overlay.style.padding = "24px";
  overlay.style.boxSizing = "border-box";

  const panel = document.createElement("div");
  panel.style.background = "#fff";
  panel.style.border = "4px solid #d0021b";
  panel.style.boxShadow = "0 8px 24px rgba(0,0,0,0.4)";
  panel.style.borderRadius = "8px";
  panel.style.maxWidth = "720px";
  panel.style.width = "100%";
  panel.style.padding = "28px 36px";
  panel.style.position = "relative";
  panel.style.textAlign = "center";

  const title = document.createElement("div");
  title.textContent = "WARNING: This site may be a phishing attempt.";
  title.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif";
  title.style.fontWeight = "800";
  title.style.color = "#d0021b";
  title.style.fontSize = "28px";
  title.style.lineHeight = "1.3";
  title.style.marginBottom = "10px";

  const message = document.createElement("div");
  message.textContent = "If you were not expecting this page, close it and verify the URL.";
  message.style.fontFamily = title.style.fontFamily;
  message.style.fontSize = "16px";
  message.style.color = "#222";
  message.style.opacity = "0.95";
  message.style.marginBottom = "8px";

  const close = document.createElement("button");
  close.textContent = "×";
  close.setAttribute("aria-label", "Dismiss warning overlay");
  close.style.position = "absolute";
  close.style.top = "8px";
  close.style.right = "12px";
  close.style.width = "40px";
  close.style.height = "40px";
  close.style.border = "none";
  close.style.borderRadius = "6px";
  close.style.background = "#d0021b";
  close.style.color = "#fff";
  close.style.fontSize = "24px";
  close.style.cursor = "pointer";
  close.style.lineHeight = "40px";
  close.style.textAlign = "center";
  close.style.boxShadow = "0 2px 6px rgba(0,0,0,0.2)";

  function removeOverlay() {
    overlay.remove();
  }

  close.addEventListener("click", removeOverlay);

  // Also allow ESC to dismiss
  const onKeyDown = (ev) => {
    if (ev.key === "Escape") {
      removeOverlay();
      document.removeEventListener("keydown", onKeyDown, true);
    }
  };
  document.addEventListener("keydown", onKeyDown, true);

  panel.appendChild(close);
  panel.appendChild(title);
  panel.appendChild(message);
  overlay.appendChild(panel);
  document.documentElement.appendChild(overlay);
})();
