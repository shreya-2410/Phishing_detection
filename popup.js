document.addEventListener("DOMContentLoaded", async () => {
  const statusDiv = document.getElementById("status");
  const detailsDiv = document.getElementById("details");
  if (!statusDiv || !detailsDiv) return;

  try {
    const { isSuspicious, suspiciousUrl, suspiciousReason } = await chrome.storage.local.get([
      "isSuspicious",
      "suspiciousUrl",
      "suspiciousReason",
    ]);

    // Reset classes and contents
    statusDiv.classList.remove("safe", "warning");
    detailsDiv.textContent = "";

    if (isSuspicious) {
      statusDiv.classList.add("warning");
      statusDiv.textContent = "This site is suspicious.";

      if (suspiciousUrl || suspiciousReason) {
        const urlText = suspiciousUrl ? suspiciousUrl : "(URL not available)";
        const reasonText = suspiciousReason ? suspiciousReason : "Unknown reason";
        detailsDiv.textContent = `${urlText} — ${reasonText}`;
      }
    } else {
      statusDiv.classList.add("safe");
      statusDiv.textContent = "Safe to browse";
      detailsDiv.textContent = "No warnings for this page.";
    }
  } catch (e) {
    statusDiv.classList.remove("warning");
    statusDiv.classList.add("safe");
    statusDiv.textContent = "Safe to browse";
    detailsDiv.textContent = "Unable to load detection status.";
  }
});
