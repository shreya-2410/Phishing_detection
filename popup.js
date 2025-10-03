document.addEventListener("DOMContentLoaded", async () => {
  try {
    const statusDiv = document.getElementById("status");
    if (!statusDiv) return;

    const { isSuspicious } = await chrome.storage.local.get("isSuspicious");
    const suspicious = Boolean(isSuspicious);

    // Reset classes
    statusDiv.classList.remove("safe", "warning");

    if (suspicious) {
      statusDiv.classList.add("warning");
      statusDiv.textContent = "Phishing Detected";
    } else {
      statusDiv.classList.add("safe");
      statusDiv.textContent = "Safe to browse";
    }
  } catch (e) {
    // If storage access fails, show safe by default
    const statusDiv = document.getElementById("status");
    if (statusDiv) {
      statusDiv.classList.remove("warning");
      statusDiv.classList.add("safe");
      statusDiv.textContent = "Safe to browse";
    }
  }
});
