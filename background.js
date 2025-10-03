// background.js - MV3 service worker

const BADGE_WARN_TEXT = "WARN";

function isIpAddress(hostname) {
  // IPv4 check
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    const octets = hostname.split(".").map(Number);
    return octets.every((octet) => octet >= 0 && octet <= 255);
  }
  // IPv6 (loose) check
  if (/^[0-9a-f:]+$/i.test(hostname) && hostname.includes(":")) {
    return true;
  }
  return false;
}

function analyzeUrl(urlString) {
  const reasons = [];
  try {
    const url = new URL(urlString);

    // Only analyze http(s)
    if (!/^https?:$/.test(url.protocol)) {
      return reasons;
    }

    const hostname = url.hostname.toLowerCase();
    const fullUrl = url.href.toLowerCase();

    if (hostname.includes("xn--")) {
      reasons.push("IDN (punycode) domain");
    }

    if (isIpAddress(hostname)) {
      reasons.push("IP address as hostname");
    }

    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 4) {
      reasons.push("Many hyphens in domain");
    }

    if (fullUrl.includes("@")) {
      reasons.push("Contains '@' in URL");
    }

    const sensitiveKeywords = /(login|verify|account|secure|wallet|password)/i;
    if (sensitiveKeywords.test(url.pathname) || sensitiveKeywords.test(url.search)) {
      reasons.push("Sensitive keywords in path/query");
    }
  } catch (e) {
    // Invalid URL or parsing error: treat as no reasons
  }
  return reasons;
}

async function updateBadge(tabId, reasons) {
  try {
    if (reasons.length > 0) {
      await chrome.action.setBadgeText({ tabId, text: BADGE_WARN_TEXT });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: "#d0021b" });
      await chrome.action.setTitle({ tabId, title: `Suspicious URL: ${reasons.join(", ")}` });
    } else {
      await chrome.action.setBadgeText({ tabId, text: "" });
      await chrome.action.setTitle({ tabId, title: "Phishing Detector" });
    }
  } catch (e) {
    // Ignore errors (tab may not exist anymore)
  }
}

async function analyzeTab(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab || !tab.url) return;

    if (
      tab.url.startsWith("chrome://") ||
      tab.url.startsWith("chrome-extension://") ||
      tab.url.startsWith("about:")
    ) {
      await updateBadge(tabId, []);
      return;
    }

    const reasons = analyzeUrl(tab.url);
    await updateBadge(tabId, reasons);
  } catch (e) {
    // Tab may have been closed or become inaccessible
  }
}

chrome.runtime.onInstalled.addListener(() => {
  // Service worker installed; badge will be updated on tab events
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    analyzeTab(tabId);
    const url = tab && tab.url ? tab.url : undefined;
    if (url && checkUrlForPhishing(url)) {
      warnUserAboutSuspiciousUrl(tabId, url);
    }
  }
});

chrome.tabs.onActivated.addListener((activeInfo) => {
  analyzeTab(activeInfo.tabId);
});

function checkUrlForPhishing(urlString) {
  try {
    if (typeof urlString !== "string") return false;
    const lower = urlString.toLowerCase();
    const hasLogin = lower.includes("login");
    const hasDigit = /\d/.test(urlString);
    return hasLogin && hasDigit; // e.g., "login123"
  } catch (e) {
    return false;
  }
}

async function warnUserAboutSuspiciousUrl(tabId, urlString) {
  try {
    if (!/^https?:/i.test(urlString)) return; // Don't inject on non-web schemes
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (message) => {
        alert(message);
      },
      args: [
        "Warning: This URL looks suspicious (contains 'login' and numbers). Proceed with caution.",
      ],
    });
  } catch (e) {
    // Some pages (e.g., Chrome Web Store) disallow injection; ignore errors
  }
}
