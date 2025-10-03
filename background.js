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

function getRegistrableDomain(hostname) {
  const labels = hostname.split(".").filter(Boolean);
  if (labels.length >= 2) {
    return labels.slice(-2).join(".");
  }
  return hostname;
}

function isLegitimateDomain(hostname) {
  // Small whitelist of widely trusted domains. Reduce false positives.
  const registrable = getRegistrableDomain(hostname.toLowerCase());
  const whitelist = new Set([
    "amazon.com",
    "google.com",
    "wikipedia.org",
    "github.com",
    "microsoft.com",
    "apple.com",
    "paypal.com",
    "netflix.com",
  ]);
  return whitelist.has(registrable);
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
    if (url) {
      checkUrlForPhishing(tabId, url);
    }
  }
});

chrome.tabs.onActivated.addListener((activeInfo) => {
  analyzeTab(activeInfo.tabId);
});

async function checkUrlForPhishing(tabId, urlString) {
  // Applies several simple heuristics to flag likely phishing URLs.
  // Stores the result in chrome.storage.local as { isSuspicious: boolean }.
  try {
    if (typeof urlString !== "string" || !/^https?:/i.test(urlString)) return;

    const parsed = new URL(urlString);
    const hostname = parsed.hostname.toLowerCase();
    const fullUrl = parsed.href;

    // Early allowlist: known legitimate domains
    if (isLegitimateDomain(hostname)) {
      chrome.storage.local.set({ isSuspicious: false });
      return false;
    }

    let suspicious = false;

    // 1) Long/obfuscated URL: Excessive length and encoding may hide the true destination
    //    Attackers often use very long paths/queries or heavy percent-encoding to obscure intent.
    const urlIsVeryLong = fullUrl.length >= 140; // length threshold
    const percentEncodedCount = (fullUrl.match(/%[0-9a-fA-F]{2}/g) || []).length; // %xx sequences
    const manyEncodedSegments = percentEncodedCount >= 8;
    const pathSegments = parsed.pathname.split("/").filter(Boolean).length;
    const tooManySegments = pathSegments >= 6;
    if (urlIsVeryLong || manyEncodedSegments || tooManySegments) {
      suspicious = true;
    }

    // 2) IP address in place of domain: Phishing sites often hide behind raw IPs
    //    Legitimate brands rarely ask users to log in on a bare IP address.
    if (!suspicious && isIpAddress(hostname)) {
      suspicious = true;
    }

    // 3) Brand impersonation via character substitution (e.g., amaz0n -> amazon)
    //    Homoglyph/leet substitutions are a common trick to mimic trusted brands.
    const brands = [
      "google",
      "facebook",
      "apple",
      "microsoft",
      "amazon",
      "paypal",
      "netflix",
      "chase",
      "bankofamerica",
      "github",
    ];

    const leetNormalize = (label) =>
      label
        .toLowerCase()
        .replace(/0/g, "o")
        .replace(/[1!]/g, "l")
        .replace(/3/g, "e")
        .replace(/4/g, "a")
        .replace(/5/g, "s")
        .replace(/7/g, "t")
        .replace(/@/g, "a");

    const labels = hostname.split(".");
    const secondLevel = labels.length >= 2 ? labels[labels.length - 2] : hostname;
    const normalizedSecondLevel = leetNormalize(secondLevel);

    const looksLikeBrand = brands.some((brand) => {
      if (normalizedSecondLevel === brand && secondLevel !== brand) return true; // e.g., amaz0n -> amazon
      // Also consider simple prefix/suffix tricks like "secure-amazon-login"
      return (
        leetNormalize(secondLevel).includes(brand) &&
        secondLevel !== brand
      );
    });
    if (!suspicious && looksLikeBrand) {
      suspicious = true;
    }

    // 3b) Brand in userinfo + IP as host (e.g., www.amazon.com@192.168.0.1)
    //     The brand appears before '@' to mislead; the real host is the IP after '@'.
    const hasAtInUrl = fullUrl.includes("@");
    const userInfoRaw = decodeURIComponent(
      [parsed.username, parsed.password].filter(Boolean).join(":")
    );
    const brandInUserInfo = brands.some((brand) =>
      leetNormalize(userInfoRaw).includes(brand)
    );
    if (!suspicious && hasAtInUrl && isIpAddress(hostname) && brandInUserInfo) {
      suspicious = true;
    }

    // 4) Punycode/IDN usage: Can mask visually deceptive characters (IDN homograph attacks)
    //    While not always malicious, it warrants extra caution when present with other signals.
    const usesPunycode = hostname.includes("xn--");
    if (!suspicious && usesPunycode) {
      suspicious = true;
    }

    // 5) Excessive subdomains or hyphens: Often used to confuse users about the true domain
    const hyphenCount = (hostname.match(/-/g) || []).length;
    const subdomainCount = Math.max(labels.length - 2, 0);
    if (!suspicious && (hyphenCount >= 4 || subdomainCount >= 3)) {
      suspicious = true;
    }

    // 6) Sensitive keywords only when paired with non-standard TLDs
    //    Attackers often choose cheap TLDs (.xyz, .biz, etc.) to host phishing with keywords.
    const sensitiveKeywords = /(login|verify|account|secure|wallet|password|reset|unlock|support)/i;
    const pathAndQuery = `${parsed.pathname}${parsed.search}`.toLowerCase();
    const hasSensitiveKeyword = sensitiveKeywords.test(pathAndQuery);
    const tld = labels.length ? labels[labels.length - 1] : "";
    const nonStandardTlds = new Set([
      "xyz",
      "biz",
      "top",
      "click",
      "link",
      "zip",
      "online",
      "fit",
      "loan",
      "gq",
      "cf",
      "ml",
      "work",
    ]);
    if (!suspicious && hasSensitiveKeyword && nonStandardTlds.has(tld)) {
      suspicious = true;
    }

    // Persist detection status for popup consumption
    chrome.storage.local.set({ isSuspicious: suspicious });
  } catch (e) {
    // Ignore unexpected errors
  }
}
