// background.js - MV3 service worker

const BADGE_WARN_TEXT = "WARN";
const ICON_SAFE = "icon_safe.png";
const ICON_WARNING = "icon_warning.png";
const ICON_DEFAULT = "icon_default.png";
// ML decision thresholds
const ML_HIGH_THRESHOLD = 0.8; // Strong signal of phishing
const ML_LOW_THRESHOLD = 0.55; // Weak-to-moderate signal

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

function isWhitelisted(hostname) {
  // Hard allowlist of well-known, legitimate domains to avoid false positives
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
    "cloudflare.com",
    "mozilla.org",
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
  if (changeInfo.status === "loading") {
    // While loading, show default icon to indicate in-progress check
    chrome.action.setIcon({ tabId, path: ICON_DEFAULT });
  } else if (changeInfo.status === "complete") {
    analyzeTab(tabId);
    const url = tab && tab.url ? tab.url : undefined;
    if (url) {
      checkUrlForPhishing(tabId, url);
      // Also invoke ML model prediction for passive scoring
      loadModelAndPredict(url).then((score) => {
        if (typeof score === "number") {
          // Optionally, we could combine this score with heuristics later
          // For now, this is a passive call demonstrating integration
          // eslint-disable-next-line no-console
          console.log("ML phishing probability:", score.toFixed(3));
        }
      }).catch(() => {});
    }
  }
});

chrome.tabs.onActivated.addListener((activeInfo) => {
  analyzeTab(activeInfo.tabId);
});

// Receive messages from content scripts (placeholder handler)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  try {
    if (message && message.type === "HOVER_URL" && typeof message.url === "string") {
      const tabId = sender && sender.tab ? sender.tab.id : undefined;
      if (typeof tabId === "number") {
        // Run phishing check, then respond to content script with the result
        (async () => {
          let result = false;
          try {
            const res = await checkUrlForPhishing(tabId, message.url);
            result = Boolean(res);
          } catch (_) {
            result = false;
          }
          try {
            sendResponse({ isSuspicious: result });
          } catch (_) {}
        })();
        return true; // Keep the message channel open for async sendResponse
      }
    }
    // eslint-disable-next-line no-console
    console.log("Received message from content script:", message);
  } catch (_) {}
});

async function checkUrlForPhishing(tabId, urlString) {
  // Applies several simple heuristics to flag likely phishing URLs.
  // Stores the result in chrome.storage.local as { isSuspicious: boolean }.
  try {
    if (typeof urlString !== "string" || !/^https?:/i.test(urlString)) return;

    const parsed = new URL(urlString);
    const hostname = parsed.hostname.toLowerCase();
    const fullUrl = parsed.href;

    // Early allowlist (override all rules): if whitelisted, do not flag
    if (isWhitelisted(hostname)) {
      chrome.storage.local.set({ isSuspicious: false });
      try {
        await chrome.action.setIcon({ tabId, path: ICON_SAFE });
      } catch (_) {}
      return false;
    }

    // Secondary allowlist to further reduce noise
    if (isLegitimateDomain(hostname)) {
      chrome.storage.local.set({ isSuspicious: false });
      try {
        await chrome.action.setIcon({ tabId, path: ICON_SAFE });
      } catch (_) {}
      return false;
    }

    let suspicious = false;
    let reason = null;
    const reasonsList = [];
    const strongSignals = [];

    // 1) Long/obfuscated URL: Excessive length and encoding may hide the true destination.
    //    Attackers often use very long paths/queries or heavy percent-encoding to obscure intent.
    const urlIsVeryLong = fullUrl.length >= 140; // length threshold
    const percentEncodedCount = (fullUrl.match(/%[0-9a-fA-F]{2}/g) || []).length; // %xx sequences
    const manyEncodedSegments = percentEncodedCount >= 8;
    const pathSegments = parsed.pathname.split("/").filter(Boolean).length;
    const tooManySegments = pathSegments >= 6;
    if (urlIsVeryLong || manyEncodedSegments || tooManySegments) {
      suspicious = true;
      reasonsList.push("long_obfuscated");
      if (!reason) reason = "long/obfuscated URL"; // Hard to visually verify destination
    }

    // 2) IP address in place of domain: Phishing sites often hide behind raw IPs
    //    Legitimate brands rarely ask users to log in on a bare IP address.
    if (!suspicious && isIpAddress(hostname)) {
      suspicious = true;
      reasonsList.push("ip_host");
      strongSignals.push("ip_host");
      if (!reason) reason = "contains IP address"; // Brands seldom use bare IPs for user actions
    }

    // 3) Brand impersonation via character substitution (e.g., amaz0n -> amazon).
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
      reasonsList.push("brand_impersonation");
      if (!reason) reason = "brand impersonation"; // Character substitutions mimic trusted brands
    }

    // 3b) Brand in userinfo + IP as host (e.g., www.amazon.com@192.168.0.1).
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
      reasonsList.push("brand_userinfo_ip");
      strongSignals.push("brand_userinfo_ip");
      if (!reason) reason = "brand in userinfo with IP host"; // Misleads by placing brand before '@'
    }

    // 3c) Brand directly combined with an IP or immediate digits in the hostname (e.g., amazon.192.168.1.1, amazon123.com).
    //     Attackers append IPs or digits to brand names to trick users at a glance.
    const hostnameHasIp = /\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(hostname);
    const brandFollowedByDigitsInSLD = brands.some((brand) =>
      new RegExp(`^${brand}\\d+$`).test(normalizedSecondLevel)
    );
    const brandAppearsAndIp = brands.some((brand) => hostname.includes(brand)) && hostnameHasIp;
    if (!suspicious && (brandAppearsAndIp || brandFollowedByDigitsInSLD)) {
      suspicious = true;
      reasonsList.push("brand_digits_ip");
      strongSignals.push("brand_digits_ip");
      if (!reason) reason = "brand with digits/IP in hostname"; // Adds digits/IP to trusted brand name
    }

    // 4) Punycode/IDN usage: Can mask visually deceptive characters (IDN homograph attacks).
    //    While not always malicious, it warrants extra caution when present with other signals.
    const usesPunycode = hostname.includes("xn--");
    if (!suspicious && usesPunycode) {
      suspicious = true;
      reasonsList.push("punycode");
      if (!reason) reason = "punycode/IDN usage"; // IDN can hide deceptive look-alike characters
    }

    // 5) Excessive subdomains or hyphens: Often used to confuse users about the true domain.
    const hyphenCount = (hostname.match(/-/g) || []).length;
    const subdomainCount = Math.max(labels.length - 2, 0);
    if (!suspicious && (hyphenCount >= 4 || subdomainCount >= 3)) {
      suspicious = true;
      reasonsList.push("structure_noisy");
      if (!reason) reason = "excessive subdomains/hyphens"; // Overly complex hosts confuse true domain
    }

    // 6) Sensitive keywords only when paired with non-standard TLDs.
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
      reasonsList.push("keyword_tld");
      if (!reason) reason = "sensitive keywords with non-standard TLD"; // Cheap TLD plus login keywords
    }

    // 7) Very long and complex URLs that are hard to read.
    //    High symbol density and many query params are often used to obfuscate malicious targets.
    const nonAlnumCount = (fullUrl.replace(/[a-z0-9]/gi, "")).length;
    const nonAlnumRatio = nonAlnumCount / Math.max(fullUrl.length, 1);
    const queryCount = Array.from(new URLSearchParams(parsed.search).keys()).length;
    const veryLongAndComplex = fullUrl.length >= 220 || (fullUrl.length >= 160 && (nonAlnumRatio >= 0.35 || queryCount >= 10));
    if (!suspicious && veryLongAndComplex) {
      suspicious = true;
      reasonsList.push("very_complex");
      if (!reason) reason = "very long and complex URL"; // Hard-to-read URLs can conceal malicious intent
    }

    // Integrate ML model prediction to reduce false positives.
    // Strategy:
    // - If the ML score is high (>= ML_HIGH_THRESHOLD), mark as suspicious.
    // - If ML score is moderate (< high) and there are no strong heuristic signals, prefer ML and clear suspicion.
    // - If strong signals exist, keep suspicious even if ML is low (defense in depth).
    try {
      const mlScore = await loadModelAndPredict(fullUrl);
      if (typeof mlScore === "number") {
        if (mlScore >= ML_HIGH_THRESHOLD) {
          suspicious = true;
          if (!reason) reason = `ml_high_score_${mlScore.toFixed(2)}`;
        } else if (strongSignals.length === 0) {
          // Let ML override softer heuristics when it disagrees
          if (mlScore < ML_LOW_THRESHOLD) {
            suspicious = false;
            reason = null;
          }
        }
      }
    } catch (_) {
      // If ML path fails, fall back to heuristics-only
    }

    // Persist detection status and update action icon
    chrome.storage.local.set({
      isSuspicious: suspicious,
      suspiciousUrl: suspicious ? fullUrl : null,
      suspiciousReason: suspicious ? reason : null,
    });
    try {
      await chrome.action.setIcon({ tabId, path: suspicious ? ICON_WARNING : ICON_SAFE });
    } catch (_) {}
    return suspicious;
  } catch (e) {
    // Ignore unexpected errors
  }
}

// Loads a pre-trained TensorFlow.js model and predicts phishing probability for a URL
// How this will work (high level):
// 1) Preprocess the input URL into numerical features suitable for the model (e.g., character-level
//    sequences, bag-of-characters, tokenized components like hostname/path/tld lengths, presence of
//    specific symbols). This step mirrors the preprocessing used during model training.
// 2) Use tf.loadLayersModel to load the model from the extension's packaged assets (model.json and
//    associated weight files). Keep a cached instance to avoid reloading for each prediction.
// 3) Run model.predict on the prepared tensor to get a phishing probability. Compare against a
//    threshold (e.g., 0.5) to produce a boolean isPhishing result.
// Note: Full preprocessing and tensor construction are not implemented yet; this scaffolds the API.
let cachedTfModel = null;
async function loadModelAndPredict(url) {
  // Ensure TensorFlow.js is available in the service worker context. With MV3, we whitelist the
  // CDN in the extension_pages CSP so importing TFJS at runtime is allowed if needed. In many setups
  // you would also bundle TFJS or import it as an ES module.
  if (!self.tf || !self.tf.loadLayersModel) {
    // Dynamically import TensorFlow.js from CDN as a fallback
    try {
      await import("https://cdn.jsdelivr.net/npm/@tensorflow/tfjs@4.14.0/dist/tf.min.js");
    } catch (e) {
      console.warn("Failed to load TensorFlow.js:", e);
      return null;
    }
  }

  try {
    if (!cachedTfModel) {
      const modelUrl = chrome.runtime.getURL("model.json");
      cachedTfModel = await tf.loadLayersModel(modelUrl);
    }
    // Build feature vector expected by the model using extractFeatures(url)
    const features = extractFeatures(url);
    const inputTensor = tf.tensor2d([features]); // shape [1, num_features]
    const output = cachedTfModel.predict(inputTensor);
    // Ensure we get a scalar probability in [0, 1]
    const probTensor = Array.isArray(output) ? output[0] : output;
    const data = await probTensor.data();
    const probability = data[0] ?? 0;
    inputTensor.dispose();
    if (probTensor !== output) probTensor.dispose();
    if (output && output.dispose) output.dispose();
    return probability;
  } catch (e) {
    console.warn("Prediction failed:", e);
    return null;
  }
}

/**
 * Extracts a fixed-length numeric feature vector from a URL string.
 * Feature order:
 *  [0] urlLength            - Total length of the URL string
 *  [1] dotCount             - Count of '.' characters in the full URL
 *  [2] hyphenCount          - Count of '-' characters in the full URL
 *  [3] usesHttps            - 1 if protocol is HTTPS, else 0
 *  [4] hostIsIp             - 1 if hostname is an IP address, else 0
 * The function is resilient to missing schemes and malformed URLs.
 */
function extractFeatures(urlString) {
  const input = typeof urlString === "string" ? urlString : "";
  const urlLength = input.length;
  const dotCount = (input.match(/\./g) || []).length;
  const hyphenCount = (input.match(/-/g) || []).length;

  let usesHttps = 0;
  let hostIsIp = 0;

  let parsed = null;
  try {
    parsed = new URL(input);
  } catch (_) {
    // If scheme is missing, try http:// prefix
    try {
      parsed = new URL("http://" + input);
    } catch (_) {
      parsed = null;
    }
  }

  if (parsed) {
    usesHttps = parsed.protocol === "https:" ? 1 : 0;
    try {
      const hostname = parsed.hostname.toLowerCase();
      hostIsIp = isIpAddress(hostname) ? 1 : 0;
    } catch (_) {
      hostIsIp = 0;
    }
  }

  return [urlLength, dotCount, hyphenCount, usesHttps, hostIsIp];
}
