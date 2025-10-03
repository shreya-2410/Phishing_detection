'use strict';

// Listen for tab updates and run phishing check when a page finishes loading.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo && changeInfo.status === 'complete' && tab && typeof tab.url === 'string') {
    checkUrlForPhishing(tab.url);
  }
});

/**
 * Checks a URL string for a simple phishing heuristic and warns the user.
 * Heuristic: If the URL contains the word 'login' (case-insensitive) and any digit, flag as suspicious.
 *
 * @param {string} urlString - The URL to check.
 * @returns {boolean} True if suspicious by heuristic; otherwise false.
 */
function checkUrlForPhishing(urlString) {
  if (typeof urlString !== 'string' || urlString.length === 0) {
    return false;
  }

  const containsLoginWord = /login/i.test(urlString);
  const containsAnyDigit = /\d/.test(urlString);
  const isSuspicious = containsLoginWord && containsAnyDigit;

  if (isSuspicious) {
    notifySuspiciousUrl(urlString);
  }

  return isSuspicious;
}

/**
 * Creates a user-visible notification warning about a suspicious URL.
 * Requires the "notifications" permission in the extension manifest.
 *
 * @param {string} urlString - The suspicious URL to display to the user.
 */
function notifySuspiciousUrl(urlString) {
  try {
    if (chrome && chrome.notifications && typeof chrome.notifications.create === 'function') {
      const notificationId = `phishing-warning-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
      chrome.notifications.create(notificationId, {
        type: 'basic',
        iconUrl: 'icon.png', // Ensure an icon exists in your extension package
        title: 'Suspicious URL detected',
        message: 'This page may be a phishing attempt: ' + urlString,
        priority: 2,
      });
    } else {
      // Fallback: at least log a warning if notifications API is unavailable
      console.warn('[Phishing Detection] Suspicious URL detected:', urlString);
    }
  } catch (error) {
    console.warn('[Phishing Detection] Failed to create notification:', error);
  }
}

// Expose function for potential testing or reuse
// eslint-disable-next-line no-undef
if (typeof self !== 'undefined') {
  // no-op guard for service worker context
}
