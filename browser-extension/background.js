// background.js
// Handles communication between the popup, content script, and the ZK Sync Server.

chrome.runtime.onInstalled.addListener(() => {
  console.log("NEXUS Vault Extension Installed.");
});

// Mock local encrypted storage for the extension
let localEncryptedVault = null;

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "check_domain") {
    const currentDomain = new URL(request.url).hostname;
    // Basic Phishing Detection / Domain Match
    // In a real app, this queries the decrypted vault to see if there's a match.
    // For now, we mock a safe response or flag if it's a known lookalike (e.g. paypa1.com).
    
    const lookalikes = ["paypa1.com", "g00gle.com", "micros0ft.com"];
    if (lookalikes.includes(currentDomain)) {
      sendResponse({ status: "phishing_alert" });
    } else {
      sendResponse({ status: "safe", domain: currentDomain });
    }
  }
  return true;
});
