// content.js
// Injected into all web pages. Detects login forms and auto-fills them.

function detectAndFill() {
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  if (passwordInputs.length > 0) {
    // Notify background script to check domain
    chrome.runtime.sendMessage({ action: "check_domain", url: window.location.href }, (response) => {
      if (response && response.status === "phishing_alert") {
        alert("🚨 NEXUS VAULT WARNING: This domain appears to be a phishing lookalike. AutoFill disabled.");
        return;
      }
      
      // Look for the associated username field (usually just before the password field)
      passwordInputs.forEach(pwdField => {
        const form = pwdField.closest('form');
        let userField = null;
        if (form) {
          userField = form.querySelector('input[type="text"], input[type="email"]');
        }

        // Add a visual indicator to the input field
        pwdField.style.backgroundImage = "url('chrome-extension://" + chrome.runtime.id + "/icon16.png')";
        pwdField.style.backgroundRepeat = "no-repeat";
        pwdField.style.backgroundPosition = "98% 50%";
        pwdField.style.backgroundSize = "16px";
        
        pwdField.addEventListener('focus', () => {
          // Ask for vault unlock if locked, else autofill
          console.log("NEXUS AutoFill Ready.");
          // Mock Autofill action for demo:
          // userField.value = "demo@nexus.com";
          // pwdField.value = "my_secure_password123";
        });
      });
    });
  }
}

// Run when DOM is fully loaded
window.addEventListener('load', detectAndFill);
