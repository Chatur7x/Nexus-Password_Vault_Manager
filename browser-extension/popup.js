document.getElementById('unlock-btn').addEventListener('click', () => {
  const pwd = document.getElementById('master-pwd').value;
  const status = document.getElementById('status-msg');
  
  if (pwd) {
    status.innerText = "Deriving key (Argon2id) & fetching ZK sync...";
    
    // Simulate key derivation and vault fetch
    setTimeout(() => {
      document.getElementById('login-view').style.display = 'none';
      document.getElementById('vault-view').style.display = 'block';
    }, 1500);
  }
});

document.getElementById('fill-btn').addEventListener('click', () => {
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    chrome.scripting.executeScript({
      target: {tabId: tabs[0].id},
      function: () => {
        // Find inputs and fill them
        const pwdInput = document.querySelector('input[type="password"]');
        if (pwdInput) {
          pwdInput.value = "SecureAutoFill123!";
          const form = pwdInput.closest('form');
          if(form) {
            const userField = form.querySelector('input[type="text"], input[type="email"]');
            if(userField) userField.value = "admin@nexus.com";
          }
        } else {
          alert("No password field found on this page.");
        }
      }
    });
  });
});
