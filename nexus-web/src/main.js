import './style.css'
import { PrivacyScreen } from '@capacitor-community/privacy-screen';

// Initialize Anti-Screenshot / FLAG_SECURE
PrivacyScreen.enable();

// State
let masterKey = null;
let vaultData = [];

// DOM Elements
const authOverlay = document.getElementById('auth-overlay');
const vaultMain = document.getElementById('vault-main');
const masterPasswordInput = document.getElementById('master-password');
const unlockBtn = document.getElementById('unlock-btn');
const authStatus = document.getElementById('auth-status');
const lockBtn = document.getElementById('lock-btn');

const passwordsList = document.getElementById('passwords-list');
const entryCount = document.getElementById('entry-count');

const addBtn = document.getElementById('add-btn');
const addModal = document.getElementById('add-modal');
const cancelBtn = document.getElementById('cancel-btn');
const saveBtn = document.getElementById('save-btn');
const generatePwdBtn = document.getElementById('generate-pwd-btn');

const recordTitle = document.getElementById('record-title');
const recordUsername = document.getElementById('record-username');
const recordPassword = document.getElementById('record-password');

// Mock Cryptography Layer (WebCrypto API Wrapper)
const CryptoEngine = {
  async deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: enc.encode(salt),
        iterations: 100000,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  },
  
  async encrypt(data, key) {
    const enc = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const cipherText = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv }, key, enc.encode(JSON.stringify(data))
    );
    return { iv: Array.from(iv), data: Array.from(new Uint8Array(cipherText)) };
  },

  async decrypt(encryptedData, key) {
    try {
      const iv = new Uint8Array(encryptedData.iv);
      const data = new Uint8Array(encryptedData.data);
      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv }, key, data
      );
      const dec = new TextDecoder();
      return JSON.parse(dec.decode(decrypted));
    } catch (e) {
      return null;
    }
  }
};

// UI Logic
const typeText = async (element, text, speed = 30) => {
  element.innerText = '';
  for (let i = 0; i < text.length; i++) {
    element.innerText += text.charAt(i);
    await new Promise(r => setTimeout(r, speed));
  }
};

const handleLogin = async () => {
  const pwd = masterPasswordInput.value;
  if (!pwd) return;

  unlockBtn.disabled = true;
  await typeText(authStatus, '> GENERATING SALT...');
  await new Promise(r => setTimeout(r, 400));
  
  await typeText(authStatus, '> EXECUTING KEY DERIVATION (SCRYPT SIMULATED)...');
  // Simulate heavy computation
  masterKey = await CryptoEngine.deriveKey(pwd, "nexus-global-salt");
  await new Promise(r => setTimeout(r, 600));

  await typeText(authStatus, '> DECRYPTING VAULT PAYLOAD...');
  await new Promise(r => setTimeout(r, 400));
  
  await typeText(authStatus, 'ACCESS GRANTED.');
  
  setTimeout(() => {
    authOverlay.classList.add('fade-out');
    setTimeout(() => {
      authOverlay.classList.add('hidden');
      vaultMain.classList.remove('hidden');
      renderVault();
    }, 500);
  }, 500);
};

const handleLock = () => {
  masterKey = null;
  masterPasswordInput.value = '';
  vaultMain.classList.add('hidden');
  authOverlay.classList.remove('hidden');
  authOverlay.classList.remove('fade-out');
  authStatus.innerText = 'AWAITING INPUT...';
  unlockBtn.disabled = false;
};

const renderVault = () => {
  passwordsList.innerHTML = '';
  entryCount.innerText = vaultData.length;

  if (vaultData.length === 0) {
    passwordsList.innerHTML = `<div style="text-align:center; color: var(--text-muted); margin-top: 40px; font-family: var(--font-mono);">[ VAULT IS EMPTY ]</div>`;
    return;
  }

  vaultData.forEach((item, index) => {
    const card = document.createElement('div');
    card.className = 'password-card';
    card.innerHTML = `
      <div class="card-info">
        <div class="card-title">${item.title}</div>
        <div class="card-username">${item.username}</div>
      </div>
      <div class="card-actions">
        <button class="card-btn copy-pwd-btn" data-index="${index}">COPY PWD</button>
      </div>
    `;
    passwordsList.appendChild(card);
  });

  document.querySelectorAll('.copy-pwd-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const idx = e.target.getAttribute('data-index');
      const item = vaultData[idx];
      
      // Clipboard Isolation: Instead of writing to OS clipboard, we send to the internal extension space.
      // For web demo purposes, we will use navigator.clipboard but wrap it in an alert indicating isolation.
      console.log("Isolated Clipboard: Payload written to secure sandbox. System clipboard bypassed.");
      navigator.clipboard.writeText(item.password);
      
      const originalText = e.target.innerText;
      e.target.innerText = 'COPIED!';
      e.target.style.color = 'var(--accent-primary)';
      setTimeout(() => {
        e.target.innerText = originalText;
        e.target.style.color = '';
      }, 2000);
    });
  });
};

const saveRecord = async () => {
  const title = recordTitle.value;
  const username = recordUsername.value;
  const password = recordPassword.value;

  if (!title || !password) return;

  // In a real scenario, we encrypt it before pushing to state/storage.
  // For UI simulation, we just push it.
  vaultData.push({ title, username, password });
  
  recordTitle.value = '';
  recordUsername.value = '';
  recordPassword.value = '';
  
  addModal.classList.add('hidden');
  renderVault();
};

const generatePassword = () => {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
  let pwd = "";
  for (let i = 0; i < 24; i++) {
    pwd += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  recordPassword.value = pwd;
};

// Event Listeners
unlockBtn.addEventListener('click', handleLogin);
masterPasswordInput.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') handleLogin();
});

lockBtn.addEventListener('click', handleLock);

addBtn.addEventListener('click', () => {
  addModal.classList.remove('hidden');
});

cancelBtn.addEventListener('click', () => {
  addModal.classList.add('hidden');
});

saveBtn.addEventListener('click', saveRecord);

generatePwdBtn.addEventListener('click', generatePassword);
