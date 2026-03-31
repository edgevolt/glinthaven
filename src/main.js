/**
 * Main — Application entry point and view router.
 */

import './index.css';
import { initTerminal } from './terminal.js';
import { renderSettings, hasVault, isVaultUnlocked, unlockVault } from './settings.js';
import { initWizard } from './wizard.js';

// --- DOM References ---
const hero = document.getElementById('landing-hero');
const terminalView = document.getElementById('terminal-view');
const launchBtn = document.getElementById('launch-terminal-btn');
const settingsBtn = document.getElementById('settings-btn');
const helpBtn = document.getElementById('help-btn');
const settingsModal = document.getElementById('settings-modal');
const settingsClose = document.getElementById('settings-close');
const terminalInput = document.getElementById('terminal-input');

// --- Vault UI ---
const vaultModal = document.getElementById('vault-modal');
const vaultTitle = document.getElementById('vault-title');
const vaultDesc = document.getElementById('vault-desc');
const vaultInput = document.getElementById('vault-password');
const vaultSubmit = document.getElementById('vault-submit');
const vaultError = document.getElementById('vault-error');

// --- Terms UI ---
const termsModal = document.getElementById('terms-modal');
const termsAcceptBtn = document.getElementById('terms-accept-btn');

if (termsAcceptBtn) {
  termsAcceptBtn.addEventListener('click', () => {
    localStorage.setItem('glinthaven_terms_accepted', 'true');
    termsModal.classList.add('hidden');
    showTerminal();
  });
}

async function handleVault() {
  const pwd = vaultInput.value;
  if (!pwd) return;

  vaultSubmit.disabled = true;
  vaultSubmit.textContent = 'Decrypting...';

  const success = await unlockVault(pwd);
  if (success) {
    vaultModal.classList.add('hidden');
    initTerminal();
    initWizard();
  } else {
    vaultError.style.display = 'block';
    vaultInput.value = '';
    vaultInput.focus();
    vaultSubmit.disabled = false;
    vaultSubmit.textContent = 'Unlock Sandbox';
  }
}

if (vaultSubmit) vaultSubmit.addEventListener('click', handleVault);
if (vaultInput) {
  vaultInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleVault();
  });
}

// --- Launch Terminal ---
function showTerminal() {
  if (!localStorage.getItem('glinthaven_terms_accepted')) {
    termsModal.classList.remove('hidden');
    return;
  }

  hero.classList.add('hidden');
  terminalView.classList.remove('hidden');
  
  if (isVaultUnlocked()) {
    initTerminal();
    initWizard();
  } else {
    if (!hasVault()) {
      vaultTitle.textContent = 'Create Master Password';
      vaultDesc.textContent = 'Please create a master password to encrypt your API keys locally on this device.';
      vaultSubmit.textContent = 'Create Vault & Launch';
    } else {
      vaultTitle.textContent = 'Unlock Local Vault';
      vaultDesc.textContent = 'Enter your Master Password to decrypt your API keys.';
      vaultSubmit.textContent = 'Unlock Sandbox';
    }
    vaultModal.classList.remove('hidden');
    setTimeout(() => vaultInput.focus(), 100);
  }
}

launchBtn.addEventListener('click', showTerminal);

// Also allow Enter key from landing
document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !hero.classList.contains('hidden')) {
    e.preventDefault();
    showTerminal();
  }
});

// --- Settings Modal ---
settingsBtn.addEventListener('click', () => {
  renderSettings(document.getElementById('settings-body'));
  settingsModal.classList.remove('hidden');
});

helpBtn.addEventListener('click', () => {
  // Focus terminal and type help
  if (terminalInput) {
    terminalInput.value = 'help';
    terminalInput.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
  }
});

settingsClose.addEventListener('click', () => {
  settingsModal.classList.add('hidden');
  if (terminalInput) terminalInput.focus();
});

// Close modal on overlay click
settingsModal.addEventListener('click', (e) => {
  if (e.target === settingsModal) {
    settingsModal.classList.add('hidden');
    if (terminalInput) terminalInput.focus();
  }
});

// Close modal on Escape
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !settingsModal.classList.contains('hidden')) {
    settingsModal.classList.add('hidden');
    if (terminalInput) terminalInput.focus();
  }
});

// --- Check for direct-to-terminal URL param ---
const params = new URLSearchParams(window.location.search);
if (params.has('terminal') || params.has('t')) {
  showTerminal();
}
