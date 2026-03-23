/**
 * Main — Application entry point and view router.
 */

import './index.css';
import { initTerminal } from './terminal.js';
import { renderSettings } from './settings.js';

// --- DOM References ---
const hero = document.getElementById('landing-hero');
const terminalView = document.getElementById('terminal-view');
const launchBtn = document.getElementById('launch-terminal-btn');
const settingsBtn = document.getElementById('settings-btn');
const helpBtn = document.getElementById('help-btn');
const settingsModal = document.getElementById('settings-modal');
const settingsClose = document.getElementById('settings-close');
const terminalInput = document.getElementById('terminal-input');

// --- Launch Terminal ---
function showTerminal() {
  hero.classList.add('hidden');
  terminalView.classList.remove('hidden');
  initTerminal();
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
