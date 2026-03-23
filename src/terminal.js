/**
 * Terminal — CLI interface for the web app.
 * Handles input, history, command routing, and output rendering.
 */

import { detectIOC } from './ioc-detector.js';
import { queryIOC } from './api-client.js';
import { getHelpOutput } from './help.js';
import { getKeyStatus, renderSettings } from './settings.js';
import {
  renderLoading,
  removeLoading,
  renderResult,
  renderDetected,
  renderSection,
  renderSummary,
} from './results-renderer.js';

const BANNER = `   __ _  _ _       _    _
  / _\` || (_)_ __ | |_ | |__   __ _ __   __ ___  _ __
 | (_| || | | '_ \\| __|| '_ \\ / _\` |\\ \\ / // _ \\| '_ \\
  \\__, ||_|_|_| |_|\\__||_| |_|\\__,_| \\_V /|  __/| | | |
  |___/                                    \\___| |_| |_|`;

let output;
let input;
let statusText;
let statusDot;
let history = [];
let historyIndex = -1;
let isProcessing = false;
let debugMode = false;

/**
 * Initialize the terminal.
 */
export function initTerminal() {
  output = document.getElementById('terminal-output');
  input = document.getElementById('terminal-input');
  statusText = document.getElementById('status-text');
  statusDot = document.querySelector('.status-dot');

  // Restore history from sessionStorage
  try {
    const saved = sessionStorage.getItem('glinthaven_history');
    if (saved) history = JSON.parse(saved);
  } catch {}

  // Attach events
  input.addEventListener('keydown', handleKeyDown);

  // Click anywhere in output to focus input
  output.addEventListener('click', () => input.focus());

  // Show welcome
  showWelcome();
  input.focus();
}

function showWelcome() {
  appendHTML(`<div class="term-banner">${escHTML(BANNER)}</div>`);
  appendHTML(`<div class="term-line term-system">Welcome to Glinthaven — fast IOC threat intelligence lookup.</div>`);
  appendHTML(`<div class="term-line term-system">Type <span style="color:var(--cyan)">help start</span> if you're new, or just paste an IOC to search.</div>`);

  // Show key status summary
  const keys = getKeyStatus();
  const configured = keys.filter(k => k.configured).length;
  const total = keys.length;

  if (configured === 0) {
    appendHTML(`<div class="term-line term-warning" style="margin-top:var(--sp-sm)">⚡ No API keys configured. Type <span style="color:var(--cyan)">settings</span> to add keys, or try a search — AlienVault OTX works without one.</div>`);
  } else {
    appendHTML(`<div class="term-line term-system" style="margin-top:var(--sp-sm)">API keys: ${configured}/${total} configured. Type <span style="color:var(--cyan)">settings</span> to manage.</div>`);
  }
  appendHTML(`<div style="height:var(--sp-md)"></div>`);
}

function handleKeyDown(e) {
  if (e.key === 'Enter') {
    e.preventDefault();
    const cmd = input.value.trim();
    if (!cmd || isProcessing) return;
    executeCommand(cmd);
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    navigateHistory(-1);
  } else if (e.key === 'ArrowDown') {
    e.preventDefault();
    navigateHistory(1);
  }
}

function navigateHistory(direction) {
  if (history.length === 0) return;

  if (direction === -1) {
    // Go back
    if (historyIndex < history.length - 1) {
      historyIndex++;
    }
  } else {
    // Go forward
    if (historyIndex > 0) {
      historyIndex--;
    } else {
      historyIndex = -1;
      input.value = '';
      return;
    }
  }

  input.value = history[historyIndex] || '';
}

async function executeCommand(raw) {
  // Echo the command
  appendHTML(`<div class="term-cmd"><span class="prompt">❯</span> ${escHTML(raw)}</div>`);

  // Add to history
  history.unshift(raw);
  if (history.length > 100) history.pop();
  historyIndex = -1;
  try { sessionStorage.setItem('glinthaven_history', JSON.stringify(history)); } catch {}

  input.value = '';

  // Parse command
  const parts = raw.split(/\s+/);
  const cmd = parts[0].toLowerCase();
  const args = parts.slice(1).join(' ');

  switch (cmd) {
    case 'help':
      appendHTML(getHelpOutput(args));
      break;
    case 'clear':
      output.innerHTML = '';
      break;
    case 'history':
      showHistory();
      break;
    case 'settings':
      openSettings();
      break;
    case 'about':
      showAbout();
      break;
    case 'debug':
      toggleDebug(args);
      break;
    case 'search':
      await handleSearch(args);
      break;
    default:
      // Try interpreting the entire input as an IOC
      await handleSearch(raw);
      break;
  }

  scrollToBottom();
}

async function handleSearch(query) {
  if (!query) {
    appendHTML(`<div class="term-line term-warning">Please provide an IOC to search. Type <span style="color:var(--cyan)">help ioc</span> for supported types.</div>`);
    return;
  }

  // Parse --debug flag from search args
  let useDebug = debugMode;
  let cleanQuery = query;
  if (/--debug\b/.test(query)) {
    useDebug = true;
    cleanQuery = query.replace(/--debug\s*/g, '').trim();
  }

  const ioc = detectIOC(cleanQuery);

  if (!ioc) {
    appendHTML(`<div class="term-line term-error">Could not detect IOC type for: "${escHTML(cleanQuery)}"</div>`);
    appendHTML(`<div class="term-line term-system">Supported types: IPv4, IPv6, Domain, URL, Hash (MD5/SHA1/SHA256), Email, CVE</div>`);
    appendHTML(`<div class="term-line term-system">Type <span style="color:var(--cyan)">help examples</span> for example queries.</div>`);
    return;
  }

  // Show what was detected
  appendHTML(renderDetected(ioc));
  if (useDebug) {
    appendHTML(`<div class="term-line term-system" style="font-size:0.8rem">⚙ Debug mode active — showing latency, HTTP status, and endpoints</div>`);
  }
  appendHTML(renderSection(`Querying threat intelligence sources`));

  setStatus('Searching…', true);
  isProcessing = true;
  input.disabled = true;

  // Show loading for each source
  const results = await queryIOC(ioc, (update) => {
    if (update.status === 'loading') {
      appendHTML(renderLoading(update.source));
    } else {
      removeLoading(update.source);
      appendHTML(renderResult(update));
      scrollToBottom();
    }
  }, { debug: useDebug });

  // Summary
  appendHTML(renderSummary(results));

  isProcessing = false;
  input.disabled = false;
  setStatus('Ready', false);
  input.focus();
}

function toggleDebug(args) {
  const arg = args.trim().toLowerCase();
  if (arg === 'on' || arg === '1' || arg === 'true') {
    debugMode = true;
    appendHTML(`<div class="term-line term-info">⚙ Debug mode <strong>ON</strong> — all searches will show debug info.</div>`);
  } else if (arg === 'off' || arg === '0' || arg === 'false') {
    debugMode = false;
    appendHTML(`<div class="term-line term-system">⚙ Debug mode <strong>OFF</strong>.</div>`);
  } else {
    debugMode = !debugMode;
    appendHTML(`<div class="term-line term-info">⚙ Debug mode <strong>${debugMode ? 'ON' : 'OFF'}</strong>${debugMode ? ' — all searches will show debug info' : ''}.</div>`);
  }
  appendHTML(`<div class="term-line term-system">You can also use <span style="color:var(--cyan)">--debug</span> on individual searches, e.g. <span style="color:var(--cyan)">8.8.8.8 --debug</span></div>`);
}

function showHistory() {
  if (history.length === 0) {
    appendHTML(`<div class="term-line term-system">No command history yet.</div>`);
    return;
  }
  appendHTML(renderSection('Command History'));
  const items = history.slice(0, 20);
  let html = '';
  items.forEach((cmd, i) => {
    html += `<div class="term-line"><span style="color:var(--text-muted);min-width:2em;display:inline-block">${i + 1}.</span> ${escHTML(cmd)}</div>`;
  });
  if (history.length > 20) html += `<div class="term-line term-system">… and ${history.length - 20} more</div>`;
  appendHTML(html);
}

function showAbout() {
  appendHTML(`<div class="term-section">About Glinthaven</div>
<div class="term-line"><strong>Glinthaven</strong> — Where security research and OTI find their flow.</div>
<div class="term-line" style="margin-top:var(--sp-sm)">Paste an IP, domain, hash, URL, email, or CVE and instantly query multiple threat intel sources in parallel.</div>
<div class="term-line" style="margin-top:var(--sp-sm)">Sources: VirusTotal · AbuseIPDB · Shodan · AlienVault OTX</div>
<div class="term-line term-system" style="margin-top:var(--sp-sm)">All data stays in your browser. API keys are stored in localStorage.</div>`);
}

function openSettings() {
  const modal = document.getElementById('settings-modal');
  const body = document.getElementById('settings-body');
  renderSettings(body);
  modal.classList.remove('hidden');

  appendHTML(`<div class="term-line term-system">Settings panel opened. Configure your API keys there.</div>`);
}

/* --- DOM helpers --- */

function appendHTML(html) {
  const div = document.createElement('div');
  div.innerHTML = html;
  while (div.firstChild) {
    output.appendChild(div.firstChild);
  }
  scrollToBottom();
}

function scrollToBottom() {
  requestAnimationFrame(() => {
    output.scrollTop = output.scrollHeight;
  });
}

function setStatus(text, busy) {
  if (statusText) statusText.textContent = text;
  if (statusDot) {
    statusDot.classList.toggle('busy', busy);
  }
}

function escHTML(str) {
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}
