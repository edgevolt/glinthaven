/**
 * Terminal — CLI interface for the web app.
 * Handles input, history, command routing, and output rendering.
 */

import { detectIOC } from './ioc-detector.js';
import { queryIOC } from './api-client.js';
import { getHelpOutput } from './help.js';
import { getKeyStatus, renderSettings, getPreference } from './settings.js';
import {
  renderLoading,
  removeLoading,
  renderResult,
  renderDetected,
  renderSection,
  renderSummary,
} from './results-renderer.js';
import { launchWizard } from './wizard.js';
import { lockVault } from './settings.js';
import pkg from '../package.json';

const BANNER = `   __ _  _ _       _    _
  / _\` || (_)_ __ | |_ | |__   __ _ __   __ ___  _ __
 | (_| || | | '_ \\| __|| '_ \\ / _\` |\\ \\ / // _ \\| '_ \\
  \\__, ||_|_|_| |_|\\__||_| |_|\\__,_| \\_V /|  __/| | | |
  |___/                                    \\___||_| |_|`;

let output;
let input;
let statusText;
let statusDot;
let history = [];
let historyIndex = -1;
let isProcessing = false;
let debugMode = false;
let autocompleteEnabled = true; // updated from preference on init
let sessionNotes = [];

// Commands available for Tab completion
const COMMANDS = [
  'help', 'clear', 'history', 'settings', 'setup', 'lock', 'about', 'debug', 'search',
  'note', 'notes', 'note-clear'
];
// Sub-completions for commands that take arguments
const COMMAND_ARGS = {
  help:  ['start', 'ioc', 'commands', 'examples', 'sources'],
  debug: ['on', 'off'],
};

/**
 * Initialize the terminal.
 */
export function initTerminal() {
  output = document.getElementById('terminal-output');
  input = document.getElementById('terminal-input');
  statusText = document.getElementById('status-text');
  statusDot = document.querySelector('.status-dot');

  // Load autocomplete preference (default: enabled)
  autocompleteEnabled = getPreference('autocomplete', true);

  // Restore history from sessionStorage
  try {
    const saved = sessionStorage.getItem('glinthaven_history');
    if (saved) history = JSON.parse(saved);
    
    const savedNotes = sessionStorage.getItem('glinthaven_notes');
    if (savedNotes) sessionNotes = JSON.parse(savedNotes);
  } catch { }

  // Build the ghost-text overlay that shows inline completion hints
  setupGhostText();

  // Attach events
  input.addEventListener('keydown', handleKeyDown);
  input.addEventListener('input', updateGhost);

  // Live-update autocomplete toggle from the settings panel
  window.addEventListener('glinthaven:pref-changed', (e) => {
    if (e.detail.name === 'autocomplete') {
      autocompleteEnabled = e.detail.value;
      clearGhost();
    }
  });

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
  if (e.key === 'Tab') {
    e.preventDefault();
    if (autocompleteEnabled) applyCompletion();
    return;
  }
  if (e.key === 'Enter') {
    e.preventDefault();
    clearGhost();
    const cmd = input.value.trim();
    if (!cmd || isProcessing) return;
    executeCommand(cmd);
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    clearGhost();
    navigateHistory(-1);
  } else if (e.key === 'ArrowDown') {
    e.preventDefault();
    clearGhost();
    navigateHistory(1);
  } else if (e.key === 'Escape') {
    clearGhost();
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
  try { sessionStorage.setItem('glinthaven_history', JSON.stringify(history)); } catch { }

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
    case 'setup':
      launchWizard(true);
      break;
    case 'lock':
      lockVault();
      location.reload();
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
    case 'note':
      addNote(args);
      break;
    case 'notes':
      showNotes();
      break;
    case 'note-clear':
      clearNotes();
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
    cleanQuery = cleanQuery.replace(/--debug\s*/g, '').trim();
  }

  // Parse --source or -s flag
  let specificSource = null;
  const sourceMatch = cleanQuery.match(/--source(?:=|\s+)([a-zA-Z0-9-]+)|-s\s+([a-zA-Z0-9-]+)/);
  if (sourceMatch) {
    specificSource = sourceMatch[1] || sourceMatch[2];
    cleanQuery = cleanQuery.replace(sourceMatch[0], '').trim();
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
  
  if (specificSource) {
    appendHTML(renderSection(`Querying threat intel source: ${specificSource}`));
  } else {
    appendHTML(renderSection(`Querying threat intelligence sources`));
  }

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
  }, { debug: useDebug, sourceFilter: specificSource });

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
  appendHTML(`<div class="term-section">About Glinthaven <span style="color:var(--text-muted); font-size:0.85em; font-weight:normal;">v${pkg.version}</span></div>
<div class="term-line"><strong>Glinthaven</strong> — Where security research and OSINT find their flow.</div>
<div class="term-line" style="margin-top:var(--sp-sm)">Paste an IP, domain, hash, URL, email, or CVE and instantly query multiple threat intel sources in parallel.</div>
<div class="term-line" style="margin-top:var(--sp-sm)">Sources: VirusTotal · AbuseIPDB · Shodan · AlienVault OTX · NIST NVD · urlscan.io</div>
<div class="term-line term-system" style="margin-top:var(--sp-sm)">All data stays in your browser. API keys are stored in localStorage.</div>`);
}

function openSettings() {
  const modal = document.getElementById('settings-modal');
  const body = document.getElementById('settings-body');
  renderSettings(body);
  modal.classList.remove('hidden');

  appendHTML(`<div class="term-line term-system">Settings panel opened. Configure your API keys there.</div>`);
}

function addNote(text) {
  if (!text) {
    appendHTML(`<div class="term-line term-warning">Usage: <span style="color:var(--cyan)">note &lt;text&gt;</span></div>`);
    return;
  }
  const timestamp = new Date().toLocaleTimeString();
  sessionNotes.push({ text, timestamp });
  try { sessionStorage.setItem('glinthaven_notes', JSON.stringify(sessionNotes)); } catch { }
  appendHTML(`<div class="term-line term-system">📝 Note saved continuously for this session. Use <span style="color:var(--cyan)">notes</span> to read.</div>`);
}

function showNotes() {
  if (sessionNotes.length === 0) {
    appendHTML(`<div class="term-line term-system">No notes saved. Type <span style="color:var(--cyan)">note [your text]</span> to add one.</div>`);
    return;
  }
  appendHTML(`<div class="term-section">Session Notes</div>`);
  let html = '';
  sessionNotes.forEach((n, i) => {
    html += `<div class="term-line"><span style="color:var(--text-muted);font-size:0.8rem;margin-right:0.5em">[${n.timestamp}]</span> ${escHTML(n.text)}</div>`;
  });
  appendHTML(html);
}

function clearNotes() {
  sessionNotes = [];
  try { sessionStorage.removeItem('glinthaven_notes'); } catch { }
  appendHTML(`<div class="term-line term-system">📝 All session notes cleared.</div>`);
}

/* --- Autocomplete --- */

let ghostEl = null;
let currentCompletion = '';

function setupGhostText() {
  // Wrap the input in a relative-positioned div so the ghost
  // sits flush with the start of the typed text (left: 0 = input's left edge).
  const wrapper = document.createElement('div');
  wrapper.style.cssText = 'position:relative;flex:1;display:flex;align-items:center;';

  input.parentElement.insertBefore(wrapper, input);
  wrapper.appendChild(input);
  // Re-apply width so the input still fills the wrapper
  input.style.width = '100%';

  ghostEl = document.createElement('span');
  ghostEl.id = 'terminal-ghost';
  ghostEl.setAttribute('aria-hidden', 'true');
  ghostEl.style.cssText = `
    position: absolute;
    top: 50%;
    transform: translateY(-50%);
    left: 0;
    pointer-events: none;
    font-family: var(--font-mono);
    font-size: 0.9rem;
    line-height: 1;
    white-space: pre;
    color: transparent;
    user-select: none;
  `;
  wrapper.appendChild(ghostEl);
}

/**
 * Find the best completion for the current input value.
 * @returns {{ full: string, suffix: string } | null}
 */
function findCompletion(raw) {
  const trimmed = raw.trimStart();
  if (!trimmed) return null;

  const parts = trimmed.split(/\s+/);
  const cmd = parts[0].toLowerCase();

  if (parts.length === 1) {
    // Complete the command name
    const match = COMMANDS.find(c => c.startsWith(cmd) && c !== cmd);
    if (!match) return null;
    return { full: match, suffix: match.slice(cmd.length) };
  }

  if (parts.length === 2 && COMMAND_ARGS[cmd]) {
    // Complete a sub-argument
    const partial = parts[1].toLowerCase();
    const match = COMMAND_ARGS[cmd].find(a => a.startsWith(partial) && a !== partial);
    if (!match) return null;
    const full = `${cmd} ${match}`;
    const suffix = match.slice(partial.length);
    return { full, suffix };
  }

  return null;
}

function updateGhost() {
  if (!autocompleteEnabled || !ghostEl) { clearGhost(); return; }

  const raw = input.value;
  const result = findCompletion(raw);

  if (!result || !result.suffix) { clearGhost(); return; }

  currentCompletion = result.full;

  // Measure how wide the current typed text is so we can position the ghost suffix
  const canvas = updateGhost._canvas || (updateGhost._canvas = document.createElement('canvas'));
  const ctx = canvas.getContext('2d');
  const style = window.getComputedStyle(input);
  ctx.font = `${style.fontSize} ${style.fontFamily}`;
  const typedWidth = ctx.measureText(raw).width;

  ghostEl.style.left = `${typedWidth}px`;
  ghostEl.style.color = 'var(--text-muted)';
  ghostEl.textContent = result.suffix;
}

function clearGhost() {
  currentCompletion = '';
  if (ghostEl) {
    ghostEl.textContent = '';
    ghostEl.style.color = 'transparent';
  }
}

function applyCompletion() {
  if (!currentCompletion) {
    // No pending ghost — cycle through all commands starting with current input
    const raw = input.value.trimStart();
    const result = findCompletion(raw);
    if (result) {
      input.value = result.full;
      updateGhost();
    }
    return;
  }
  input.value = currentCompletion;
  clearGhost();
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
