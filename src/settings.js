/**
 * Settings — API key management using localStorage.
 *
 * Dynamically pulls service definitions from the source registry,
 * so adding a new source automatically adds it to the settings panel.
 */

import { getAllSources } from './source-registry.js';
import { encryptVault, decryptVault } from './crypto.js';

const STORAGE_KEY = 'glinthaven_vault';

let unlockedKeys = {};
let activePassword = null;
let isUnlocked = false;

export function hasVault() {
  try {
    return !!localStorage.getItem(STORAGE_KEY);
  } catch {
    return false;
  }
}

export function isVaultUnlocked() {
  return isUnlocked;
}

export async function unlockVault(password) {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    // New vault creation
    activePassword = password;
    unlockedKeys = {};
    isUnlocked = true;
    
    // Migrate legacy plaintext keys
    for (let i = localStorage.length - 1; i >= 0; i--) {
       const k = localStorage.key(i);
       if (k && k.startsWith('glinthaven_key_')) {
          const id = k.replace('glinthaven_key_', '');
          unlockedKeys[id] = localStorage.getItem(k);
          localStorage.removeItem(k);
       }
       if (k && k.startsWith('glinthaven_enabled_')) {
          const id = k.replace('glinthaven_enabled_', '');
          unlockedKeys[`_enabled_${id}`] = localStorage.getItem(k) === 'true';
          localStorage.removeItem(k);
       }
    }
    await flushVault(); 
    return true;
  }

  // Existing vault
  try {
    const vaultData = JSON.parse(raw);
    const plaintext = await decryptVault(vaultData, password);
    unlockedKeys = JSON.parse(plaintext);
    activePassword = password;
    isUnlocked = true;
    return true;
  } catch (err) {
    return false; // Wrong password
  }
}

export async function lockVault() {
  unlockedKeys = {};
  activePassword = null;
  isUnlocked = false;
}

async function flushVault() {
  if (!isUnlocked || !activePassword) return;
  const plaintext = JSON.stringify(unlockedKeys);
  const vaultData = await encryptVault(plaintext, activePassword);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(vaultData));
}

/**
 * Get the stored API key for a source.
 * @param {string} sourceId
 * @returns {string}
 */
export function getApiKey(sourceId) {
  if (!isUnlocked) return '';
  return unlockedKeys[sourceId] || '';
}

/**
 * Save an API key for a source.
 * @param {string} sourceId
 * @param {string} key
 */
export function setApiKey(sourceId, key) {
  if (!isUnlocked) return;
  if (key) {
    unlockedKeys[sourceId] = key.trim();
  } else {
    delete unlockedKeys[sourceId];
  }
  flushVault().catch(console.error);
}

/**
 * Check if a source is enabled (defaults to true).
 * @param {string} sourceId
 * @returns {boolean}
 */
export function isSourceEnabled(sourceId) {
  if (!isUnlocked) return false;
  const val = unlockedKeys[`_enabled_${sourceId}`];
  return val === undefined ? true : val;
}

/**
 * Enable or disable a source.
 * @param {string} sourceId
 * @param {boolean} enabled
 */
export function setSourceEnabled(sourceId, enabled) {
  if (!isUnlocked) return;
  unlockedKeys[`_enabled_${sourceId}`] = !!enabled;
  flushVault().catch(console.error);
}

/**
 * Render the settings form into the modal body.
 * Automatically includes all registered sources.
 */
export function renderSettings(container) {
  container.innerHTML = '';
  const sources = getAllSources();

  // Group by category
  const categories = {};
  for (const src of sources) {
    if (!categories[src.category]) categories[src.category] = [];
    categories[src.category].push(src);
  }

  const sortedCategories = Object.keys(categories).sort();

  for (const cat of sortedCategories) {
    const header = document.createElement('h3');
    header.className = 'setting-category-title';
    header.textContent = cat;
    container.appendChild(header);

    for (const src of categories[cat]) {
      const group = document.createElement('div');
      group.className = 'setting-group';

      const currentKey = getApiKey(src.id);
      const hasKey = currentKey.length > 0;
      const requiredLabel = src.requiresKey ? 'required' : 'optional';

      group.innerHTML = `
        <label class="setting-label">
          <input type="checkbox" class="source-toggle" data-source="${src.id}" ${isSourceEnabled(src.id) ? 'checked' : ''} style="margin-right:0.5em" />
          ${src.name}
          <span class="service-badge">${hasKey ? '✓ configured' : requiredLabel}</span>
        </label>
        <p class="setting-hint">${src.rateLimit}. <a href="${src.signupUrl}" target="_blank" rel="noopener">Get a free key →</a></p>
        <input class="setting-input" type="password" placeholder="Paste your API key…" data-source="${src.id}" value="${currentKey}" />
      `;
      container.appendChild(group);
    }
  }

  // Listen for changes
  container.querySelectorAll('.setting-input').forEach(input => {
    input.addEventListener('change', () => {
      const id = input.dataset.source;
      setApiKey(id, input.value);
      const badge = input.closest('.setting-group').querySelector('.service-badge');
      const src = sources.find(s => s.id === id);
      badge.textContent = input.value.trim() ? '✓ configured' : (src?.requiresKey ? 'required' : 'optional');
    });
  });

  container.querySelectorAll('.source-toggle').forEach(checkbox => {
    checkbox.addEventListener('change', () => {
      setSourceEnabled(checkbox.dataset.source, checkbox.checked);
    });
  });
}

/**
 * Get a summary of configured keys for terminal display.
 * @returns {Array<{name: string, configured: boolean, required: boolean}>}
 */
export function getKeyStatus() {
  return getAllSources().map(src => ({
    name: src.name,
    configured: getApiKey(src.id).length > 0,
    required: src.requiresKey,
  }));
}
