/**
 * Settings — API key management using localStorage.
 *
 * Dynamically pulls service definitions from the source registry,
 * so adding a new source automatically adds it to the settings panel.
 */

import { getAllSources } from './source-registry.js';

const STORAGE_PREFIX = 'glinthaven_key_';

/**
 * Get the stored API key for a source.
 * @param {string} sourceId
 * @returns {string}
 */
export function getApiKey(sourceId) {
  try {
    return localStorage.getItem(STORAGE_PREFIX + sourceId) || '';
  } catch {
    return '';
  }
}

/**
 * Save an API key for a source.
 * @param {string} sourceId
 * @param {string} key
 */
export function setApiKey(sourceId, key) {
  try {
    if (key) {
      localStorage.setItem(STORAGE_PREFIX + sourceId, key.trim());
    } else {
      localStorage.removeItem(STORAGE_PREFIX + sourceId);
    }
  } catch {
    // localStorage unavailable
  }
}

/**
 * Render the settings form into the modal body.
 * Automatically includes all registered sources.
 */
export function renderSettings(container) {
  container.innerHTML = '';
  const sources = getAllSources();

  for (const src of sources) {
    const group = document.createElement('div');
    group.className = 'setting-group';

    const currentKey = getApiKey(src.id);
    const hasKey = currentKey.length > 0;
    const requiredLabel = src.requiresKey ? 'required' : 'optional';

    group.innerHTML = `
      <label class="setting-label">
        ${src.name}
        <span class="service-badge">${hasKey ? '✓ configured' : requiredLabel}</span>
      </label>
      <p class="setting-hint">${src.rateLimit}. <a href="${src.signupUrl}" target="_blank" rel="noopener">Get a free key →</a></p>
      <input class="setting-input" type="password" placeholder="Paste your API key…" data-source="${src.id}" value="${currentKey}" />
    `;
    container.appendChild(group);
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
