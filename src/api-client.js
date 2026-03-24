/**
 * API Client — Queries threat intelligence sources via the source registry.
 *
 * This module is intentionally thin — all source-specific logic lives in
 * individual source modules under src/sources/.
 */

import { getSourcesForType } from './source-registry.js';
import { getApiKey, isSourceEnabled } from './settings.js';

/**
 * Query all applicable sources for a given IOC.
 * @param {{ type: string, value: string }} ioc
 * @param {(update: object) => void} onUpdate — called as each source responds
 * @param {{ debug?: boolean }} [options]
 * @returns {Promise<object[]>}
 */
export async function queryIOC(ioc, onUpdate, options = {}) {
  const sources = getSourcesForType(ioc.type);
  const results = [];
  const debug = options.debug || false;

  const promises = sources.map(async (source) => {
    if (!isSourceEnabled(source.id)) return;

    // Check for required API key
    const apiKey = getApiKey(source.id);
    if (source.requiresKey && !apiKey) {
      const errorData = {
        source: source.name,
        status: 'error',
        error: `No API key configured. Run "settings" to add your ${source.name} key.`,
      };
      onUpdate(errorData);
      results.push(errorData);
      return;
    }

    const startTime = performance.now();

    try {
      onUpdate({ source: source.name, status: 'loading' });

      // Intercept fetch to capture debug metadata
      const debugMeta = { endpoint: null, httpStatus: null, httpStatusText: null };
      const originalFetch = globalThis.fetch;

      if (debug) {
        globalThis.fetch = async (url, opts) => {
          debugMeta.endpoint = typeof url === 'string' ? url : url.toString();
          const res = await originalFetch(url, opts);
          debugMeta.httpStatus = res.status;
          debugMeta.httpStatusText = res.statusText;
          return res;
        };
      }

      let data;
      try {
        data = await source.query(ioc, apiKey);
      } finally {
        if (debug) globalThis.fetch = originalFetch;
      }

      const elapsed = performance.now() - startTime;

      const update = { source: source.name, status: 'done', data };
      if (debug) {
        update.debug = {
          latencyMs: Math.round(elapsed),
          httpStatus: debugMeta.httpStatus,
          httpStatusText: debugMeta.httpStatusText,
          endpoint: debugMeta.endpoint,
          sourceId: source.id,
        };
      }
      onUpdate(update);
      results.push({ source: source.name, ...data, ...(debug ? { debug: update.debug } : {}) });

    } catch (err) {
      const elapsed = performance.now() - startTime;
      const errorData = {
        source: source.name,
        status: 'error',
        error: err.message || 'Unknown error',
      };
      if (debug) {
        errorData.debug = {
          latencyMs: Math.round(elapsed),
          sourceId: source.id,
          errorType: err.constructor?.name || 'Error',
        };
      }
      onUpdate(errorData);
      results.push(errorData);
    }
  });

  await Promise.allSettled(promises);
  return results;
}
