/**
 * Results Renderer — Formats API results into terminal-styled HTML output blocks.
 */

/**
 * Render a loading indicator for a source.
 */
export function renderLoading(sourceName) {
  return `<div class="term-loading" id="loader-${slug(sourceName)}">
    <span class="spinner"></span>
    <span>Querying ${sourceName}…</span>
  </div>`;
}

/**
 * Remove the loading indicator for a source.
 */
export function removeLoading(sourceName) {
  const el = document.getElementById(`loader-${slug(sourceName)}`);
  if (el) el.remove();
}

/**
 * Render a completed result block from a source.
 */
export function renderResult(update) {
  if (update.status === 'error') {
    return renderError(update.source, update.error, update.debug);
  }

  const data = update.data;
  const severity = data.severity || 'info';

  let html = `<div class="term-result-block severity-${severity}">`;
  html += `<div class="term-kv"><span class="key">Source</span><span class="value" style="font-weight:600">${esc(update.source)}</span></div>`;

  // Render fields
  if (data.fields) {
    for (const f of data.fields) {
      const cls = f.severity ? ` ${f.severity}` : '';
      html += `<div class="term-kv"><span class="key">${esc(f.key)}</span><span class="value${cls}">${esc(f.value)}</span></div>`;
    }
  }

  // Render tags
  if (data.tags && data.tags.length > 0) {
    html += `<div style="margin-top:0.4em">`;
    for (const tag of data.tags) {
      const cls = getTagClass(tag);
      html += `<span class="term-tag ${cls}">${esc(tag)}</span>`;
    }
    html += `</div>`;
  }

  // Render debug info
  if (update.debug) {
    html += renderDebugInfo(update.debug);
  }

  html += `</div>`;
  return html;
}

/**
 * Render an error block.
 */
export function renderError(sourceName, message, debug) {
  let html = `<div class="term-result-block severity-info">
    <div class="term-kv"><span class="key">Source</span><span class="value">${esc(sourceName)}</span></div>
    <div class="term-kv"><span class="key">Error</span><span class="value danger">${esc(message)}</span></div>`;
  if (debug) {
    html += renderDebugInfo(debug);
  }
  html += `</div>`;
  return html;
}

/**
 * Render the IOC detection info header.
 */
export function renderDetected(ioc) {
  return `<div class="term-line term-info">⟐  Detected <strong>${esc(ioc.label)}</strong>: <span style="color:var(--text-primary)">${esc(ioc.value)}</span></div>`;
}

/**
 * Render a section header.
 */
export function renderSection(text) {
  return `<div class="term-section">${esc(text)}</div>`;
}

/**
 * Render a summary line after all sources complete.
 */
export function renderSummary(results) {
  const errorCount = results.filter(r => r.status === 'error').length;
  const successCount = results.length - errorCount;

  const hasDanger = results.some(r => r.severity === 'high');
  const hasWarn = results.some(r => r.severity === 'medium');

  let summaryClass = 'term-success';
  let icon = '✓';
  let msg = `${successCount} source${successCount !== 1 ? 's' : ''} queried successfully`;

  if (hasDanger) {
    summaryClass = 'term-error';
    icon = '⚠';
    msg += ' — threats detected';
  } else if (hasWarn) {
    summaryClass = 'term-warning';
    icon = '⚡';
    msg += ' — some concerns found';
  }

  if (errorCount > 0) msg += ` (${errorCount} error${errorCount > 1 ? 's' : ''})`;

  return `<div class="term-line ${summaryClass}" style="margin-top:var(--sp-md)">${icon}  ${msg}</div>`;
}

/* --- Helpers --- */

function esc(str) {
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

function slug(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
}

function getTagClass(tag) {
  const t = tag.toLowerCase();
  if (['malicious', 'malware', 'phishing', 'ransomware', 'trojan', 'exploit'].includes(t)) return 'tag-danger';
  if (['suspicious', 'tor', 'proxy', 'vulnerable', 'reported'].includes(t)) return 'tag-warn';
  if (['clean', 'safe', 'whitelisted'].includes(t)) return 'tag-safe';
  return 'tag-info';
}

function renderDebugInfo(debug) {
  let html = `<details class="term-details" style="margin-top:0.5em">`;
  html += `<summary>⚙ Debug Info</summary><div class="term-details-body">`;
  if (debug.latencyMs !== undefined) {
    const color = debug.latencyMs < 500 ? 'good' : debug.latencyMs < 2000 ? 'warn' : 'danger';
    html += `<div class="term-kv"><span class="key">Latency</span><span class="value ${color}">${debug.latencyMs}ms</span></div>`;
  }
  if (debug.httpStatus) {
    const color = debug.httpStatus < 300 ? 'good' : debug.httpStatus < 500 ? 'warn' : 'danger';
    html += `<div class="term-kv"><span class="key">HTTP Status</span><span class="value ${color}">${debug.httpStatus} ${esc(debug.httpStatusText || '')}</span></div>`;
  }
  if (debug.endpoint) {
    html += `<div class="term-kv"><span class="key">Endpoint</span><span class="value neutral" style="font-size:0.75rem;word-break:break-all">${esc(debug.endpoint)}</span></div>`;
  }
  if (debug.sourceId) {
    html += `<div class="term-kv"><span class="key">Source ID</span><span class="value neutral">${esc(debug.sourceId)}</span></div>`;
  }
  if (debug.errorType) {
    html += `<div class="term-kv"><span class="key">Error Type</span><span class="value danger">${esc(debug.errorType)}</span></div>`;
  }
  html += `</div></details>`;
  return html;
}
