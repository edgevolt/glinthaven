/**
 * WiGLE Source
 * https://www.wigle.net
 *
 * Supports: MAC address (BSSID) and SSID (WiFi network name)
 * Requires: free API key — use the "Encoded for use" base64 token from
 *           https://wigle.net/account under the API section.
 *
 * Authentication: HTTP Basic Auth via the pre-encoded base64 token.
 *   Paste the full encoded token (e.g. "AID...==") directly into the key field.
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'wigle',
  name: 'WiGLE',
  category: 'Network & Infrastructure',
  supportedTypes: ['mac', 'ssid'],
  requiresKey: true,
  signupUrl: 'https://www.wigle.net/account',
  rateLimit: 'Free tier — paste the "Encoded for use" token from your account',

  async testAuth(apiKey) {
    const res = await fetch('/api/proxy/wigle/api/v2/profile/user', {
      headers: { 'Authorization': `Basic ${apiKey}` },
    });
    if (res.status === 401 || res.status === 403) throw new Error('API key invalid — use the "Encoded for use" token from wigle.net/account');
    if (!res.ok) throw new Error('Could not verify WiGLE API key');
  },

  async query(ioc, apiKey) {
    const param = ioc.type === 'mac'
      ? `netid=${encodeURIComponent(ioc.value)}`
      : `ssid=${encodeURIComponent(ioc.value)}`;

    const res = await fetch(`/api/proxy/wigle/api/v2/network/search?${param}&resultsPerPage=5`, {
      headers: { 'Authorization': `Basic ${apiKey}` },
    });

    if (res.status === 401 || res.status === 403) throw new Error('WiGLE authentication failed. Check your API token.');
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const json = await res.json();
    return normalize(json, ioc);
  },
};

function normalize(json, ioc) {
  const results = json.results || [];
  const total   = json.totalResults || 0;

  if (results.length === 0) {
    return {
      severity: 'info',
      fields: [
        { key: 'Query', value: ioc.value },
        { key: 'Result', value: 'No records found in WiGLE database' },
      ],
      tags: [],
    };
  }

  const first = results[0];

  // Severity: open/WEP networks are higher concern; unknown/hidden SSIDs too
  let severity = 'info';
  const encryption = (first.encryption || '').toUpperCase();
  if (encryption === 'NONE' || encryption === 'WEP') severity = 'high';
  else if (encryption === 'WPA') severity = 'medium';
  else if (total > 1) severity = 'low';

  const fields = [
    { key: 'Total Records', value: `${total.toLocaleString()}` },
    { key: 'SSID', value: first.ssid || '(hidden)' },
    { key: 'BSSID', value: first.netid || 'Unknown' },
    { key: 'Encryption', value: first.encryption || 'Unknown',
      severity: encryption === 'NONE' ? 'danger' : encryption === 'WEP' ? 'warn' : undefined },
    { key: 'Channel', value: first.channel != null ? String(first.channel) : 'Unknown' },
    { key: 'First Seen', value: first.firsttime ? formatDate(first.firsttime) : 'Unknown' },
    { key: 'Last Seen', value: first.lasttime ? formatDate(first.lasttime) : 'Unknown' },
    { key: 'Location', value: formatLocation(first) },
    { key: 'Country', value: first.country || 'Unknown' },
    { key: 'City', value: first.city || 'Unknown' },
  ];

  if (total > 1) {
    fields.push({ key: 'Additional Records', value: `${total - 1} more network(s) on record` });
  }

  const tags = [];
  if (total > 0) tags.push('wifi-tracked');
  if (encryption === 'NONE') tags.push('open-network');
  if (encryption === 'WEP') tags.push('weak-encryption');
  if (!first.ssid || first.ssid === '') tags.push('hidden-ssid');

  return { severity, fields, tags };
}

function formatLocation(net) {
  const lat = net.trilat;
  const lng = net.trilong;
  if (lat != null && lng != null) {
    return `${parseFloat(lat).toFixed(4)}, ${parseFloat(lng).toFixed(4)}`;
  }
  return 'Unknown';
}

function formatDate(isoStr) {
  try {
    return new Date(isoStr).toLocaleDateString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
    });
  } catch {
    return isoStr;
  }
}
