/**
 * VirusTotal Source
 * https://www.virustotal.com
 *
 * Supports: file hashes, IPs, domains, URLs
 * Requires: free API key (4 requests/min)
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'virustotal',
  name: 'VirusTotal',
  supportedTypes: ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256'],
  requiresKey: true,
  signupUrl: 'https://www.virustotal.com/gui/join-us',
  rateLimit: '4 requests/min',

  async query(ioc, apiKey) {
    let endpoint;
    if (['md5', 'sha1', 'sha256'].includes(ioc.type)) {
      endpoint = `https://www.virustotal.com/api/v3/files/${ioc.value}`;
    } else if (ioc.type === 'domain') {
      endpoint = `https://www.virustotal.com/api/v3/domains/${ioc.value}`;
    } else if (['ipv4', 'ipv6'].includes(ioc.type)) {
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${ioc.value}`;
    } else if (ioc.type === 'url') {
      const urlId = btoa(ioc.value).replace(/=+$/, '');
      endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
    }

    const res = await fetch(endpoint, {
      headers: { 'x-apikey': apiKey },
    });

    if (res.status === 404) {
      return { severity: 'info', fields: [{ key: 'Result', value: 'Not found in VirusTotal database' }] };
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const json = await res.json();
    return normalize(json, ioc.type);
  },
};

function normalize(json, type) {
  const attrs = json.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const total = Object.values(stats).reduce((a, b) => a + b, 0);

  let severity = 'info';
  if (malicious > 5) severity = 'high';
  else if (malicious > 0 || suspicious > 0) severity = 'medium';
  else if (total > 0) severity = 'low';

  const fields = [
    { key: 'Detection', value: `${malicious}/${total} engines flagged as malicious`, severity: malicious > 0 ? 'danger' : 'good' },
  ];

  if (stats.suspicious) fields.push({ key: 'Suspicious', value: `${suspicious} engines`, severity: 'warn' });
  if (attrs.reputation !== undefined) fields.push({ key: 'Reputation', value: `${attrs.reputation}` });

  if (type === 'domain' || type === 'ipv4' || type === 'ipv6') {
    if (attrs.country) fields.push({ key: 'Country', value: attrs.country });
    if (attrs.as_owner) fields.push({ key: 'AS Owner', value: attrs.as_owner });
    if (attrs.network) fields.push({ key: 'Network', value: attrs.network });
  }

  if (['md5', 'sha1', 'sha256'].includes(type)) {
    if (attrs.meaningful_name) fields.push({ key: 'Name', value: attrs.meaningful_name });
    if (attrs.type_description) fields.push({ key: 'Type', value: attrs.type_description });
    if (attrs.size) fields.push({ key: 'Size', value: formatBytes(attrs.size) });
    if (attrs.sha256) fields.push({ key: 'SHA-256', value: attrs.sha256 });
  }

  const tags = [];
  if (attrs.tags) tags.push(...attrs.tags.slice(0, 8));
  if (malicious > 0) tags.unshift('malicious');

  return { severity, fields, tags };
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}
