/**
 * Shodan Source
 * https://www.shodan.io
 *
 * Supports: IPv4 addresses
 * Requires: free API key
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'shodan',
  name: 'Shodan',
  category: 'Network & Infrastructure',
  supportedTypes: ['ipv4'],
  requiresKey: true,
  signupUrl: 'https://account.shodan.io/register',
  rateLimit: '1 request/sec (free tier)',

  async testAuth(apiKey) {
    const res = await fetch(`/api/proxy/shodan/api-info?key=${apiKey}`);
    if (res.status === 401) throw new Error('API Key invalid');
    if (!res.ok) throw new Error('Could not verify API key');
  },

  async query(ioc, apiKey) {
    const res = await fetch(`/api/proxy/shodan/shodan/host/${ioc.value}?key=${apiKey}`);

    if (res.status === 404) {
      return { severity: 'info', fields: [{ key: 'Result', value: 'Host not found in Shodan' }] };
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const json = await res.json();
    return normalize(json);
  },
};

function normalize(json) {
  const ports = json.ports || [];
  const vulns = json.vulns || [];

  let severity = 'info';
  if (vulns.length > 5) severity = 'high';
  else if (vulns.length > 0) severity = 'medium';
  else if (ports.length > 10) severity = 'medium';

  const fields = [
    { key: 'Organization', value: json.org || 'Unknown' },
    { key: 'OS', value: json.os || 'Unknown' },
    { key: 'Open Ports', value: ports.join(', ') || 'None detected' },
    { key: 'City', value: json.city || 'Unknown' },
    { key: 'Country', value: json.country_name || 'Unknown' },
  ];

  if (vulns.length > 0) {
    fields.push({ key: 'Vulnerabilities', value: `${vulns.length} CVEs found`, severity: 'danger' });
    fields.push({ key: 'Top CVEs', value: vulns.slice(0, 5).join(', ') });
  }

  if (json.hostnames?.length) fields.push({ key: 'Hostnames', value: json.hostnames.join(', ') });

  const tags = [];
  if (vulns.length > 0) tags.push('vulnerable');

  return { severity, fields, tags };
}
