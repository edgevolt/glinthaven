/**
 * AbuseIPDB Source
 * https://www.abuseipdb.com
 *
 * Supports: IPv4 and IPv6 addresses
 * Requires: free API key (1,000 checks/day)
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'abuseipdb',
  name: 'AbuseIPDB',
  supportedTypes: ['ipv4', 'ipv6'],
  requiresKey: true,
  signupUrl: 'https://www.abuseipdb.com/register',
  rateLimit: '1,000 checks/day',

  async query(ioc, apiKey) {
    const res = await fetch(
      `/api/proxy/abuseipdb?ipAddress=${encodeURIComponent(ioc.value)}`,
      { headers: { Key: apiKey, Accept: 'application/json' } }
    );

    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    const json = await res.json();
    return normalize(json);
  },
};

function normalize(json) {
  const d = json.data || {};
  const score = d.abuseConfidenceScore || 0;

  let severity = 'info';
  if (score >= 75) severity = 'high';
  else if (score >= 25) severity = 'medium';
  else if (score > 0) severity = 'low';

  const fields = [
    { key: 'Abuse Score', value: `${score}%`, severity: score >= 75 ? 'danger' : score >= 25 ? 'warn' : 'good' },
    { key: 'Total Reports', value: `${d.totalReports || 0}` },
    { key: 'ISP', value: d.isp || 'Unknown' },
    { key: 'Domain', value: d.domain || 'Unknown' },
    { key: 'Country', value: d.countryCode || 'Unknown' },
    { key: 'Usage Type', value: d.usageType || 'Unknown' },
  ];

  if (d.isWhitelisted) fields.push({ key: 'Whitelisted', value: 'Yes', severity: 'good' });
  if (d.isTor) fields.push({ key: 'Tor Node', value: 'Yes', severity: 'warn' });

  const tags = [];
  if (score >= 75) tags.push('malicious');
  if (d.isTor) tags.push('tor');
  if (d.isWhitelisted) tags.push('whitelisted');

  return { severity, fields, tags };
}
