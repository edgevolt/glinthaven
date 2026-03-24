/**
 * urlscan.io Source
 * https://urlscan.io
 *
 * Supports: IPv4, IPv6, domain, url
 * Requires: free API key
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'urlscan',
  name: 'urlscan.io',
  category: 'Sandboxing & Analysis',
  supportedTypes: ['ipv4', 'ipv6', 'domain', 'url'],
  requiresKey: true,
  signupUrl: 'https://urlscan.io/user/signup',
  rateLimit: '5000 requests/day',

  async testAuth(apiKey) {
    const res = await fetch(`/api/proxy/urlscan?q=domain:example.com`, {
      headers: { 'api-key': apiKey }
    });
    if (res.status === 401) throw new Error('API Key invalid');
    if (res.status === 429) throw new Error('Rate limit exceeded');
    if (!res.ok) throw new Error('Could not verify API key');
  },

  async query(ioc, apiKey) {
    let q = '';
    if (ioc.type === 'ipv4' || ioc.type === 'ipv6') {
      q = `ip:"${ioc.value}"`;
    } else if (ioc.type === 'domain') {
      q = `page.domain:"${ioc.value}"`;
    } else if (ioc.type === 'url') {
      q = `page.url:"${ioc.value}"`;
    }

    const res = await fetch(`/api/proxy/urlscan?q=${encodeURIComponent(q)}`, {
      headers: { 'api-key': apiKey }
    });

    if (!res.ok) {
      if (res.status === 401) throw new Error('API Key invalid');
      if (res.status === 429) throw new Error('Rate limit exceeded');
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }

    const json = await res.json();
    return normalize(json);
  },
};

function normalize(json) {
  const results = json.results || [];

  if (results.length === 0) {
    return {
      severity: 'info',
      fields: [{ key: 'Result', value: 'No recent scans found' }]
    };
  }

  // Get the most recent scan
  const latest = results[0];
  const total = json.total || results.length;

  let maliciousCount = 0;
  for (const r of results) {
    if (r.verdicts?.overall?.malicious) maliciousCount++;
  }

  let severity = 'low';
  if (maliciousCount > 0) severity = 'high';
  else if (latest.verdicts?.urlscan?.malicious) severity = 'high';

  const fields = [
    { key: 'Total Scans', value: `${total} scans found` }
  ];

  if (latest.task?.time) {
    const date = new Date(latest.task.time).toLocaleString();
    fields.push({ key: 'Latest Scan', value: date });
  }

  if (latest.page?.domain) {
    fields.push({ key: 'Domain', value: latest.page.domain });
  }

  if (latest.page?.ip) {
    fields.push({ key: 'Server IP', value: latest.page.ip });
  }

  if (latest.page?.server) {
    fields.push({ key: 'Server Type', value: latest.page.server });
  }

  if (latest.page?.asn) {
    const asnName = latest.page.asnname || latest.page.asn;
    fields.push({ key: 'ASN Name', value: asnName });
  }

  if (latest.verdicts?.overall?.malicious) {
    fields.push({ key: 'Verdict', value: 'MALICIOUS', severity: 'danger' });
  } else {
    fields.push({ key: 'Verdict', value: 'Clean', severity: 'good' });
  }

  const tags = [];
  if (maliciousCount > 0) tags.push('malicious');

  return { severity, fields, tags };
}
