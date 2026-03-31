/**
 * Netlas.io Source
 * https://netlas.io
 *
 * Supports: IPs, Domains
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'netlas',
  name: 'Netlas',
  category: 'Network & Infrastructure',
  supportedTypes: ['ipv4', 'ipv6', 'domain'],
  requiresKey: true,
  signupUrl: 'https://app.netlas.io/registration/',
  rateLimit: 'Varies by plan (Free available)',

  async testAuth(apiKey) {
    const res = await fetch(`/api/proxy/netlas/users/current/`, {
      headers: { 'X-Api-Key': apiKey }
    });
    if (res.status === 401 || res.status === 403) throw new Error('API Key invalid');
    if (!res.ok) throw new Error('Could not verify API key');
  },

  async query(ioc, apiKey) {
    const res = await fetch(`/api/proxy/netlas/host/${ioc.value}/`, {
      headers: { 'X-Api-Key': apiKey }
    });

    if (res.status === 404) {
      return { severity: 'info', fields: [{ key: 'Result', value: 'Not found in Netlas' }] };
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const json = await res.json();
    return normalize(json);
  },
};

function normalize(json) {
  const ports = json.ports || [];
  const iocs = Array.isArray(json.ioc) ? json.ioc : [];
  const domainsCount = json.domains_count || 0;
  const isVpn = json.privacy?.is_vpn;
  const isProxy = json.privacy?.is_proxy;
  const isTor = json.privacy?.is_tor;

  let severity = 'info';
  if (iocs.length > 0) severity = 'high';
  else if (isVpn || isProxy || isTor) severity = 'medium';

  const fields = [];

  if (ports.length > 0) {
    fields.push({ key: 'Open Ports', value: ports.map(p => p.port).filter(Boolean).join(', ') });
  }

  if (json.geo && json.geo.country) {
    fields.push({ key: 'Country', value: json.geo.country });
  }

  if (domainsCount > 0) {
    fields.push({ key: 'Domains Count', value: domainsCount.toString() });
  }

  if (iocs.length > 0) {
    fields.push({ key: 'Threats', value: `${iocs.length} threat indicators found`, severity: 'danger' });
    const tags = [];
    iocs.forEach(i => {
      if (i.threat) tags.push(...i.threat);
      if (i.tags) tags.push(...i.tags);
    });
    if (tags.length > 0) {
      fields.push({ key: 'Threat Tags', value: [...new Set(tags)].join(', ') });
    }
  }

  const tags = [];
  if (isVpn) tags.push('vpn');
  if (isProxy) tags.push('proxy');
  if (isTor) tags.push('tor');
  if (iocs.length > 0) tags.push('malicious');

  return { severity, fields, tags: [...new Set(tags)] };
}
