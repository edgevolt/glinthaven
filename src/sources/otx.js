/**
 * AlienVault OTX Source
 * https://otx.alienvault.com
 *
 * Supports: IPv4, IPv6, domains, URLs, file hashes, CVEs
 * API key optional — works without one, key gives higher rate limits
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'otx',
  name: 'AlienVault OTX',
  supportedTypes: ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'cve'],
  requiresKey: false,
  signupUrl: 'https://otx.alienvault.com/accounts/signup/',
  rateLimit: 'Unlimited (higher with key)',

  async query(ioc, apiKey) {
    let endpoint;
    if (['ipv4', 'ipv6'].includes(ioc.type)) {
      const section = ioc.type === 'ipv4' ? 'IPv4' : 'IPv6';
      endpoint = `https://otx.alienvault.com/api/v1/indicators/${section}/${ioc.value}/general`;
    } else if (ioc.type === 'domain') {
      endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${ioc.value}/general`;
    } else if (ioc.type === 'url') {
      endpoint = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(ioc.value)}/general`;
    } else if (['md5', 'sha1', 'sha256'].includes(ioc.type)) {
      endpoint = `https://otx.alienvault.com/api/v1/indicators/file/${ioc.value}/general`;
    } else if (ioc.type === 'cve') {
      endpoint = `https://otx.alienvault.com/api/v1/indicators/cve/${ioc.value}/general`;
    }

    if (!endpoint) throw new Error('Unsupported IOC type for OTX');

    const headers = {};
    if (apiKey) headers['X-OTX-API-KEY'] = apiKey;

    const res = await fetch(endpoint, { headers });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const json = await res.json();
    return normalize(json, ioc.type);
  },
};

function normalize(json, type) {
  const pulseCount = json.pulse_info?.count || 0;
  const pulses = json.pulse_info?.pulses || [];

  let severity = 'info';
  if (pulseCount >= 10) severity = 'high';
  else if (pulseCount >= 3) severity = 'medium';
  else if (pulseCount > 0) severity = 'low';

  const fields = [
    { key: 'Pulse Count', value: `${pulseCount} threat reports`, severity: pulseCount >= 10 ? 'danger' : pulseCount > 0 ? 'warn' : 'good' },
  ];

  if (type === 'cve') {
    if (json.cvss) fields.push({ key: 'CVSS Score', value: `${json.cvss.Score || 'N/A'}`, severity: (json.cvss.Score || 0) >= 7 ? 'danger' : 'neutral' });
    if (json.description) fields.push({ key: 'Description', value: json.description.slice(0, 200) });
    if (json.modified) fields.push({ key: 'Last Modified', value: json.modified });
  }

  if (json.country_name) fields.push({ key: 'Country', value: json.country_name });
  if (json.asn) fields.push({ key: 'ASN', value: json.asn });

  if (pulses.length > 0) {
    const topPulses = pulses.slice(0, 3).map(p => p.name).join('; ');
    fields.push({ key: 'Related Pulses', value: topPulses });
  }

  const tags = [];
  if (pulseCount > 0) tags.push('reported');
  pulses.slice(0, 3).forEach(p => {
    if (p.tags) tags.push(...p.tags.slice(0, 2));
  });

  return { severity, fields, tags: [...new Set(tags)].slice(0, 8) };
}
