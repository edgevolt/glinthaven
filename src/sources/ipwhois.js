/**
 * IPWhois Source
 * https://ipwhois.io/
 *
 * Supports: IPv4, IPv6
 * Free tier (ipwho.is): No API key required, 1 request/second limit.
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'ipwhois',
  name: 'IPWhois',
  category: 'Network & Infrastructure',
  supportedTypes: ['ipv4', 'ipv6'],
  requiresKey: false,
  signupUrl: 'https://ipwhois.io/',
  rateLimit: 'Free tier: 1 request/second',

  async query(ioc) {
    const res = await fetch(`/api/proxy/ipwhois/${ioc.value}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const json = await res.json();
    if (!json.success) {
      return {
        severity: 'info',
        fields: [{ key: 'Result', value: json.message || 'Lookup failed' }],
        tags: [],
      };
    }

    return normalize(json);
  },
};

function normalize(json) {
  const fields = [
    { key: 'IP Type', value: json.type },
    { key: 'Country', value: `${json.country} (${json.country_code})` },
    { key: 'Region', value: json.region },
    { key: 'City', value: json.city },
    { key: 'Coordinates', value: `${json.latitude}, ${json.longitude}` },
    { key: 'ASN', value: json.connection?.asn },
    { key: 'Organization', value: json.connection?.org },
    { key: 'ISP', value: json.connection?.isp },
    { key: 'Domain', value: json.connection?.domain },
  ].filter(f => f.value != null && f.value !== '');

  const tags = [];
  if (json.security?.is_proxy) tags.push('proxy');
  if (json.security?.is_tor) tags.push('tor');
  if (json.security?.is_vpn) tags.push('vpn');
  if (json.security?.is_anonymous) tags.push('anonymous');

  let severity = 'info';
  if (tags.length > 0) severity = 'medium';

  return { severity, fields, tags };
}
