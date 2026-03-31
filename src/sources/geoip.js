/**
 * GeoIP Source via IP-API.com
 * https://ip-api.com/
 *
 * Supports: IPv4, IPv6
 * Free tier: No API key required, 45 requests/minute limit (non-commercial only).
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'geoip',
  name: 'GeoIP (ip-api)',
  category: 'Network & Infrastructure',
  supportedTypes: ['ipv4', 'ipv6'],
  requiresKey: false,
  signupUrl: 'https://ip-api.com/',
  rateLimit: 'Free tier: 45 req/min',

  async query(ioc) {
    // We request specific fields to get maximum detail including proxy/hosting detection
    const fields = 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query';
    const res = await fetch(`/api/proxy/geoip/${ioc.value}?fields=${fields}`);
    
    // IP-API rate limit hit
    if (res.status === 429) throw new Error('GeoIP rate limit exceeded (45 requests/minute)');
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const json = await res.json();
    if (json.status === 'fail') {
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
    { key: 'Country', value: `${json.country} (${json.countryCode})` },
    { key: 'Region', value: json.regionName },
    { key: 'City', value: json.city },
    { key: 'Timezone', value: json.timezone },
    { key: 'Zip / Postal', value: json.zip },
    { key: 'Coordinates', value: `${json.lat}, ${json.lon}` },
    { key: 'ASN/Network', value: json.as },
    { key: 'ISP', value: json.isp },
    { key: 'Organization', value: json.org },
  ].filter(f => f.value != null && f.value !== '');

  const tags = [];
  if (json.mobile) tags.push('mobile-connection');
  if (json.proxy) tags.push('proxy/vpn');
  if (json.hosting) tags.push('datacenter/hosting');

  let severity = 'info';
  if (json.proxy || json.hosting) severity = 'low';

  return { severity, fields, tags };
}
