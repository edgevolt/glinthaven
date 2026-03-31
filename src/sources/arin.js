/**
 * ARIN RDAP Source
 * https://rdap.arin.net/registry/ip/
 *
 * Supports: IPv4, IPv6
 * Free tier: No API key required, open REST standard.
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'arin',
  name: 'ARIN RDAP',
  category: 'Network & Infrastructure',
  supportedTypes: ['ipv4', 'ipv6'],
  requiresKey: false,
  signupUrl: 'https://www.arin.net/resources/registry/whois/rdap/',
  rateLimit: 'Public open registry',

  async query(ioc) {
    const res = await fetch(`/api/proxy/arin/${ioc.value}`);
    if (res.status === 404) {
      return {
        severity: 'info',
        fields: [{ key: 'Result', value: 'IP not found in ARIN registry (likely managed by RIPE/APNIC/LACNIC/AFRINIC)' }],
        tags: [],
      };
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const json = await res.json();
    return normalize(json);
  },
};

function normalize(json) {
  const fields = [];

  if (json.name) fields.push({ key: 'Network Name', value: json.name });
  if (json.type) fields.push({ key: 'Type', value: json.type });
  if (json.parentHandle) fields.push({ key: 'Parent Handle', value: json.parentHandle });
  
  if (json.startAddress && json.endAddress) {
    fields.push({ key: 'IP Range', value: `${json.startAddress} - ${json.endAddress}` });
  }

  // Parse entities (organizations, abuse contacts, etc.)
  if (json.entities && json.entities.length > 0) {
    const orgs = [];
    for (const ent of json.entities) {
      if (ent.vcardArray && ent.vcardArray.length > 1) {
        // vCard format parsing: look for 'fn' (full name), 'org'
        const fnProp = ent.vcardArray[1].find(p => p[0] === 'fn');
        const orgProp = ent.vcardArray[1].find(p => p[0] === 'org');

        if (orgProp && orgProp[3]) {
          orgs.push(orgProp[3]);
        } else if (fnProp && fnProp[3]) {
          orgs.push(fnProp[3]);
        }
      }
    }
    
    if (orgs.length > 0) {
      fields.push({ key: 'Registrants', value: [...new Set(orgs)].join(', ') });
    }
  }

  // CIDR notation (usually in the remarks or derived from events, but sometimes unavailable directly without parsing)
  // We'll leave it simple to ARIN JSON top-level properties.

  return { severity: 'info', fields, tags: ['registry-data'] };
}
