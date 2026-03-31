/**
 * Certificate Transparency Source (crt.sh)
 * https://crt.sh
 *
 * Supports: domains (Subdomain discovery via SSL cert logs)
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'crtsh',
  name: 'crt.sh (Certificate Transparency)',
  category: 'Network & Infrastructure',
  supportedTypes: ['domain'],
  requiresKey: false,
  signupUrl: 'https://crt.sh/',
  rateLimit: 'Slow for massive domains',

  async query(ioc, apiKey) {
    if (ioc.type !== 'domain') throw new Error('Unsupported IOC type for crt.sh');

    // To cast a wider net, query with wildcard prefix for the domain payload
    const endpoint = `/api/proxy/crtsh?q=%.${encodeURIComponent(ioc.value)}`;
    const res = await fetch(endpoint);

    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    // Wait for large JSON response
    const json = await res.json();
    return normalize(json, ioc.value);
  },
};

function normalize(json, targetDomain) {
  let severity = 'info';
  const fields = [];
  const tags = [];

  // Edge cases where crt.sh drops errors or timeout DB text instead of JSON
  if (!Array.isArray(json)) {
    return { severity: 'info', fields: [{ key: 'Status', value: 'No results or rate limited.' }] };
  }

  const certs = json;

  let allHostnames = new Set();
  let subdomains = new Set();
  let isWildcardFound = false;
  
  // Extract all name_value identifiers (often multi-line if SANs are present)
  for (let record of certs) {
    if (record.name_value) {
      record.name_value.split('\\n').forEach(val => {
        val = val.trim().toLowerCase();
        allHostnames.add(val);
        if (val.startsWith('*.')) {
           isWildcardFound = true;
           val = val.substring(2);
        }
        if (val.endsWith(targetDomain)) {
           subdomains.add(val);
        }
      });
    }
  }

  fields.push({ key: 'Total Certificates Tracked', value: certs.length.toString() });

  if (isWildcardFound) {
    fields.push({ key: 'Wildcard Cert', value: 'Detected (Infrastructure obscures exact subdomains)' });
    tags.push('wildcard');
  }

  const subsArray = [...subdomains];
  if (subsArray.length > 0) {
    // Only show the first 15 so UI doesn't lag hard on mega domains
    const displaySubs = subsArray.length > 15 ? subsArray.slice(0, 15).join(', ') + `... and ${subsArray.length - 15} more` : subsArray.join(', ');
    fields.push({ key: 'Unique Subdomains (SANs)', value: displaySubs });

    if (subsArray.length > 15) tags.push('large-infrastructure');
  }

  return { severity, fields, tags };
}
