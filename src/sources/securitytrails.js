/**
 * SecurityTrails Source
 * https://securitytrails.com
 *
 * Supports: domains, IPv4, IPv6
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'securitytrails',
  name: 'SecurityTrails',
  category: 'Network & Infrastructure',
  supportedTypes: ['domain', 'ipv4', 'ipv6'],
  requiresKey: true,
  signupUrl: 'https://securitytrails.com/app/signup',
  rateLimit: '50 requests / month (free tier)',

  async testAuth(apiKey) {
    const res = await fetch(`/api/proxy/securitytrails/ping`, {
      headers: { 'APIKEY': apiKey }
    });
    if (res.status === 401 || res.status === 403) throw new Error('API Key invalid');
    if (!res.ok) throw new Error('Could not verify API key');
  },

  async query(ioc, apiKey) {
    let endpoint = '';
    let isDomain = ioc.type === 'domain';
    
    // Determine the base query depending on ioc type
    // SecurityTrails maps IPs to /ips/ and domains to /domain/
    if (isDomain) {
      endpoint = `/api/proxy/securitytrails/domain/${encodeURIComponent(ioc.value)}`;
    } else {
      endpoint = `/api/proxy/securitytrails/ips/${encodeURIComponent(ioc.value)}/whois`;
    }

    const res = await fetch(endpoint, {
      headers: { 'APIKEY': apiKey }
    });

    if (res.status === 401) throw new Error('Invalid SecurityTrails API Key');
    if (res.status === 429) throw new Error('SecurityTrails limit exceeded');
    if (res.status === 404) {
      return { severity: 'info', fields: [{ key: 'Result', value: 'No records found in SecurityTrails' }] };
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const json = await res.json();
    
    // For domains, try to do a fast subdomain sweep if acceptable
    let subData = null;
    if (isDomain) {
      try {
        const subReq = await fetch(`/api/proxy/securitytrails/domain/${encodeURIComponent(ioc.value)}/subdomains?children_only=false&include_inactive=false`, {
          headers: { 'APIKEY': apiKey }
        });
        if (subReq.ok) {
           subData = await subReq.json();
        }
      } catch (e) {
        // Silently fail if rate limited on the followup request
      }
    }

    return normalize(ioc.type, json, subData);
  },
};

function normalize(type, json, subData) {
  let severity = 'info';
  const fields = [];
  const tags = [];
  
  if (type === 'domain') {
    if (json.alexa_rank && json.alexa_rank > 0) {
      fields.push({ key: 'Global Rank', value: json.alexa_rank.toString() });
      if (json.alexa_rank < 50000) tags.push('popular');
    }

    if (json.current_dns) {
      if (json.current_dns.a && json.current_dns.a.values) {
        fields.push({ key: 'A Records', value: json.current_dns.a.values.map(v => v.ip).join(', ') });
      }
      if (json.current_dns.mx && json.current_dns.mx.values) {
        fields.push({ key: 'MX Records', value: json.current_dns.mx.values.map(v => v.hostname).join(', ') });
      }
      if (json.current_dns.ns && json.current_dns.ns.values) {
        fields.push({ key: 'Nameservers', value: json.current_dns.ns.values.map(v => v.hostname).join(', ') });
      }
    }

    if (json.hostname) fields.push({ key: 'Registered Hostname', value: json.hostname });
    
    if (subData && subData.subdomains) {
      const subs = subData.subdomains.map(s => `${s}.${json.hostname}`);
      
      const count = subData.subdomains.length;
      if (count > 0) {
        fields.push({
          key: 'Subdomains Enumerable',
          value: count > 10 ? `${subs.slice(0, 10).join(', ')} ... and ${count - 10} more` : subs.join(', ')
        });
      }
    }
  } else {
    // IPv4, IPv6
    // SecurityTrails usually returns WHOIS data for IPs on their free tier via the endpoint
    if (json.record && json.record.contacts) {
      const org = json.record.contacts.organization;
      if (org) fields.push({ key: 'Organization', value: org });
    }
    if (json.record && json.record.netblocks) {
       fields.push({ key: 'Netblock', value: json.record.netblocks.map(n => n.netblock).join(', ') });
    }
  }

  return { severity, fields, tags };
}
