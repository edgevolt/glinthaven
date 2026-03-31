/**
 * BGPView Source
 * https://bgpview.io
 *
 * Supports: IP addresses, ASNs
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'bgpview',
  name: 'BGPView API',
  category: 'Network & Infrastructure',
  supportedTypes: ['ipv4', 'ipv6', 'asn'],
  requiresKey: false,
  signupUrl: 'https://bgpview.io/',
  rateLimit: 'Fair use',

  async query(ioc, apiKey) {
    let endpoint = '';
    
    if (ioc.type === 'asn') {
      const asnNumber = ioc.value.replace(/AS/i, '');
      endpoint = `/api/proxy/bgpview/asn/${encodeURIComponent(asnNumber)}/prefixes`;
    } else {
      endpoint = `/api/proxy/bgpview/ip/${encodeURIComponent(ioc.value)}`;
    }

    const res = await fetch(endpoint);

    if (res.status === 404) {
      return { severity: 'info', fields: [{ key: 'Result', value: 'No global BGP routing information found.'}]};
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const json = await res.json();
    
    // Also grab basic ASN info if it's an ASN query to get the owner name
    let asnInfo = null;
    if (ioc.type === 'asn') {
       try {
         const infoReq = await fetch(`/api/proxy/bgpview/asn/${encodeURIComponent(ioc.value.replace(/AS/i, ''))}`);
         if (infoReq.ok) asnInfo = await infoReq.json();
       } catch(e) {}
    }

    return normalize(ioc.type, json, asnInfo);
  },
};

function normalize(type, json, asnInfo) {
  let severity = 'info';
  const fields = [];
  const tags = [];
  
  if (!json || json.status !== 'ok' || !json.data) {
     return { severity, fields: [{ key: 'Status', value: 'Malformed or empty BGP response'}] };
  }

  if (type === 'asn') {
    // Basic ASN info
    if (asnInfo && asnInfo.data) {
       fields.push({ key: 'ASN Holder', value: asnInfo.data.name + (asnInfo.data.description_short ? ` (${asnInfo.data.description_short})` : '') });
       fields.push({ key: 'Country', value: asnInfo.data.country_code });
    }

    const v4 = json.data.ipv4_prefixes || [];
    const v6 = json.data.ipv6_prefixes || [];
    const totalLines = v4.length + v6.length;
    
    // Show total advertised prefixes count
    fields.push({ key: 'Allocated Prefixes', value: `${v4.length} IPv4, ${v6.length} IPv6 routed prefixes.` });
    
    const displayList = [...v4.map(p => p.prefix), ...v6.map(p => p.prefix)];
    
    if (displayList.length > 0) {
      const shown = displayList.length > 20 ? displayList.slice(0, 20).join(', ') + `... and ${displayList.length - 20} more` : displayList.join(', ');
      fields.push({ key: 'Advertised IP Ranges', value: shown });
      if (displayList.length > 50) tags.push('massive-network');
    }
  } else {
    // IPv4, IPv6 logic
    const ptr = json.data.ptr_record;
    if (ptr) fields.push({ key: 'PTR Record', value: ptr });

    const activePrefixes = json.data.prefixes || [];
    if (activePrefixes.length > 0) {
      const topPrefix = activePrefixes[0];
      fields.push({ key: 'Routed NetBlock (Prefix)', value: topPrefix.prefix });
      if (topPrefix.asn) {
         fields.push({ key: 'Network Owner (ASN)', value: `AS${topPrefix.asn.asn} — ${topPrefix.asn.name} (${topPrefix.asn.country_code})` });
         tags.push(`AS${topPrefix.asn.asn}`);
      }
    } else {
      fields.push({ key: 'Routing', value: 'Not globally routable (or unadvertised BGP space)'});
    }
  }

  return { severity, fields, tags };
}
