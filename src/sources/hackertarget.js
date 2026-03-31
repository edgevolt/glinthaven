/**
 * HackerTarget Source
 * https://hackertarget.com
 *
 * Supports: domains (DNS Enum, Subdomains), IPs (Reverse IP)
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'hackertarget',
  name: 'HackerTarget',
  category: 'Network & Infrastructure',
  supportedTypes: ['domain', 'ipv4', 'ipv6'],
  requiresKey: false,
  signupUrl: 'https://hackertarget.com/',
  rateLimit: '100 queries / day per IP',

  async query(ioc, apiKey) {
    const isIp = ['ipv4', 'ipv6'].includes(ioc.type);
    
    // We'll run a primary and secondary lookup depending on the type
    let primaryReq, secondaryReq, traceReq;
    
    if (isIp) {
      // Reverse IP lookup to find domains hosted on this IP
      primaryReq = fetch(`/api/proxy/hackertarget/reverseiplookup?q=${encodeURIComponent(ioc.value)}`);
    } else {
      // Domain lookup
      primaryReq = fetch(`/api/proxy/hackertarget/dnslookup?q=${encodeURIComponent(ioc.value)}`);
      secondaryReq = fetch(`/api/proxy/hackertarget/hostsearch?q=${encodeURIComponent(ioc.value)}`);
    }

    // Always fetch an MTR
    traceReq = fetch(`/api/proxy/hackertarget/mtr?q=${encodeURIComponent(ioc.value)}`).catch(() => null);

    const [primaryRes, secondaryRes, traceRes] = await Promise.all([
      primaryReq,
      secondaryReq ? secondaryReq : Promise.resolve(null),
      traceReq
    ]);

    if (!primaryRes.ok) throw new Error(`HTTP ${primaryRes.status}: ${primaryRes.statusText}`);

    // The backend intercepts json but hackertarget returns raw text which might be json-serialized as a string by our proxy
    let primaryData = await primaryRes.json();
    let secondaryData = secondaryRes && secondaryRes.ok ? await secondaryRes.json() : '';
    let traceData = traceRes && traceRes.ok ? await traceRes.json() : '';

    return normalize(ioc.type, primaryData, secondaryData, traceData);
  },
};

function normalize(type, primaryText, secondaryText, traceText) {
  let severity = 'info';
  const fields = [];
  const tags = [];
  
  // Clean up proxy-jsonified text if it's passed as a literal string
  if (typeof primaryText !== 'string') primaryText = JSON.stringify(primaryText);
  if (typeof secondaryText !== 'string') secondaryText = JSON.stringify(secondaryText || '');
  if (typeof traceText !== 'string') traceText = JSON.stringify(traceText || '');

  // Handle errors thrown back by the free API (e.g. rate limit)
  if (primaryText.includes('API count exceeded') || secondaryText.includes('API count exceeded')) {
    throw new Error('HackerTarget free API limit exceeded (100 daily limit hit).');
  }
  if (primaryText.includes('error check your api query')) {
    return { severity: 'info', fields: [{ key: 'Result', value: 'Invalid query format' }] };
  }

  if (['ipv4', 'ipv6'].includes(type)) {
    // Reverse IP output
    const lines = primaryText.split(/[\\n\n]/).filter(l => l.trim() && l !== '"' && !l.includes('No records found'));
    if (lines.length > 0) {
      const displayLines = lines.length > 15 ? [...lines.slice(0, 15), `...and ${lines.length - 15} more`] : lines;
      fields.push({ key: 'Hosted Domains', value: displayLines.join(', ') });
    } else {
      fields.push({ key: 'Hosted Domains', value: 'None identified' });
    }
  } else {
    // DNS Lookup output
    const dnsLines = primaryText.split(/[\\n\n]/).filter(l => l.trim() && l !== '"');
    
    // Group DNS Records
    const aRecords = [];
    const nsRecords = [];
    const mxRecords = [];
    const txtRecords = [];
    
    dnsLines.forEach(line => {
      if (line.includes(' : A : ')) aRecords.push(line.split(' : A : ')[1]);
      else if (line.includes(' : NS : ')) nsRecords.push(line.split(' : NS : ')[1]);
      else if (line.includes(' : MX : ')) mxRecords.push(line.split(' : MX : ')[1]);
      else if (line.includes(' : TXT : ')) txtRecords.push(line.split(' : TXT : ')[1]);
    });
    
    if (aRecords.length > 0) fields.push({ key: 'A Records', value: aRecords.join(', ') });
    if (nsRecords.length > 0) fields.push({ key: 'Nameservers', value: nsRecords.join(', ') });
    if (mxRecords.length > 0) fields.push({ key: 'Mail Servers', value: mxRecords.join(', ') });
    if (txtRecords.length > 0) fields.push({ key: 'TXT Records', value: txtRecords.map(t => t.slice(0, 50) + (t.length > 50 ? '...' : '')).join(' | ') });

    // Host search output (Subdomains)
    const hostLines = secondaryText.split(/[\\n\n]/).filter(l => l.trim() && l !== '"');
    if (hostLines.length > 0) {
      const subs = hostLines.map(l => l.split(',')[0]).filter(Boolean);
      const uniqueSubs = [...new Set(subs)];
      if (uniqueSubs.length > 0) {
        fields.push({ 
          key: 'Subdomains Detected', 
          value: uniqueSubs.length > 10 ? `${uniqueSubs.slice(0, 10).join(', ')} ... (${uniqueSubs.length} total)` : uniqueSubs.join(', ') 
        });
        if (uniqueSubs.length > 10) tags.push('large-infrastructure');
      }
    }
  }

  // Handle MTR Traceroute text block natively
  if (traceText && !traceText.includes('API count exceeded') && !traceText.includes('error check your api query')) {
    const lines = traceText.split(/[\\n\n]/).filter(l => l.trim() && l !== '"' && !l.startsWith('HOST:') && !l.startsWith('Start:'));
    if (lines.length > 0) {
      // Condense traceroute to multiline view 
      fields.push({ key: 'MTR Traceroute Path', value: lines.join('\n') });
    }
  }

  return { severity, fields, tags };
}
